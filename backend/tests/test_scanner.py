import asyncio
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from webriskaudit import METHODOLOGY_VERSION, __version__
from webriskaudit.checks import ALL_CHECKS, DISPLAY_ORDER
from webriskaudit.checks.base import Check, CheckFn, Outcome
from webriskaudit.context import ScanContext
from webriskaudit.models import Category, Status
from webriskaudit.net.domain import InvalidDomainError
from webriskaudit.net.http import GuardedFetcher
from webriskaudit.net.types import (
    DnsUnavailableError,
    FetchError,
    FetchErrorReason,
    HttpResponse,
    NoAnswerError,
    TlsProbeError,
    TlsProbeResult,
)
from webriskaudit.scanner import (
    DnsUnavailableScanError,
    DomainNotFoundError,
    NonPublicTargetError,
    Scanner,
)

from .fakes import DnsAnswer, FakeFetcher, FakeResolver, FakeTlsProber, response

PUBLIC_V4 = "93.184.215.14"
HOME = "https://example.com/"
PLAIN = "http://example.com/"

GOOD_TXT: dict[str, DnsAnswer] = {
    "example.com": ["v=spf1 include:_spf.example.net -all"],
    "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
    "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"],
}
GOOD_HEADERS = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    (
        "Content-Security-Policy",
        "script-src 'nonce-r4nd0m' 'strict-dynamic'; frame-ancestors 'self'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Server", "nginx"),
]


def good_certificate() -> TlsProbeResult:
    now = datetime.now(UTC)
    return TlsProbeResult(
        verified=True,
        protocol="TLSv1.3",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=60),
        issuer="Let's Encrypt (R11)",
        subject_alt_names=("example.com",),
    )


def make_scanner(
    addresses: DnsAnswer | None = None,
    *,
    txt: dict[str, DnsAnswer] | None = None,
    pages: dict[str, HttpResponse | FetchError] | None = None,
    checks: Sequence[Check] = ALL_CHECKS,
    deadline: float = 45.0,
    check_timeout: float = 30.0,
) -> Scanner:
    resolver = FakeResolver(
        txt_records=dict(txt or {}),
        address_records={"example.com": [PUBLIC_V4] if addresses is None else addresses},
    )
    return Scanner(
        resolver=resolver,
        fetcher=FakeFetcher(dict(pages or {})),
        tls=FakeTlsProber(good_certificate()),
        checks=checks,
        deadline=deadline,
        check_timeout=check_timeout,
    )


# --- Pre-check -------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "this-domain-does-not-exist.invalid",
        "localhost",
        "printer.local",
        "127.0.0.1",
        "http://[::1]/",
        "",
        "example",
    ],
)
async def test_invalid_input_is_refused_before_any_lookup(raw: str) -> None:
    scanner = make_scanner()
    with pytest.raises(InvalidDomainError):
        await scanner.scan(raw)
    assert isinstance(scanner.resolver, FakeResolver)
    assert scanner.resolver.queries == []


async def test_regression_nxdomain_is_refused_instead_of_scored() -> None:
    # v1 awarded "benefit of the doubt" points and scored a non-existent domain 75/100.
    resolver = FakeResolver()  # every name is NXDOMAIN
    fetcher = FakeFetcher()
    scanner = Scanner(resolver=resolver, fetcher=fetcher, tls=FakeTlsProber(good_certificate()))
    with pytest.raises(DomainNotFoundError) as caught:
        await scanner.scan("no-such-name-1f3a.example.org")
    assert caught.value.domain == "no-such-name-1f3a.example.org"
    assert resolver.queries == [("A/AAAA", "no-such-name-1f3a.example.org")]
    assert fetcher.requests == []


async def test_dns_failure_in_the_precheck_is_reported() -> None:
    scanner = make_scanner(DnsUnavailableError("example.com"))
    with pytest.raises(DnsUnavailableScanError):
        await scanner.scan("example.com")


@pytest.mark.parametrize(
    "addresses",
    [["10.0.0.5"], [PUBLIC_V4, "127.0.0.1"], ["::ffff:127.0.0.1"], ["169.254.169.254"]],
)
async def test_non_public_addresses_are_refused(addresses: list[str]) -> None:
    scanner = make_scanner(addresses)
    with pytest.raises(NonPublicTargetError):
        await scanner.scan("example.com")
    assert isinstance(scanner.fetcher, FakeFetcher)
    assert scanner.fetcher.requests == []


async def test_input_is_normalized_before_scanning() -> None:
    report = await make_scanner().scan("  HTTPS://Example.COM:443/path?q=1  ")
    assert report.domain == "example.com"


# --- Reports ---------------------------------------------------------------------


async def test_well_configured_domain_scores_100() -> None:
    pages: dict[str, HttpResponse | FetchError] = {
        PLAIN: response(HOME, redirects=(PLAIN,)),
        HOME: response(HOME, headers=GOOD_HEADERS),
    }
    before = datetime.now(UTC)
    report = await make_scanner(txt=GOOD_TXT, pages=pages).scan("example.com")

    assert [c.id for c in report.checks] == list(DISPLAY_ORDER)
    assert {c.id: c.status for c in report.checks if c.weight} == {
        c.id: Status.PASS for c in report.checks if c.weight
    }
    assert (report.score, report.grade) == (100, "A")
    assert report.coverage.model_dump() == {"scored": 12, "inconclusive": 0, "total": 12}
    assert [(c.id, c.score) for c in report.categories] == [
        (Category.EMAIL, 100),
        (Category.TRANSPORT, 100),
        (Category.HEADERS, 100),
    ]
    assert report.scanned_at.tzinfo is UTC
    assert before <= report.scanned_at <= datetime.now(UTC)
    assert report.duration_ms >= 0
    assert (report.scanner_version, report.methodology_version) == (
        __version__,
        METHODOLOGY_VERSION,
    )


async def test_all_inconclusive_has_no_score() -> None:
    @dataclass
    class DownResolver(FakeResolver):
        async def txt(self, name: str) -> list[str]:
            raise DnsUnavailableError(name)

    timeout = FetchError(FetchErrorReason.TIMEOUT, "no response within 10 s")
    scanner = Scanner(
        resolver=DownResolver(address_records={"example.com": [PUBLIC_V4]}),
        fetcher=FakeFetcher({PLAIN: timeout, HOME: timeout}),
        tls=FakeTlsProber(TlsProbeError(FetchErrorReason.TIMEOUT, "no TLS handshake")),
    )
    report = await scanner.scan("example.com")
    scored = [c for c in report.checks if c.weight]
    assert all(c.status is Status.INCONCLUSIVE for c in scored)
    assert (report.score, report.grade) == (None, None)
    assert report.coverage.model_dump() == {"scored": 0, "inconclusive": 12, "total": 12}
    assert all(c.score is None for c in report.categories)


async def test_domain_without_addresses_still_runs_email_checks() -> None:
    scanner = make_scanner(NoAnswerError("example.com"), txt=GOOD_TXT)
    report = await scanner.scan("example.com")
    by_id = {c.id: c for c in report.checks}

    assert [by_id[i].status for i in ("email.spf", "email.dmarc", "email.dkim")] == [
        Status.PASS
    ] * 3
    others = [c for c in report.checks if c.category is not Category.EMAIL]
    assert all(c.status is Status.INCONCLUSIVE for c in others)
    assert all("no A/AAAA record" in c.summary for c in others)
    assert isinstance(scanner.fetcher, FakeFetcher)
    assert isinstance(scanner.tls, FakeTlsProber)
    assert (scanner.fetcher.requests, scanner.tls.probes) == ([], [])
    # 25 of 90 points completed is under half, so there is no overall score.
    assert (report.score, report.coverage.scored) == (None, 3)


# --- Concurrency, timeouts and the deadline -------------------------------------------


def check(check_id: str, run: CheckFn) -> Check:
    return Check(check_id, check_id, Category.EMAIL, 10, run)


async def passes(ctx: ScanContext) -> Outcome:
    return Outcome(Status.PASS, "fine")


async def hangs(ctx: ScanContext) -> Outcome:
    await asyncio.sleep(3600)
    return Outcome(Status.PASS, "unreachable")


async def test_checks_run_concurrently() -> None:
    started = asyncio.Event()

    async def waits_for_the_other(ctx: ScanContext) -> Outcome:
        await started.wait()
        return Outcome(Status.PASS, "the other check was already running")

    async def signals(ctx: ScanContext) -> Outcome:
        started.set()
        return Outcome(Status.PASS, "started")

    checks = [check("t.waits", waits_for_the_other), check("t.signals", signals)]
    report = await make_scanner(checks=checks, deadline=5.0).scan("example.com")
    assert [c.status for c in report.checks] == [Status.PASS, Status.PASS]


async def test_deadline_makes_slow_checks_inconclusive() -> None:
    checks = [check("t.fast", passes), check("t.slow", hangs)]
    begun = time.perf_counter()
    report = await make_scanner(checks=checks, deadline=0.05).scan("example.com")
    assert time.perf_counter() - begun < 1
    fast, slow = report.checks
    assert fast.status is Status.PASS
    assert (slow.status, slow.points) == (Status.INCONCLUSIVE, 0)
    assert "timed out" in slow.summary
    assert report.coverage.model_dump() == {"scored": 1, "inconclusive": 1, "total": 2}


async def test_per_check_timeout_applies_before_the_deadline() -> None:
    checks = [check("t.fast", passes), check("t.slow", hangs)]
    report = await make_scanner(checks=checks, deadline=30.0, check_timeout=0.05).scan(
        "example.com"
    )
    assert [c.status for c in report.checks] == [Status.PASS, Status.INCONCLUSIVE]
    assert report.checks[1].summary == "The check did not finish within 0.05 seconds and timed out."


async def test_requests_still_running_at_the_deadline_are_cancelled() -> None:
    @dataclass
    class HangingFetcher:
        cancelled: bool = False

        async def get(self, url: str) -> HttpResponse:
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                self.cancelled = True
                raise
            raise AssertionError("unreachable")

    async def fetches(ctx: ScanContext) -> Outcome:
        await ctx.homepage()
        return Outcome(Status.PASS, "unreachable")

    fetcher = HangingFetcher()
    scanner = Scanner(
        resolver=FakeResolver(address_records={"example.com": [PUBLIC_V4]}),
        fetcher=fetcher,
        tls=FakeTlsProber(good_certificate()),
        checks=[check("t.fetches", fetches)],
        deadline=0.05,
    )
    report = await scanner.scan("example.com")
    await asyncio.sleep(0)  # let the cancellation reach the request
    assert report.checks[0].status is Status.INCONCLUSIVE
    assert fetcher.cancelled


# --- Hostile sites ----------------------------------------------------------------


@pytest.mark.parametrize("location", [":http://[", ":https://a-[::1"])
async def test_malformed_location_is_a_fetch_error_not_a_crash(
    location: str, caplog: pytest.LogCaptureFixture
) -> None:
    # urljoin raised ValueError here, which escaped the fetcher, made 12 checks
    # "fail unexpectedly" and logged a traceback for each.
    def network(request: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers=[("Location", location)])

    resolver = FakeResolver(address_records={"example.com": [PUBLIC_V4]})
    fetcher = GuardedFetcher(resolver, transport=httpx.MockTransport(network))
    scanner = Scanner(
        resolver=resolver, fetcher=fetcher, tls=FakeTlsProber(TlsProbeResult(verified=True))
    )
    caplog.set_level(logging.ERROR)
    report = await scanner.scan("example.com")
    assert all(check.summary != "The check failed unexpectedly." for check in report.checks)
    hsts = next(check for check in report.checks if check.id == "transport.hsts")
    assert (
        hsts.summary == "The home page could not be fetched: the server sent a malformed response."
    )
    assert not [record for record in caplog.records if record.exc_info]


HOSTILE_META = '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'">'


class HostileFetcher(FakeFetcher):
    """A home page built to bloat the report: 1 MB of <meta> policies, no </head>."""

    async def get(self, url: str) -> HttpResponse:
        if url.startswith("http://"):
            return response(HOME, redirects=(url,))
        headers = [
            ("Content-Type", "text/html"),
            ("Content-Security-Policy", ", ".join(["script-src 'self'"] * 5000)),
            *[("Server", f"nginx/1.{i}") for i in range(500)],
        ]
        return response(HOME, headers=headers, body=(HOSTILE_META * 14_000)[:1_000_000])


async def test_report_size_is_bounded_for_a_hostile_site() -> None:
    txt: dict[str, DnsAnswer] = {
        "example.com": [f"v=spf1 ip4:192.0.2.{i % 250} -all" for i in range(5000)],
        "_dmarc.example.com": [
            f"v=DMARC1; p=reject; rua=mailto:{i}@example.com" for i in range(3500)
        ],
    }
    scanner = Scanner(
        resolver=FakeResolver(txt_records=txt, address_records={"example.com": [PUBLIC_V4]}),
        fetcher=HostileFetcher(),
        tls=FakeTlsProber(TlsProbeResult(verified=True)),
    )
    report = await scanner.scan("example.com")
    assert len(report.model_dump_json()) < 64_000
    assert all(len(check.evidence) <= 20 for check in report.checks)
