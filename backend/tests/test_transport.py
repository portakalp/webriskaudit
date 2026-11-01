from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from webriskaudit.checks.base import run_check
from webriskaudit.checks.transport import (
    CHECKS,
    HTTPS_REDIRECT,
    TLS_CERTIFICATE,
    evaluate_certificate,
    evaluate_probe_error,
    evaluate_redirect,
    evaluate_redirect_error,
    is_ipv6_only,
    is_same_site_host,
)
from webriskaudit.models import Category, Evidence, Status
from webriskaudit.net.http import GuardedFetcher
from webriskaudit.net.types import (
    FetchError,
    FetchErrorReason,
    TlsProbeError,
    TlsProbeResult,
)

from .fakes import FakeFetcher, FakeResolver, FakeTlsProber, make_context, response

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
DAY = timedelta(days=1)


def cert(lifetime: timedelta, remaining: timedelta, protocol: str = "TLSv1.3") -> TlsProbeResult:
    """A verified certificate of the given lifetime with ``remaining`` left at NOW."""
    return TlsProbeResult(
        verified=True,
        protocol=protocol,
        not_before=NOW - (lifetime - remaining),
        not_after=NOW + remaining,
        issuer="Let's Encrypt",
        subject_alt_names=("example.com", "www.example.com"),
    )


def labels(items: list[Evidence]) -> dict[str, str]:
    return {item.label: item.value for item in items}


# --- registry ------------------------------------------------------------------


def test_registry_matches_the_specification() -> None:
    assert [(c.id, c.title, c.category, c.weight) for c in CHECKS] == [
        ("transport.tls_certificate", "TLS certificate", Category.TRANSPORT, 15),
        ("transport.https_redirect", "HTTP to HTTPS redirect", Category.TRANSPORT, 5),
    ]
    assert all(c.references for c in CHECKS)
    assert all(r.url.startswith("https://") for c in CHECKS for r in c.references)


# --- TLS certificate -------------------------------------------------------------


@pytest.mark.parametrize(
    ("lifetime_days", "remaining", "expected"),
    [
        # 90-day certificate: a quarter is 22.5 days.
        (90, 60 * DAY, Status.PASS),
        (90, 22.5 * DAY, Status.PASS),
        (90, 22.5 * DAY - timedelta(seconds=1), Status.WARN),
        (90, 7 * DAY, Status.WARN),
        (90, 7 * DAY - timedelta(seconds=1), Status.FAIL),
        (90, 6 * DAY, Status.FAIL),
        (90, timedelta(hours=3), Status.FAIL),
        (90, timedelta(0), Status.FAIL),
        (90, -DAY, Status.FAIL),
        # 47-day certificate: a quarter is 11.75 days.
        (47, 30 * DAY, Status.PASS),
        (47, 11.75 * DAY, Status.PASS),
        (47, 11 * DAY, Status.WARN),
        (47, 6 * DAY, Status.FAIL),
        # 398-day certificate: a quarter is 99.5 days.
        (398, 200 * DAY, Status.PASS),
        (398, 99.5 * DAY, Status.PASS),
        (398, 99 * DAY, Status.WARN),
        (398, 6 * DAY, Status.FAIL),
        # 45-day certificate: a sixth is 7.5 days, so the 7-day floor still applies.
        (45, 11 * DAY, Status.WARN),
        (45, 7 * DAY - timedelta(seconds=1), Status.FAIL),
    ],
)
def test_certificate_validity(lifetime_days: int, remaining: timedelta, expected: Status) -> None:
    outcome = evaluate_certificate(cert(lifetime_days * DAY, remaining), NOW)
    assert outcome.status is expected
    assert (outcome.remediation is None) == (expected is Status.PASS)


@pytest.mark.parametrize(
    ("remaining", "summary"),
    [
        (6 * DAY, "The certificate expires in 6 days."),
        (DAY + timedelta(hours=2), "The certificate expires in 1 day."),
        (timedelta(hours=3), "The certificate expires in 3 hours."),
        (timedelta(minutes=30), "The certificate expires in less than an hour."),
        (-2 * DAY, "The certificate expired on 2026-10-30T12:00:00Z."),
        (20 * DAY, "The certificate has 20 days of its 90 days left, so renewal is overdue."),
        (60 * DAY, "The certificate from Let's Encrypt is trusted and valid for 60 more days."),
    ],
)
def test_certificate_summaries(remaining: timedelta, summary: str) -> None:
    assert evaluate_certificate(cert(90 * DAY, remaining), NOW).summary == summary


SHORT_LIVED = timedelta(hours=160)  # Let's Encrypt's "shortlived" profile


@pytest.mark.parametrize(
    ("remaining", "expected", "summary"),
    [
        (
            SHORT_LIVED - timedelta(minutes=5),
            Status.PASS,
            "The certificate from Let's Encrypt is trusted and valid for 6 more days.",
        ),
        (
            timedelta(hours=80),
            Status.PASS,
            "The certificate from Let's Encrypt is trusted and valid for 3 more days.",
        ),
        # A quarter of 160 hours is 40 hours, a sixth is about 26.7 hours.
        (
            timedelta(hours=39),
            Status.WARN,
            "The certificate has 1 day of its 160 hours left, so renewal is overdue.",
        ),
        (timedelta(hours=26), Status.FAIL, "The certificate expires in 1 day."),
        (timedelta(hours=10), Status.FAIL, "The certificate expires in 10 hours."),
    ],
)
def test_short_lived_certificates_are_judged_by_their_lifetime(
    remaining: timedelta, expected: Status, summary: str
) -> None:
    outcome = evaluate_certificate(cert(SHORT_LIVED, remaining), NOW)
    assert (outcome.status, outcome.summary) == (expected, summary)
    assert labels(outcome.evidence)["Lifetime"] == "160 hours"


def test_certificate_evidence() -> None:
    names = tuple(f"host{i}.example.com" for i in range(7))
    result = TlsProbeResult(
        verified=True,
        protocol="TLSv1.3",
        not_before=NOW - 30 * DAY,
        not_after=NOW + 60 * DAY,
        issuer="Let's Encrypt",
        subject_alt_names=names,
    )
    shown = labels(evaluate_certificate(result, NOW).evidence)
    assert shown == {
        "Issuer": "Let's Encrypt",
        "Valid from": "2026-10-02T12:00:00Z",
        "Valid until": "2026-12-31T12:00:00Z",
        "Days left": "60",
        "Lifetime": "90 days",
        "Protocol": "TLSv1.3",
        "Names": ", ".join(names[:5]) + " and 2 more",
    }


def test_naive_datetimes_are_read_as_utc() -> None:
    result = TlsProbeResult(
        verified=True,
        not_before=datetime(2026, 9, 1),  # naive on purpose
        not_after=datetime(2026, 11, 30),
    )
    assert evaluate_certificate(result, NOW).status is Status.PASS


def test_outdated_protocol_warns() -> None:
    outcome = evaluate_certificate(cert(90 * DAY, 60 * DAY, protocol="TLSv1.1"), NOW)
    assert outcome.status is Status.WARN
    assert outcome.summary == "The server negotiated TLSv1.1, which is deprecated."
    assert outcome.remediation is not None
    assert "TLSv1.2 TLSv1.3" in outcome.remediation


@pytest.mark.parametrize("protocol", ["TLSv1.2", "TLSv1.3"])
def test_current_protocols_pass(protocol: str) -> None:
    assert evaluate_certificate(cert(90 * DAY, 60 * DAY, protocol), NOW).status is Status.PASS


def test_worst_finding_wins_and_all_are_listed() -> None:
    outcome = evaluate_certificate(cert(90 * DAY, 6 * DAY, protocol="TLSv1"), NOW)
    assert outcome.status is Status.FAIL
    assert outcome.summary == "The certificate expires in 6 days."
    assert "TLSv1, which is deprecated" in labels(outcome.evidence)["Issues"]
    assert outcome.remediation is not None
    assert "Renew the certificate" in outcome.remediation
    assert "Disable TLS 1.0 and 1.1" in outcome.remediation


def test_unverified_certificate_fails_with_the_error() -> None:
    result = TlsProbeResult(
        verified=False,
        error="certificate verify failed: unable to get local issuer certificate",
    )
    outcome = evaluate_certificate(result, NOW)
    assert outcome.status is Status.FAIL
    assert outcome.summary == (
        "The certificate on port 443 is not trusted: "
        "certificate verify failed: unable to get local issuer certificate."
    )
    assert labels(outcome.evidence)["Verification error"].startswith("certificate verify")


def test_expired_certificate_reported_by_the_prober_fails() -> None:
    result = TlsProbeResult(verified=False, error="certificate has expired")
    outcome = evaluate_certificate(result, NOW)
    assert outcome.status is Status.FAIL
    assert "certificate has expired" in outcome.summary


def test_unverified_without_error_text() -> None:
    outcome = evaluate_certificate(TlsProbeResult(verified=False), NOW)
    assert outcome.status is Status.FAIL
    assert "unknown verification error" in outcome.summary


def test_verified_without_dates_is_inconclusive() -> None:
    outcome = evaluate_certificate(TlsProbeResult(verified=True, protocol="TLSv1.3"), NOW)
    assert outcome.status is Status.INCONCLUSIVE


@pytest.mark.parametrize(
    ("reason", "expected", "summary"),
    [
        (FetchErrorReason.CONNECT, Status.FAIL, "No HTTPS service answered on port 443."),
        (
            FetchErrorReason.NETWORK,
            Status.INCONCLUSIVE,
            "The connection to port 443 was reset or the host was unreachable, which does not "
            "show whether an HTTPS service runs there.",
        ),
        (FetchErrorReason.TLS, Status.FAIL, "The TLS handshake on port 443 failed."),
        (FetchErrorReason.TIMEOUT, Status.INCONCLUSIVE, "The TLS handshake on port 443 timed out."),
        (
            FetchErrorReason.BLOCKED,
            Status.INCONCLUSIVE,
            "The TLS probe was blocked because the target address is not public.",
        ),
        (FetchErrorReason.DNS, Status.INCONCLUSIVE, "The TLS probe on port 443 failed (dns)."),
    ],
)
def test_probe_errors(reason: FetchErrorReason, expected: Status, summary: str) -> None:
    outcome = evaluate_probe_error(TlsProbeError(reason, "details"))
    assert (outcome.status, outcome.summary) == (expected, summary)
    assert labels(outcome.evidence) == {"Error": "details"}


async def test_tls_check_probes_port_443() -> None:
    prober = FakeTlsProber(cert(90 * DAY, 60 * DAY))
    result = await run_check(TLS_CERTIFICATE, make_context(tls=prober))
    assert prober.probes == [("example.com", 443)]
    assert result.status is Status.PASS
    assert result.points == 15


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        (FetchErrorReason.CONNECT, Status.FAIL),
        (FetchErrorReason.NETWORK, Status.INCONCLUSIVE),
        (FetchErrorReason.TIMEOUT, Status.INCONCLUSIVE),
        (FetchErrorReason.BLOCKED, Status.INCONCLUSIVE),
    ],
)
async def test_tls_check_refused_timeout_blocked(
    reason: FetchErrorReason, expected: Status
) -> None:
    prober = FakeTlsProber(TlsProbeError(reason, "probe failed"))
    result = await run_check(TLS_CERTIFICATE, make_context(tls=prober))
    assert result.status is expected


async def test_tls_check_without_addresses_is_inconclusive() -> None:
    prober = FakeTlsProber(cert(90 * DAY, 60 * DAY))
    result = await run_check(TLS_CERTIFICATE, make_context(addresses=(), tls=prober))
    assert result.status is Status.INCONCLUSIVE
    assert "no A/AAAA record" in result.summary
    assert prober.probes == []


# --- HTTP to HTTPS redirect ------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "domain", "expected"),
    [
        ("example.com", "example.com", True),
        ("www.example.com", "example.com", True),
        ("example.com", "www.example.com", True),
        ("EXAMPLE.com.", "example.com", True),
        ("shop.example.com", "example.com", False),
        ("www.www.example.com", "example.com", False),
        ("example.org", "example.com", False),
        ("notexample.com", "example.com", False),
    ],
)
def test_is_same_site_host(host: str, domain: str, expected: bool) -> None:
    assert is_same_site_host(host, domain) is expected


@pytest.mark.parametrize(
    ("domain", "chain", "expected", "summary"),
    [
        (
            "example.com",
            ["http://example.com/", "https://example.com/"],
            Status.PASS,
            "http://example.com/ redirects straight to HTTPS on example.com.",
        ),
        (
            "example.com",
            ["http://example.com/", "https://www.example.com/", "https://www.example.com/en/"],
            Status.PASS,
            "http://example.com/ redirects straight to HTTPS on www.example.com.",
        ),
        (
            "www.example.com",
            ["http://www.example.com/", "https://example.com/"],
            Status.PASS,
            "http://www.example.com/ redirects straight to HTTPS on example.com.",
        ),
        (
            "example.com",
            ["http://example.com/", "http://www.example.com/", "https://www.example.com/"],
            Status.WARN,
            "The redirect from http://example.com/ passes through 1 more plain HTTP hop "
            "before reaching HTTPS.",
        ),
        (
            "example.com",
            [
                "http://example.com/",
                "http://www.example.com/",
                "http://www.example.com/home",
                "https://www.example.com/home",
            ],
            Status.WARN,
            "The redirect from http://example.com/ passes through 2 more plain HTTP hops "
            "before reaching HTTPS.",
        ),
        (
            "example.com",
            ["http://example.com/", "https://example.net/"],
            Status.WARN,
            "http://example.com/ redirects straight to HTTPS, but on another host (example.net).",
        ),
        (
            "example.com",
            ["http://example.com/"],
            Status.FAIL,
            "http://example.com/ is served over plain HTTP (status 200) instead of redirecting "
            "to HTTPS.",
        ),
        (
            "example.com",
            ["http://example.com/", "https://example.com/", "http://example.com/plain"],
            Status.FAIL,
            "http://example.com/ is served over plain HTTP (status 200) instead of redirecting "
            "to HTTPS.",
        ),
    ],
)
def test_redirect_chains(domain: str, chain: list[str], expected: Status, summary: str) -> None:
    page = response(chain[-1], redirects=tuple(chain[:-1]))
    outcome = evaluate_redirect(domain, page)
    assert (outcome.status, outcome.summary) == (expected, summary)
    assert labels(outcome.evidence)["Redirect chain"] == " -> ".join(chain)
    assert (outcome.remediation is None) == (expected is Status.PASS)


def test_plain_http_error_page_still_fails() -> None:
    outcome = evaluate_redirect("example.com", response("http://example.com/", status=404))
    assert outcome.status is Status.FAIL
    assert labels(outcome.evidence)["Final status"] == "404"


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        (FetchErrorReason.CONNECT, Status.PASS),
        (FetchErrorReason.NETWORK, Status.INCONCLUSIVE),
        (FetchErrorReason.TIMEOUT, Status.INCONCLUSIVE),
        (FetchErrorReason.BLOCKED, Status.INCONCLUSIVE),
        (FetchErrorReason.DNS, Status.INCONCLUSIVE),
        (FetchErrorReason.TLS, Status.INCONCLUSIVE),
        (FetchErrorReason.PROTOCOL, Status.INCONCLUSIVE),
        (FetchErrorReason.TOO_MANY_REDIRECTS, Status.INCONCLUSIVE),
    ],
)
def test_redirect_errors(reason: FetchErrorReason, expected: Status) -> None:
    outcome = evaluate_redirect_error("example.com", FetchError(reason, "x" * 500))
    assert outcome.status is expected
    shown = labels(outcome.evidence)
    assert shown["Request"] == "http://example.com/"
    assert len(shown["Error"]) == 300


async def test_redirect_check_port_80_closed() -> None:
    fetcher = FakeFetcher()  # unknown URLs fail to connect
    result = await run_check(HTTPS_REDIRECT, make_context(fetcher=fetcher))
    assert fetcher.requests == ["http://example.com/"]
    assert result.status is Status.PASS
    assert result.summary == "Port 80 is closed, so nothing is served over plain HTTP."


async def test_redirect_check_timeout() -> None:
    error = FetchError(FetchErrorReason.TIMEOUT, "timed out after 10 s")
    fetcher = FakeFetcher(pages={"http://example.com/": error})
    result = await run_check(HTTPS_REDIRECT, make_context(fetcher=fetcher))
    assert result.status is Status.INCONCLUSIVE
    assert result.summary == "The plain HTTP request timed out."


async def test_redirect_check_follows_the_fetched_chain() -> None:
    page = response("https://example.com/", redirects=("http://example.com/",))
    fetcher = FakeFetcher(pages={"http://example.com/": page})
    result = await run_check(HTTPS_REDIRECT, make_context(fetcher=fetcher))
    assert (result.status, result.points) == (Status.PASS, 5)


async def test_redirect_check_without_addresses_is_inconclusive() -> None:
    fetcher = FakeFetcher()
    result = await run_check(HTTPS_REDIRECT, make_context(addresses=(), fetcher=fetcher))
    assert result.status is Status.INCONCLUSIVE
    assert fetcher.requests == []


def test_refused_redirect_target_is_not_port_80_closed() -> None:
    error = FetchError(
        FetchErrorReason.CONNECT,
        "could not connect to www.example.com",
        url="https://www.example.com/",
    )
    outcome = evaluate_redirect_error("example.com", error)
    assert outcome.status is Status.INCONCLUSIVE
    assert outcome.summary == "A redirect target of the plain HTTP request could not be reached."
    assert labels(outcome.evidence)["Failed URL"] == "https://www.example.com/"


def test_refused_first_request_is_port_80_closed() -> None:
    error = FetchError(FetchErrorReason.CONNECT, "refused", url="http://example.com/")
    assert evaluate_redirect_error("example.com", error).status is Status.PASS


def reset(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadError("[Errno 54] Connection reset by peer", request=request)


def unreachable(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("[Errno 65] No route to host", request=request)


@pytest.mark.parametrize("network", [reset, unreachable])
async def test_reset_or_unreachable_port_80_is_not_closed(
    network: Callable[[httpx.Request], httpx.Response],
) -> None:
    # Port 80 accepted the connection (or was never reached), so it is not "closed".
    resolver = FakeResolver(address_records={"example.com": ["93.184.215.14"]})
    fetcher = GuardedFetcher(resolver, transport=httpx.MockTransport(network))
    ctx = make_context(resolver=resolver)
    ctx.fetcher = fetcher
    result = await run_check(HTTPS_REDIRECT, ctx)
    assert result.status is Status.INCONCLUSIVE
    assert result.summary.startswith("The plain HTTP connection was reset")


def test_redirect_evidence_hides_session_ids_and_query_strings() -> None:
    page = response(
        "https://example.com/;jsessionid=8F3A2B9C41D7E0A5?next=%2F",
        redirects=("http://example.com/",),
    )
    outcome = evaluate_redirect("example.com", page)
    chain = labels(outcome.evidence)["Redirect chain"]
    assert chain == "http://example.com/ -> https://example.com/;...?..."
    assert all("8F3A" not in item.value for item in outcome.evidence)

    error = FetchError(
        FetchErrorReason.CONNECT, "refused", url="https://sso.example.net/login?state=s3cr3t"
    )
    shown = labels(evaluate_redirect_error("example.com", error).evidence)
    assert shown["Failed URL"] == "https://sso.example.net/login?..."


@pytest.mark.parametrize(
    ("addresses", "expected"),
    [
        ((), False),
        (("93.184.215.14",), False),
        (("93.184.215.14", "2606:2800:21f:cb07::1"), False),
        (("2606:2800:21f:cb07::1",), True),
    ],
)
def test_is_ipv6_only(addresses: tuple[str, ...], expected: bool) -> None:
    assert is_ipv6_only(addresses) is expected


async def test_connection_failures_on_ipv6_only_hosts_are_inconclusive() -> None:
    prober = FakeTlsProber(TlsProbeError(FetchErrorReason.CONNECT, "could not connect"))
    fetcher = FakeFetcher()  # unknown URLs fail to connect
    ctx = make_context(addresses=("2606:2800:21f:cb07::1",), fetcher=fetcher, tls=prober)
    for check in (TLS_CERTIFICATE, HTTPS_REDIRECT):
        result = await run_check(check, ctx)
        assert result.status is Status.INCONCLUSIVE
        assert "IPv6 connectivity" in result.summary
