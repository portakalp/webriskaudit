import asyncio
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from starlette.types import Message

from webriskaudit import METHODOLOGY_VERSION, __version__
from webriskaudit.api import PROBLEM_BASE, ScanService, create_app
from webriskaudit.logs import JsonFormatter
from webriskaudit.models import Category, CheckResult, ScanReport, Status
from webriskaudit.net.dns import DnsResolver
from webriskaudit.net.types import DnsUnavailableError, TlsProbeResult
from webriskaudit.scanner import Scanner
from webriskaudit.scoring import summarize
from webriskaudit.settings import Settings

from .fakes import DnsAnswer, FakeFetcher, FakeResolver, FakeTlsProber, response

ALLOWED_ORIGIN = "https://webriskaudit.com"
SCAN = "/api/v1/scan"


def make_report(domain: str) -> ScanReport:
    results = [
        CheckResult(
            id="email.spf",
            title="SPF record",
            category=Category.EMAIL,
            status=Status.PASS,
            weight=10,
            points=10,
            summary="The SPF record ends in -all.",
            duration_ms=3,
        )
    ]
    score, grade, coverage, categories = summarize(results)
    return ScanReport(
        domain=domain,
        scanned_at=datetime(2026, 11, 1, 12, 0, tzinfo=UTC),
        duration_ms=12,
        score=score,
        grade=grade,
        coverage=coverage,
        categories=categories,
        checks=results,
        scanner_version=__version__,
        methodology_version=METHODOLOGY_VERSION,
    )


@dataclass
class FakeScan:
    """Stands in for Scanner.scan: records calls, can fail or wait for a release."""

    error: Exception | None = None
    release: asyncio.Event | None = None
    calls: list[str] = field(default_factory=list)

    async def __call__(self, domain: str) -> ScanReport:
        self.calls.append(domain)
        if self.release is not None:
            await self.release.wait()
        if self.error is not None:
            raise self.error
        return make_report(domain)


def real_scanner(address_records: dict[str, DnsAnswer]) -> Scanner:
    """The real scanner on fakes; names missing from ``address_records`` are NXDOMAIN."""
    return Scanner(
        resolver=FakeResolver(address_records=address_records),
        fetcher=FakeFetcher(),
        tls=FakeTlsProber(TlsProbeResult(verified=True)),
    )


@asynccontextmanager
async def client(
    app: FastAPI, ip: str = "198.51.100.7", *, raise_app_exceptions: bool = True
) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(
        app=app, client=(ip, 50000), raise_app_exceptions=raise_app_exceptions
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


def problem(reply: httpx.Response, status: int, slug: str) -> dict[str, object]:
    assert reply.status_code == status
    assert reply.headers["content-type"] == "application/problem+json"
    body = reply.json()
    assert isinstance(body, dict)
    assert set(body) == {"type", "title", "status", "detail"}
    assert body["type"] == PROBLEM_BASE + slug
    assert body["status"] == status
    return body


# --- Scans ---------------------------------------------------------------------------


async def test_scan_returns_the_report_for_the_normalized_domain() -> None:
    scan = FakeScan()
    async with client(create_app(settings=Settings(), scan=scan)) as http:
        reply = await http.post(SCAN, json={"domain": " https://Example.COM/some/path "})
    assert reply.status_code == 200
    assert reply.headers["content-type"] == "application/json"
    assert scan.calls == ["example.com"]
    body = reply.json()
    assert set(body) == set(ScanReport.model_fields)
    assert ScanReport.model_validate(body) == make_report("example.com")


async def test_scan_with_the_real_scanner_returns_every_check() -> None:
    scanner = real_scanner({"example.com": ["93.184.215.14"]})
    app = create_app(settings=Settings(), scan=scanner.scan)
    async with client(app) as http:
        reply = await http.post(SCAN, json={"domain": "example.com"})
    assert reply.status_code == 200
    report = ScanReport.model_validate(reply.json())
    assert len(report.checks) == 16
    assert report.coverage.total == 12


# --- Problem details -----------------------------------------------------------------


@pytest.mark.parametrize(
    "domain", ["this-domain-does-not-exist.invalid", "localhost", "10.0.0.1", "", "a..b"]
)
async def test_invalid_domain(domain: str) -> None:
    scan = FakeScan()
    async with client(create_app(settings=Settings(), scan=scan)) as http:
        reply = await http.post(SCAN, json={"domain": domain})
    body = problem(reply, 422, "invalid-domain")
    assert body["title"] == "Invalid domain"
    assert scan.calls == []


@pytest.mark.parametrize(
    "content",
    [b"{}", b'{"domain": 5}', b"not json", b'["example.com"]', b'{"domain": null}'],
)
async def test_invalid_request_body(content: bytes) -> None:
    scan = FakeScan()
    async with client(create_app(settings=Settings(), scan=scan)) as http:
        reply = await http.post(SCAN, content=content, headers={"content-type": "application/json"})
    body = problem(reply, 422, "invalid-request")
    assert str(body["detail"]).startswith('Send a JSON object such as {"domain": "example.com"}')
    assert scan.calls == []


@pytest.mark.parametrize(
    ("records", "status", "slug"),
    [
        ({}, 422, "domain-not-found"),
        ({"example.com": ["10.0.0.5"]}, 422, "non-public-target"),
        ({"example.com": DnsUnavailableError("example.com")}, 502, "dns-unavailable"),
    ],
)
async def test_precheck_errors(records: dict[str, DnsAnswer], status: int, slug: str) -> None:
    scanner = real_scanner(records)
    async with client(create_app(settings=Settings(), scan=scanner.scan)) as http:
        reply = await http.post(SCAN, json={"domain": "example.com"})
    body = problem(reply, status, slug)
    assert "example.com" in str(body["detail"])


async def test_unexpected_error_is_a_generic_500() -> None:
    scan = FakeScan(error=RuntimeError("secret detail from /etc/resolv.conf"))
    async with client(create_app(settings=Settings(), scan=scan)) as http:
        reply = await http.post(SCAN, json={"domain": "example.com"})
    body = problem(reply, 500, "internal-error")
    assert "secret" not in reply.text
    assert "RuntimeError" not in reply.text
    assert body["detail"] == "The scan failed unexpectedly. Please try again later."


async def test_failed_scans_are_not_cached() -> None:
    scan = FakeScan(error=RuntimeError("boom"))
    async with client(create_app(settings=Settings(), scan=scan)) as http:
        await http.post(SCAN, json={"domain": "example.com"})
        scan.error = None
        reply = await http.post(SCAN, json={"domain": "example.com"})
    assert reply.status_code == 200
    assert scan.calls == ["example.com", "example.com"]


async def test_unknown_route_and_wrong_method_are_problem_details() -> None:
    async with client(create_app(settings=Settings(), scan=FakeScan())) as http:
        missing = await http.get("/api/v1/nothing")
        wrong = await http.get(SCAN)
    assert missing.status_code == 404
    assert missing.headers["content-type"] == "application/problem+json"
    assert missing.json() == {
        "type": "about:blank",
        "title": "Not Found",
        "status": 404,
        "detail": "Not Found",
    }
    assert wrong.status_code == 405
    assert wrong.headers["content-type"] == "application/problem+json"
    assert wrong.headers["allow"] == "POST"


# --- Rate limit, cache and coalescing ---------------------------------------------------


async def test_rate_limit_answers_429_with_retry_after() -> None:
    settings = Settings(rate_limit_scans=2, rate_limit_window=600)
    async with client(create_app(settings=settings, scan=FakeScan())) as http:
        first = await http.post(SCAN, json={"domain": "one.example.com"})
        second = await http.post(SCAN, json={"domain": "two.example.com"})
        limited = await http.post(SCAN, json={"domain": "three.example.com"})
    assert (first.status_code, second.status_code) == (200, 200)
    body = problem(limited, 429, "rate-limited")
    retry_after = int(limited.headers["retry-after"])
    assert 590 <= retry_after <= 600
    assert f"{retry_after} seconds" in str(body["detail"])


async def test_rate_limit_is_per_client_and_cache_hits_do_not_count() -> None:
    app = create_app(settings=Settings(rate_limit_scans=1), scan=FakeScan())
    async with client(app, ip="198.51.100.7") as first, client(app, ip="203.0.113.9") as other:
        assert (await first.post(SCAN, json={"domain": "example.com"})).status_code == 200
        # A cached report costs nothing, so it is served even after the limit is used up.
        assert (await first.post(SCAN, json={"domain": "example.com"})).status_code == 200
        assert (await first.post(SCAN, json={"domain": "example.org"})).status_code == 429
        assert (await other.post(SCAN, json={"domain": "example.org"})).status_code == 200


async def test_repeated_scans_are_served_from_the_cache() -> None:
    scan = FakeScan()
    async with client(create_app(settings=Settings(), scan=scan)) as http:
        first = await http.post(SCAN, json={"domain": "example.com"})
        second = await http.post(SCAN, json={"domain": "https://EXAMPLE.com/"})
    assert scan.calls == ["example.com"]
    assert first.json() == second.json()


async def test_cache_can_be_turned_off() -> None:
    scan = FakeScan()
    async with client(create_app(settings=Settings(cache_ttl=0), scan=scan)) as http:
        for _ in range(2):
            assert (await http.post(SCAN, json={"domain": "example.com"})).status_code == 200
    assert scan.calls == ["example.com", "example.com"]


async def test_concurrent_requests_for_one_domain_share_one_scan() -> None:
    # With caching off, only coalescing can keep this to one scan.
    scan = FakeScan(release=asyncio.Event())
    async with client(create_app(settings=Settings(cache_ttl=0), scan=scan)) as http:
        requests = [
            asyncio.create_task(http.post(SCAN, json={"domain": "example.com"})) for _ in range(3)
        ]
        await asyncio.sleep(0.05)  # let every request reach the running scan
        assert scan.release is not None
        scan.release.set()
        replies = await asyncio.gather(*requests)
    assert [reply.status_code for reply in replies] == [200, 200, 200]
    assert scan.calls == ["example.com"]


async def test_concurrent_scans_are_capped() -> None:
    running = 0
    peak = 0

    async def scan(domain: str) -> ScanReport:
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.01)
        running -= 1
        return make_report(domain)

    settings = Settings(max_concurrent_scans=2, rate_limit_scans=0)
    async with client(create_app(settings=settings, scan=scan)) as http:
        replies = await asyncio.gather(
            *(http.post(SCAN, json={"domain": f"site{n}.example.com"}) for n in range(6))
        )
    assert all(reply.status_code == 200 for reply in replies)
    assert peak == 2


# --- CORS --------------------------------------------------------------------------


def preflight(origin: str) -> dict[str, str]:
    return {
        "Origin": origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    }


async def test_cors_preflight_from_an_allowed_origin() -> None:
    async with client(create_app(settings=Settings(), scan=FakeScan())) as http:
        reply = await http.options(SCAN, headers=preflight(ALLOWED_ORIGIN))
    assert reply.status_code == 200
    assert reply.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
    assert "POST" in reply.headers["access-control-allow-methods"]
    assert "access-control-allow-credentials" not in reply.headers


async def test_cors_preflight_from_another_origin_is_denied() -> None:
    async with client(create_app(settings=Settings(), scan=FakeScan())) as http:
        reply = await http.options(SCAN, headers=preflight("https://evil.example.net"))
    assert reply.status_code == 400
    assert "access-control-allow-origin" not in reply.headers


async def test_cors_headers_on_errors_expose_retry_after() -> None:
    settings = Settings(rate_limit_scans=1)
    async with client(create_app(settings=settings, scan=FakeScan())) as http:
        headers = {"Origin": ALLOWED_ORIGIN}
        await http.post(SCAN, json={"domain": "example.com"}, headers=headers)
        limited = await http.post(SCAN, json={"domain": "example.org"}, headers=headers)
    assert limited.status_code == 429
    assert limited.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
    assert "retry-after" in limited.headers["access-control-expose-headers"].lower()


# --- Service routes, OpenAPI and logging --------------------------------------------------


async def test_health_and_root() -> None:
    async with client(create_app(settings=Settings(), scan=FakeScan())) as http:
        health = await http.get("/health")
        root = await http.get("/")
    assert (health.status_code, health.json()) == (200, {"status": "ok"})
    assert root.json() == {
        "name": "WebRiskAudit API",
        "version": __version__,
        "revision": None,
        "docs": "/docs",
    }


async def test_root_names_the_revision() -> None:
    revision = "0123456789abcdef0123456789abcdef01234567"
    async with client(create_app(settings=Settings(revision=revision), scan=FakeScan())) as http:
        root = await http.get("/")
    assert root.json()["revision"] == revision


async def test_api_docs_are_served_by_default() -> None:
    async with client(create_app(settings=Settings(), scan=FakeScan())) as http:
        replies = [await http.get(path) for path in ("/docs", "/redoc", "/openapi.json")]
    assert [reply.status_code for reply in replies] == [200, 200, 200]


async def test_api_docs_can_be_switched_off() -> None:
    app = create_app(settings=Settings(api_docs_enabled=False), scan=FakeScan())
    async with client(app) as http:
        replies = [
            await http.get(path)
            for path in ("/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json")
        ]
        root = await http.get("/")
    for reply in replies:
        assert reply.status_code == 404
        assert reply.headers["content-type"] == "application/problem+json"
    assert root.json()["docs"] is None
    # The committed openapi.json is still produced from the app object.
    assert app.openapi() == create_app(settings=Settings(), scan=FakeScan()).openapi()


def test_openapi_documents_problem_responses() -> None:
    schema = create_app(settings=Settings(), scan=FakeScan()).openapi()
    responses = schema["paths"][SCAN]["post"]["responses"]
    assert set(responses) == {"200", "400", "403", "413", "422", "429", "500", "502", "503"}
    for status in ("400", "403", "413", "422", "429", "500", "502", "503"):
        content = responses[status]["content"]
        assert list(content) == ["application/problem+json"]
        assert content["application/problem+json"]["schema"] == {
            "$ref": "#/components/schemas/ProblemDetails"
        }
    assert "Retry-After" in responses["429"]["headers"]
    assert "Retry-After" in responses["503"]["headers"]
    assert "ProblemDetails" in schema["components"]["schemas"]
    assert "HTTPValidationError" not in schema["components"]["schemas"]


async def test_one_json_log_line_per_scan_without_client_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="webriskaudit.api")
    async with client(create_app(settings=Settings(), scan=FakeScan()), ip="198.51.100.7") as http:
        await http.post(SCAN, json={"domain": "example.com"})
        await http.post(SCAN, json={"domain": "example.com"})
        await http.post(SCAN, json={"domain": "not a domain"})
        await http.post(SCAN, json={"domain": "x" * 2049, "extra": "secret-input"})
    lines = [
        json.loads(JsonFormatter().format(r)) for r in caplog.records if r.getMessage() == "scan"
    ]
    assert [line.get("cache") for line in lines] == ["miss", "hit", None, None]
    assert [line["outcome"] for line in lines] == ["ok", "ok", "invalid-domain", "invalid-request"]
    assert all(line["severity"] == "INFO" for line in lines)
    first = lines[0]
    assert first["domain"] == "example.com"
    assert (first["score"], first["grade"]) == (100, "A")
    assert first["coverage"] == {"scored": 1, "inconclusive": 0, "total": 1}
    assert isinstance(first["duration_ms"], int)
    assert isinstance(first["queue_ms"], int)
    assert isinstance(first["scan_ms"], int)
    assert (lines[1]["queue_ms"], lines[1]["scan_ms"]) == (None, None)  # from the cache
    assert "domain" not in lines[2]  # raw input of a failed request is not logged
    assert lines[3] == {
        "time": lines[3]["time"],
        "severity": "INFO",
        "level": "info",
        "logger": "webriskaudit.api",
        "message": "scan",
        "outcome": "invalid-request",
        "validation_errors": 1,
        "error_types": ["string_too_long"],
    }
    for raw in ("198.51.100.7", "not a domain", "xxxx", "secret-input"):
        assert raw not in caplog.text
        assert all(raw not in json.dumps(line) for line in lines)


async def test_scan_line_times_the_wait_for_a_slot(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="webriskaudit.api")
    scan = FakeScan(release=asyncio.Event())
    settings = Settings(max_concurrent_scans=1, queue_timeout=0.05, rate_limit_scans=0)
    async with client(create_app(settings=settings, scan=scan)) as http:
        running = asyncio.create_task(http.post(SCAN, json={"domain": "one.example.com"}))
        await asyncio.sleep(0.01)
        late = await http.post(SCAN, json={"domain": "two.example.com"})
        await asyncio.sleep(0.02)
        assert scan.release is not None
        scan.release.set()
        await running
    assert late.status_code == 503
    lines = {
        line["domain"]: line
        for line in (
            json.loads(JsonFormatter().format(r))
            for r in caplog.records
            if r.getMessage() == "scan"
        )
    }
    busy, done = lines["two.example.com"], lines["one.example.com"]
    assert busy["outcome"] == "scanner-busy"
    assert busy["queue_ms"] >= 40  # waited for the queue timeout, then gave up
    assert busy["scan_ms"] is None
    assert done["outcome"] == "ok"
    assert done["queue_ms"] < 40
    assert done["scan_ms"] >= 20
    assert done["duration_ms"] >= done["queue_ms"] + done["scan_ms"]


async def test_startup_line_lists_the_settings_without_secrets(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("webriskaudit.api.configure_logging", lambda: None)
    caplog.set_level(logging.INFO, logger="webriskaudit.api")
    settings = Settings(
        origin_auth_secrets=(SECRET,),
        client_ip_header="CF-Connecting-IP",
        api_docs_enabled=False,
        revision="abc123",
        dns_nameservers=("1.1.1.1", "9.9.9.10"),
    )
    app = create_app(settings=settings, scan=FakeScan())
    async with app.router.lifespan_context(app):
        pass
    [record] = [r for r in caplog.records if r.getMessage() == "startup"]
    line = json.loads(JsonFormatter().format(record))
    assert line["severity"] == "INFO"
    assert (line["version"], line["revision"]) == (__version__, "abc123")
    assert line["allowed_origins"] == list(settings.allowed_origins)
    assert line["rate_limit_scans"] == settings.rate_limit_scans
    assert line["dns_nameservers"] == ["1.1.1.1", "9.9.9.10"]
    assert (line["origin_auth"], line["origin_auth_secrets"]) == ("enabled", 1)
    assert line["client_ip_header"] == "CF-Connecting-IP"
    assert line["api_docs"] == "disabled"
    assert SECRET not in caplog.text


async def test_expired_state_is_swept_by_any_request() -> None:
    settings = Settings(rate_limit_window=0.05, cache_ttl=0.05)
    app = create_app(settings=settings, scan=FakeScan())
    service = app.state.scans
    assert isinstance(service, ScanService)
    async with client(app) as http:
        assert (await http.post(SCAN, json={"domain": "example.com"})).status_code == 200
        counts = (len(service._per_client), len(service._overall), len(service._cache))
        assert counts == (1, 1, 1)
        await asyncio.sleep(0.06)
        assert (await http.get("/health")).status_code == 200
    assert (len(service._per_client), len(service._overall), len(service._cache)) == (0, 0, 0)


# --- Abuse controls: client keys, budgets and the scan queue ---------------------------


async def test_ipv6_clients_share_a_limit_per_64() -> None:
    # A client with a /64 could otherwise use a new address for every scan.
    app = create_app(settings=Settings(rate_limit_scans=2), scan=FakeScan())
    statuses = []
    for n, ip in enumerate(["2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2:ffff::9"]):
        async with client(app, ip=ip) as http:
            statuses.append(
                (await http.post(SCAN, json={"domain": f"s{n}.example.com"})).status_code
            )
    assert statuses == [200, 200, 429]
    async with client(app, ip="2001:db8:1:3::1") as other:  # another /64
        assert (await other.post(SCAN, json={"domain": "s9.example.com"})).status_code == 200


async def test_overall_budget_of_new_scans_answers_503() -> None:
    settings = Settings(global_rate_limit_scans=2, rate_limit_window=600)
    app = create_app(settings=settings, scan=FakeScan())
    replies = []
    for n in range(3):
        async with client(app, ip=f"198.51.100.{n + 1}") as http:
            replies.append(await http.post(SCAN, json={"domain": f"g{n}.example.com"}))
    assert [reply.status_code for reply in replies[:2]] == [200, 200]
    body = problem(replies[2], 503, "scanner-busy")
    assert 590 <= int(replies[2].headers["retry-after"]) <= 600
    assert "limit of new scans" in str(body["detail"])


async def test_one_new_scan_per_client_at_a_time() -> None:
    scan = FakeScan(release=asyncio.Event())
    app = create_app(settings=Settings(), scan=scan)
    async with client(app) as http:
        first = asyncio.create_task(http.post(SCAN, json={"domain": "example.com"}))
        await asyncio.sleep(0.05)
        second = await http.post(SCAN, json={"domain": "example.org"})
        # Joining the scan that is already running costs nothing.
        same = asyncio.create_task(http.post(SCAN, json={"domain": "example.com"}))
        await asyncio.sleep(0.05)
        assert scan.release is not None
        scan.release.set()
        replies = await asyncio.gather(first, same)
    body = problem(second, 429, "rate-limited")
    assert second.headers["retry-after"] == "5"
    assert "still running" in str(body["detail"])
    assert [reply.status_code for reply in replies] == [200, 200]
    assert scan.calls == ["example.com"]


async def test_full_queue_answers_503_without_counting_against_the_client() -> None:
    scan = FakeScan(release=asyncio.Event())
    settings = Settings(max_concurrent_scans=1, max_queued_scans=1, rate_limit_scans=1)
    app = create_app(settings=settings, scan=scan)
    async with client(app, ip="198.51.100.1") as a, client(app, ip="198.51.100.2") as b:
        running = asyncio.create_task(a.post(SCAN, json={"domain": "one.example.com"}))
        waiting = asyncio.create_task(b.post(SCAN, json={"domain": "two.example.com"}))
        await asyncio.sleep(0.05)
        async with client(app, ip="198.51.100.3") as c:
            refused = await c.post(SCAN, json={"domain": "three.example.com"})
            assert scan.release is not None
            scan.release.set()
            await asyncio.gather(running, waiting)
            # The refused client's limit of 1 was not used up by the 503.
            retried = await c.post(SCAN, json={"domain": "three.example.com"})
    problem(refused, 503, "scanner-busy")
    assert refused.headers["retry-after"] == "10"
    assert retried.status_code == 200
    assert scan.calls == ["one.example.com", "two.example.com", "three.example.com"]


async def test_waiting_for_a_slot_is_bounded() -> None:
    scan = FakeScan(release=asyncio.Event())
    settings = Settings(max_concurrent_scans=1, queue_timeout=0.05, rate_limit_scans=0)
    app = create_app(settings=settings, scan=scan)
    async with client(app) as http:
        running = asyncio.create_task(http.post(SCAN, json={"domain": "one.example.com"}))
        await asyncio.sleep(0.01)
        late = await http.post(SCAN, json={"domain": "two.example.com"})
        assert scan.release is not None
        scan.release.set()
        await running
        # A scan that never got a slot is not cached: asking again scans it.
        again = await http.post(SCAN, json={"domain": "two.example.com"})
    body = problem(late, 503, "scanner-busy")
    assert "No scan slot became free in time" in str(body["detail"])
    assert again.status_code == 200
    assert scan.calls == ["one.example.com", "two.example.com"]


def disconnecting_receive(body: bytes, gone: asyncio.Event) -> Callable[[], Awaitable[Message]]:
    """An ASGI receive that delivers ``body`` and reports a disconnect once ``gone`` is set."""
    sent = False

    async def receive() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        await gone.wait()
        return {"type": "http.disconnect"}

    return receive


async def scan_request_until(app: FastAPI, domain: str, gone: asyncio.Event) -> list[Message]:
    """Call the app directly, like uvicorn, for a client that disconnects when ``gone`` is set."""
    body = json.dumps({"domain": domain}).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": SCAN,
        "raw_path": SCAN.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"content-type", b"application/json"), (b"host", b"testserver")],
        "client": ("198.51.100.9", 50000),
        "server": ("testserver", 80),
    }
    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, disconnecting_receive(body, gone), send)
    return sent


async def test_waiting_scan_is_cancelled_when_its_client_disconnects() -> None:
    scan = FakeScan(release=asyncio.Event())
    settings = Settings(max_concurrent_scans=1, rate_limit_scans=0)
    app = create_app(settings=settings, scan=scan)
    gone = asyncio.Event()
    async with client(app) as http:
        running = asyncio.create_task(http.post(SCAN, json={"domain": "one.example.com"}))
        await asyncio.sleep(0.01)
        waiting = asyncio.create_task(scan_request_until(app, "two.example.com", gone))
        await asyncio.sleep(0.01)
        gone.set()
        sent = await asyncio.wait_for(waiting, 1)
        assert sent[0]["status"] == 499  # nobody reads it; the client is gone
        assert scan.release is not None
        scan.release.set()
        assert (await running).status_code == 200
        await asyncio.sleep(0.01)
    assert scan.calls == ["one.example.com"]  # two.example.com never took the slot


async def test_new_request_right_after_a_dropped_scan_starts_a_fresh_one() -> None:
    scan = FakeScan(release=asyncio.Event())
    settings = Settings(max_concurrent_scans=1, rate_limit_scans=0)
    app = create_app(settings=settings, scan=scan)
    gone = asyncio.Event()
    async with client(app) as http:
        running = asyncio.create_task(http.post(SCAN, json={"domain": "one.example.com"}))
        await asyncio.sleep(0.01)
        waiting = asyncio.create_task(scan_request_until(app, "two.example.com", gone))
        await asyncio.sleep(0.01)
        gone.set()
        await asyncio.wait_for(waiting, 1)
        # The dropped scan may not have finished cancelling yet.
        retry = asyncio.create_task(http.post(SCAN, json={"domain": "two.example.com"}))
        await asyncio.sleep(0.01)
        assert scan.release is not None
        scan.release.set()
        replies = await asyncio.wait_for(asyncio.gather(running, retry), 1)
    assert [reply.status_code for reply in replies] == [200, 200]
    assert scan.calls == ["one.example.com", "two.example.com"]


async def test_scan_dropped_a_moment_ago_is_not_joined() -> None:
    scan = FakeScan(release=asyncio.Event())
    service = ScanService(scan, Settings(max_concurrent_scans=1, rate_limit_scans=0))
    holder = asyncio.create_task(service.report("one.example.com", "198.51.100.1"))
    leaver = asyncio.create_task(service.report("two.example.com", "198.51.100.2"))
    await asyncio.sleep(0.01)
    leaver.cancel()
    await asyncio.sleep(0)  # the leaver cancels its waiting scan, which is still cancelling
    assert scan.release is not None
    scan.release.set()
    report, source = await asyncio.wait_for(service.report("two.example.com", "198.51.100.3"), 1)
    assert (report.domain, source) == ("two.example.com", "miss")
    await holder
    assert scan.calls == ["one.example.com", "two.example.com"]


async def test_running_scan_finishes_and_is_cached_after_its_client_disconnects() -> None:
    scan = FakeScan(release=asyncio.Event())
    app = create_app(settings=Settings(rate_limit_scans=0), scan=scan)
    gone = asyncio.Event()
    request = asyncio.create_task(scan_request_until(app, "example.com", gone))
    await asyncio.sleep(0.01)
    gone.set()
    await asyncio.wait_for(request, 1)
    assert scan.release is not None
    scan.release.set()
    await asyncio.sleep(0.01)
    async with client(app) as http:
        assert (await http.post(SCAN, json={"domain": "example.com"})).status_code == 200
    assert scan.calls == ["example.com"]  # the second request was a cache hit


# --- Origin authentication and the client address ---------------------------------------

SECRET = "s" * 32
NEW_SECRET = "n" * 64
BEHIND_PROXY = Settings(
    rate_limit_scans=1, origin_auth_secrets=(SECRET,), client_ip_header="CF-Connecting-IP"
)


def via_proxy(address: str, secret: str = SECRET, **extra: str) -> dict[str, str]:
    """Headers of a request that passed through the proxy."""
    return {"X-Origin-Auth": secret, "CF-Connecting-IP": address, **extra}


async def test_spoofed_forwarded_for_is_ignored_without_a_proxy() -> None:
    app = create_app(settings=Settings(rate_limit_scans=1), scan=FakeScan())
    async with client(app, ip="198.51.100.7") as http:
        first = await http.post(
            SCAN, json={"domain": "one.example.com"}, headers={"X-Forwarded-For": "203.0.113.1"}
        )
        second = await http.post(
            SCAN,
            json={"domain": "two.example.com"},
            headers={"X-Forwarded-For": "203.0.113.2", "CF-Connecting-IP": "203.0.113.3"},
        )
    assert first.status_code == 200
    problem(second, 429, "rate-limited")  # one client: the TCP peer


async def test_client_address_comes_from_the_proxy_header() -> None:
    scan = FakeScan()
    app = create_app(settings=BEHIND_PROXY, scan=scan)
    async with client(app, ip="10.0.0.1") as http:  # every request comes from the proxy
        first = await http.post(
            SCAN, json={"domain": "one.example.com"}, headers=via_proxy("198.51.100.1")
        )
        other = await http.post(
            SCAN, json={"domain": "two.example.com"}, headers=via_proxy("198.51.100.2")
        )
        spoofed = await http.post(
            SCAN,
            json={"domain": "three.example.com"},
            headers=via_proxy("198.51.100.1", **{"X-Forwarded-For": "203.0.113.9"}),
        )
    assert (first.status_code, other.status_code) == (200, 200)
    problem(spoofed, 429, "rate-limited")  # X-Forwarded-For does not make a new client
    assert scan.calls == ["one.example.com", "two.example.com"]


@pytest.mark.parametrize(
    "headers",
    [
        {"CF-Connecting-IP": "198.51.100.1"},
        {"X-Origin-Auth": "wrong", "CF-Connecting-IP": "198.51.100.1"},
        {"X-Origin-Auth": SECRET[:-1], "CF-Connecting-IP": "198.51.100.1"},
        {"X-Origin-Auth": SECRET + "x", "CF-Connecting-IP": "198.51.100.1"},
        {"X-Origin-Auth": "", "CF-Connecting-IP": "198.51.100.1"},
    ],
)
async def test_request_without_the_secret_is_forbidden(headers: dict[str, str]) -> None:
    scan = FakeScan()
    async with client(create_app(settings=BEHIND_PROXY, scan=scan)) as http:
        reply = await http.post(SCAN, json={"domain": "example.com"}, headers=headers)
    problem(reply, 403, "forbidden")
    assert scan.calls == []


@pytest.mark.parametrize(
    "headers",
    [
        [(b"x-origin-auth", b"wrong"), (b"x-origin-auth", SECRET.encode())],
        [(b"x-origin-auth", "ş".encode() * 16)],  # not ASCII
    ],
)
async def test_repeated_or_non_ascii_secret_header_is_forbidden(
    headers: list[tuple[bytes, bytes]],
) -> None:
    async with client(create_app(settings=BEHIND_PROXY, scan=FakeScan())) as http:
        reply = await http.post(
            SCAN,
            json={"domain": "example.com"},
            headers=[*headers, (b"cf-connecting-ip", b"198.51.100.1")],
        )
    problem(reply, 403, "forbidden")


async def test_every_route_but_health_and_root_needs_the_secret() -> None:
    async with client(create_app(settings=BEHIND_PROXY, scan=FakeScan())) as http:
        health = await http.get("/health")
        root = await http.get("/")
        refused = [
            await http.post("/health"),
            await http.get("/docs"),
            await http.get("/openapi.json"),
            await http.get("/api/v1/nothing"),
            await http.options(SCAN, headers=preflight(ALLOWED_ORIGIN)),
        ]
    assert (health.status_code, root.status_code) == (200, 200)
    for reply in refused:
        problem(reply, 403, "forbidden")


@pytest.mark.parametrize(
    ("path", "headers"),
    [
        ("/anything", []),
        ("/health", []),
        (SCAN, [(b"x-origin-auth", SECRET.encode())]),
    ],
)
async def test_websockets_are_closed_by_origin_auth(
    path: str, headers: list[tuple[bytes, bytes]]
) -> None:
    app = create_app(settings=BEHIND_PROXY, scan=FakeScan())
    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "scheme": "ws",
        "http_version": "1.1",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"token=raw",
        "root_path": "",
        "headers": [(b"host", b"testserver"), *headers],
        "client": ("198.51.100.7", 50000),
        "server": ("testserver", 80),
        "subprotocols": [],
    }
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "websocket.connect"}

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)
    # 1008 (policy violation), not the router's 1000 for a route that does not exist.
    assert sent == [{"type": "websocket.close", "code": 1008, "reason": ""}]


async def test_two_secrets_allow_a_rotation() -> None:
    settings = Settings(
        origin_auth_secrets=(SECRET, NEW_SECRET), client_ip_header="CF-Connecting-IP"
    )
    async with client(create_app(settings=settings, scan=FakeScan())) as http:
        old = await http.post(
            SCAN, json={"domain": "one.example.com"}, headers=via_proxy("198.51.100.1")
        )
        new = await http.post(
            SCAN, json={"domain": "two.example.com"}, headers=via_proxy("198.51.100.2", NEW_SECRET)
        )
        other = await http.post(
            SCAN, json={"domain": "three.example.com"}, headers=via_proxy("198.51.100.3", "o" * 32)
        )
    assert (old.status_code, new.status_code) == (200, 200)
    problem(other, 403, "forbidden")


@pytest.mark.parametrize(
    ("first", "second", "third"),
    [
        ("2001:db8:1:2::1", "2001:db8:1:2:ffff::9", "2001:db8:1:3::1"),
        # Cloudflare's address for requests from Workers on other zones: one client.
        ("2a06:98c0:3600::103", "2a06:98c0:3600::103", "2a06:98c0:3601::103"),
        ("::ffff:198.51.100.7", "198.51.100.7", "198.51.100.8"),
    ],
)
async def test_proxy_header_addresses_are_keyed_like_peers(
    first: str, second: str, third: str
) -> None:
    async with client(create_app(settings=BEHIND_PROXY, scan=FakeScan())) as http:
        replies = [
            await http.post(SCAN, json={"domain": f"s{n}.example.com"}, headers=via_proxy(address))
            for n, address in enumerate((first, second, third))
        ]
    assert [reply.status_code for reply in replies] == [200, 429, 200]


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Origin-Auth": SECRET},
        via_proxy(""),
        via_proxy("unknown"),
        via_proxy("198.51.100.1, 203.0.113.9"),
        via_proxy("198.51.100.256"),
        via_proxy("2001:db8::/64"),
    ],
)
async def test_missing_or_invalid_client_address_is_a_400(headers: dict[str, str]) -> None:
    scan = FakeScan()
    async with client(create_app(settings=BEHIND_PROXY, scan=scan)) as http:
        reply = await http.post(SCAN, json={"domain": "example.com"}, headers=headers)
    body = problem(reply, 400, "invalid-client-ip")
    assert body["detail"] == "The proxy in front of the API did not pass a valid client address."
    assert scan.calls == []


async def test_repeated_client_address_header_is_a_400() -> None:
    async with client(create_app(settings=BEHIND_PROXY, scan=FakeScan())) as http:
        reply = await http.post(
            SCAN,
            json={"domain": "example.com"},
            headers=[
                ("X-Origin-Auth", SECRET),
                ("CF-Connecting-IP", "198.51.100.1"),
                ("CF-Connecting-IP", "198.51.100.2"),
            ],
        )
    problem(reply, 400, "invalid-client-ip")


async def test_scan_line_names_the_address_source_but_not_the_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="webriskaudit.api")
    peer_app = create_app(settings=Settings(), scan=FakeScan())
    async with client(peer_app, ip="198.51.100.7") as http:
        await http.post(SCAN, json={"domain": "example.com"})
    async with client(create_app(settings=BEHIND_PROXY, scan=FakeScan())) as http:
        await http.post(SCAN, json={"domain": "example.org"}, headers=via_proxy("203.0.113.9"))
    lines = [
        json.loads(JsonFormatter().format(r)) for r in caplog.records if r.getMessage() == "scan"
    ]
    assert [line["client_ip_source"] for line in lines] == ["peer", "header"]
    for address in ("198.51.100.7", "203.0.113.9", SECRET):
        assert address not in caplog.text
        assert all(address not in json.dumps(line) for line in lines)


# --- Request size ---------------------------------------------------------------------


async def test_large_body_is_refused_before_it_is_read() -> None:
    scan = FakeScan()
    body = json.dumps({"domain": "a" * 50_000}).encode()
    async with client(create_app(settings=Settings(), scan=scan)) as http:
        reply = await http.post(
            SCAN,
            content=body,
            headers={"content-type": "application/json", "origin": ALLOWED_ORIGIN},
        )
    detail = problem(reply, 413, "request-too-large")["detail"]
    assert detail == "The request body is larger than 8192 bytes."
    assert reply.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
    assert scan.calls == []


async def test_large_streamed_body_is_cut_off() -> None:
    chunks_read = 0

    async def chunks() -> AsyncIterator[bytes]:
        nonlocal chunks_read
        yield b'{"domain": "'
        for _ in range(10_000):
            chunks_read += 1
            yield b"a" * 1000
        yield b'"}'

    async with client(create_app(settings=Settings(), scan=FakeScan())) as http:
        reply = await http.post(
            SCAN, content=chunks(), headers={"content-type": "application/json"}
        )
    problem(reply, 413, "request-too-large")
    assert chunks_read < 20


async def test_overlong_domain_is_an_invalid_request() -> None:
    async with client(create_app(settings=Settings(), scan=FakeScan())) as http:
        reply = await http.post(SCAN, json={"domain": "a" * 2049})
    assert "at most 2048 characters" in str(problem(reply, 422, "invalid-request")["detail"])


def test_openapi_documents_the_domain_length_limit() -> None:
    schema = create_app(settings=Settings(), scan=FakeScan()).openapi()
    assert (
        schema["components"]["schemas"]["ScanRequest"]["properties"]["domain"]["maxLength"] == 2048
    )


# --- Report size ----------------------------------------------------------------------


async def test_hostile_home_page_gives_a_small_report() -> None:
    meta = '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'">'
    page = response(
        "https://example.com/",
        headers=[
            ("Content-Type", "text/html"),
            ("Content-Security-Policy", ", ".join(["script-src 'self'"] * 5000)),
        ],
        body=(meta * 14_000)[:1_000_000],
    )
    fetcher = FakeFetcher(
        {"https://example.com/": page, "http://example.com/": response("https://example.com/")}
    )
    scanner = Scanner(
        resolver=FakeResolver(address_records={"example.com": ["93.184.215.14"]}),
        fetcher=fetcher,
        tls=FakeTlsProber(TlsProbeResult(verified=True)),
    )
    async with client(create_app(settings=Settings(), scan=scanner.scan)) as http:
        reply = await http.post(SCAN, json={"domain": "example.com"})
    assert reply.status_code == 200
    assert len(reply.content) < 64_000


# --- DNS ------------------------------------------------------------------------------


def test_configured_nameservers_reach_the_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[DnsResolver] = []

    def recording_resolver(**kwargs: Any) -> DnsResolver:
        built.append(DnsResolver(**kwargs))
        return built[-1]

    monkeypatch.setattr("webriskaudit.api.DnsResolver", recording_resolver)
    create_app(settings=Settings(dns_nameservers=("192.0.2.53", "2001:db8::53")))
    assert [resolver.nameservers for resolver in built] == [("192.0.2.53", "2001:db8::53")]
