"""HTTP API: ``POST /api/v1/scan`` plus service info and a health check.

Errors are RFC 9457 problem details (``application/problem+json``). Abuse
controls live in this process: a request body size limit, per-client and
overall rate limits on new scans, a short-lived report cache that also
coalesces concurrent scans of one domain, and a cap on scans running or
waiting for a slot, with a time limit on the wait.

Run with ``uvicorn webriskaudit.api:app``.
"""

import asyncio
import logging
import math
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from webriskaudit import __version__
from webriskaudit.cache import ResultCache
from webriskaudit.logs import configure_logging
from webriskaudit.models import ScanReport
from webriskaudit.net.dns import DnsResolver
from webriskaudit.net.domain import InvalidDomainError, normalize_domain
from webriskaudit.ratelimit import RateLimiter, client_key
from webriskaudit.scanner import (
    DnsUnavailableScanError,
    DomainNotFoundError,
    NonPublicTargetError,
    ScanError,
    Scanner,
)
from webriskaudit.settings import Settings

ScanFn = Callable[[str], Awaitable[ScanReport]]

PROBLEM_BASE = "https://webriskaudit.com/problems/"
PROBLEM_MEDIA_TYPE = "application/problem+json"

MAX_BODY_BYTES = 8192
"""Largest request body read; a scan request needs a few hundred bytes."""
MAX_DOMAIN_LENGTH = 2048
BUSY_RETRY_AFTER = 10
"""Seconds a client is asked to wait when the scanner has no room for a new scan."""
RUNNING_RETRY_AFTER = 5
"""Seconds a client is asked to wait while its previous new scan is still running."""

logger = logging.getLogger(__name__)


# --- Models ------------------------------------------------------------------


class ScanRequest(BaseModel):
    domain: str = Field(
        description="Domain name or URL to scan. The host is scanned as given (www. is kept).",
        examples=["example.com"],
        max_length=MAX_DOMAIN_LENGTH,
    )


class ProblemDetails(BaseModel):
    """An error response (RFC 9457 problem details)."""

    type: str = Field(
        description="URI that identifies the problem type.",
        examples=[PROBLEM_BASE + "invalid-domain"],
    )
    title: str = Field(description="Short summary of the problem type.")
    status: int = Field(description="HTTP status code.")
    detail: str = Field(description="Explanation of this occurrence, safe to show to users.")


class ServiceInfo(BaseModel):
    name: str
    version: str
    docs: str


class Health(BaseModel):
    status: Literal["ok"]


# --- Problems ----------------------------------------------------------------


class ProblemError(Exception):
    """An error answered with problem details."""

    def __init__(
        self,
        status: int,
        slug: str,
        title: str,
        detail: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status = status
        self.slug = slug
        self.title = title
        self.detail = detail
        self.headers = headers


_SCAN_ERRORS: dict[type[ScanError], tuple[int, str, str]] = {
    DomainNotFoundError: (422, "domain-not-found", "Domain not found"),
    NonPublicTargetError: (422, "non-public-target", "Non-public target"),
    DnsUnavailableScanError: (502, "dns-unavailable", "DNS unavailable"),
}


def problem_response(
    status: int,
    type_: str,
    title: str,
    detail: str,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body = ProblemDetails(type=type_, title=title, status=status, detail=detail)
    return JSONResponse(
        body.model_dump(), status_code=status, headers=headers, media_type=PROBLEM_MEDIA_TYPE
    )


def _problem_doc(description: str, **extra: Any) -> dict[str, Any]:
    content = {PROBLEM_MEDIA_TYPE: {"schema": {"$ref": "#/components/schemas/ProblemDetails"}}}
    return {"description": description, "content": content, **extra}


def _retry_after_doc(description: str) -> dict[str, Any]:
    return {"Retry-After": {"description": description, "schema": {"type": "integer"}}}


_SCAN_RESPONSES: dict[int | str, dict[str, Any]] = {
    413: _problem_doc(
        f"The request body is larger than {MAX_BODY_BYTES} bytes (request-too-large)."
    ),
    422: _problem_doc(
        "The input is not a public domain name (invalid-domain), the body is malformed "
        "(invalid-request), the domain does not exist (domain-not-found), or it resolves to a "
        "non-public address (non-public-target)."
    ),
    429: _problem_doc(
        "Too many new scans from this client, or its previous new scan is still running "
        "(rate-limited). A client is an IPv4 address or an IPv6 /64 network.",
        headers=_retry_after_doc("Seconds until this client may start another scan."),
    ),
    500: _problem_doc("The scan failed unexpectedly (internal-error)."),
    502: _problem_doc("DNS gave no usable answer for the domain (dns-unavailable)."),
    503: _problem_doc(
        "The scanner has no room for a new scan: too many are running or waiting, none could "
        "start in time, or the overall limit of new scans is used up (scanner-busy).",
        headers=_retry_after_doc("Seconds until a new scan is likely to be accepted."),
    ),
}


def _rate_limited(seconds: float, detail: str) -> ProblemError:
    wait = max(1, math.ceil(seconds))
    return ProblemError(
        429,
        "rate-limited",
        "Too many scans",
        detail.format(seconds=wait),
        {"Retry-After": str(wait)},
    )


def _busy(seconds: float, detail: str) -> ProblemError:
    wait = max(1, math.ceil(seconds))
    return ProblemError(
        503,
        "scanner-busy",
        "Scanner busy",
        detail.format(seconds=wait),
        {"Retry-After": str(wait)},
    )


# --- Scanning service ----------------------------------------------------------


class ScannerBusyError(Exception):
    """A new scan waited longer than the queue timeout for a slot."""


@dataclass
class _NewScan:
    """A scan started by this service that is waiting for a slot or running."""

    client: str
    """Rate limit key of the client that started it."""
    callers: int = 0
    """Requests waiting for its report."""
    started: bool = False
    """True once it holds a slot."""


_OVERALL = "*"


class ScanService:
    """Cache, coalescing, rate limits and a bounded queue around a scan function.

    New scans take one of ``max_concurrent_scans`` slots. At most
    ``max_queued_scans`` more wait for one, each for ``queue_timeout`` seconds
    at most. While the per-client limit is on, a client may have one new scan
    running or waiting at a time. A waiting scan is cancelled once every
    request for it has gone away.
    """

    def __init__(self, scan: ScanFn, settings: Settings) -> None:
        self._scan = scan
        self._cache: ResultCache[ScanReport] = ResultCache(settings.cache_ttl)
        self._per_client = RateLimiter(settings.rate_limit_scans, settings.rate_limit_window)
        self._overall = RateLimiter(settings.global_rate_limit_scans, settings.rate_limit_window)
        self._slots = asyncio.Semaphore(settings.max_concurrent_scans)
        self._capacity = settings.max_concurrent_scans + settings.max_queued_scans
        self._queue_timeout = settings.queue_timeout
        self._scans: dict[asyncio.Task[ScanReport], _NewScan] = {}

    async def report(self, domain: str, client: str) -> tuple[ScanReport, str]:
        """The report for a normalized domain and where it came from: miss, hit or coalesced.

        Only a new scan counts against the rate limits.
        """
        cached = self._cache.get(domain)
        if cached is not None:
            return cached, "hit"
        task = self._cache.running(domain)
        if task is not None and task.cancelling():
            task = None  # dropped by its last caller a moment ago and not finished yet
        source = "coalesced"
        if task is None:
            key = client_key(client)
            self._admit(key)
            scan = _NewScan(key)
            task = self._cache.start(domain, self._run(domain, scan))
            self._scans[task] = scan
            task.add_done_callback(self._finished)
            source = "miss"
        return await self._join(task), source

    def _admit(self, client: str) -> None:
        """Count a new scan for ``client``, or raise the problem that refuses it."""
        wait = self._per_client.wait(client)
        if wait is not None:
            raise _rate_limited(
                wait, "Too many scans from this address. Try again in {seconds} seconds."
            )
        if self._per_client.enabled and any(scan.client == client for scan in self._scans.values()):
            raise _rate_limited(
                RUNNING_RETRY_AFTER,
                "A scan from this address is still running. Try again when it has finished.",
            )
        wait = self._overall.wait(_OVERALL)
        if wait is not None:
            raise _busy(
                wait,
                "The scanner has reached its limit of new scans for now. Try again in "
                "{seconds} seconds.",
            )
        if len(self._scans) >= self._capacity:
            raise _busy(
                BUSY_RETRY_AFTER,
                "The scanner is busy with other scans. Try again in {seconds} seconds.",
            )
        self._per_client.hit(client)
        self._overall.hit(_OVERALL)

    async def _join(self, task: asyncio.Task[ScanReport]) -> ScanReport:
        """Wait for a shared scan. The scan outlives this caller unless it never started."""
        scan = self._scans.get(task)
        if scan is None:  # finished already
            return await asyncio.shield(task)
        scan.callers += 1
        try:
            return await asyncio.shield(task)
        finally:
            scan.callers -= 1
            if scan.callers == 0 and not scan.started and not task.done():
                task.cancel()
                self._scans.pop(task, None)  # it no longer takes a queue place or the client's turn

    async def _run(self, domain: str, scan: _NewScan) -> ScanReport:
        try:
            async with asyncio.timeout(self._queue_timeout):
                await self._slots.acquire()
        except TimeoutError:
            raise ScannerBusyError from None
        scan.started = True
        try:
            return await self._scan(domain)
        finally:
            self._slots.release()

    def _finished(self, task: asyncio.Task[ScanReport]) -> None:
        self._scans.pop(task, None)


# --- Request body limit ----------------------------------------------------------


class BodySizeLimit:
    """Answers 413 to a request whose body is over ``max_bytes``, before the app reads it.

    Bodies up to that size are buffered here and handed to the app unchanged,
    so a large or endless body is never read or parsed in full.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if _content_length(scope) > self.max_bytes:
            await self._refuse(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return  # the client went away while sending the body
            body += message.get("body", b"")
            if len(body) > self.max_bytes:
                await self._refuse(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if replayed:
                return await receive()
            replayed = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, send)

    async def _refuse(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = problem_response(
            413,
            PROBLEM_BASE + "request-too-large",
            "Request too large",
            f"The request body is larger than {self.max_bytes} bytes.",
        )
        await response(scope, receive, send)


def _content_length(scope: Scope) -> int:
    """The declared Content-Length, or 0 when absent or not a number."""
    for name, value in scope.get("headers", ()):
        if name.lower() == b"content-length" and value.strip().isdigit():
            return int(value)
    return 0


# --- Application -----------------------------------------------------------------


class _Api(FastAPI):
    def openapi(self) -> dict[str, Any]:
        first = self.openapi_schema is None
        schema = super().openapi()
        if first:
            components = schema.setdefault("components", {}).setdefault("schemas", {})
            components["ProblemDetails"] = ProblemDetails.model_json_schema()
        return schema


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    yield


def _client_ip(request: Request) -> str:
    # Behind a reverse proxy, uvicorn --proxy-headers puts the real client here.
    return request.client.host if request.client else "unknown"


async def _until_disconnected(request: Request) -> None:
    """Return once the client has disconnected; the request body has been read by then."""
    while (await request.receive())["type"] != "http.disconnect":
        pass


async def _unless_disconnected[T](request: Request, work: Awaitable[T]) -> T:
    """Await ``work``, but cancel it if the client disconnects first.

    uvicorn does not cancel a handler whose client has gone away, so without
    this a scan waiting for a slot would wait, and then run, for nobody.
    """
    task = asyncio.ensure_future(work)
    watcher = asyncio.ensure_future(_until_disconnected(request))
    try:
        await asyncio.wait((task, watcher), return_when=asyncio.FIRST_COMPLETED)
    except asyncio.CancelledError:
        task.cancel()
        raise
    finally:
        watcher.cancel()
    if task.done():
        return task.result()
    task.cancel()
    await asyncio.wait((task,))
    raise ProblemError(
        499,
        "client-disconnected",
        "Client disconnected",
        "The client closed the connection before the scan finished.",
    )


def create_app(*, settings: Settings | None = None, scan: ScanFn | None = None) -> FastAPI:
    """Build the API. ``scan`` replaces the real scanner (tests inject fakes)."""
    settings = settings or Settings.from_env()
    if scan is None:
        scan = Scanner(
            resolver=DnsResolver(nameservers=settings.dns_nameservers),
            deadline=settings.scan_deadline,
            check_timeout=settings.check_timeout,
        ).scan
    service = ScanService(scan, settings)

    app = _Api(
        title="WebRiskAudit API",
        version=__version__,
        description="Passive security posture scanner for domains: email authentication, "
        "HTTPS/TLS and HTTP security headers, with evidence for every verdict.",
        lifespan=_lifespan,
    )
    # Added first, so CORS wraps it and a 413 still carries CORS headers.
    app.add_middleware(BodySizeLimit, max_bytes=MAX_BODY_BYTES)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        expose_headers=["Retry-After"],
    )
    _add_problem_handlers(app)

    @app.get("/", response_model=ServiceInfo, summary="Service information")
    async def root() -> ServiceInfo:
        return ServiceInfo(name="WebRiskAudit API", version=__version__, docs="/docs")

    @app.get("/health", response_model=Health, summary="Liveness check")
    async def health() -> Health:
        return Health(status="ok")

    @app.post(
        "/api/v1/scan",
        response_model=ScanReport,
        responses=_SCAN_RESPONSES,
        summary="Scan a domain",
    )
    async def scan_domain(body: ScanRequest, request: Request) -> ScanReport:
        """Run every check against the domain, or return a recent report from the cache."""
        started = time.perf_counter()
        outcome = "cancelled"
        fields: dict[str, object] = {}
        try:
            domain = _normalize(body.domain)
            fields["domain"] = domain
            report, source = await _unless_disconnected(
                request, _report(service, domain, _client_ip(request))
            )
            fields |= {
                "cache": source,
                "score": report.score,
                "grade": report.grade,
                "coverage": report.coverage.model_dump(),
            }
            outcome = "ok"
            return report
        except ProblemError as problem:
            outcome = problem.slug
            raise
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000)
            entry = {"outcome": outcome, **fields, "duration_ms": duration_ms}
            logger.info("scan", extra={"fields": entry})

    return app


def _normalize(raw: str) -> str:
    try:
        return normalize_domain(raw)
    except InvalidDomainError as exc:
        raise ProblemError(422, "invalid-domain", "Invalid domain", exc.message) from None


async def _report(service: ScanService, domain: str, client: str) -> tuple[ScanReport, str]:
    try:
        return await service.report(domain, client)
    except ProblemError:
        raise
    except ScanError as exc:
        status, slug, title = _SCAN_ERRORS[type(exc)]
        raise ProblemError(status, slug, title, exc.message) from None
    except ScannerBusyError:
        raise _busy(
            BUSY_RETRY_AFTER,
            "No scan slot became free in time. Try again in {seconds} seconds.",
        ) from None
    except Exception:
        logger.exception("scan of %s failed", domain)
        raise ProblemError(
            500,
            "internal-error",
            "Internal error",
            "The scan failed unexpectedly. Please try again later.",
        ) from None


def _add_problem_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProblemError)
    async def problem(request: Request, exc: ProblemError) -> JSONResponse:
        return problem_response(
            exc.status, PROBLEM_BASE + exc.slug, exc.title, exc.detail, exc.headers
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            f"{'.'.join(str(part) for part in error.get('loc', ()))}: {error.get('msg', '')}"
            for error in exc.errors()[:3]
        ]
        detail = 'Send a JSON object such as {"domain": "example.com"}'
        return problem_response(
            422,
            PROBLEM_BASE + "invalid-request",
            "Invalid request",
            f"{detail} ({'; '.join(errors)})." if errors else f"{detail}.",
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        title = _status_phrase(exc.status_code)
        detail = exc.detail if isinstance(exc.detail, str) else title
        return problem_response(exc.status_code, "about:blank", title, detail, exc.headers)

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception) -> JSONResponse:
        logger.error("unhandled error", exc_info=exc)
        return problem_response(
            500,
            PROBLEM_BASE + "internal-error",
            "Internal error",
            "The request failed unexpectedly. Please try again later.",
        )


def _status_phrase(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return "Error"


app = create_app()
