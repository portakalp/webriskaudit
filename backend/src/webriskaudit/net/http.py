"""HTTP fetcher that only talks to public addresses (SSRF guard).

Every hop, including each redirect, is checked before any connection: http or
https on the default port, no credentials in the URL, a real domain name, and
every resolved address public. The request then goes to one of those resolved
addresses ("pinning"), so a second DNS answer cannot redirect the connection.
For https the hostname is sent as SNI and used for certificate verification.
"""

import asyncio
import ssl
import zlib
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, replace

import httpx

from webriskaudit import USER_AGENT
from webriskaudit.net.addresses import is_public_address, pick_address
from webriskaudit.net.domain import InvalidDomainError, normalize_domain
from webriskaudit.net.tls import verified_context
from webriskaudit.net.types import (
    DnsError,
    FetchError,
    FetchErrorReason,
    HttpResponse,
    Resolver,
)

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
# Only codings that can be decoded with a bounded output size are offered.
ACCEPT_ENCODING = "gzip, deflate"
# Share of the time budget kept back so a slow body is cut off (and flagged as
# truncated) before the overall deadline throws away the status and headers.
_BODY_RESERVE = 0.1


@dataclass(frozen=True)
class _Hop:
    url: httpx.URL
    """The URL as addressed, with the hostname."""
    host: str
    address: str
    """The public address the connection is pinned to."""


class GuardedFetcher:
    """Fetcher with SSRF guards, address pinning and manual redirects.

    ``timeout`` bounds one whole ``get()`` (DNS, redirects and body included).
    ``transport`` replaces the network in tests (``httpx.MockTransport``); the
    fetcher never closes it.
    """

    def __init__(
        self,
        resolver: Resolver,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 10.0,
        max_redirects: int = 5,
        max_body_bytes: int = 1_000_000,
    ) -> None:
        self._resolver = resolver
        self._transport = transport
        self._timeout = timeout
        self._max_redirects = max_redirects
        self._max_body_bytes = max_body_bytes
        self._ssl_context = verified_context()

    async def get(self, url: str) -> HttpResponse:
        deadline = asyncio.get_running_loop().time() + self._timeout
        try:
            async with asyncio.timeout_at(deadline):
                return await self._follow(_parse_url(url), deadline)
        except TimeoutError:
            raise FetchError(
                FetchErrorReason.TIMEOUT, f"no response within {self._timeout:g} s"
            ) from None

    async def _follow(self, url: httpx.URL, deadline: float) -> HttpResponse:
        history: list[HttpResponse] = []
        while True:
            try:
                response = await self._request(await self._pin(url), deadline)
            except FetchError as exc:
                exc.url = str(url)
                raise
            location = response.header("location")
            if response.status not in REDIRECT_STATUSES or location is None:
                redirects = tuple(hop.url for hop in history)
                return replace(response, redirects=redirects, history=tuple(history))
            if len(history) >= self._max_redirects:
                raise FetchError(
                    FetchErrorReason.TOO_MANY_REDIRECTS,
                    f"more than {self._max_redirects} redirects",
                )
            history.append(response)
            url = _redirect_target(url, location)

    async def _pin(self, url: httpx.URL) -> _Hop:
        host = check_url(url)
        try:
            addresses = await self._resolver.addresses(host)
        except DnsError as exc:
            raise FetchError(FetchErrorReason.DNS, f"{host} could not be resolved") from exc
        if not addresses or not all(is_public_address(address) for address in addresses):
            raise FetchError(FetchErrorReason.BLOCKED, f"{host} resolves to a non-public address")
        return _Hop(url=url, host=host, address=pick_address(addresses))

    async def _request(self, hop: _Hop, deadline: float) -> HttpResponse:
        """One GET to the pinned address, without following redirects."""
        transport = self._transport or httpx.AsyncHTTPTransport(
            verify=self._ssl_context, trust_env=False, retries=0
        )
        try:
            response = await transport.handle_async_request(self._build_request(hop))
            try:
                return await self._read(hop, response, deadline)
            finally:
                await response.aclose()
        except httpx.HTTPError as exc:
            raise map_httpx_error(exc, hop.host) from exc
        finally:
            if self._transport is None:
                await transport.aclose()

    def _build_request(self, hop: _Hop) -> httpx.Request:
        extensions: dict[str, object] = {"timeout": httpx.Timeout(self._timeout).as_dict()}
        if hop.url.scheme == "https":
            # httpcore uses this name for SNI and certificate hostname checks
            # instead of the address in the URL.
            extensions["sni_hostname"] = hop.host
        return httpx.Request(
            "GET",
            hop.url.copy_with(host=hop.address),
            headers={
                "Host": hop.host,
                "User-Agent": USER_AGENT,
                "Accept": ACCEPT,
                "Accept-Encoding": ACCEPT_ENCODING,
            },
            extensions=extensions,
        )

    async def _read(self, hop: _Hop, response: httpx.Response, deadline: float) -> HttpResponse:
        body, truncated = b"", False
        if response.status_code not in REDIRECT_STATUSES:
            body, truncated = await read_body(
                response,
                ", ".join(response.headers.get_list("content-encoding")),
                self._max_body_bytes,
                stop_at=deadline - self._timeout * _BODY_RESERVE,
            )
        return HttpResponse(
            url=str(hop.url),
            status=response.status_code,
            headers=tuple(response.headers.multi_items()),
            body=body,
            truncated=truncated,
        )


def check_url(url: httpx.URL) -> str:
    """The normalized hostname of ``url`` if it may be fetched; else FetchError BLOCKED."""
    if url.scheme not in ("http", "https"):
        raise FetchError(FetchErrorReason.BLOCKED, "only http and https URLs are fetched")
    if url.userinfo:
        raise FetchError(FetchErrorReason.BLOCKED, "URLs with credentials are not fetched")
    if url.port is not None:  # httpx reports None for the scheme's default port
        raise FetchError(FetchErrorReason.BLOCKED, f"port {url.port} is not fetched")
    blocked = FetchError(FetchErrorReason.BLOCKED, "the host is not a public domain name")
    try:
        raw_host = url.raw_host.decode("ascii")
        host = normalize_domain(raw_host)
    except (InvalidDomainError, UnicodeDecodeError) as exc:
        raise blocked from exc
    # normalize_domain reads its input like a URL: for "evil.com\.example.com"
    # it returns "evil.com", while the URL (and the report) would name the host
    # httpx parsed. Both must agree on the host that is contacted.
    if host != raw_host.lower().rstrip("."):
        raise blocked
    return host


def map_httpx_error(exc: httpx.HTTPError, host: str) -> FetchError:
    """Translate an httpx exception into the foundation's FetchError.

    Only a refused connection is CONNECT: it shows that nothing listens on the
    port. Unreachable hosts and connections reset after they were accepted are
    NETWORK, since they say nothing about the service.
    """
    if isinstance(exc, httpx.TimeoutException):
        return FetchError(FetchErrorReason.TIMEOUT, f"{host} did not respond in time")
    causes = list(_causes(exc))
    ssl_error = next((e for e in causes if isinstance(e, ssl.SSLError)), None)
    if ssl_error is not None:
        detail = _ssl_detail(ssl_error)
        return FetchError(FetchErrorReason.TLS, f"TLS handshake with {host} failed: {detail}")
    if isinstance(exc, httpx.ConnectError) and any(
        isinstance(e, ConnectionRefusedError) for e in causes
    ):
        return FetchError(FetchErrorReason.CONNECT, f"{host} refused the connection")
    if isinstance(exc, httpx.NetworkError):
        error = next((e.strerror for e in causes if isinstance(e, OSError) and e.strerror), None)
        detail = f": {error}" if error else ""
        return FetchError(FetchErrorReason.NETWORK, f"the connection to {host} failed{detail}")
    return FetchError(FetchErrorReason.PROTOCOL, f"invalid HTTP response from {host}")


def _ssl_detail(error: ssl.SSLError) -> str:
    """The most specific text OpenSSL gave; the attributes exist only on errors it raised."""
    return str(getattr(error, "verify_message", None) or getattr(error, "reason", None) or error)


def _causes(exc: BaseException) -> Iterator[BaseException]:
    """``exc`` and every exception that led to it, nearest first.

    httpx wraps the socket error twice (httpx, then httpcore) and anyio may
    wrap it in an exception group, so causes, contexts and group members are
    all followed.
    """
    seen: set[int] = set()
    pending = deque([exc])
    while pending:
        current = pending.popleft()
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        pending.extend(e for e in (current.__cause__, current.__context__) if e is not None)


def _parse_url(url: str) -> httpx.URL:
    try:
        return httpx.URL(url).copy_with(fragment=None)
    except (httpx.InvalidURL, ValueError) as exc:
        raise FetchError(FetchErrorReason.BLOCKED, "the URL is not valid") from exc


def _redirect_target(current: httpx.URL, location: str) -> httpx.URL:
    # urllib's urljoin, which httpx uses, raises a plain ValueError for some
    # malformed locations such as ":http://[".
    try:
        return current.join(location.strip()).copy_with(fragment=None)
    except (httpx.InvalidURL, ValueError) as exc:
        raise FetchError(FetchErrorReason.PROTOCOL, "the redirect location is not valid") from exc


async def read_body(
    response: httpx.Response, coding: str, limit: int, *, stop_at: float | None = None
) -> tuple[bytes, bool]:
    """Read and decode at most ``limit`` body bytes; True if the body was cut short.

    A body that breaks off, fails to decode or is still arriving at ``stop_at``
    (event loop time) is kept as far as it got and flagged as truncated: the
    status and headers are still valid.
    """
    decoder = _Decoder(coding)
    body = bytearray()
    raw_seen = 0
    try:
        async with asyncio.timeout_at(stop_at):
            async for chunk in response.aiter_raw():
                raw_seen += len(chunk)
                body += decoder.decode(chunk, limit - len(body) + 1)
                if len(body) > limit or raw_seen > 2 * limit:
                    return bytes(body[:limit]), True
    except (TimeoutError, httpx.TransportError, zlib.error):
        return bytes(body[:limit]), True
    return bytes(body), False


class _Decoder:
    """Decodes a gzip or deflate body without producing more than asked for.

    httpx's own decoders inflate a whole network read at once, so a small
    compressed chunk could expand to many megabytes before a size cap applies.
    Unknown or stacked codings pass through undecoded, as in httpx.
    """

    def __init__(self, coding: str) -> None:
        codings = [c.strip().lower() for c in coding.split(",")]
        codings = [c for c in codings if c and c != "identity"]
        self._coding = codings[0] if len(codings) == 1 else None
        self._started = False
        self._zlib: zlib._Decompress | None = None
        if self._coding in ("gzip", "x-gzip"):
            self._zlib = zlib.decompressobj(zlib.MAX_WBITS | 16)
        elif self._coding == "deflate":
            self._zlib = zlib.decompressobj(zlib.MAX_WBITS)

    def decode(self, data: bytes, limit: int) -> bytes:
        """At most ``limit`` (>= 1) decoded bytes of ``data``. Raises zlib.error."""
        if self._zlib is None:
            return data[:limit]
        try:
            return self._zlib.decompress(data, limit)
        except zlib.error:
            if self._started or self._coding != "deflate":
                raise
            # Some servers send raw deflate without the zlib wrapper.
            self._zlib = zlib.decompressobj(-zlib.MAX_WBITS)
            return self._zlib.decompress(data, limit)
        finally:
            self._started = True
