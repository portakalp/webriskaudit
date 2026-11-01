import asyncio
import errno
import gzip
import ssl
import zlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from tests.fakes import DnsAnswer, FakeResolver
from webriskaudit import USER_AGENT
from webriskaudit.net.http import ACCEPT_ENCODING, GuardedFetcher, map_httpx_error
from webriskaudit.net.types import (
    DnsUnavailableError,
    FetchError,
    FetchErrorReason,
    NoAnswerError,
)

PUBLIC_V4 = "93.184.215.14"
PUBLIC_V6 = "2606:2800:21f:cb07:6820:80da:af6b:8b2c"
ADDRESSES: dict[str, DnsAnswer] = {
    "example.com": [PUBLIC_V4],
    "www.example.com": [PUBLIC_V4, PUBLIC_V6],
    "cdn.example.net": [PUBLIC_V6],
    "xn--bcher-kva.de": ["198.51.99.1"],
    "internal.example.com": ["10.0.0.5"],
    "metadata.example.com": ["169.254.169.254"],
    "mixed.example.com": [PUBLIC_V4, "127.0.0.1"],
    "mapped.example.com": ["::ffff:127.0.0.1"],
    "down.example.com": DnsUnavailableError("down.example.com"),
    "empty.example.com": NoAnswerError("empty.example.com"),
}

Page = Callable[[], httpx.Response]


def reply(
    status: int = 200, headers: list[tuple[str, str]] | None = None, body: bytes = b""
) -> httpx.Response:
    # A stream (not ``content=``) keeps the body unread, like a real transport.
    return httpx.Response(status, headers=headers or [], stream=httpx.ByteStream(body))


def redirect(location: str, status: int = 301) -> Page:
    return lambda: reply(status, [("Location", location)])


def ok(body: bytes = b"ok", headers: list[tuple[str, str]] | None = None) -> Page:
    return lambda: reply(200, headers, body)


@dataclass
class Network:
    """Serves pages by logical URL (scheme, Host header, path) and records requests."""

    pages: dict[str, Page]
    requests: list[httpx.Request] = field(default_factory=list)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.raw_path.decode()
        page = self.pages.get(f"{request.url.scheme}://{request.headers['host']}{path}")
        return page() if page is not None else reply(404)


def make_fetcher(
    pages: dict[str, Page], **options: Any
) -> tuple[GuardedFetcher, Network, FakeResolver]:
    network = Network(pages)
    resolver = FakeResolver(address_records=dict(ADDRESSES))
    fetcher = GuardedFetcher(resolver, transport=httpx.MockTransport(network), **options)
    return fetcher, network, resolver


async def fetch_error(fetcher: GuardedFetcher, url: str) -> FetchError:
    with pytest.raises(FetchError) as caught:
        await fetcher.get(url)
    return caught.value


# --- pinning ------------------------------------------------------------------


async def test_request_goes_to_pinned_address_with_host_header_and_sni() -> None:
    fetcher, network, resolver = make_fetcher({"https://example.com/path?q=1": ok(b"hello")})

    result = await fetcher.get("https://example.com/path?q=1#section")

    assert (result.url, result.status, result.body) == (
        "https://example.com/path?q=1",
        200,
        b"hello",
    )
    [request] = network.requests
    assert str(request.url) == f"https://{PUBLIC_V4}/path?q=1"
    assert request.headers["host"] == "example.com"
    assert request.extensions["sni_hostname"] == "example.com"
    assert resolver.queries == [("A/AAAA", "example.com")]


async def test_request_headers() -> None:
    fetcher, network, _ = make_fetcher({"https://example.com/": ok()})
    await fetcher.get("https://example.com/")
    headers = network.requests[0].headers
    assert headers["user-agent"] == USER_AGENT
    assert headers["accept"].startswith("text/html")
    assert headers["accept-encoding"] == ACCEPT_ENCODING
    assert "cookie" not in headers
    assert "authorization" not in headers


async def test_plain_http_has_no_sni_extension() -> None:
    fetcher, network, _ = make_fetcher({"http://example.com/": ok()})
    await fetcher.get("http://example.com/")
    [request] = network.requests
    assert str(request.url) == f"http://{PUBLIC_V4}/"
    assert "sni_hostname" not in request.extensions


async def test_prefers_ipv4_and_brackets_ipv6() -> None:
    fetcher, network, _ = make_fetcher(
        {"https://www.example.com/": ok(), "https://cdn.example.net/": ok()}
    )
    await fetcher.get("https://www.example.com/")
    await fetcher.get("https://cdn.example.net/")
    assert network.requests[0].url.host == PUBLIC_V4
    assert str(network.requests[1].url) == f"https://[{PUBLIC_V6}]/"
    assert network.requests[1].headers["host"] == "cdn.example.net"


async def test_idn_and_trailing_dot_hosts_use_the_normalized_name() -> None:
    fetcher, network, resolver = make_fetcher({"https://xn--bcher-kva.de/": ok()})
    await fetcher.get("https://Bücher.de/")
    await fetcher.get("https://xn--bcher-kva.de./")
    assert [r.headers["host"] for r in network.requests] == ["xn--bcher-kva.de"] * 2
    assert [r.extensions["sni_hostname"] for r in network.requests] == ["xn--bcher-kva.de"] * 2
    assert resolver.queries == [("A/AAAA", "xn--bcher-kva.de")] * 2


# --- redirects ----------------------------------------------------------------


async def test_follows_redirects_and_records_the_chain() -> None:
    fetcher, network, resolver = make_fetcher(
        {
            "http://example.com/": redirect("https://example.com/"),
            "https://example.com/": redirect("https://www.example.com/", status=308),
            "https://www.example.com/": ok(b"home"),
        }
    )

    result = await fetcher.get("http://example.com/")

    assert result.url == "https://www.example.com/"
    assert result.redirects == ("http://example.com/", "https://example.com/")
    assert result.body == b"home"
    # The redirect responses are kept too, so HSTS can be read from each hop.
    assert [(hop.url, hop.status) for hop in result.history] == [
        ("http://example.com/", 301),
        ("https://example.com/", 308),
    ]
    assert result.history[1].header("location") == "https://www.example.com/"
    assert [r.headers["host"] for r in network.requests] == [
        "example.com",
        "example.com",
        "www.example.com",
    ]
    assert [name for _, name in resolver.queries] == [
        "example.com",
        "example.com",
        "www.example.com",
    ]


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("/login", "https://example.com/login"),
        ("next", "https://example.com/a/next"),
        ("../up", "https://example.com/up"),
        ("?page=2", "https://example.com/a/b?page=2"),
        ("//www.example.com/x", "https://www.example.com/x"),
        ("  https://www.example.com/y  ", "https://www.example.com/y"),
        ("https://example.com:443/default-port", "https://example.com/default-port"),
    ],
)
async def test_resolves_relative_redirects(location: str, expected: str) -> None:
    fetcher, _, _ = make_fetcher(
        {
            "https://example.com/a/b": redirect(location, status=302),
            expected: ok(b"target"),
        }
    )
    result = await fetcher.get("https://example.com/a/b")
    assert (result.url, result.body) == (expected, b"target")


@pytest.mark.parametrize(
    "location",
    [
        # IP literals in every spelling
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://2130706433/",
        "http://0x7f.1/",
        "http://127.1/",
        # names that resolve, or would resolve, to non-public addresses
        "http://localhost/",
        "http://localhost.:80/",
        "http://printer.local/",
        "http://internal.example.com/",
        "http://metadata.example.com/",
        "http://mixed.example.com/",
        "http://mapped.example.com/",
        # ports, schemes and credentials
        "https://example.com:8443/",
        "http://example.com:443/",
        "https://example.com:80/",
        "http://example.com:22/",
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "javascript:alert(1)",
        "data:text/html,hi",
        "https://user:pass@example.com/",
        "https://user@example.com/",
        # hosts that httpx and normalize_domain would read differently
        "http://evil.com\\.example.com/",
        "https://example.com\\@evil.com/",
    ],
)
async def test_blocks_unsafe_redirect_targets(location: str) -> None:
    fetcher, network, _ = make_fetcher({"https://example.com/": redirect(location)})
    error = await fetch_error(fetcher, "https://example.com/")
    assert error.reason is FetchErrorReason.BLOCKED
    assert len(network.requests) == 1  # nothing was sent to the target


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "https://internal.example.com/",
        "https://mixed.example.com/",
        "https://user:pass@example.com/",
        "https://example.com:8443/",
        "ftp://example.com/",
        "/relative/path",
        "",
        "http://[::1/",
    ],
)
async def test_blocks_unsafe_initial_urls(url: str) -> None:
    fetcher, network, _ = make_fetcher({})
    error = await fetch_error(fetcher, url)
    assert error.reason is FetchErrorReason.BLOCKED
    assert network.requests == []


async def test_redirect_loop_stops_after_max_redirects() -> None:
    fetcher, network, _ = make_fetcher(
        {"https://example.com/": redirect("https://example.com/", status=302)}, max_redirects=5
    )
    error = await fetch_error(fetcher, "https://example.com/")
    assert error.reason is FetchErrorReason.TOO_MANY_REDIRECTS
    assert len(network.requests) == 6


async def test_follows_exactly_max_redirects() -> None:
    pages = {f"https://example.com/{i}": redirect(f"/{i + 1}", status=307) for i in range(3)}
    pages["https://example.com/3"] = ok(b"done")
    fetcher, _, _ = make_fetcher(pages, max_redirects=3)
    result = await fetcher.get("https://example.com/0")
    assert result.body == b"done"
    assert len(result.redirects) == 3


@pytest.mark.parametrize(
    "location",
    ["https://nowhere.example.org/", "https://down.example.com/", "https://empty.example.com/"],
)
async def test_unresolvable_redirect_target_is_a_dns_error(location: str) -> None:
    fetcher, _, _ = make_fetcher({"https://example.com/": redirect(location)})
    error = await fetch_error(fetcher, "https://example.com/")
    assert error.reason is FetchErrorReason.DNS


@dataclass
class RebindingResolver:
    """Answers with a public address first and a private one afterwards."""

    answers: list[list[str]]

    async def txt(self, name: str) -> list[str]:
        raise NoAnswerError(name)

    async def addresses(self, name: str) -> list[str]:
        return self.answers.pop(0)


async def test_every_hop_is_resolved_and_checked_again() -> None:
    network = Network({"https://example.com/": redirect("https://example.com/next")})
    resolver = RebindingResolver([[PUBLIC_V4], ["127.0.0.1"]])
    fetcher = GuardedFetcher(resolver, transport=httpx.MockTransport(network))
    error = await fetch_error(fetcher, "https://example.com/")
    assert error.reason is FetchErrorReason.BLOCKED
    assert len(network.requests) == 1


async def test_redirect_status_without_location_is_final() -> None:
    fetcher, _, _ = make_fetcher({"https://example.com/": lambda: reply(302)})
    result = await fetcher.get("https://example.com/")
    assert (result.status, result.redirects) == (302, ())


@pytest.mark.parametrize(
    "location",
    # urljoin raises a plain ValueError for the last two.
    ["http://[::1", "http://0177.0.0.1/", "http://a.com:x/", ":http://[", ":https://a-[::1"],
)
async def test_malformed_redirect_location_is_a_protocol_error(location: str) -> None:
    fetcher, network, _ = make_fetcher({"https://example.com/": redirect(location)})
    error = await fetch_error(fetcher, "https://example.com/")
    assert error.reason is FetchErrorReason.PROTOCOL
    assert len(network.requests) == 1


# --- response handling -------------------------------------------------------


async def test_header_names_are_lower_cased_and_repeats_kept_in_order() -> None:
    headers = [
        ("Set-Cookie", "a=1; Secure"),
        ("X-Frame-Options", "DENY"),
        ("set-cookie", "b=2; HttpOnly"),
    ]
    fetcher, _, _ = make_fetcher({"https://example.com/": ok(headers=headers)})
    result = await fetcher.get("https://example.com/")
    assert result.headers == (
        ("set-cookie", "a=1; Secure"),
        ("x-frame-options", "DENY"),
        ("set-cookie", "b=2; HttpOnly"),
    )
    assert result.header_all("Set-Cookie") == ["a=1; Secure", "b=2; HttpOnly"]


@pytest.mark.parametrize(
    ("size", "truncated"),
    [(0, False), (999, False), (1000, False), (1001, True), (50_000, True)],
)
async def test_body_is_capped(size: int, truncated: bool) -> None:
    fetcher, _, _ = make_fetcher({"https://example.com/": ok(b"x" * size)}, max_body_bytes=1000)
    result = await fetcher.get("https://example.com/")
    assert len(result.body) == min(size, 1000)
    assert result.truncated is truncated


class Chunks(httpx.AsyncByteStream):
    """A response body that arrives in pieces, then optionally stalls or breaks."""

    def __init__(self, *chunks: bytes, stall: float = 0.0, error: Exception | None = None):
        self._chunks = chunks
        self._stall = stall
        self._error = error

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk
        if self._stall:
            await asyncio.sleep(self._stall)
        if self._error is not None:
            raise self._error


async def test_body_cap_applies_across_chunks() -> None:
    def page() -> httpx.Response:
        return httpx.Response(200, stream=Chunks(b"a" * 400, b"b" * 400, b"c" * 400))

    fetcher, _, _ = make_fetcher({"https://example.com/": page}, max_body_bytes=1000)
    result = await fetcher.get("https://example.com/")
    assert result.body == b"a" * 400 + b"b" * 400 + b"c" * 200
    assert result.truncated


async def test_broken_body_keeps_headers_and_partial_body() -> None:
    def page() -> httpx.Response:
        stream = Chunks(b"<html>", error=httpx.RemoteProtocolError("peer closed connection"))
        return httpx.Response(200, headers=[("X-Test", "1")], stream=stream)

    fetcher, _, _ = make_fetcher({"https://example.com/": page})
    result = await fetcher.get("https://example.com/")
    assert (result.status, result.body, result.truncated) == (200, b"<html>", True)
    assert result.header("x-test") == "1"


async def test_slow_body_is_cut_off_before_the_deadline() -> None:
    def page() -> httpx.Response:
        return httpx.Response(200, headers=[("X-Test", "1")], stream=Chunks(b"<html>", stall=5))

    fetcher, _, _ = make_fetcher({"https://example.com/": page}, timeout=0.3)
    result = await fetcher.get("https://example.com/")
    assert (result.body, result.truncated, result.header("x-test")) == (b"<html>", True, "1")


def compressed(coding: str, data: bytes) -> Page:
    return ok(data, headers=[("Content-Encoding", coding)])


HTML = b"<html>" + b"privacy " * 100 + b"</html>"


@pytest.mark.parametrize(
    "page",
    [
        compressed("gzip", gzip.compress(HTML)),
        compressed("x-gzip", gzip.compress(HTML)),
        compressed("GZIP", gzip.compress(HTML)),
        compressed("deflate", zlib.compress(HTML)),
        compressed("identity, gzip", gzip.compress(HTML)),
        ok(HTML),
    ],
)
async def test_decodes_content_encoding(page: Page) -> None:
    fetcher, _, _ = make_fetcher({"https://example.com/": page})
    result = await fetcher.get("https://example.com/")
    assert (result.body, result.truncated) == (HTML, False)


async def test_decodes_raw_deflate() -> None:
    raw = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    data = raw.compress(HTML) + raw.flush()
    fetcher, _, _ = make_fetcher({"https://example.com/": compressed("deflate", data)})
    result = await fetcher.get("https://example.com/")
    assert result.body == HTML


async def test_decompression_bomb_is_capped_while_decoding() -> None:
    bomb = gzip.compress(b"\0" * 50_000_000)  # ~50 kB on the wire
    fetcher, _, _ = make_fetcher(
        {"https://example.com/": compressed("gzip", bomb)}, max_body_bytes=1000
    )
    result = await fetcher.get("https://example.com/")
    assert (len(result.body), result.truncated) == (1000, True)


async def test_corrupt_compressed_body_keeps_headers() -> None:
    page = compressed("gzip", b"\x1f\x8b\x08\x00not really gzip")
    fetcher, _, _ = make_fetcher({"https://example.com/": page})
    result = await fetcher.get("https://example.com/")
    assert (result.status, result.body, result.truncated) == (200, b"", True)
    assert result.header("content-encoding") == "gzip"


@pytest.mark.parametrize("coding", ["br", "zstd", "gzip, gzip"])
async def test_unsupported_codings_pass_through(coding: str) -> None:
    fetcher, _, _ = make_fetcher({"https://example.com/": compressed(coding, b"\x8b\x00raw")})
    result = await fetcher.get("https://example.com/")
    assert (result.body, result.truncated) == (b"\x8b\x00raw", False)


async def test_redirect_body_is_not_read() -> None:
    def page() -> httpx.Response:
        stream = Chunks(b"moved", error=httpx.ReadError("would break if read"))
        return httpx.Response(301, headers=[("Location", "/home")], stream=stream)

    fetcher, _, _ = make_fetcher({"https://example.com/": page, "https://example.com/home": ok()})
    result = await fetcher.get("https://example.com/")
    assert result.url == "https://example.com/home"


# --- errors -------------------------------------------------------------------


def certificate_error() -> ssl.SSLCertVerificationError:
    error = ssl.SSLCertVerificationError(
        1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
    )
    error.verify_message = "certificate has expired"
    return error


def raising(exc: Exception, cause: BaseException | None = None) -> Page:
    def page() -> httpx.Response:
        raise exc from cause

    return page


def refused() -> BaseException:
    """What anyio raises for a refused connection, as httpcore wraps it."""
    try:
        try:
            raise ConnectionRefusedError(errno.ECONNREFUSED, "Connect call failed")
        except ConnectionRefusedError as exc:
            raise OSError("All connection attempts failed") from exc
    except OSError as exc:
        return exc


@pytest.mark.parametrize(
    ("page", "reason"),
    [
        (raising(httpx.ConnectError("failed"), refused()), FetchErrorReason.CONNECT),
        (
            raising(
                httpx.ConnectError("failed"),
                BaseExceptionGroup("attempts", [ConnectionRefusedError(errno.ECONNREFUSED, "no")]),
            ),
            FetchErrorReason.CONNECT,
        ),
        # Accepted and then reset, or never reached: says nothing about the service.
        (raising(httpx.ConnectError("Connection refused")), FetchErrorReason.NETWORK),
        (
            raising(httpx.ConnectError("failed"), OSError(errno.EHOSTUNREACH, "No route to host")),
            FetchErrorReason.NETWORK,
        ),
        (raising(httpx.ReadError("Connection reset by peer")), FetchErrorReason.NETWORK),
        (raising(httpx.WriteError("Broken pipe")), FetchErrorReason.NETWORK),
        (raising(httpx.ConnectTimeout("timed out")), FetchErrorReason.TIMEOUT),
        (raising(httpx.ReadTimeout("timed out")), FetchErrorReason.TIMEOUT),
        (raising(httpx.RemoteProtocolError("illegal status line")), FetchErrorReason.PROTOCOL),
        (raising(httpx.ConnectError("handshake"), certificate_error()), FetchErrorReason.TLS),
        (raising(httpx.ConnectError("handshake"), ssl.SSLError(1, "alert")), FetchErrorReason.TLS),
    ],
)
async def test_transport_errors_are_mapped(page: Page, reason: FetchErrorReason) -> None:
    fetcher, _, _ = make_fetcher({"https://example.com/": page})
    error = await fetch_error(fetcher, "https://example.com/")
    assert error.reason is reason
    assert error.url == "https://example.com/"


async def test_error_names_the_redirect_hop_that_failed() -> None:
    fetcher, _, _ = make_fetcher(
        {
            "http://example.com/": redirect("https://www.example.com/"),
            "https://www.example.com/": raising(httpx.ConnectError("failed"), refused()),
        }
    )
    error = await fetch_error(fetcher, "http://example.com/")
    assert (error.reason, error.url) == (FetchErrorReason.CONNECT, "https://www.example.com/")


def test_network_error_message_names_the_socket_error() -> None:
    try:
        raise httpx.ReadError("") from ConnectionResetError(
            errno.ECONNRESET, "Connection reset by peer"
        )
    except httpx.ReadError as exc:
        error = map_httpx_error(exc, "example.com")
    assert error.reason is FetchErrorReason.NETWORK
    assert str(error) == "the connection to example.com failed: Connection reset by peer"


def test_tls_error_message_names_the_verification_failure() -> None:
    try:
        raise httpx.ConnectError("[SSL] certificate verify failed") from certificate_error()
    except httpx.ConnectError as exc:
        error = map_httpx_error(exc, "example.com")
    assert error.reason is FetchErrorReason.TLS
    assert str(error) == "TLS handshake with example.com failed: certificate has expired"


def test_tls_error_found_through_nested_causes() -> None:
    try:
        try:
            raise ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number")
        except ssl.SSLError as inner:
            raise httpx.ConnectError("start_tls failed") from inner
    except httpx.ConnectError as exc:
        error = map_httpx_error(exc, "example.com")
    assert error.reason is FetchErrorReason.TLS


async def test_overall_deadline_covers_a_slow_server() -> None:
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return reply()

    fetcher = GuardedFetcher(
        FakeResolver(address_records=dict(ADDRESSES)),
        transport=httpx.MockTransport(slow),
        timeout=0.05,
    )
    error = await fetch_error(fetcher, "https://example.com/")
    assert error.reason is FetchErrorReason.TIMEOUT


class SlowResolver(FakeResolver):
    async def addresses(self, name: str) -> list[str]:
        await asyncio.sleep(5)
        return [PUBLIC_V4]


async def test_overall_deadline_covers_slow_dns() -> None:
    fetcher = GuardedFetcher(
        SlowResolver(), transport=httpx.MockTransport(Network({})), timeout=0.05
    )
    error = await fetch_error(fetcher, "https://example.com/")
    assert error.reason is FetchErrorReason.TIMEOUT
