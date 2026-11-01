"""SNI, hostname verification and pinning over real TLS sockets, on 127.0.0.1 only.

The other network tests stop at httpx.MockTransport or a fake connection, so
they only show that the hostname is handed to httpcore and ssl. These tests
show that it is used: the handshake carries the hostname as SNI, and the
certificate is checked against the hostname, not the pinned address.

The fetcher and the probe connect to the pinned public address on port 443.
A patched network layer sends that connection to a local server on an
ephemeral port, so nothing leaves the machine. The server's certificates come
from a throwaway CA (trustme).
"""

import asyncio
import socket
import ssl
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpcore
import pytest
import trustme

import webriskaudit.net.http as http_module
import webriskaudit.net.tls as tls_module
from webriskaudit.net.http import GuardedFetcher
from webriskaudit.net.tls import TlsProbe
from webriskaudit.net.types import FetchError, FetchErrorReason

from .fakes import FakeResolver

pytestmark = pytest.mark.allow_hosts(["127.0.0.1"])

PINNED = "93.184.215.14"
GOOD = "good.example.com"
OTHER = "other.example.com"


def resolver() -> FakeResolver:
    return FakeResolver(address_records={GOOD: [PINNED], OTHER: [PINNED]})


@dataclass
class Server:
    """What the local TLS server saw, and where the client tried to connect."""

    port: int = 0
    sni: list[str | None] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    connects: list[tuple[str, int]] = field(default_factory=list)
    lookups: list[str] = field(default_factory=list)


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


def trusting(ca: trustme.CA) -> ssl.SSLContext:
    """Built like verified_context(), with the throwaway CA as the only trust anchor."""
    return ssl.create_default_context(cadata=ca.cert_pem.bytes().decode("ascii"))


async def answer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, seen: Server) -> None:
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        for line in head.decode("latin-1").split("\r\n")[1:]:
            name, _, value = line.partition(":")
            if name.lower() == "host":
                seen.hosts.append(value.strip())
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
    except (OSError, asyncio.IncompleteReadError, TimeoutError):
        pass  # the TLS probe and refused handshakes close without a request
    finally:
        writer.close()


@asynccontextmanager
async def serving(
    ca: trustme.CA, monkeypatch: pytest.MonkeyPatch, *names: str, trust: bool = True
) -> AsyncIterator[Server]:
    """A TLS server for a certificate of ``names``, reached through (PINNED, 443)."""
    seen = Server()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert(*names).configure_cert(context)
    context.sni_callback = lambda _obj, name, _ctx: seen.sni.append(name)

    server = await asyncio.start_server(
        lambda r, w: answer(r, w, seen), "127.0.0.1", 0, ssl=context
    )
    seen.port = server.sockets[0].getsockname()[1]

    def local(host: str, port: int) -> tuple[str, int]:
        seen.connects.append((host, port))
        assert (host, port) == (PINNED, 443), "only the pinned address on port 443 is contacted"
        return "127.0.0.1", seen.port

    connect_tcp = httpcore.AnyIOBackend.connect_tcp

    async def mapped_connect_tcp(
        self: httpcore.AnyIOBackend, host: str, port: int, *args: Any, **kwargs: Any
    ) -> httpcore.AsyncNetworkStream:
        return await connect_tcp(self, *local(host, port), *args, **kwargs)

    open_connection = asyncio.open_connection

    async def mapped_open_connection(
        host: str, port: int, **kwargs: Any
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await open_connection(*local(host, port), **kwargs)

    getaddrinfo = socket.getaddrinfo

    def recording_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Iterable[Any]:
        seen.lookups.append(str(host))
        return getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", mapped_connect_tcp)
    monkeypatch.setattr(asyncio, "open_connection", mapped_open_connection)
    monkeypatch.setattr(socket, "getaddrinfo", recording_getaddrinfo)
    if trust:
        monkeypatch.setattr(http_module, "verified_context", lambda: trusting(ca))
        monkeypatch.setattr(tls_module, "verified_context", lambda: trusting(ca))
    try:
        yield seen
    finally:
        server.close()
        await server.wait_closed()
        # The scanned names never reach the system resolver: only pinned addresses do.
        assert not any("example.com" in name for name in seen.lookups)


# --- GuardedFetcher ------------------------------------------------------------------


async def test_fetcher_sends_the_hostname_as_sni_and_host(
    ca: trustme.CA, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with serving(ca, monkeypatch, GOOD) as seen:
        page = await GuardedFetcher(resolver(), timeout=5).get(f"https://{GOOD}/")
    assert (page.status, page.body, page.url) == (200, b"ok", f"https://{GOOD}/")
    assert seen.connects == [(PINNED, 443)]
    assert (seen.sni, seen.hosts) == ([GOOD], [GOOD])


async def test_fetcher_checks_the_certificate_against_the_hostname(
    ca: trustme.CA, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with serving(ca, monkeypatch, GOOD) as seen:
        with pytest.raises(FetchError) as caught:
            await GuardedFetcher(resolver(), timeout=5).get(f"https://{OTHER}/")
    assert caught.value.reason is FetchErrorReason.TLS
    assert "Hostname mismatch" in str(caught.value)
    assert (seen.sni, seen.hosts) == ([OTHER], [])


async def test_fetcher_rejects_a_certificate_for_the_pinned_address(
    ca: trustme.CA, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The URL sent to httpcore holds the IP; a certificate for that IP must
    # still fail, because the name being verified is the hostname.
    async with serving(ca, monkeypatch, PINNED):
        with pytest.raises(FetchError) as caught:
            await GuardedFetcher(resolver(), timeout=5).get(f"https://{GOOD}/")
    assert caught.value.reason is FetchErrorReason.TLS
    assert "Hostname mismatch" in str(caught.value)


async def test_fetcher_trusts_only_the_certifi_bundle(
    ca: trustme.CA, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with serving(ca, monkeypatch, GOOD, trust=False):
        with pytest.raises(FetchError) as caught:
            await GuardedFetcher(resolver(), timeout=5).get(f"https://{GOOD}/")
    assert caught.value.reason is FetchErrorReason.TLS
    assert "unable to get local issuer certificate" in str(caught.value)


# --- TlsProbe -------------------------------------------------------------------------


async def test_probe_verifies_the_hostname_with_sni(
    ca: trustme.CA, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with serving(ca, monkeypatch, GOOD) as seen:
        result = await TlsProbe(resolver(), timeout=5).probe(GOOD)
    assert result.verified
    assert result.subject_alt_names == (GOOD,)
    assert result.protocol in ("TLSv1.2", "TLSv1.3")
    assert (seen.connects, seen.sni) == ([(PINNED, 443)], [GOOD])


@pytest.mark.parametrize(
    ("names", "host"),
    [((GOOD,), OTHER), ((PINNED,), GOOD)],
    ids=["other-name", "pinned-address-only"],
)
async def test_probe_reports_a_hostname_mismatch(
    names: tuple[str, ...], host: str, ca: trustme.CA, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with serving(ca, monkeypatch, *names):
        result = await TlsProbe(resolver(), timeout=5).probe(host)
    assert not result.verified
    assert result.error is not None
    assert "Hostname mismatch" in result.error


async def test_probe_trusts_only_the_certifi_bundle(
    ca: trustme.CA, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with serving(ca, monkeypatch, GOOD, trust=False):
        result = await TlsProbe(resolver(), timeout=5).probe(GOOD)
    assert not result.verified
    assert result.error == "unable to get local issuer certificate"
