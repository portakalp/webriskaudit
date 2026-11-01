"""Interfaces between checks and the network.

Checks only see these types. The real implementations live in ``dns``,
``http`` and ``tls``; tests use the fakes in ``tests/fakes.py``.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol

# --- DNS ---------------------------------------------------------------------


class DnsError(Exception):
    """Base class for DNS lookup failures."""


class NxDomainError(DnsError):
    """The queried name does not exist."""


class NoAnswerError(DnsError):
    """The name exists but has no records of the requested type."""


class DnsUnavailableError(DnsError):
    """No usable answer: timeout, SERVFAIL or no reachable nameserver."""


class Resolver(Protocol):
    async def txt(self, name: str) -> list[str]:
        """TXT records of ``name``, each with its character-strings joined.

        Raises NxDomainError, NoAnswerError or DnsUnavailableError.
        """
        ...

    async def addresses(self, name: str) -> list[str]:
        """A and AAAA addresses of ``name`` as strings.

        Raises NxDomainError if the name does not exist, NoAnswerError if it has
        neither record type, DnsUnavailableError otherwise.
        """
        ...


# --- HTTP --------------------------------------------------------------------


class FetchErrorReason(StrEnum):
    BLOCKED = "blocked"  # target or redirect points at a non-public address, port or scheme
    TIMEOUT = "timeout"
    CONNECT = "connect"  # connection refused: nothing listens on the port
    NETWORK = "network"  # unreachable, or reset or aborted after connecting
    TLS = "tls"  # certificate verification or handshake failed
    TOO_MANY_REDIRECTS = "too_many_redirects"
    DNS = "dns"  # a redirect target did not resolve
    PROTOCOL = "protocol"  # malformed response


class FetchError(Exception):
    def __init__(self, reason: FetchErrorReason, message: str, *, url: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.url = url
        """The URL whose request failed, when known; after redirects, a later hop."""


@dataclass(frozen=True)
class HttpResponse:
    url: str
    """Final URL after redirects."""
    status: int
    headers: tuple[tuple[str, str], ...]
    """Raw header pairs, lower-cased names, in received order (keeps repeated Set-Cookie)."""
    body: bytes
    """Decoded body as far as it was read; see ``truncated``."""
    truncated: bool = False
    """True if the body was cut off: size cap, time budget, or a broken or undecodable stream."""
    redirects: tuple[str, ...] = ()
    """URLs that answered with a redirect before ``url``, in order."""
    history: tuple["HttpResponse", ...] = ()
    """The redirect responses themselves (headers, no body), parallel to ``redirects``."""

    def header(self, name: str) -> str | None:
        """First value of a header, or None."""
        name = name.lower()
        return next((value for key, value in self.headers if key == name), None)

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key == name]

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class Fetcher(Protocol):
    async def get(self, url: str) -> HttpResponse:
        """GET ``url`` with SSRF guards and manual redirect handling.

        Raises FetchError.
        """
        ...


# --- TLS ---------------------------------------------------------------------


class TlsProbeError(Exception):
    def __init__(self, reason: FetchErrorReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class TlsProbeResult:
    verified: bool
    """Chain and hostname verified against the bundled CA store."""
    error: str | None = None
    """Verification error when ``verified`` is False."""
    protocol: str | None = None
    """Negotiated protocol, e.g. ``TLSv1.3``."""
    not_before: datetime | None = None
    not_after: datetime | None = None
    issuer: str | None = None
    subject_alt_names: tuple[str, ...] = field(default_factory=tuple)


class TlsProber(Protocol):
    async def probe(self, host: str, port: int = 443) -> TlsProbeResult:
        """Handshake with ``host`` on a public address and report the certificate.

        Raises TlsProbeError when no handshake happens (timeout, refused,
        blocked address). A completed handshake with an untrusted certificate
        returns ``verified=False`` instead.
        """
        ...
