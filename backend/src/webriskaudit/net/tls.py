"""TLS handshake probe that reports the server certificate."""

import asyncio
import ssl
from collections.abc import Mapping
from datetime import UTC, datetime

import certifi

from webriskaudit.net.addresses import is_public_address, pick_address
from webriskaudit.net.domain import InvalidDomainError, normalize_domain
from webriskaudit.net.types import (
    DnsError,
    FetchErrorReason,
    Resolver,
    TlsProbeError,
    TlsProbeResult,
)

ALLOWED_PORTS = frozenset({443})


def verified_context() -> ssl.SSLContext:
    """Client context that checks the chain against certifi's CA bundle and the hostname.

    The TLS 1.2 floor is set explicitly: on some platforms the default context
    reports MINIMUM_SUPPORTED and leaves the floor to the system crypto policy.
    """
    context = ssl.create_default_context(cafile=certifi.where())
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class TlsProbe:
    """Handshakes with a host's pinned public address, using the hostname for SNI."""

    def __init__(self, resolver: Resolver, *, timeout: float = 10.0) -> None:
        self._resolver = resolver
        self._timeout = timeout
        self._context = verified_context()

    async def probe(self, host: str, port: int = 443) -> TlsProbeResult:
        try:
            async with asyncio.timeout(self._timeout):
                hostname, address = await self._pin(host, port)
                return await self._handshake(hostname, address, port)
        except TimeoutError:
            raise TlsProbeError(
                FetchErrorReason.TIMEOUT, f"no TLS handshake within {self._timeout:g} s"
            ) from None
        except OSError as exc:  # includes ssl.SSLError
            outcome = map_tls_error(exc, host)
            if isinstance(outcome, TlsProbeError):
                raise outcome from exc
            return outcome

    async def _pin(self, host: str, port: int) -> tuple[str, str]:
        if port not in ALLOWED_PORTS:
            raise TlsProbeError(FetchErrorReason.BLOCKED, f"port {port} is not probed")
        try:
            hostname = normalize_domain(host)
            addresses = await self._resolver.addresses(hostname)
        except InvalidDomainError as exc:
            raise TlsProbeError(FetchErrorReason.BLOCKED, exc.message) from exc
        except DnsError as exc:
            raise TlsProbeError(FetchErrorReason.DNS, str(exc)) from exc
        if not addresses or not all(is_public_address(address) for address in addresses):
            raise TlsProbeError(
                FetchErrorReason.BLOCKED, f"{hostname} resolves to a non-public address"
            )
        return hostname, pick_address(addresses)

    async def _handshake(self, hostname: str, address: str, port: int) -> TlsProbeResult:
        _, writer = await asyncio.open_connection(
            address, port, ssl=self._context, server_hostname=hostname
        )
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                raise TlsProbeError(FetchErrorReason.PROTOCOL, "no TLS session was established")
            return certificate_result(ssl_object.getpeercert() or {}, ssl_object.version())
        finally:
            writer.close()


def map_tls_error(exc: OSError, host: str) -> TlsProbeResult | TlsProbeError:
    """An untrusted certificate is a result; any other failed handshake is an error.

    Only a refused connection is CONNECT (nothing listens on port 443). An
    unreachable host or a reset connection is NETWORK: it may be the network
    or a filter in front of the scanner, not proof that there is no service.
    """
    if isinstance(exc, ssl.SSLCertVerificationError):
        message = str(getattr(exc, "verify_message", None) or exc)
        return TlsProbeResult(verified=False, error=message)
    if isinstance(exc, ssl.SSLError):
        reason = str(getattr(exc, "reason", None) or exc)
        return TlsProbeError(FetchErrorReason.TLS, f"TLS handshake with {host} failed: {reason}")
    if isinstance(exc, TimeoutError):
        return TlsProbeError(FetchErrorReason.TIMEOUT, f"{host} did not answer in time")
    if isinstance(exc, ConnectionRefusedError):
        return TlsProbeError(FetchErrorReason.CONNECT, f"{host} refused the connection on port 443")
    detail = f": {exc.strerror}" if exc.strerror else ""
    return TlsProbeError(
        FetchErrorReason.NETWORK, f"the connection to {host} on port 443 failed{detail}"
    )


def certificate_result(cert: Mapping[str, object], protocol: str | None) -> TlsProbeResult:
    """Build a verified result from an ``SSLObject.getpeercert()`` dictionary."""
    return TlsProbeResult(
        verified=True,
        protocol=protocol,
        not_before=_cert_time(cert.get("notBefore")),
        not_after=_cert_time(cert.get("notAfter")),
        issuer=_issuer_name(cert.get("issuer")),
        subject_alt_names=_dns_names(cert.get("subjectAltName")),
    )


def _cert_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=UTC)
    except ValueError:
        return None


def _issuer_name(issuer: object) -> str | None:
    """``Organization (Common Name)``, or whichever of the two is present."""
    attributes: dict[str, str] = {}
    for rdn in issuer if isinstance(issuer, tuple) else ():
        for pair in rdn if isinstance(rdn, tuple) else ():
            if isinstance(pair, tuple) and len(pair) == 2:
                attributes.setdefault(str(pair[0]), str(pair[1]))
    organization = attributes.get("organizationName")
    common_name = attributes.get("commonName")
    if organization and common_name and organization != common_name:
        return f"{organization} ({common_name})"
    return organization or common_name


def _dns_names(entries: object) -> tuple[str, ...]:
    if not isinstance(entries, tuple):
        return ()
    return tuple(
        str(entry[1])
        for entry in entries
        if isinstance(entry, tuple) and len(entry) == 2 and entry[0] == "DNS"
    )
