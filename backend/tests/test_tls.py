import asyncio
import errno
import ssl
from datetime import UTC, datetime
from typing import Any

import pytest

from tests.fakes import DnsAnswer, FakeResolver
from webriskaudit.net.tls import TlsProbe, certificate_result, map_tls_error, verified_context
from webriskaudit.net.types import (
    DnsUnavailableError,
    FetchErrorReason,
    TlsProbeError,
    TlsProbeResult,
)

PEER_CERT: dict[str, Any] = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": (
        (("countryName", "US"),),
        (("organizationName", "Let's Encrypt"),),
        (("commonName", "E7"),),
    ),
    "version": 3,
    "serialNumber": "0512A9D3C0E4F1",
    "notBefore": "Sep 30 00:12:45 2026 GMT",
    "notAfter": "Dec 29 00:12:44 2026 GMT",
    "subjectAltName": (
        ("DNS", "example.com"),
        ("DNS", "www.example.com"),
        ("IP Address", "93.184.215.14"),
    ),
}


def test_certificate_result_parses_peer_certificate() -> None:
    result = certificate_result(PEER_CERT, "TLSv1.3")
    assert result == TlsProbeResult(
        verified=True,
        protocol="TLSv1.3",
        not_before=datetime(2026, 9, 30, 0, 12, 45, tzinfo=UTC),
        not_after=datetime(2026, 12, 29, 0, 12, 44, tzinfo=UTC),
        issuer="Let's Encrypt (E7)",
        subject_alt_names=("example.com", "www.example.com"),
    )


@pytest.mark.parametrize(
    ("issuer", "expected"),
    [
        (
            ((("organizationName", "DigiCert Inc"),), (("commonName", "DigiCert G2"),)),
            "DigiCert Inc (DigiCert G2)",
        ),
        (((("commonName", "Self Signed CA"),),), "Self Signed CA"),
        (((("organizationName", "Example Org"),),), "Example Org"),
        (((("organizationName", "Same"),), (("commonName", "Same"),)), "Same"),
        (((("countryName", "US"),),), None),
        ((), None),
        ("not a tuple", None),
    ],
)
def test_issuer_name(issuer: object, expected: str | None) -> None:
    assert certificate_result({"issuer": issuer}, None).issuer == expected


def test_certificate_result_tolerates_missing_or_malformed_fields() -> None:
    result = certificate_result({"notBefore": "yesterday", "subjectAltName": "nope"}, None)
    assert result.verified
    assert (result.not_before, result.not_after, result.issuer) == (None, None, None)
    assert result.subject_alt_names == ()


def verification_error(message: str) -> ssl.SSLCertVerificationError:
    error = ssl.SSLCertVerificationError(1, f"[SSL: CERTIFICATE_VERIFY_FAILED] {message}")
    error.verify_message = message
    return error


@pytest.mark.parametrize(
    "message",
    [
        "certificate has expired",
        "Hostname mismatch, certificate is not valid for 'example.com'.",
        "self-signed certificate",
        "unable to get local issuer certificate",
    ],
)
def test_verification_failure_is_a_result(message: str) -> None:
    outcome = map_tls_error(verification_error(message), "example.com")
    assert outcome == TlsProbeResult(verified=False, error=message)


@pytest.mark.parametrize(
    ("exc", "reason"),
    [
        (ssl.SSLError(1, "[SSL: TLSV1_ALERT_PROTOCOL_VERSION] alert"), FetchErrorReason.TLS),
        (ssl.SSLEOFError(8, "EOF occurred in violation of protocol"), FetchErrorReason.TLS),
        (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), FetchErrorReason.CONNECT),
        # Only a refusal shows that nothing listens on port 443.
        (ConnectionResetError(errno.ECONNRESET, "reset"), FetchErrorReason.NETWORK),
        (ConnectionAbortedError(errno.ECONNABORTED, "aborted"), FetchErrorReason.NETWORK),
        (OSError(errno.EHOSTUNREACH, "No route to host"), FetchErrorReason.NETWORK),
        (OSError(errno.ENETUNREACH, "Network is unreachable"), FetchErrorReason.NETWORK),
        (TimeoutError(), FetchErrorReason.TIMEOUT),
    ],
)
def test_handshake_failures_are_errors(exc: OSError, reason: FetchErrorReason) -> None:
    outcome = map_tls_error(exc, "example.com")
    assert isinstance(outcome, TlsProbeError)
    assert outcome.reason is reason


def test_verified_context_checks_chain_and_hostname() -> None:
    context = verified_context()
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


# --- TlsProbe with a fake connection --------------------------------------------


class FakeSslObject:
    def getpeercert(self) -> dict[str, Any]:
        return PEER_CERT

    def version(self) -> str:
        return "TLSv1.3"


class FakeWriter:
    def __init__(self) -> None:
        self.closed = False

    def get_extra_info(self, name: str) -> object:
        return FakeSslObject() if name == "ssl_object" else None

    def close(self) -> None:
        self.closed = True


class FakeConnector:
    """Stands in for asyncio.open_connection and records how it was called."""

    def __init__(self, error: BaseException | None = None, delay: float = 0.0) -> None:
        self.calls: list[tuple[str, int, dict[str, Any]]] = []
        self.writer = FakeWriter()
        self._error = error
        self._delay = delay

    async def __call__(self, host: str, port: int, **kwargs: Any) -> tuple[None, FakeWriter]:
        self.calls.append((host, port, kwargs))
        await asyncio.sleep(self._delay)
        if self._error is not None:
            raise self._error
        return None, self.writer


ADDRESSES: dict[str, DnsAnswer] = {
    "example.com": ["2606:2800:21f:cb07:6820:80da:af6b:8b2c", "93.184.215.14"],
    "internal.example.com": ["10.0.0.5"],
    "mixed.example.com": ["93.184.215.14", "169.254.169.254"],
    "down.example.com": DnsUnavailableError("down.example.com"),
}


def probe_with(
    connector: FakeConnector, monkeypatch: pytest.MonkeyPatch, **options: Any
) -> TlsProbe:
    monkeypatch.setattr(asyncio, "open_connection", connector)
    return TlsProbe(FakeResolver(address_records=dict(ADDRESSES)), **options)


async def test_probe_connects_to_pinned_address_with_sni(monkeypatch: pytest.MonkeyPatch) -> None:
    connector = FakeConnector()
    result = await probe_with(connector, monkeypatch).probe("Example.com")

    [(host, port, kwargs)] = connector.calls
    assert (host, port) == ("93.184.215.14", 443)
    assert kwargs["server_hostname"] == "example.com"
    assert kwargs["ssl"].verify_mode is ssl.CERT_REQUIRED
    assert result.verified
    assert result.issuer == "Let's Encrypt (E7)"
    assert connector.writer.closed


async def test_probe_reports_untrusted_certificate(monkeypatch: pytest.MonkeyPatch) -> None:
    connector = FakeConnector(error=verification_error("certificate has expired"))
    result = await probe_with(connector, monkeypatch).probe("example.com")
    assert result == TlsProbeResult(verified=False, error="certificate has expired")


@pytest.mark.parametrize(
    ("host", "port", "reason"),
    [
        ("internal.example.com", 443, FetchErrorReason.BLOCKED),
        ("mixed.example.com", 443, FetchErrorReason.BLOCKED),
        ("127.0.0.1", 443, FetchErrorReason.BLOCKED),
        ("localhost", 443, FetchErrorReason.BLOCKED),
        ("example.com", 8443, FetchErrorReason.BLOCKED),
        ("nowhere.example.org", 443, FetchErrorReason.DNS),
        ("down.example.com", 443, FetchErrorReason.DNS),
    ],
)
async def test_probe_refuses_before_connecting(
    host: str, port: int, reason: FetchErrorReason, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector = FakeConnector()
    with pytest.raises(TlsProbeError) as caught:
        await probe_with(connector, monkeypatch).probe(host, port)
    assert caught.value.reason is reason
    assert connector.calls == []


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), FetchErrorReason.CONNECT),
        (ConnectionResetError(errno.ECONNRESET, "reset"), FetchErrorReason.NETWORK),
        (ssl.SSLError(1, "handshake failure"), FetchErrorReason.TLS),
    ],
)
async def test_probe_connection_errors(
    error: OSError, reason: FetchErrorReason, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(TlsProbeError) as caught:
        await probe_with(FakeConnector(error=error), monkeypatch).probe("example.com")
    assert caught.value.reason is reason


async def test_probe_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = probe_with(FakeConnector(delay=5), monkeypatch, timeout=0.05)
    with pytest.raises(TlsProbeError) as caught:
        await probe.probe("example.com")
    assert caught.value.reason is FetchErrorReason.TIMEOUT
