"""Public-address guard, plus the pure parts of the DNS resolver that produces addresses."""

# dnspython's exception constructors are untyped.
# mypy: disable-error-code="no-untyped-call"

import dns.exception
import dns.message
import dns.name
import dns.resolver
import pytest

from webriskaudit.net.addresses import is_public_address, pick_address
from webriskaudit.net.dns import decode_txt, dns_error, merge_address_answers
from webriskaudit.net.types import (
    DnsError,
    DnsUnavailableError,
    NoAnswerError,
    NxDomainError,
)


@pytest.mark.parametrize(
    "ip",
    [
        # IPv4
        "0.0.0.0",  # noqa: S104 (a test value, not a bind address)
        "0.1.2.3",
        "10.0.0.1",
        "10.255.255.255",
        "100.64.0.1",
        "100.127.255.255",
        "127.0.0.1",
        "127.255.255.254",
        "169.254.169.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.0.0.1",
        "192.0.2.10",
        "192.88.99.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.7",
        "203.0.113.9",
        "224.0.0.1",
        "239.255.255.250",
        "240.0.0.1",
        "255.255.255.255",
        # IPv6
        "::",
        "::1",
        "fe80::1",
        "fe80::1%en0",
        "fc00::1",
        "fd12:3456:789a::1",
        "fec0::1",
        "ff02::1",
        "100::1",
        "2001:db8::1",
        "2001:2::1",
        "2001:10::1",
        "3fff::1",
        "64:ff9b:1::a00:1",
        "4000::1",
        # IPv6 carrying a non-public IPv4 address
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "::ffff:0.0.0.0",
        "::127.0.0.1",
        "::10.0.0.1",
        "2002:7f00:1::1",
        "2002:c0a8:101::1",
        "64:ff9b::7f00:1",
        "64:ff9b::a9fe:a9fe",
        "2001:0:4136:e378::3f57:fefe",  # Teredo, client 192.168.1.1
        "2001:0:a00:1::f7f7:f7f7",  # Teredo, server 10.0.0.1
    ],
)
def test_rejects_non_public_addresses(ip: str) -> None:
    assert not is_public_address(ip)


@pytest.mark.parametrize(
    "ip",
    [
        "",
        "localhost",
        "999.1.1.1",
        "1.2.3",
        "127.1",
        "0x7f.0.0.1",
        "010.0.0.1",
        " 8.8.8.8",
        "8.8.8.8%eth0",
        "2606:4700:4700::1111%eth0",
        "[2606:4700:4700::1111]",
    ],
)
def test_rejects_unparsable_input(ip: str) -> None:
    assert not is_public_address(ip)


@pytest.mark.parametrize(
    "ip",
    [
        "1.1.1.1",
        "8.8.8.8",
        "93.184.215.14",
        "100.63.255.255",
        "100.128.0.1",
        "172.15.255.255",
        "172.32.0.1",
        "192.169.0.1",
        "198.17.255.255",
        "198.20.0.1",
        "223.255.255.255",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
        "2a00:1450:4001:80b::200e",
        "2001:200::1",
        # Embedded addresses decide for IPv4-carrying IPv6 forms.
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "2002:808:808::1",
        "2001:0:4136:e378::f7f7:f7f7",  # Teredo, server and client public
    ],
)
def test_accepts_public_addresses(ip: str) -> None:
    assert is_public_address(ip)


def test_pick_address_prefers_ipv4() -> None:
    assert pick_address(["2606:4700::1", "93.184.215.14", "1.1.1.1"]) == "93.184.215.14"
    assert pick_address(["2606:4700::1", "2606:4700::2"]) == "2606:4700::1"


# --- DnsResolver helpers ------------------------------------------------------


def test_decode_txt_joins_strings_and_replaces_bad_utf8() -> None:
    assert decode_txt([b"v=spf1 include:_spf.example.com ", b"-all"]) == (
        "v=spf1 include:_spf.example.com -all"
    )
    assert decode_txt([b"caf\xc3\xa9 \xff"]) == "café �"


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (dns.resolver.NXDOMAIN(), NxDomainError),
        (dns.resolver.NoAnswer(), NoAnswerError),
        (dns.name.NameTooLong(), NxDomainError),
        (dns.name.LabelTooLong(), NxDomainError),
        (dns.resolver.LifetimeTimeout(timeout=5.0, errors=[]), DnsUnavailableError),
        (dns.resolver.NoNameservers(), DnsUnavailableError),
        (dns.resolver.YXDOMAIN(), DnsUnavailableError),
        (dns.exception.DNSException(), DnsUnavailableError),
    ],
)
def test_dns_error_mapping(exc: dns.exception.DNSException, expected: type[DnsError]) -> None:
    error = dns_error(exc, "example.com")
    assert type(error) is expected
    assert "example.com" in str(error)


def test_dns_error_message_does_not_leak_resolver_details() -> None:
    request = dns.message.make_query("example.com", "A")
    errors = [("Do53:10.0.0.2@53", False, 53, "SERVFAIL", None)]
    exc = dns.resolver.NoNameservers(request=request, errors=errors)
    assert "10.0.0.2" in str(exc)
    assert str(dns_error(exc, "example.com")) == "DNS lookup for example.com failed"


A = ["93.184.215.14"]
AAAA = ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"]
NX = NxDomainError("x")
NO = NoAnswerError("x")
DOWN = DnsUnavailableError("x")


@pytest.mark.parametrize(
    ("ipv4", "ipv6", "expected"),
    [
        (A, AAAA, A + AAAA),
        (A, NO, A),
        (NO, AAAA, AAAA),
        (A, DOWN, A),
        (DOWN, AAAA, AAAA),
        (NX, NX, NxDomainError),
        (NO, NO, NoAnswerError),
        (NX, NO, NoAnswerError),
        (NO, DOWN, DnsUnavailableError),
        (NX, DOWN, DnsUnavailableError),
        (DOWN, DOWN, DnsUnavailableError),
    ],
)
def test_merge_address_answers(
    ipv4: list[str] | DnsError,
    ipv6: list[str] | DnsError,
    expected: list[str] | type[DnsError],
) -> None:
    if isinstance(expected, list):
        assert merge_address_answers("example.com", ipv4, ipv6) == expected
    else:
        with pytest.raises(expected):
            merge_address_answers("example.com", ipv4, ipv6)


def test_merge_address_answers_reraises_unexpected_errors() -> None:
    with pytest.raises(RuntimeError):
        merge_address_answers("example.com", A, RuntimeError("bug"))
