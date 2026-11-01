import pytest

from webriskaudit.net.domain import InvalidDomainError, normalize_domain

LONGEST_NAME = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 57, "com"])  # 253 characters


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("Example.COM", "example.com"),
        ("  example.com\n", "example.com"),
        ("example.com.", "example.com"),
        ("www.example.com", "www.example.com"),
        ("deep.sub.example.co.uk", "deep.sub.example.co.uk"),
        ("163.com", "163.com"),
        ("1password.com", "1password.com"),
        ("a-b.example.com", "a-b.example.com"),
        ("r3---sn-4g5e6nz7.googlevideo.com", "r3---sn-4g5e6nz7.googlevideo.com"),
        # URLs: scheme, userinfo, port, path, query and fragment are dropped.
        ("https://www.example.com/path?q=1#top", "www.example.com"),
        ("http://example.com", "example.com"),
        ("HTTPS://EXAMPLE.COM:443/", "example.com"),
        ("//example.com/", "example.com"),
        ("example.com:443", "example.com"),
        ("example.com:8080/admin", "example.com"),
        ("example.com:", "example.com"),
        ("example.com/", "example.com"),
        ("example.com?x=1", "example.com"),
        ("example.com#top", "example.com"),
        ("user:pass@example.com", "example.com"),
        ("https://user@example.com:8443/", "example.com"),
        # Like browsers, the authority ends at a backslash.
        ("https://example.com\\@evil.example.net/", "example.com"),
        # IDN: lower-cased A-labels, IDNA 2008 (non-transitional) rules.
        ("bücher.de", "xn--bcher-kva.de"),
        ("https://BÜCHER.de/path", "xn--bcher-kva.de"),
        ("faß.de", "xn--fa-hia.de"),
        ("пример.рф", "xn--e1afmkfd.xn--p1ai"),
        ("例え。jp", "xn--r8jz45g.jp"),
        ("XN--BCHER-KVA.de", "xn--bcher-kva.de"),
        # A name that resolves to a private address is still a valid name; the
        # address check happens after resolution.
        ("127.0.0.1.nip.io", "127.0.0.1.nip.io"),
        ("a" * 63 + ".com", "a" * 63 + ".com"),
        (LONGEST_NAME, LONGEST_NAME),
        (LONGEST_NAME + ".", LONGEST_NAME),
    ],
)
def test_accepts_and_normalizes(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        # IPv4 in every spelling a URL parser or inet_aton accepts.
        "127.0.0.1",
        "127.0.0.1.",
        "127.0.0.1:80",
        "http://127.0.0.1/",
        "user@127.0.0.1",
        "example.com@127.0.0.1",
        "169.254.169.254",
        "8.8.8.8",
        "0.0.0.0",  # noqa: S104 (a test value, not a bind address)
        "127.1",
        "127.0.1",
        "0x7f.0.0.1",
        "0x7f.1",
        "0177.0.0.1",
        "017700000001",
        "0x7f000001",
        "2130706433",
        "http://2130706433/",
        "foo.0x7f",
        "example.0x",
        "\uff11\uff12\uff17\uff0e\uff10\uff0e\uff10\uff0e\uff11",  # full-width 127.0.0.1
        # IPv6, bare and bracketed.
        "::1",
        "[::1]",
        "[::1]:443",
        "http://[::1]/",
        "::ffff:127.0.0.1",
        "[::ffff:7f00:1]",
        "fe80::1%25en0",
        "[fe80::1%25en0]",
        "2001:db8::1",
        "http://[2001:db8::1]:8080/",
    ],
)
def test_rejects_ip_literals(raw: str) -> None:
    with pytest.raises(InvalidDomainError, match="IP addresses cannot be scanned"):
        normalize_domain(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "localhost",
        "LOCALHOST.",
        "http://localhost:3000/",
        "app.localhost",
        "printer.local",
        "db.internal",
        "x.invalid",
        "site.test",
        "www.example",
        "abcdefghijklmnop.onion",
        "router.home.arpa",
        "1.0.0.127.in-addr.arpa",
        "my.alt",
        "server.corp",
        "nas.home",
        "例え.test",
    ],
)
def test_rejects_special_use_names(raw: str) -> None:
    with pytest.raises(InvalidDomainError, match="reserved for special use"):
        normalize_domain(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "intranet",
        "com",
        "https://",
        "@",
        "user@",
        "-example.com",
        "example-.com",
        "exa_mple.com",
        "exa mple.com",
        "exa\tmple.com",
        "ex%61mple.com",
        "example..com",
        ".example.com",
        "example.com..",
        "a" * 64 + ".com",
        "a" + LONGEST_NAME,
        "example.123",
        "xn--a.com",
        "xn--zz.com",
        "☃.com",
        "ftp://example.com/",
        "file:///etc/passwd",
        "javascript://example.com/",
        "example.com:99999",
        "example.com:abc",
        "example.com:-1",
        "x" * 3000,
    ],
)
def test_rejects_invalid_names(raw: str) -> None:
    with pytest.raises(InvalidDomainError):
        normalize_domain(raw)


def test_error_carries_a_user_facing_message() -> None:
    with pytest.raises(InvalidDomainError) as caught:
        normalize_domain("ftp://example.com")
    assert caught.value.message == "Only http and https URLs are supported."
    assert str(caught.value) == caught.value.message
