"""Turn user input into the hostname that gets scanned.

The result is a lower-case ASCII (IDNA A-label) name with at least two labels.
IP literals and special-use names are refused here, before any DNS lookup; the
addresses a name resolves to are checked separately in ``addresses``.
"""

import ipaddress
import re

import idna

_MAX_INPUT_LENGTH = 2048
_MAX_NAME_LENGTH = 253
_SCHEME = re.compile(r"^([a-z][a-z0-9+.-]*)://", re.IGNORECASE)
_LDH_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
# WHATWG URL parsing treats a host whose last label is a number (decimal or
# 0x-hex) as an IPv4 address, e.g. "0x7f.1" or "127.1".
_NUMERIC_LABEL = re.compile(r"^(?:[0-9]+|0x[0-9a-f]*)$")

# Names that never point at the public internet: RFC 6761 (localhost, invalid,
# test, example), RFC 6762 (local), RFC 7686 (onion), RFC 9476 (alt), the arpa
# infrastructure zone (incl. home.arpa, RFC 8375), ICANN's private-use
# "internal", and the names ICANN resolved never to delegate (corp, home, mail).
SPECIAL_USE_TLDS = frozenset(
    {
        "alt",
        "arpa",
        "corp",
        "example",
        "home",
        "internal",
        "invalid",
        "local",
        "localhost",
        "mail",
        "onion",
        "test",
    }
)


class InvalidDomainError(ValueError):
    """The input is not a public domain name we are willing to scan."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def normalize_domain(raw: str) -> str:
    """Return the lower-case A-label hostname in ``raw`` or raise InvalidDomainError.

    Accepts a bare name or a URL; drops the scheme, userinfo, port, path and a
    trailing dot. ``www.`` is kept: the host is scanned as given.
    """
    host = _extract_host(raw)
    name = _to_ascii(host)
    _validate(name)
    return name


def _extract_host(raw: str) -> str:
    text = raw.strip()
    if not text:
        raise InvalidDomainError("Enter a domain name such as example.com.")
    if len(text) > _MAX_INPUT_LENGTH:
        raise InvalidDomainError("The input is too long to be a domain name.")
    match = _SCHEME.match(text)
    if match:
        if match.group(1).lower() not in ("http", "https"):
            raise InvalidDomainError("Only http and https URLs are supported.")
        text = text[match.end() :]
    elif text.startswith("//"):
        text = text[2:]
    # Browsers end the authority at "/", "\", "?" or "#", and take the host
    # from after the last "@"; doing the same avoids parser differentials.
    authority = re.split(r"[/\\?#]", text, maxsplit=1)[0]
    authority = authority.rsplit("@", 1)[-1]
    return _strip_port(authority)


def _strip_port(authority: str) -> str:
    if authority.startswith("[") or authority.count(":") > 1:
        raise InvalidDomainError("IP addresses cannot be scanned; enter a domain name.")
    host, colon, port = authority.partition(":")
    if colon and port and not (port.isascii() and port.isdigit() and int(port) <= 65535):
        raise InvalidDomainError("The port number is not valid.")
    return host


def _to_ascii(host: str) -> str:
    if not host.isascii():
        try:
            # UTS 46 mapping folds case and full-width forms (including the
            # ideographic full stop) before IDNA 2008 validation.
            host = idna.encode(host, uts46=True, transitional=False, std3_rules=True).decode()
        except UnicodeError as exc:  # idna.IDNAError and codec errors
            raise InvalidDomainError("The domain is not a valid internationalized name.") from exc
    host = host.lower()
    return host[:-1] if host.endswith(".") else host


def _validate(name: str) -> None:
    if not name:
        raise InvalidDomainError("Enter a domain name such as example.com.")
    labels = name.split(".")
    if _is_ip_literal(name) or _NUMERIC_LABEL.match(labels[-1]):
        raise InvalidDomainError("IP addresses cannot be scanned; enter a domain name.")
    if labels[-1] in SPECIAL_USE_TLDS:
        raise InvalidDomainError(
            f"Names under .{labels[-1]} are reserved for special use and cannot be scanned."
        )
    if len(name) > _MAX_NAME_LENGTH:
        raise InvalidDomainError("The domain name is longer than 253 characters.")
    if len(labels) < 2:
        raise InvalidDomainError("Enter a full domain name such as example.com.")
    for label in labels:
        _validate_label(label)


def _validate_label(label: str) -> None:
    if not _LDH_LABEL.match(label):
        raise InvalidDomainError(
            "Each part of a domain name must be 1-63 letters, digits or hyphens "
            "and cannot start or end with a hyphen."
        )
    if label.startswith("xn--"):
        try:
            idna.decode(label)
        except UnicodeError as exc:
            raise InvalidDomainError("The domain contains an invalid IDNA label.") from exc


def _is_ip_literal(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return False
    return True
