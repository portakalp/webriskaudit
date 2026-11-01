"""Runtime settings of the API, read from environment variables."""

import ipaddress
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

DEFAULT_ALLOWED_ORIGINS = ("http://localhost:3000", "https://webriskaudit.com")
MIN_SECRET_LENGTH = 32

_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
"""An HTTP field name (RFC 9110 token)."""
_SECRET = re.compile(r"[\x21-\x7e]+")
"""Visible ASCII: a header value without spaces that no proxy will rewrite."""
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


class SettingsError(ValueError):
    """An environment variable holds a value the API cannot use."""


@dataclass(frozen=True)
class Settings:
    allowed_origins: tuple[str, ...] = DEFAULT_ALLOWED_ORIGINS
    """Browser origins allowed by CORS (ALLOWED_ORIGINS, comma-separated)."""
    rate_limit_scans: int = 10
    """New scans per client per window (RATE_LIMIT_SCANS); 0 turns the limit off.

    A client is an IPv4 address or an IPv6 /64 network."""
    rate_limit_window: float = 600.0
    """Length of the rate limit windows in seconds (RATE_LIMIT_WINDOW_SECONDS)."""
    global_rate_limit_scans: int = 600
    """New scans per window from all clients together (GLOBAL_RATE_LIMIT_SCANS); 0 is off."""
    cache_ttl: float = 600.0
    """How long a report is served from the cache (CACHE_TTL_SECONDS); 0 turns it off."""
    max_concurrent_scans: int = 4
    """Scans running at the same time (MAX_CONCURRENT_SCANS); others wait for a slot."""
    max_queued_scans: int = 16
    """New scans that may wait for a slot (MAX_QUEUED_SCANS); more are refused with 503."""
    queue_timeout: float = 30.0
    """Longest wait for a slot in seconds (QUEUE_TIMEOUT_SECONDS) before a 503."""
    scan_deadline: float = 45.0
    """Overall time budget of one scan in seconds (SCAN_DEADLINE_SECONDS)."""
    check_timeout: float = 30.0
    """Time budget of a single check in seconds (CHECK_TIMEOUT_SECONDS)."""
    dns_nameservers: tuple[str, ...] = ()
    """Recursive resolvers to query (DNS_NAMESERVERS, comma-separated IP addresses).

    Empty uses the system's resolvers, which on cloud hosts may also answer for
    private zones; see the README's deployment notes."""
    origin_auth_secrets: tuple[str, ...] = field(default=(), repr=False)
    """Accepted values of the X-Origin-Auth header (ORIGIN_AUTH_SECRETS, comma-separated).

    Empty turns origin authentication off. When set, every request except
    ``GET /health`` and ``GET /`` must carry one of them, and the client
    address is read from ``client_ip_header``. Two values allow a rotation."""
    client_ip_header: str | None = None
    """Header the proxy puts the client address in (CLIENT_IP_HEADER), such as
    CF-Connecting-IP. Required with, and only allowed with, origin authentication."""
    api_docs_enabled: bool = True
    """Serve /docs, /redoc and /openapi.json (API_DOCS_ENABLED)."""
    revision: str | None = None
    """Commit the running image was built from (WEBRISKAUDIT_REVISION, set by the image build)."""

    def __post_init__(self) -> None:
        for number, secret in enumerate(self.origin_auth_secrets, start=1):
            # The message never contains the value.
            if len(secret) < MIN_SECRET_LENGTH or not _SECRET.fullmatch(secret):
                raise SettingsError(
                    f"ORIGIN_AUTH_SECRETS entry {number} must be at least {MIN_SECRET_LENGTH} "
                    "visible ASCII characters without spaces or commas"
                )
        if self.client_ip_header is not None and not _HEADER_NAME.fullmatch(self.client_ip_header):
            raise SettingsError(
                f"CLIENT_IP_HEADER must be a header name, got {self.client_ip_header!r}"
            )
        if self.origin_auth_secrets and self.client_ip_header is None:
            raise SettingsError("ORIGIN_AUTH_SECRETS needs CLIENT_IP_HEADER")
        if self.client_ip_header is not None and not self.origin_auth_secrets:
            raise SettingsError(
                "CLIENT_IP_HEADER needs ORIGIN_AUTH_SECRETS; without origin authentication "
                "anyone could set the header"
            )

    @property
    def origin_auth_enabled(self) -> bool:
        return bool(self.origin_auth_secrets)

    def summary(self) -> dict[str, object]:
        """The effective settings without secrets, for the startup log line."""
        return {
            "revision": self.revision,
            "allowed_origins": list(self.allowed_origins),
            "rate_limit_scans": self.rate_limit_scans,
            "rate_limit_window_seconds": self.rate_limit_window,
            "global_rate_limit_scans": self.global_rate_limit_scans,
            "cache_ttl_seconds": self.cache_ttl,
            "max_concurrent_scans": self.max_concurrent_scans,
            "max_queued_scans": self.max_queued_scans,
            "queue_timeout_seconds": self.queue_timeout,
            "scan_deadline_seconds": self.scan_deadline,
            "check_timeout_seconds": self.check_timeout,
            "dns_nameservers": list(self.dns_nameservers) or "system",
            "origin_auth": "enabled" if self.origin_auth_enabled else "disabled",
            "origin_auth_secrets": len(self.origin_auth_secrets),
            "client_ip_header": self.client_ip_header,
            "api_docs": "enabled" if self.api_docs_enabled else "disabled",
        }

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        """Settings from ``env`` (default: the process environment). Raises SettingsError."""
        env = os.environ if env is None else env
        origins = env.get("ALLOWED_ORIGINS")
        return cls(
            allowed_origins=(
                DEFAULT_ALLOWED_ORIGINS if origins is None else parse_origins(origins)
            ),
            rate_limit_scans=_read(env, "RATE_LIMIT_SCANS", 10, int, minimum=0),
            rate_limit_window=_read(env, "RATE_LIMIT_WINDOW_SECONDS", 600.0, float, minimum=1),
            global_rate_limit_scans=_read(env, "GLOBAL_RATE_LIMIT_SCANS", 600, int, minimum=0),
            cache_ttl=_read(env, "CACHE_TTL_SECONDS", 600.0, float, minimum=0),
            max_concurrent_scans=_read(env, "MAX_CONCURRENT_SCANS", 4, int, minimum=1),
            max_queued_scans=_read(env, "MAX_QUEUED_SCANS", 16, int, minimum=0),
            queue_timeout=_read(env, "QUEUE_TIMEOUT_SECONDS", 30.0, float, minimum=1),
            scan_deadline=_read(env, "SCAN_DEADLINE_SECONDS", 45.0, float, minimum=1),
            check_timeout=_read(env, "CHECK_TIMEOUT_SECONDS", 30.0, float, minimum=1),
            dns_nameservers=parse_nameservers(env.get("DNS_NAMESERVERS", "")),
            origin_auth_secrets=_split(env.get("ORIGIN_AUTH_SECRETS", "")),
            client_ip_header=env.get("CLIENT_IP_HEADER", "").strip() or None,
            api_docs_enabled=_read_bool(env, "API_DOCS_ENABLED", True),
            revision=env.get("WEBRISKAUDIT_REVISION", "").strip() or None,
        )


def parse_origins(value: str) -> tuple[str, ...]:
    """Comma-separated origins, trimmed, without empty entries or a trailing slash."""
    return tuple(origin.rstrip("/") for origin in _split(value))


def parse_nameservers(value: str) -> tuple[str, ...]:
    """Comma-separated IP addresses of resolvers. Raises SettingsError."""
    servers = _split(value)
    for server in servers:
        try:
            ipaddress.ip_address(server)
        except ValueError:
            raise SettingsError(f"DNS_NAMESERVERS must list IP addresses, got {server!r}") from None
    return servers


def _split(value: str) -> tuple[str, ...]:
    """Comma-separated values, trimmed, without empty entries."""
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _read_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise SettingsError(f"{name} must be true or false, got {raw!r}")


def _read[T: (int, float)](
    env: Mapping[str, str], name: str, default: T, convert: Callable[[str], T], *, minimum: T
) -> T:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = convert(raw.strip())
    except ValueError:
        raise SettingsError(f"{name} must be a number, got {raw!r}") from None
    if value < minimum:
        raise SettingsError(f"{name} must be at least {minimum}, got {raw!r}")
    return value
