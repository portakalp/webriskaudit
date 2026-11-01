"""Runtime settings of the API, read from environment variables."""

import ipaddress
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass

DEFAULT_ALLOWED_ORIGINS = ("http://localhost:3000", "https://webriskaudit.com")


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
        )


def parse_origins(value: str) -> tuple[str, ...]:
    """Comma-separated origins, trimmed, without empty entries or a trailing slash."""
    return tuple(origin.strip().rstrip("/") for origin in value.split(",") if origin.strip())


def parse_nameservers(value: str) -> tuple[str, ...]:
    """Comma-separated IP addresses of resolvers. Raises SettingsError."""
    servers = tuple(server.strip() for server in value.split(",") if server.strip())
    for server in servers:
        try:
            ipaddress.ip_address(server)
        except ValueError:
            raise SettingsError(f"DNS_NAMESERVERS must list IP addresses, got {server!r}") from None
    return servers


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
