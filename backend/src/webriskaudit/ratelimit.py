"""Rate limits on new scans, kept in memory of one process."""

import ipaddress
import time
from collections import deque
from collections.abc import Callable

IPV6_PREFIX = 64
"""IPv6 clients are limited per /64 network, the usual allocation to one subscriber."""
DEFAULT_MAX_KEYS = 10_000


def client_key(address: str) -> str:
    """The rate limit key of a client address.

    An IPv4 address is its own key. An IPv6 client usually holds a whole /64
    and can use a new address for every request, so it is keyed by that
    network; an IPv4-mapped IPv6 address counts as its IPv4 address. Anything
    else (such as "unknown") is used as given.
    """
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return address
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.IPv6Network((ip, IPV6_PREFIX), strict=False))
    return str(ip)


class RateLimiter:
    """Sliding window: at most ``limit`` hits per ``window`` seconds for each key.

    A refused hit is not recorded, so retrying early does not extend the wait.
    A ``limit`` of 0 turns the limiter off. At most ``max_keys`` keys are
    tracked: past that, the least recently active key is forgotten, which
    bounds memory at the cost of being lenient to that key.
    """

    def __init__(
        self,
        limit: int,
        window: float,
        *,
        max_keys: int = DEFAULT_MAX_KEYS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = limit
        self._window = window
        self._max_keys = max_keys
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        """Key -> hit times, least recently active key first."""
        self._next_sweep = 0.0

    @property
    def enabled(self) -> bool:
        return self._limit > 0

    def wait(self, key: str) -> float | None:
        """Seconds until ``key`` may hit again, or None if it may now. Records nothing."""
        if self._limit <= 0:
            return None
        hits = self._hits.get(key)
        if hits is None:
            return None
        now = self._clock()
        while hits and hits[0] <= now - self._window:
            hits.popleft()
        if len(hits) >= self._limit:
            return hits[0] + self._window - now
        return None

    def hit(self, key: str) -> float | None:
        """Record a hit for ``key``: None if allowed, else seconds until one would be."""
        if self._limit <= 0:
            return None
        wait = self.wait(key)
        if wait is not None:
            return wait
        now = self._clock()
        self._sweep(now)
        hits = self._hits.pop(key, None) or deque()
        hits.append(now)
        self._hits[key] = hits
        while len(self._hits) > self._max_keys:
            del self._hits[next(iter(self._hits))]
        return None

    def __len__(self) -> int:
        """Number of keys currently tracked."""
        return len(self._hits)

    def _sweep(self, now: float) -> None:
        """Forget keys whose hits have all expired, at most once per window."""
        if now < self._next_sweep:
            return
        self._next_sweep = now + self._window
        cutoff = now - self._window
        for key in [key for key, hits in self._hits.items() if not hits or hits[-1] <= cutoff]:
            del self._hits[key]
