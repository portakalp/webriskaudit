"""Rate limiter and report cache, driven by a fake clock."""

import asyncio
from dataclasses import dataclass

import pytest

from webriskaudit.cache import ResultCache
from webriskaudit.ratelimit import RateLimiter, client_key


@dataclass
class Clock:
    now: float = 1000.0

    def __call__(self) -> float:
        return self.now


# --- RateLimiter ------------------------------------------------------------------


def test_allows_up_to_the_limit_then_reports_the_wait() -> None:
    clock = Clock()
    limiter = RateLimiter(2, 60, clock=clock)
    assert limiter.hit("a") is None
    clock.now += 10
    assert limiter.hit("a") is None
    assert limiter.hit("a") == 50  # the first hit leaves the window in 50 s
    clock.now += 50
    assert limiter.hit("a") is None


def test_refused_hits_do_not_extend_the_wait() -> None:
    clock = Clock()
    limiter = RateLimiter(1, 60, clock=clock)
    limiter.hit("a")
    for _ in range(5):
        clock.now += 10
        limiter.hit("a")
    clock.now += 10
    assert limiter.hit("a") is None


def test_keys_are_independent() -> None:
    limiter = RateLimiter(1, 60, clock=Clock())
    assert limiter.hit("a") is None
    assert limiter.hit("b") is None
    assert limiter.hit("a") is not None


def test_zero_limit_turns_the_limiter_off() -> None:
    limiter = RateLimiter(0, 60, clock=Clock())
    assert all(limiter.hit("a") is None for _ in range(100))
    assert len(limiter) == 0


def test_idle_keys_are_forgotten() -> None:
    clock = Clock()
    limiter = RateLimiter(5, 60, clock=clock)
    for key in ("a", "b", "c"):
        limiter.hit(key)
    clock.now += 61
    limiter.hit("d")
    assert len(limiter) == 1


def test_sweep_forgets_expired_keys_without_a_new_hit() -> None:
    clock = Clock()
    limiter = RateLimiter(5, 60, clock=clock)
    limiter.hit("a")
    limiter.hit("b")
    clock.now += 30
    limiter.hit("c")
    limiter.hit("a")  # active again: now the most recent key
    clock.now += 31
    limiter.sweep()
    assert len(limiter) == 2  # b expired; a and c each have a hit in the window
    assert limiter.wait("b") is None
    clock.now += 30
    limiter.sweep()
    assert len(limiter) == 0


def test_sweep_forgets_a_key_emptied_by_wait() -> None:
    clock = Clock()
    limiter = RateLimiter(1, 60, clock=clock)
    limiter.hit("a")
    clock.now += 61
    assert limiter.wait("a") is None
    limiter.sweep()
    assert len(limiter) == 0


def test_wait_records_nothing() -> None:
    clock = Clock()
    limiter = RateLimiter(1, 60, clock=clock)
    assert limiter.wait("a") is None
    assert limiter.wait("a") is None
    assert len(limiter) == 0
    limiter.hit("a")
    assert limiter.wait("a") == 60


def test_least_recently_active_key_is_dropped_at_the_key_limit() -> None:
    clock = Clock()
    limiter = RateLimiter(1, 60, max_keys=2, clock=clock)
    for key in ("a", "b"):
        limiter.hit(key)
        clock.now += 1
    limiter.hit("c")
    assert len(limiter) == 2
    assert limiter.wait("a") is None  # forgotten
    assert limiter.wait("b") is not None
    assert limiter.wait("c") is not None


@pytest.mark.parametrize(
    ("address", "key"),
    [
        ("198.51.100.7", "198.51.100.7"),
        ("2001:db8:1:2::1", "2001:db8:1:2::/64"),
        ("2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"),
        ("2001:DB8:1:3::1", "2001:db8:1:3::/64"),
        ("::ffff:198.51.100.7", "198.51.100.7"),
        ("fe80::1%eth0", "fe80::/64"),
        ("unknown", "unknown"),
    ],
)
def test_client_key(address: str, key: str) -> None:
    assert client_key(address) == key


# --- ResultCache ------------------------------------------------------------------


async def value(result: str) -> str:
    return result


async def failure() -> str:
    raise RuntimeError("boom")


async def test_results_are_kept_until_they_expire() -> None:
    clock = Clock()
    cache: ResultCache[str] = ResultCache(60, clock=clock)
    assert await cache.start("k", value("v")) == "v"
    assert cache.running("k") is None
    clock.now += 59
    assert cache.get("k") == "v"
    clock.now += 1
    assert cache.get("k") is None
    assert len(cache) == 0


async def test_running_task_is_shared_until_it_finishes() -> None:
    cache: ResultCache[str] = ResultCache(60, clock=Clock())
    release = asyncio.Event()

    async def slow() -> str:
        await release.wait()
        return "v"

    task = cache.start("k", slow())
    assert cache.running("k") is task
    assert cache.get("k") is None
    release.set()
    await task
    assert (cache.running("k"), cache.get("k")) == (None, "v")


async def test_failures_are_not_cached() -> None:
    cache: ResultCache[str] = ResultCache(60, clock=Clock())
    task = cache.start("k", failure())
    with pytest.raises(RuntimeError):
        await task
    assert (cache.running("k"), cache.get("k")) == (None, None)


async def test_cancelled_work_is_not_cached() -> None:
    cache: ResultCache[str] = ResultCache(60, clock=Clock())
    task = cache.start("k", asyncio.sleep(3600, result="v"))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert (cache.running("k"), cache.get("k")) == (None, None)


async def test_sweep_drops_expired_results() -> None:
    clock = Clock()
    cache: ResultCache[str] = ResultCache(60, clock=clock)
    await cache.start("a", value("a"))
    clock.now += 30
    await cache.start("b", value("b"))
    clock.now += 30
    cache.sweep()
    assert len(cache) == 1
    assert cache.get("b") == "b"
    clock.now += 30
    cache.sweep()
    assert len(cache) == 0


async def test_zero_ttl_caches_nothing() -> None:
    cache: ResultCache[str] = ResultCache(0, clock=Clock())
    await cache.start("k", value("v"))
    assert cache.get("k") is None


async def test_oldest_entries_are_evicted_at_the_size_limit() -> None:
    cache: ResultCache[str] = ResultCache(60, max_entries=2, clock=Clock())
    for key in ("a", "b", "c"):
        await cache.start(key, value(key))
    assert [cache.get(key) for key in ("a", "b", "c")] == [None, "b", "c"]
