"""Short-lived result cache with in-flight coalescing, kept in memory of one process."""

import asyncio
import time
from collections.abc import Callable, Coroutine
from functools import partial
from typing import Any


class ResultCache[T]:
    """Results by key for ``ttl`` seconds, plus the computations still running.

    Concurrent callers for the same key share one running task, so a domain
    is scanned once however many clients ask for it at the same moment.
    Failed or cancelled computations are not cached. A ``ttl`` of 0 keeps
    coalescing but caches nothing.
    """

    def __init__(
        self,
        ttl: float,
        *,
        max_entries: int = 1024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl
        self._max_entries = max_entries
        self._clock = clock
        self._done: dict[str, tuple[float, T]] = {}
        """Key -> (expiry time, result), oldest first."""
        self._running: dict[str, asyncio.Task[T]] = {}

    def get(self, key: str) -> T | None:
        """The cached result for ``key``, if it has not expired."""
        entry = self._done.get(key)
        if entry is None:
            return None
        expires, result = entry
        if expires <= self._clock():
            del self._done[key]
            return None
        return result

    def running(self, key: str) -> asyncio.Task[T] | None:
        """The task still computing ``key``, if any."""
        return self._running.get(key)

    def start(self, key: str, work: Coroutine[Any, Any, T]) -> asyncio.Task[T]:
        """Run ``work`` as the shared task for ``key``; its result is cached on success."""
        task = asyncio.create_task(work)
        self._running[key] = task
        task.add_done_callback(partial(self._finished, key))
        return task

    def __len__(self) -> int:
        """Number of cached results, including expired ones not yet dropped."""
        return len(self._done)

    def _finished(self, key: str, task: asyncio.Task[T]) -> None:
        if self._running.get(key) is task:
            del self._running[key]
        # Reading the exception also marks it as retrieved when no caller is left.
        if task.cancelled() or task.exception() is not None or self._ttl <= 0:
            return
        self._store(key, task.result())

    def _store(self, key: str, result: T) -> None:
        now = self._clock()
        for stale in [k for k, (expires, _) in self._done.items() if expires <= now]:
            del self._done[stale]
        self._done.pop(key, None)
        while len(self._done) >= self._max_entries:
            del self._done[next(iter(self._done))]
        self._done[key] = (now + self._ttl, result)
