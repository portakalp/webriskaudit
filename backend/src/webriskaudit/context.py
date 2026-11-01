"""Per-scan state shared by all checks."""

import asyncio
from dataclasses import dataclass, field

from webriskaudit.net.types import Fetcher, HttpResponse, Resolver, TlsProber


@dataclass
class ScanContext:
    """Everything a check may use. Checks never open sockets themselves.

    ``addresses`` are the domain's A/AAAA addresses, already verified to be
    public by the scanner's pre-check. An empty tuple means the domain has no
    web server, and checks that need one should report inconclusive.
    """

    domain: str
    addresses: tuple[str, ...]
    resolver: Resolver
    fetcher: Fetcher
    tls: TlsProber
    _pages: dict[str, asyncio.Task[HttpResponse]] = field(default_factory=dict, repr=False)

    async def fetch(self, url: str) -> HttpResponse:
        """Fetch ``url`` once per scan; concurrent callers share the request.

        Raises FetchError like ``Fetcher.get``.
        """
        task = self._pages.get(url)
        if task is None:
            task = asyncio.ensure_future(self.fetcher.get(url))
            self._pages[url] = task
        return await asyncio.shield(task)

    async def homepage(self) -> HttpResponse:
        """``https://<domain>/`` after redirects. Raises FetchError."""
        return await self.fetch(f"https://{self.domain}/")

    def close(self) -> None:
        """Cancel shared requests that are still running."""
        for task in self._pages.values():
            task.cancel()
