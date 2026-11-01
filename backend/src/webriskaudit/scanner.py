"""Runs every check against one domain and builds the report.

Before any check runs, the domain is normalized and resolved: a name that does
not exist or points at a non-public address is refused outright instead of
being scored. Checks then run concurrently, each bounded by its own timeout
and by the scan deadline; a check that is still running when either expires
is reported as inconclusive.
"""

import asyncio
import time
from collections.abc import Sequence
from datetime import UTC, datetime

from webriskaudit import METHODOLOGY_VERSION, __version__
from webriskaudit.checks import ALL_CHECKS
from webriskaudit.checks.base import Check, run_check
from webriskaudit.context import ScanContext
from webriskaudit.models import CheckResult, ScanReport, Status
from webriskaudit.net.addresses import is_public_address
from webriskaudit.net.dns import DnsResolver
from webriskaudit.net.domain import normalize_domain
from webriskaudit.net.http import GuardedFetcher
from webriskaudit.net.tls import TlsProbe
from webriskaudit.net.types import (
    DnsUnavailableError,
    Fetcher,
    NoAnswerError,
    NxDomainError,
    Resolver,
    TlsProber,
)
from webriskaudit.scoring import summarize

DEFAULT_DEADLINE = 45.0
DEFAULT_CHECK_TIMEOUT = 30.0


class ScanError(Exception):
    """The scan was refused before any check ran; ``message`` is safe to show to users."""

    def __init__(self, domain: str, message: str) -> None:
        super().__init__(message)
        self.domain = domain
        self.message = message


class DomainNotFoundError(ScanError):
    def __init__(self, domain: str) -> None:
        super().__init__(domain, f"{domain} does not exist in DNS (NXDOMAIN).")


class NonPublicTargetError(ScanError):
    def __init__(self, domain: str) -> None:
        super().__init__(
            domain, f"{domain} resolves to a non-public address, so it is not scanned."
        )


class DnsUnavailableScanError(ScanError):
    def __init__(self, domain: str) -> None:
        super().__init__(domain, f"DNS did not give a usable answer for {domain}. Try again later.")


class Scanner:
    """Scans domains with shared, stateless network clients.

    Every dependency can be injected; by default the real DNS resolver,
    guarded fetcher and TLS probe are built around one resolver.
    """

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        fetcher: Fetcher | None = None,
        tls: TlsProber | None = None,
        checks: Sequence[Check] = ALL_CHECKS,
        deadline: float = DEFAULT_DEADLINE,
        check_timeout: float = DEFAULT_CHECK_TIMEOUT,
    ) -> None:
        self.resolver: Resolver = resolver or DnsResolver()
        self.fetcher: Fetcher = fetcher or GuardedFetcher(self.resolver)
        self.tls: TlsProber = tls or TlsProbe(self.resolver)
        self.checks = tuple(checks)
        self.deadline = deadline
        self.check_timeout = check_timeout

    async def scan(self, raw_domain: str) -> ScanReport:
        """Scan ``raw_domain`` (a name or URL).

        Raises InvalidDomainError for input that is not a public domain name,
        and a ScanError subclass when the pre-check refuses the domain.
        """
        domain = normalize_domain(raw_domain)
        scanned_at = datetime.now(UTC)
        started = time.perf_counter()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.deadline

        addresses = await self._precheck(domain, deadline)
        ctx = ScanContext(domain, addresses, self.resolver, self.fetcher, self.tls)
        try:
            async with asyncio.TaskGroup() as group:
                tasks = [group.create_task(self._run(c, ctx, deadline)) for c in self.checks]
        finally:
            ctx.close()
        results = [task.result() for task in tasks]

        score, grade, coverage, categories = summarize(results)
        return ScanReport(
            domain=domain,
            scanned_at=scanned_at,
            duration_ms=round((time.perf_counter() - started) * 1000),
            score=score,
            grade=grade,
            coverage=coverage,
            categories=categories,
            checks=results,
            scanner_version=__version__,
            methodology_version=METHODOLOGY_VERSION,
        )

    async def _precheck(self, domain: str, deadline: float) -> tuple[str, ...]:
        """The domain's addresses, all public; empty if it has no A/AAAA records."""
        try:
            async with asyncio.timeout_at(deadline):
                addresses = await self.resolver.addresses(domain)
        except NxDomainError:
            raise DomainNotFoundError(domain) from None
        except NoAnswerError:
            return ()  # mail-only domains exist without a web server
        except (DnsUnavailableError, TimeoutError):
            raise DnsUnavailableScanError(domain) from None
        if not all(is_public_address(address) for address in addresses):
            raise NonPublicTargetError(domain)
        return tuple(addresses)

    async def _run(self, check: Check, ctx: ScanContext, deadline: float) -> CheckResult:
        """Run one check within its timeout and the scan deadline."""
        loop = asyncio.get_running_loop()
        started = loop.time()
        limit = min(started + self.check_timeout, deadline)
        try:
            async with asyncio.timeout_at(limit):
                return await run_check(check, ctx)
        except TimeoutError:
            seconds = limit - started
            return timed_out(check, seconds, round((loop.time() - started) * 1000))


def timed_out(check: Check, seconds: float, duration_ms: int) -> CheckResult:
    """Inconclusive result for a check that did not finish in time."""
    return CheckResult(
        id=check.id,
        title=check.title,
        category=check.category,
        status=Status.INCONCLUSIVE,
        weight=check.weight,
        points=0.0,
        summary=f"The check did not finish within {seconds:.3g} seconds and timed out.",
        references=list(check.references),
        duration_ms=duration_ms,
    )
