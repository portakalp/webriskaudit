"""What a check is, and how one is run."""

import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from webriskaudit.context import ScanContext
from webriskaudit.models import Category, CheckResult, Evidence, Reference, Status
from webriskaudit.scoring import points_for

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Outcome:
    """What a check function returns; points are derived from status and weight."""

    status: Status
    summary: str
    evidence: list[Evidence] = field(default_factory=list)
    remediation: str | None = None


CheckFn = Callable[[ScanContext], Awaitable[Outcome]]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    category: Category
    weight: int
    run: CheckFn
    references: tuple[Reference, ...] = ()


def evidence(label: str, value: object) -> Evidence:
    return Evidence(label=label, value=str(value))


async def run_check(check: Check, ctx: ScanContext) -> CheckResult:
    """Run one check; an unexpected exception becomes an inconclusive result."""
    started = time.perf_counter()
    try:
        outcome = await check.run(ctx)
    except Exception:
        logger.exception("check %s failed for %s", check.id, ctx.domain)
        outcome = Outcome(Status.INCONCLUSIVE, "The check failed unexpectedly.")
    # Informational checks (weight 0) report info; scored checks never do.
    is_info = outcome.status is Status.INFO
    if outcome.status is not Status.INCONCLUSIVE and is_info != (check.weight == 0):
        raise ValueError(f"check {check.id} with weight {check.weight} returned {outcome.status}")
    return CheckResult(
        id=check.id,
        title=check.title,
        category=check.category,
        status=outcome.status,
        weight=check.weight,
        points=points_for(outcome.status, check.weight),
        summary=outcome.summary,
        evidence=outcome.evidence,
        remediation=outcome.remediation,
        references=list(check.references),
        duration_ms=round((time.perf_counter() - started) * 1000),
    )
