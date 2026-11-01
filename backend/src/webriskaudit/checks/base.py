"""What a check is, and how one is run."""

import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from webriskaudit.context import ScanContext
from webriskaudit.models import Category, CheckResult, Evidence, Reference, Status
from webriskaudit.scoring import points_for

logger = logging.getLogger(__name__)

MAX_EVIDENCE = 20
"""Most evidence items one check reports; the last says how many were left out."""
MAX_EVIDENCE_LABEL = 100
MAX_EVIDENCE_VALUE = 300
MAX_SUMMARY = 500


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


def clip(value: str, limit: int) -> str:
    """``value`` cut to ``limit`` characters, ending in "..." when it was cut."""
    return value if len(value) <= limit else value[: limit - 3] + "..."


def bounded_evidence(items: Sequence[Evidence], limit: int = MAX_EVIDENCE) -> list[Evidence]:
    """At most ``limit`` items with clipped labels and values.

    Checks keep their own evidence short; this bounds the report whatever a
    hostile site sends (thousands of policies or TXT records).
    """
    kept = list(items) if len(items) <= limit else list(items[: limit - 1])
    bounded = [
        Evidence(
            label=clip(item.label, MAX_EVIDENCE_LABEL), value=clip(item.value, MAX_EVIDENCE_VALUE)
        )
        for item in kept
    ]
    if len(items) > limit:
        bounded.append(evidence("Not shown", f"{len(items) - len(kept)} more evidence items"))
    return bounded


def redact_url(url: str) -> str:
    """``url`` for a report: scheme, host and path only.

    Query strings, fragments, credentials and ";" path parameters can carry
    session ids or tokens (``;jsessionid=``, SSO ``state``), and reports are
    cached and shown to anyone who scans the same domain. Removed parts are
    marked with "...".
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return "(invalid URL)"
    if not parts.scheme or not parts.netloc:
        return clip(url.split("?", 1)[0].split("#", 1)[0], MAX_EVIDENCE_VALUE)
    host = parts.netloc.rpartition("@")[2]
    segments = parts.path.split("/")
    path = "/".join(s.split(";", 1)[0] + (";..." if ";" in s else "") for s in segments)
    hidden = "?..." if parts.query or parts.fragment else ""
    return f"{parts.scheme}://{host}{path}{hidden}"


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
        summary=clip(outcome.summary, MAX_SUMMARY),
        evidence=bounded_evidence(outcome.evidence),
        remediation=outcome.remediation,
        references=list(check.references),
        duration_ms=round((time.perf_counter() - started) * 1000),
    )
