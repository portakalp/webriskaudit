"""Turns check results into category scores, an overall score and a grade."""

from webriskaudit.models import (
    CATEGORY_TITLES,
    Category,
    CategorySummary,
    CheckResult,
    Coverage,
    Grade,
    Status,
)

WARN_FRACTION = 0.5

# Below this share of the total scored weight completing, the report has no
# overall score: a handful of passing checks should not read as "A".
MIN_COMPLETED_WEIGHT_SHARE = 0.5

GRADE_BANDS: tuple[tuple[int, Grade], ...] = ((90, "A"), (75, "B"), (60, "C"), (45, "D"), (0, "F"))

_COMPLETED = (Status.PASS, Status.WARN, Status.FAIL)


def points_for(status: Status, weight: int) -> float:
    if status is Status.PASS:
        return float(weight)
    if status is Status.WARN:
        return weight * WARN_FRACTION
    return 0.0


def grade_for(score: int) -> Grade:
    return next(grade for floor, grade in GRADE_BANDS if score >= floor)


def _percent(points: float, possible: int) -> int | None:
    return round(100 * points / possible) if possible else None


def summarize(
    results: list[CheckResult],
) -> tuple[int | None, Grade | None, Coverage, list[CategorySummary]]:
    """Overall score, grade, coverage and per-category summaries.

    Only checks with weight > 0 that reached a verdict count: score is
    points earned over the weight of those checks, so inconclusive checks
    neither help nor hurt.
    """
    scored = [r for r in results if r.weight > 0]
    completed = [r for r in scored if r.status in _COMPLETED]

    categories = []
    for category in Category:
        if category is Category.INFO:
            continue
        in_category = [r for r in completed if r.category is category]
        possible = sum(r.weight for r in in_category)
        points = sum(r.points for r in in_category)
        categories.append(
            CategorySummary(
                id=category,
                title=CATEGORY_TITLES[category],
                score=_percent(points, possible),
                points=points,
                possible=possible,
            )
        )

    coverage = Coverage(
        scored=len(completed),
        inconclusive=len(scored) - len(completed),
        total=len(scored),
    )

    total_weight = sum(r.weight for r in scored)
    possible = sum(r.weight for r in completed)
    if not total_weight or possible < total_weight * MIN_COMPLETED_WEIGHT_SHARE:
        return None, None, coverage, categories
    score = round(100 * sum(r.points for r in completed) / possible)
    return score, grade_for(score), coverage, categories
