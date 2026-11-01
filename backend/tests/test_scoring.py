import pytest

from webriskaudit.checks.base import Check, Outcome, run_check
from webriskaudit.context import ScanContext
from webriskaudit.models import Category, CheckResult, Status
from webriskaudit.scoring import grade_for, points_for, summarize

from .fakes import make_context


def result(status: Status, weight: int = 10, category: Category = Category.EMAIL) -> CheckResult:
    return CheckResult(
        id="t",
        title="t",
        category=category,
        status=status,
        weight=weight,
        points=points_for(status, weight),
        summary="",
        duration_ms=0,
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (Status.PASS, 10.0),
        (Status.WARN, 5.0),
        (Status.FAIL, 0.0),
        (Status.INCONCLUSIVE, 0.0),
    ],
)
def test_points_for(status: Status, expected: float) -> None:
    assert points_for(status, 10) == expected


@pytest.mark.parametrize(
    ("score", "grade"),
    [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (60, "C"), (45, "D"), (0, "F")],
)
def test_grade_bands(score: int, grade: str) -> None:
    assert grade_for(score) == grade


def test_inconclusive_checks_are_left_out_of_the_score() -> None:
    score, grade, coverage, _ = summarize(
        [
            result(Status.PASS),
            result(Status.FAIL),
            result(Status.INCONCLUSIVE),
            result(Status.INFO, weight=0, category=Category.INFO),
        ]
    )
    assert coverage.model_dump() == {"scored": 2, "inconclusive": 1, "total": 3}
    assert (score, grade) == (50, "D")


def test_no_score_when_too_little_completed() -> None:
    score, grade, coverage, categories = summarize(
        [result(Status.PASS), result(Status.INCONCLUSIVE), result(Status.INCONCLUSIVE)]
    )
    assert (score, grade) == (None, None)
    assert coverage.scored == 1
    email = next(c for c in categories if c.id is Category.EMAIL)
    assert email.score == 100


def test_categories_exclude_informational_checks() -> None:
    _, _, _, categories = summarize([result(Status.WARN, category=Category.HEADERS)])
    assert [c.id for c in categories] == [Category.EMAIL, Category.TRANSPORT, Category.HEADERS]
    headers = categories[2]
    assert (headers.points, headers.possible, headers.score) == (5.0, 10, 50)
    assert categories[0].score is None


async def test_run_check_turns_exceptions_into_inconclusive() -> None:
    async def broken(ctx: ScanContext) -> Outcome:
        raise RuntimeError("boom")

    check = Check("x.broken", "Broken", Category.EMAIL, 10, broken)
    outcome = await run_check(check, make_context())
    assert outcome.status is Status.INCONCLUSIVE
    assert outcome.points == 0


async def test_run_check_rejects_info_from_scored_check() -> None:
    async def info(ctx: ScanContext) -> Outcome:
        return Outcome(Status.INFO, "")

    with pytest.raises(ValueError, match="weight 10"):
        await run_check(Check("x.info", "Info", Category.EMAIL, 10, info), make_context())
