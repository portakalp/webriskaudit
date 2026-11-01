"""Bounds and redaction applied to every check's evidence."""

import pytest

from webriskaudit.checks.base import (
    MAX_EVIDENCE,
    Check,
    Outcome,
    bounded_evidence,
    evidence,
    redact_url,
    run_check,
)
from webriskaudit.context import ScanContext
from webriskaudit.models import Category, Status

from .fakes import make_context


def test_short_evidence_is_kept_as_is() -> None:
    items = [evidence("Record", "v=spf1 -all"), evidence("Count", 3)]
    assert bounded_evidence(items) == items


def test_long_evidence_lists_end_with_a_count() -> None:
    items = [evidence(f"Record {i}", "x") for i in range(5000)]
    bounded = bounded_evidence(items)
    assert len(bounded) == MAX_EVIDENCE
    assert bounded[-2].label == f"Record {MAX_EVIDENCE - 2}"
    assert (bounded[-1].label, bounded[-1].value) == (
        "Not shown",
        f"{5000 - MAX_EVIDENCE + 1} more evidence items",
    )


def test_labels_and_values_are_clipped() -> None:
    [item] = bounded_evidence([evidence("L" * 500, "v" * 5000)])
    assert (len(item.label), len(item.value)) == (100, 300)
    assert item.value.endswith("...")


async def test_run_check_bounds_what_a_check_returns() -> None:
    async def noisy(ctx: ScanContext) -> Outcome:
        return Outcome(Status.PASS, "s" * 2000, [evidence("Policy", "p" * 1000)] * 1000)

    check = Check("headers.noisy", "Noisy", Category.HEADERS, 5, noisy)
    result = await run_check(check, make_context())
    assert len(result.evidence) == MAX_EVIDENCE
    assert len(result.summary) == 500
    assert len(result.model_dump_json()) < 10_000


@pytest.mark.parametrize(
    ("url", "shown"),
    [
        ("https://example.com/", "https://example.com/"),
        ("https://www.example.com/en/about", "https://www.example.com/en/about"),
        # Session ids, tokens and credentials never reach a cached report.
        ("https://example.com/;jsessionid=8F3A2B9C41D7", "https://example.com/;..."),
        ("https://example.com/app;sid=1/home", "https://example.com/app;.../home"),
        ("https://sso.example.net/login?state=abc&code=xyz", "https://sso.example.net/login?..."),
        ("https://example.com/#access_token=abc", "https://example.com/?..."),
        ("https://user:secret@example.com/", "https://example.com/"),
        ("http://example.com:8080/x", "http://example.com:8080/x"),
        ("/relative?token=abc", "/relative"),
    ],
)
def test_redact_url(url: str, shown: str) -> None:
    assert redact_url(url) == shown
