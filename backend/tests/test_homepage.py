"""Shared home page handling of the header, cookie and site checks."""

import pytest

from webriskaudit.checks import headers, site
from webriskaudit.checks.base import run_check
from webriskaudit.checks.homepage import fetch_failed, unusable_page
from webriskaudit.models import CheckResult, Status
from webriskaudit.net.types import FetchError, FetchErrorReason, HttpResponse

from .fakes import FakeFetcher, make_context, response

HOME = "https://example.com/"
HOMEPAGE_CHECKS = (*headers.CHECKS, *site.CHECKS)


async def run_all(
    fetcher: FakeFetcher, addresses: tuple[str, ...] = ("93.184.215.14",)
) -> dict[str, CheckResult]:
    ctx = make_context(fetcher=fetcher, addresses=addresses)
    return {check.id: await run_check(check, ctx) for check in HOMEPAGE_CHECKS}


@pytest.mark.parametrize(
    ("page", "summary"),
    [
        (response(HOME, status=403), "The home page answered with HTTP 403"),
        (response(HOME, status=503), "The home page answered with HTTP 503"),
        (
            response(HOME, headers={"cf-mitigated": "challenge"}),
            "The home page answered with a bot challenge",
        ),
        # AWS WAF Challenge: an interstitial with 202 Accepted.
        (
            response(HOME, status=202, headers={"x-amzn-waf-action": "challenge"}),
            "The home page answered with a bot challenge",
        ),
        (
            response(HOME, status=405, headers={"x-amzn-waf-action": "captcha"}),
            "The home page answered with a bot challenge",
        ),
    ],
)
def test_error_and_challenge_pages_are_unusable(page: HttpResponse, summary: str) -> None:
    outcome = unusable_page(page)
    assert outcome is not None
    assert outcome.status is Status.INCONCLUSIVE
    assert outcome.summary.startswith(summary)


@pytest.mark.parametrize("status", [200, 204, 304])
def test_successful_pages_are_usable(status: int) -> None:
    assert unusable_page(response(HOME, status=status)) is None


async def test_aws_waf_challenge_headers_are_not_scored() -> None:
    page = response(HOME, status=202, headers={"x-amzn-waf-action": "challenge"})
    results = await run_all(FakeFetcher({HOME: page}))
    for check_id in ("transport.hsts", "headers.csp", "headers.clickjacking"):
        assert results[check_id].status is Status.INCONCLUSIVE


def test_unusable_page_evidence_hides_the_query_string() -> None:
    outcome = unusable_page(response("https://example.com/login?token=abc", status=403))
    assert outcome is not None
    assert {e.label: e.value for e in outcome.evidence}["URL checked"] == (
        "https://example.com/login?..."
    )


async def test_error_page_headers_are_not_scored_but_the_cdn_is_reported() -> None:
    page = response(
        HOME,
        status=403,
        headers={"Server": "cloudflare", "CF-RAY": "8a1b2c3d4e5f-FRA", "Set-Cookie": "a=1"},
    )
    results = await run_all(FakeFetcher({HOME: page}))
    assert results.pop("info.cdn").status is Status.INFO
    assert all(r.status is Status.INCONCLUSIVE for r in results.values())
    assert results["headers.csp"].summary.startswith("The home page answered with HTTP 403")
    assert results["headers.cookies"].summary == results["headers.csp"].summary


async def test_fetch_failure_reads_the_same_in_every_check() -> None:
    error = FetchError(FetchErrorReason.TIMEOUT, "example.com did not respond in time")
    results = await run_all(FakeFetcher({HOME: error}))
    summaries = {r.summary for r in results.values()}
    assert summaries == {"The home page could not be fetched: the request timed out."}
    assert all(r.evidence[0].value == str(error) for r in results.values())


async def test_no_web_server_makes_every_home_page_check_inconclusive() -> None:
    fetcher = FakeFetcher()
    results = await run_all(fetcher, addresses=())
    assert all(r.status is Status.INCONCLUSIVE for r in results.values())
    assert all("no A/AAAA record" in r.summary for r in results.values())
    assert fetcher.requests == []


@pytest.mark.parametrize("reason", list(FetchErrorReason))
def test_every_fetch_error_reason_has_a_description(reason: FetchErrorReason) -> None:
    outcome = fetch_failed(FetchError(reason, "x" * 500))
    assert outcome.status is Status.INCONCLUSIVE
    assert len(outcome.evidence[0].value) == 300
