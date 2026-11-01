"""Loading the home page for the checks that inspect its response.

The header and cookie checks share one rule set: no A/AAAA record or a failed
fetch is inconclusive, and so is a response whose headers are probably not the
site's own (a bot challenge or an HTTP error status), since a WAF block page or
a proxy error page would otherwise be scored as the site.
"""

from collections.abc import Callable

from webriskaudit.checks.base import CheckFn, Outcome, evidence, redact_url
from webriskaudit.context import ScanContext
from webriskaudit.models import Status
from webriskaudit.net.types import FetchError, FetchErrorReason, HttpResponse

NO_WEB_SERVER = Outcome(
    Status.INCONCLUSIVE, "The domain has no A/AAAA record, so there is no web server to check."
)

FETCH_FAILURES: dict[FetchErrorReason, str] = {
    FetchErrorReason.BLOCKED: "it led to an address, port or scheme the scanner does not visit",
    FetchErrorReason.TIMEOUT: "the request timed out",
    FetchErrorReason.CONNECT: "the connection was refused",
    FetchErrorReason.NETWORK: "the connection failed",
    FetchErrorReason.TLS: "the TLS handshake or certificate check failed",
    FetchErrorReason.TOO_MANY_REDIRECTS: "it redirected too many times",
    FetchErrorReason.DNS: "a redirect target did not resolve",
    FetchErrorReason.PROTOCOL: "the server sent a malformed response",
}

_ERROR_LIMIT = 300


def fetch_failed(error: FetchError) -> Outcome:
    """Inconclusive outcome for a home page that could not be fetched."""
    message = str(error)
    if len(message) > _ERROR_LIMIT:
        message = message[: _ERROR_LIMIT - 3] + "..."
    return Outcome(
        Status.INCONCLUSIVE,
        f"The home page could not be fetched: {FETCH_FAILURES[error.reason]}.",
        [evidence("Error", message)],
    )


# Interstitials that WAFs serve instead of the page, with a 2xx status:
# Cloudflare (cf-mitigated: challenge) and AWS WAF Challenge and CAPTCHA
# (x-amzn-waf-action: challenge with 202, or captcha with 405).
_CHALLENGE_MARKERS: dict[str, frozenset[str]] = {
    "cf-mitigated": frozenset({"challenge"}),
    "x-amzn-waf-action": frozenset({"challenge", "captcha"}),
}


def is_bot_challenge(page: HttpResponse) -> bool:
    """True for a WAF's bot challenge page (Cloudflare or AWS WAF markers)."""
    return any(
        (page.header(name) or "").strip().lower() in values
        for name, values in _CHALLENGE_MARKERS.items()
    )


def unusable_page(page: HttpResponse) -> Outcome | None:
    """Inconclusive outcome when the response's headers are probably not the site's own."""
    found = [evidence("Status", page.status), evidence("URL checked", redact_url(page.url))]
    if is_bot_challenge(page):
        return Outcome(
            Status.INCONCLUSIVE,
            "The home page answered with a bot challenge, so its headers are not the site's own.",
            found,
        )
    if page.status >= 400:
        return Outcome(
            Status.INCONCLUSIVE,
            f"The home page answered with HTTP {page.status}, so its headers may come from an "
            "error or block page rather than the site.",
            found,
        )
    return None


async def load_homepage(
    ctx: ScanContext, *, require_success: bool = True
) -> HttpResponse | Outcome:
    """The home page response, or the inconclusive outcome to report instead.

    With ``require_success`` (the default), a bot challenge or an HTTP error
    status also gives an outcome instead of the page.
    """
    if not ctx.addresses:
        return NO_WEB_SERVER
    try:
        page = await ctx.homepage()
    except FetchError as error:
        return fetch_failed(error)
    if require_success and (problem := unusable_page(page)) is not None:
        return problem
    return page


def on_homepage(
    evaluate: Callable[[HttpResponse], Outcome], *, require_success: bool = True
) -> CheckFn:
    """A check function that applies ``evaluate`` to the home page response."""

    async def run(ctx: ScanContext) -> Outcome:
        page = await load_homepage(ctx, require_success=require_success)
        return page if isinstance(page, Outcome) else evaluate(page)

    return run
