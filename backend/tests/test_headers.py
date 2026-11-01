"""HTTP security header checks: pure parsers first, then the checks on a fake home page."""

from dataclasses import replace

import pytest

from webriskaudit.checks.base import run_check
from webriskaudit.checks.headers import (
    CHECKS,
    Hsts,
    ScriptIssue,
    evaluate_clickjacking,
    evaluate_content_type_options,
    evaluate_csp,
    evaluate_deprecated_headers,
    evaluate_hsts,
    evaluate_permissions_policy,
    evaluate_referrer_policy,
    evaluate_server_disclosure,
    find_meta_csp,
    has_version,
    meta_csp_policy,
    parse_csp,
    parse_hsts,
    parse_permissions_policy,
    resolve_referrer_policy,
    script_source_issues,
    split_header_values,
)
from webriskaudit.models import Category, CheckResult, Status
from webriskaudit.net.types import FetchError, FetchErrorReason, HttpResponse

from .fakes import FakeFetcher, make_context, response

URL = "https://example.com/"
Headers = list[tuple[str, str]]


def page(headers: Headers, body: str = "", url: str = URL) -> HttpResponse:
    return response(url, headers=headers, body=body)


def labels(headers: Headers, body: str = "") -> dict[str, str]:
    """Evidence of the CSP check as a dict, for spot checks."""
    return {e.label: e.value for e in evaluate_csp(page(headers, body)).evidence}


def test_split_header_values_keeps_quoted_commas() -> None:
    assert split_header_values(['a, "b, c" ,', " d"]) == ["a", '"b, c"', "d"]


# --- Strict-Transport-Security -----------------------------------------------

HSTS = "Strict-Transport-Security"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=31536000", Hsts(31536000)),
        ('max-age="31536000"', Hsts(31536000)),
        ("MAX-AGE=600; INCLUDESUBDOMAINS; Preload", Hsts(600, True, True)),
        (" max-age = 300 ;; includeSubDomains ; ", Hsts(300, include_subdomains=True)),
        ("max-age=0", Hsts(0)),
        ("max-age=63072000; includeSubDomains; future=x", Hsts(63072000, True)),
        ('max-age=1; note="a;b, c"', Hsts(1)),
    ],
)
def test_parse_hsts(value: str, expected: Hsts) -> None:
    assert parse_hsts(value) == expected


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("", "max-age directive is missing"),
        ("includeSubDomains; preload", "max-age directive is missing"),
        ("max-age=abc", "not a number"),
        ("max-age=-1", "not a number"),
        ("max-age", "not a number"),
        ('max-age="1 2"', "not a number"),
        ("max-age=", "malformed"),
        ('max-age="123', "malformed"),
        ("max age=1", "malformed"),
        ("max-age=1; max-age=2", "appears more than once"),
        ("max-age=1; MAX-AGE=1", "appears more than once"),
        ("max-age=31536000, includeSubDomains", "commas instead of semicolons"),
        ("max-age=31536000; includeSubDomains=yes", "does not take a value"),
    ],
)
def test_parse_hsts_rejects_values_browsers_ignore(value: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        parse_hsts(value)


@pytest.mark.parametrize(
    ("headers", "status", "summary"),
    [
        (
            [(HSTS, "max-age=63072000; includeSubDomains; preload")],
            Status.PASS,
            "enabled for 730 days, including subdomains",
        ),
        ([(HSTS, 'max-age="31536000"')], Status.PASS, "enabled for 365 days."),
        ([(HSTS, "max-age=15552000")], Status.PASS, "180 days"),
        ([(HSTS, "max-age=7776000")], Status.WARN, "only 90 days"),
        ([(HSTS, "max-age=300")], Status.WARN, "less than a day"),
        ([(HSTS, "max-age=0")], Status.FAIL, "max-age=0"),
        ([(HSTS, "includeSubDomains")], Status.FAIL, "invalid (the required max-age"),
        ([], Status.FAIL, "No Strict-Transport-Security header"),
        # Only the first header counts (RFC 6797 section 8.1).
        ([(HSTS, "max-age=0"), (HSTS, "max-age=31536000")], Status.FAIL, "max-age=0"),
        ([(HSTS, "max-age=31536000"), (HSTS, "max-age=0")], Status.PASS, "365 days"),
    ],
)
def test_evaluate_hsts(headers: Headers, status: Status, summary: str) -> None:
    outcome = evaluate_hsts(page(headers))
    assert outcome.status is status
    assert summary in outcome.summary
    assert (outcome.remediation is None) == (status is Status.PASS)


def test_hsts_evidence_notes_duplicate_headers() -> None:
    outcome = evaluate_hsts(page([(HSTS, "max-age=31536000; preload"), (HSTS, "max-age=1")]))
    evidence = {e.label: e.value for e in outcome.evidence}
    assert evidence["max-age"] == "31536000 seconds (365 days)"
    assert evidence["includeSubDomains"] == "no"
    assert evidence["preload"] == "yes"
    assert "2 Strict-Transport-Security headers" in evidence["Note"]


def redirected(final: str, final_headers: Headers, hops: list[tuple[str, Headers]]) -> HttpResponse:
    """A final response after the given redirect responses, as GuardedFetcher records them."""
    history = tuple(response(url, 301, headers=headers) for url, headers in hops)
    return replace(
        response(final, headers=final_headers),
        redirects=tuple(hop.url for hop in history),
        history=history,
    )


WWW = "https://www.example.com/"
YEAR = "max-age=31536000; includeSubDomains"


def test_hsts_of_another_host_does_not_count_for_the_scanned_host() -> None:
    # HSTS is per host: www's policy does not cover the apex (RFC 6797 section 8.1).
    outcome = evaluate_hsts(redirected(WWW, [(HSTS, YEAR)], [(URL, [])]))
    assert outcome.status is Status.FAIL
    assert outcome.summary == (
        "example.com redirects to www.example.com without sending Strict-Transport-Security; "
        "HSTS applies per host, so browsers do not remember HTTPS for example.com."
    )
    evidence = {e.label: e.value for e in outcome.evidence}
    assert evidence["URL checked"] == URL
    assert evidence["Redirects to"] == WWW
    assert evidence["Policy of www.example.com"] == YEAR


def test_hsts_sent_on_the_scanned_hosts_redirect_counts() -> None:
    outcome = evaluate_hsts(redirected(WWW, [], [(URL, [(HSTS, YEAR)])]))
    assert (outcome.status, outcome.summary) == (
        Status.PASS,
        "HSTS is enabled for 365 days, including subdomains.",
    )
    assert {e.label: e.value for e in outcome.evidence}["URL checked"] == URL


def test_hsts_on_a_later_response_of_the_same_host_counts() -> None:
    final = "https://example.com/en/"
    outcome = evaluate_hsts(redirected(final, [(HSTS, YEAR)], [(URL, [])]))
    assert outcome.status is Status.PASS
    assert {e.label: e.value for e in outcome.evidence}["URL checked"] == final


def test_hsts_last_valid_header_of_the_host_wins() -> None:
    final = "https://example.com/en/"
    later_invalid = redirected(final, [(HSTS, "max-age=x")], [(URL, [(HSTS, YEAR)])])
    assert evaluate_hsts(later_invalid).status is Status.PASS
    later_zero = redirected(final, [(HSTS, "max-age=0")], [(URL, [(HSTS, YEAR)])])
    assert evaluate_hsts(later_zero).status is Status.FAIL


def test_hsts_fails_when_the_home_page_ends_on_plain_http() -> None:
    final = response("http://example.com/", headers={HSTS: "max-age=31536000"}, redirects=(URL,))
    outcome = evaluate_hsts(final)
    assert outcome.status is Status.FAIL
    assert "plain HTTP" in outcome.summary


# --- Content-Security-Policy -------------------------------------------------

CSP = "Content-Security-Policy"


def test_parse_csp_reads_every_header_and_comma_separated_policy() -> None:
    policies = parse_csp(
        [
            "default-src 'self'; Script-Src 'none' https://a.example; script-src *",
            "frame-ancestors 'none', img-src\tdata:",
            " ; , ",
        ]
    )
    assert policies == [
        {"default-src": ("'self'",), "script-src": ("'none'", "https://a.example")},
        {"frame-ancestors": ("'none'",)},
        {"img-src": ("data:",)},
    ]


def test_meta_csp_is_read_from_the_head_only() -> None:
    html = (
        "<html><head><META HTTP-EQUIV='content-security-policy' "
        "content=\"script-src 'self'; frame-ancestors 'none'\"/></head>"
        '<body><meta http-equiv="Content-Security-Policy" content="script-src *"></body></html>'
    )
    assert find_meta_csp(html) == ["script-src 'self'; frame-ancestors 'none'"]
    assert meta_csp_policy(find_meta_csp(html)[0]) == {"script-src": ("'self'",)}


INLINE, EVAL = ScriptIssue.UNSAFE_INLINE, ScriptIssue.UNSAFE_EVAL
ANY_HOST, DATA = ScriptIssue.ANY_HOST, ScriptIssue.DATA_URL


@pytest.mark.parametrize(
    ("sources", "issues"),
    [
        ("'self'", []),
        ("'self' 'unsafe-inline'", [INLINE]),
        ("'self' 'UNSAFE-INLINE'", [INLINE]),
        ("'nonce-r4nd0m' 'unsafe-inline'", []),
        ("'sha256-B2yPHKaXnvFWtRChIbabYmUBFZdVfKKXHbWtWidDVF8=' 'unsafe-inline'", []),
        ("'nonce-' 'unsafe-inline'", [INLINE]),
        ("'strict-dynamic' 'unsafe-inline'", []),
        ("'nonce-r4nd0m' 'strict-dynamic' https: http: * data: 'unsafe-inline'", []),
        ("'self' 'unsafe-eval'", [EVAL]),
        ("'nonce-r4nd0m' 'strict-dynamic' 'unsafe-eval'", [EVAL]),
        ("*", [ANY_HOST]),
        ("https:", [ANY_HOST]),
        ("HTTP:", [ANY_HOST]),
        ("https://*", [ANY_HOST]),
        ("data:", [DATA]),
        ("https://cdn.example.com *.example.com blob: 'wasm-unsafe-eval'", []),
        ("data: * 'unsafe-eval' 'unsafe-inline'", [INLINE, EVAL, ANY_HOST, DATA]),
    ],
)
def test_script_source_issues(sources: str, issues: list[ScriptIssue]) -> None:
    assert script_source_issues(sources.split()) == issues


@pytest.mark.parametrize(
    ("headers", "body", "status", "summary"),
    [
        ([], "", Status.FAIL, "No Content Security Policy is enforced"),
        (
            [("Content-Security-Policy-Report-Only", "default-src 'self'")],
            "",
            Status.WARN,
            "report-only",
        ),
        (
            [(CSP, " "), ("Content-Security-Policy-Report-Only", "script-src 'self'")],
            "",
            Status.WARN,
            "report-only",
        ),
        ([(CSP, "default-src 'self'")], "", Status.PASS, "without unsafe sources"),
        ([(CSP, "default-src *; script-src 'self'")], "", Status.PASS, "without unsafe"),
        ([(CSP, "default-src 'self' 'unsafe-inline'")], "", Status.WARN, "'unsafe-inline'"),
        ([(CSP, "script-src 'nonce-abc123' 'unsafe-inline'")], "", Status.PASS, "without"),
        (
            [(CSP, "script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'")],
            "",
            Status.PASS,
            "without unsafe sources",
        ),
        ([(CSP, "script-src 'self' 'unsafe-eval'")], "", Status.WARN, "'unsafe-eval'"),
        ([(CSP, "frame-ancestors 'none'")], "", Status.WARN, "does not restrict scripts"),
        # A script must pass every policy: one strict policy is enough.
        ([(CSP, "default-src *"), (CSP, "script-src 'self'")], "", Status.PASS, "without"),
        ([(CSP, "default-src * 'unsafe-inline', script-src 'self'")], "", Status.PASS, "without"),
        (
            [(CSP, "script-src 'self' 'unsafe-inline'"), (CSP, "script-src 'unsafe-eval'")],
            "",
            Status.PASS,
            "without",
        ),
        ([(CSP, "script-src https:"), (CSP, "script-src *")], "", Status.WARN, "any host"),
        # CSP3 fallbacks: elements use script-src-elem, event handlers script-src-attr.
        (
            [(CSP, "default-src 'self'; script-src-elem 'self' 'unsafe-inline'")],
            "",
            Status.WARN,
            "'unsafe-inline'",
        ),
        (
            [(CSP, "default-src 'self'; script-src-attr 'unsafe-inline'")],
            "",
            Status.WARN,
            "'unsafe-inline'",
        ),
        ([(CSP, "default-src 'self'; script-src-elem *")], "", Status.WARN, "any host"),
        (
            [
                (
                    CSP,
                    "script-src 'self' 'unsafe-inline'; script-src-elem 'self'; "
                    "script-src-attr 'none'",
                )
            ],
            "",
            Status.PASS,
            "without unsafe sources",
        ),
        # eval() is governed by script-src only, not by script-src-elem.
        (
            [(CSP, "script-src 'self' 'unsafe-eval'; script-src-elem 'self'")],
            "",
            Status.WARN,
            "'unsafe-eval'",
        ),
        # script-src-elem alone leaves event handlers and eval() unrestricted.
        ([(CSP, "script-src-elem 'self'")], "", Status.WARN, "'unsafe-inline' and 'unsafe-eval'"),
        (
            [(CSP, "script-src-elem 'self'"), (CSP, "default-src 'self'")],
            "",
            Status.PASS,
            "without unsafe sources",
        ),
        (
            [],
            "<head><meta http-equiv=Content-Security-Policy content=\"script-src 'self'\"></head>",
            Status.PASS,
            "without unsafe sources",
        ),
        (
            [],
            '<head></head><body><meta http-equiv=Content-Security-Policy content="script-src '
            "'self'\"></body>",
            Status.FAIL,
            "No Content Security Policy",
        ),
    ],
)
def test_evaluate_csp(headers: Headers, body: str, status: Status, summary: str) -> None:
    outcome = evaluate_csp(page(headers, body))
    assert outcome.status is status
    assert summary in outcome.summary
    assert (outcome.remediation is None) == (status is Status.PASS)


def test_csp_evidence_shows_policy_sources_and_issues() -> None:
    evidence = labels([(CSP, "default-src 'self'; script-src 'self' 'unsafe-inline' data:")])
    assert evidence["Policy"] == "default-src 'self'; script-src 'self' 'unsafe-inline' data:"
    assert evidence["Script sources"] == "script-src 'self' 'unsafe-inline' data:"
    assert (
        "'unsafe-inline' lets injected inline scripts or event handlers run" in evidence["Issues"]
    )
    assert "data: URLs" in evidence["Issues"]


def test_csp_evidence_lists_element_and_attribute_sources() -> None:
    evidence = labels([(CSP, "default-src 'self'; script-src-elem 'self' 'unsafe-inline'")])
    assert evidence["Script sources"] == (
        "script-src-elem 'self' 'unsafe-inline'; default-src 'self'"
    )


def test_csp_evidence_is_bounded_for_hostile_pages() -> None:
    meta = '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'">'
    many = ", ".join(["script-src 'self'"] * 5000)
    outcome = evaluate_csp(page([(CSP, many)], meta * 10_000))
    assert outcome.status is Status.PASS
    shown = {e.label: e.value for e in outcome.evidence}
    assert shown["More meta policies"] == "9997 not shown"
    assert shown["More script restrictions"] == "14997 not shown"  # 5000 + 10000 policies
    assert len(outcome.evidence) <= 12


def test_csp_evidence_is_truncated() -> None:
    evidence = labels([(CSP, "script-src 'self' " + "https://a.example " * 50)])
    assert len(evidence["Policy"]) == 300
    assert evidence["Policy"].endswith("...")


# --- Clickjacking ------------------------------------------------------------

XFO = "X-Frame-Options"


@pytest.mark.parametrize(
    ("headers", "body", "status", "summary"),
    [
        ([(CSP, "frame-ancestors 'self'")], "", Status.PASS, "frame-ancestors limits"),
        ([(CSP, "default-src 'self'; frame-ancestors")], "", Status.PASS, "('none')"),
        # frame-ancestors overrides X-Frame-Options in both directions.
        ([(CSP, "frame-ancestors *"), (XFO, "DENY")], "", Status.FAIL, "any site"),
        (
            [(CSP, "frame-ancestors 'none'"), (XFO, "ALLOW-FROM https://a.example")],
            "",
            Status.PASS,
            "'none'",
        ),
        ([(CSP, "frame-ancestors 'self' https:")], "", Status.FAIL, "any site"),
        ([(CSP, "frame-ancestors *"), (CSP, "frame-ancestors 'self'")], "", Status.PASS, "'self'"),
        ([(CSP, "default-src 'self'"), (XFO, "DENY")], "", Status.PASS, "DENY"),
        ([(XFO, " sameorigin ")], "", Status.PASS, "SAMEORIGIN"),
        ([(XFO, "DENY, SAMEORIGIN")], "", Status.PASS, "DENY"),
        ([(XFO, "ALLOW-FROM https://partner.example")], "", Status.WARN, "ALLOW-FROM"),
        ([(XFO, "ALLOWALL")], "", Status.FAIL, "unrecognized"),
        ([], "", Status.FAIL, "Neither"),
        # frame-ancestors is ignored in a <meta> policy.
        (
            [],
            "<head><meta http-equiv=Content-Security-Policy content=\"frame-ancestors 'none'\">",
            Status.FAIL,
            "Neither",
        ),
    ],
)
def test_evaluate_clickjacking(headers: Headers, body: str, status: Status, summary: str) -> None:
    outcome = evaluate_clickjacking(page(headers, body))
    assert outcome.status is status
    assert summary in outcome.summary


def test_clickjacking_evidence_marks_ignored_x_frame_options() -> None:
    outcome = evaluate_clickjacking(page([(CSP, "frame-ancestors 'self'"), (XFO, "DENY")]))
    evidence = {e.label: e.value for e in outcome.evidence}
    assert evidence == {
        "frame-ancestors": "'self'",
        "X-Frame-Options": "DENY (ignored because frame-ancestors is set)",
    }


# --- X-Content-Type-Options --------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ([("X-Content-Type-Options", "nosniff")], Status.PASS),
        ([("X-Content-Type-Options", " NoSniff ")], Status.PASS),
        ([("X-Content-Type-Options", "nosniff, nosniff")], Status.PASS),
        ([("X-Content-Type-Options", "sniff, nosniff")], Status.FAIL),
        ([("X-Content-Type-Options", "no-sniff")], Status.FAIL),
        ([], Status.FAIL),
    ],
)
def test_evaluate_content_type_options(headers: Headers, status: Status) -> None:
    assert evaluate_content_type_options(page(headers)).status is status


# --- Referrer-Policy ---------------------------------------------------------


@pytest.mark.parametrize(
    ("values", "policy"),
    [
        (["no-referrer, unsafe-url"], "unsafe-url"),
        (["unsafe-url, no-referrer"], "no-referrer"),
        (["no-referrer, made-up-policy"], "no-referrer"),
        (["no-referrer", "Strict-Origin-When-Cross-Origin"], "strict-origin-when-cross-origin"),
        (["never"], None),
        ([""], None),
        ([], None),
    ],
)
def test_resolve_referrer_policy(values: list[str], policy: str | None) -> None:
    assert resolve_referrer_policy(values) == policy


@pytest.mark.parametrize(
    ("headers", "status", "summary"),
    [
        ([("Referrer-Policy", "strict-origin-when-cross-origin")], Status.PASS, "is strict-origin"),
        ([("Referrer-Policy", "no-referrer")], Status.PASS, "no-referrer"),
        ([("Referrer-Policy", "same-origin")], Status.PASS, "same-origin"),
        ([("Referrer-Policy", "no-referrer-when-downgrade")], Status.WARN, "full URLs"),
        ([("Referrer-Policy", "origin")], Status.WARN, "origin"),
        ([("Referrer-Policy", "origin-when-cross-origin")], Status.WARN, "plain HTTP"),
        ([("Referrer-Policy", "no-referrer, unsafe-url")], Status.FAIL, "unsafe-url"),
        ([("Referrer-Policy", "unsafe-url, strict-origin")], Status.PASS, "strict-origin"),
        ([], Status.WARN, "No Referrer-Policy header"),
        ([("Referrer-Policy", "nonsense")], Status.WARN, "no recognized value"),
    ],
)
def test_evaluate_referrer_policy(headers: Headers, status: Status, summary: str) -> None:
    outcome = evaluate_referrer_policy(page(headers))
    assert outcome.status is status
    assert summary in outcome.summary


# --- Server version disclosure -----------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("nginx", False),
        ("nginx/1.24.0", True),
        ("cloudflare", False),
        ("Express", False),
        ("PHP/8.2.1", True),
        ("Next.js", False),
        ("ECS (dcb/7F84)", False),
        ("4.0.30319", True),
    ],
)
def test_has_version(value: str, expected: bool) -> None:
    assert has_version(value) is expected


@pytest.mark.parametrize(
    ("headers", "status", "summary"),
    [
        ([("Server", "nginx")], Status.PASS, "No software version"),
        ([("Server", "cloudflare")], Status.PASS, "No software version"),
        ([], Status.PASS, "No software version"),
        ([("Server", "nginx/1.24.0")], Status.FAIL, "The Server header reveals"),
        ([("Server", "Apache/2.4.58 (Ubuntu)")], Status.FAIL, "Server header"),
        ([("X-Powered-By", "PHP/8.2.1")], Status.FAIL, "The X-Powered-By header reveals"),
        (
            [
                ("Server", "Microsoft-IIS/10.0"),
                ("X-Powered-By", "ASP.NET"),
                ("X-AspNet-Version", "4.0.30319"),
            ],
            Status.FAIL,
            "The Server and X-AspNet-Version headers reveal",
        ),
        ([("X-Powered-By", "Express")], Status.WARN, "(Express) without a version"),
        ([("Server", "nginx"), ("X-Powered-By", "Next.js")], Status.WARN, "Next.js"),
    ],
)
def test_evaluate_server_disclosure(headers: Headers, status: Status, summary: str) -> None:
    outcome = evaluate_server_disclosure(page(headers))
    assert outcome.status is status
    assert summary in outcome.summary
    assert len(outcome.evidence) == len(headers)


# --- Permissions-Policy ------------------------------------------------------


def test_parse_permissions_policy() -> None:
    features = parse_permissions_policy(
        [
            'geolocation=(), camera=(self "https://a.example,b"), fullscreen=*',
            "usb=();report-to=x",
            "bare, geolocation=(self)",
        ]
    )
    assert features == {
        "geolocation": "(self)",
        "camera": '(self "https://a.example,b")',
        "fullscreen": "*",
        "usb": "()",
    }


@pytest.mark.parametrize(
    ("headers", "summary"),
    [
        ([], "Permissions-Policy is not set."),
        ([("Feature-Policy", "camera 'none'")], "only the older Feature-Policy header"),
        (
            [("Permissions-Policy", "camera=(), microphone=(), geolocation=(self), fullscreen=*")],
            "restricts 3 features: camera, microphone, geolocation.",
        ),
        ([("Permissions-Policy", "camera=()")], "restricts 1 feature: camera."),
        (
            [("Permissions-Policy", ", ".join(f"f{n}=()" for n in range(8)))],
            "restricts 8 features: f0, f1, f2, f3, f4 and 3 more.",
        ),
        ([("Permissions-Policy", "fullscreen=*")], "restricts no features"),
    ],
)
def test_evaluate_permissions_policy(headers: Headers, summary: str) -> None:
    outcome = evaluate_permissions_policy(page(headers))
    assert outcome.status is Status.INFO
    assert summary in outcome.summary


def test_permissions_policy_evidence_groups_features() -> None:
    outcome = evaluate_permissions_policy(
        page([("Permissions-Policy", "camera=(), geolocation=(self), fullscreen=*")])
    )
    evidence = {e.label: e.value for e in outcome.evidence}
    assert evidence["Disabled"] == "camera"
    assert evidence["Limited to listed origins"] == "geolocation"
    assert evidence["Allowed for all origins"] == "fullscreen"


# --- Deprecated headers ------------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "listed"),
    [
        ([], []),
        ([("X-XSS-Protection", "0")], []),
        ([("X-XSS-Protection", "1; mode=block")], ["X-XSS-Protection"]),
        (
            [("Expect-CT", "max-age=86400, enforce"), ("Public-Key-Pins", 'pin-sha256="x"')],
            ["Expect-CT", "Public-Key-Pins"],
        ),
    ],
)
def test_evaluate_deprecated_headers(headers: Headers, listed: list[str]) -> None:
    outcome = evaluate_deprecated_headers(page(headers))
    assert outcome.status is Status.INFO
    assert [e.label for e in outcome.evidence] == listed
    if listed:
        assert outcome.summary.startswith("Deprecated security headers are sent")
        assert outcome.remediation is not None
        assert all(name in outcome.remediation for name in listed)
    else:
        assert outcome.summary == "No deprecated security headers are sent."


# --- Checks on a fake home page ----------------------------------------------

GOOD_HEADERS: Headers = [
    (HSTS, "max-age=63072000; includeSubDomains; preload"),
    (CSP, "script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; frame-ancestors 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Server", "nginx"),
    ("Permissions-Policy", "camera=(), microphone=()"),
]


async def run_all(
    fetcher: FakeFetcher, addresses: tuple[str, ...] = ("93.184.215.14",)
) -> dict[str, CheckResult]:
    ctx = make_context(fetcher=fetcher, addresses=addresses)
    return {check.id: await run_check(check, ctx) for check in CHECKS}


def test_checks_match_the_specification() -> None:
    assert [(c.id, c.category, c.weight) for c in CHECKS] == [
        ("transport.hsts", Category.TRANSPORT, 10),
        ("headers.csp", Category.HEADERS, 10),
        ("headers.clickjacking", Category.HEADERS, 5),
        ("headers.content_type_options", Category.HEADERS, 5),
        ("headers.referrer_policy", Category.HEADERS, 5),
        ("headers.server_disclosure", Category.HEADERS, 5),
        ("info.permissions_policy", Category.INFO, 0),
        ("info.deprecated_headers", Category.INFO, 0),
    ]
    for check in CHECKS:
        assert check.references
        assert all(ref.url.startswith("https://") for ref in check.references)


async def test_well_configured_home_page_passes() -> None:
    fetcher = FakeFetcher({URL: response(URL, headers=GOOD_HEADERS)})
    results = await run_all(fetcher)
    assert {id_: r.status for id_, r in results.items()} == {
        "transport.hsts": Status.PASS,
        "headers.csp": Status.PASS,
        "headers.clickjacking": Status.PASS,
        "headers.content_type_options": Status.PASS,
        "headers.referrer_policy": Status.PASS,
        "headers.server_disclosure": Status.PASS,
        "info.permissions_policy": Status.INFO,
        "info.deprecated_headers": Status.INFO,
    }
    assert sum(r.points for r in results.values()) == 40
    assert fetcher.requests == [URL]


async def test_bare_home_page_fails_the_scored_checks() -> None:
    results = await run_all(FakeFetcher({URL: response(URL)}))
    assert {id_: r.status for id_, r in results.items()} == {
        "transport.hsts": Status.FAIL,
        "headers.csp": Status.FAIL,
        "headers.clickjacking": Status.FAIL,
        "headers.content_type_options": Status.FAIL,
        "headers.referrer_policy": Status.WARN,
        "headers.server_disclosure": Status.PASS,
        "info.permissions_policy": Status.INFO,
        "info.deprecated_headers": Status.INFO,
    }


@pytest.mark.parametrize(
    ("reason", "detail"),
    [
        (FetchErrorReason.TIMEOUT, "timed out"),
        (FetchErrorReason.TLS, "TLS handshake"),
        (FetchErrorReason.BLOCKED, "does not visit"),
    ],
)
async def test_fetch_error_makes_every_check_inconclusive(
    reason: FetchErrorReason, detail: str
) -> None:
    fetcher = FakeFetcher({URL: FetchError(reason, "boom")})
    results = await run_all(fetcher)
    for result in results.values():
        assert result.status is Status.INCONCLUSIVE
        assert result.summary.startswith("The home page could not be fetched:")
        assert detail in result.summary
        assert result.points == 0
    assert fetcher.requests == [URL]


async def test_no_web_server_makes_every_check_inconclusive() -> None:
    fetcher = FakeFetcher()
    results = await run_all(fetcher, addresses=())
    assert all(r.status is Status.INCONCLUSIVE for r in results.values())
    assert "no A/AAAA record" in results["headers.csp"].summary
    assert fetcher.requests == []


async def test_hsts_check_fails_when_https_redirects_to_http() -> None:
    final = response("http://example.com/", headers=GOOD_HEADERS, redirects=(URL,))
    results = await run_all(FakeFetcher({URL: final}))
    assert results["transport.hsts"].status is Status.FAIL
    assert results["headers.csp"].status is Status.PASS
