# Turkish test strings use the dotless i on purpose.
# ruff: noqa: RUF001
from dataclasses import replace

import pytest

from webriskaudit.checks.base import Outcome, run_check
from webriskaudit.checks.site import (
    CDN,
    CHECKS,
    COOKIES,
    MAX_COOKIES_SHOWN,
    PRIVACY_POLICY,
    CookieIssue,
    SetCookie,
    cookie_issues,
    detect_cdns,
    evaluate_cdn,
    evaluate_cookies,
    evaluate_privacy_policy,
    find_privacy_links,
    fold_text,
    is_session_cookie,
    parse_set_cookie,
)
from webriskaudit.models import Category, Evidence, Status
from webriskaudit.net.types import FetchError, FetchErrorReason, HttpResponse

from .fakes import FakeFetcher, make_context, response

HOME = "https://example.com/"
COOKIE_VALUE = "s3cr3t-v4lue"


def labels(items: list[Evidence]) -> dict[str, str]:
    return {item.label: item.value for item in items}


def rendered(outcome: Outcome) -> str:
    parts = [outcome.summary, outcome.remediation or ""]
    parts += [f"{item.label} {item.value}" for item in outcome.evidence]
    return "\n".join(parts)


def test_registry_matches_the_specification() -> None:
    assert [(c.id, c.title, c.category, c.weight) for c in CHECKS] == [
        ("headers.cookies", "Cookie security", Category.HEADERS, 5),
        ("info.cdn", "CDN / edge network", Category.INFO, 0),
        ("info.privacy_policy", "Privacy policy link", Category.INFO, 0),
    ]


# --- Set-Cookie parsing ----------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("id=1", SetCookie("id")),
        (
            "id=1; Secure; HttpOnly; SameSite=Strict",
            SetCookie("id", secure=True, http_only=True, same_site="Strict"),
        ),
        (
            "id=1; secure; HTTPONLY; samesite=lax",
            SetCookie("id", secure=True, http_only=True, same_site="Lax"),
        ),
        ("id=1;SECURE;SameSite=NONE", SetCookie("id", secure=True, same_site="None")),
        # Commas in Expires do not split the header.
        (
            "id=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; SameSite=Lax",
            SetCookie("id", secure=True, same_site="Lax"),
        ),
        # Quoted values; a ";" inside quotes still ends the value, as in browsers.
        ('id="a,b c"; Secure', SetCookie("id", secure=True)),
        ('id="a;b"; HttpOnly', SetCookie("id", http_only=True)),
        # The value may contain "=".
        ("id=a=b==; Secure", SetCookie("id", secure=True)),
        # The last SameSite wins; an unknown value counts as absent.
        ("id=1; SameSite=Lax; SameSite=Strict", SetCookie("id", same_site="Strict")),
        ("id=1; SameSite=Lax; SameSite=bogus", SetCookie("id")),
        ('id=1; SameSite="Lax"', SetCookie("id")),
        (
            "id=1; Domain=.Example.COM; Path=/app",
            SetCookie("id", domain="example.com", path="/app"),
        ),
        ("id=1; Domain=; Path=relative", SetCookie("id")),
        ("  __Host-sid = 1 ; Path=/ ; Secure", SetCookie("__Host-sid", secure=True, path="/")),
        # Secure takes no value, but one does not cancel it.
        ("id=1; Secure=false", SetCookie("id", secure=True)),
        # Browsers store a pair without "=" as a nameless cookie.
        ("opaque-token; Secure", SetCookie("", secure=True)),
        ("", None),
        ("=; Secure", None),
    ],
)
def test_parse_set_cookie(header: str, expected: SetCookie | None) -> None:
    assert parse_set_cookie(header) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("PHPSESSID", True),
        ("JSESSIONID", True),
        ("connect.sid", True),
        ("ASP.NET_SessionId", True),
        ("__Host-session", True),
        ("sid", True),
        ("auth_token", True),
        ("jwt", True),
        ("remember_login", True),
        ("theme", False),
        ("_ga", False),
        ("lang", False),
    ],
)
def test_is_session_cookie(name: str, expected: bool) -> None:
    assert is_session_cookie(name) is expected


@pytest.mark.parametrize(
    ("header", "issues"),
    [
        ("theme=dark; Secure; SameSite=Lax", []),
        ("session=1; Secure; HttpOnly; SameSite=Lax", []),
        ("theme=dark; SameSite=Lax", [CookieIssue.NO_SECURE]),
        ("theme=dark; SameSite=None", [CookieIssue.SAME_SITE_NONE_WITHOUT_SECURE]),
        ("theme=dark; Secure; SameSite=None", []),
        ("theme=dark; Secure", [CookieIssue.NO_SAME_SITE]),
        ("session=1; Secure; SameSite=Lax", [CookieIssue.SESSION_WITHOUT_HTTP_ONLY]),
        (
            "PHPSESSID=1",
            [
                CookieIssue.NO_SECURE,
                CookieIssue.NO_SAME_SITE,
                CookieIssue.SESSION_WITHOUT_HTTP_ONLY,
            ],
        ),
        ("__Host-id=1; Secure; Path=/; SameSite=Strict", []),
        ("__Host-id=1; Secure; SameSite=Strict", [CookieIssue.PREFIX_RULES_BROKEN]),
        (
            "__Host-id=1; Secure; Path=/; Domain=example.com; SameSite=Strict",
            [CookieIssue.PREFIX_RULES_BROKEN],
        ),
        ("__host-id=1; Secure; SameSite=Strict", [CookieIssue.PREFIX_RULES_BROKEN]),
        ("__Secure-id=1; Secure; Domain=example.com; SameSite=Lax", []),
        (
            "__Secure-id=1; SameSite=Lax",
            [CookieIssue.NO_SECURE, CookieIssue.PREFIX_RULES_BROKEN],
        ),
    ],
)
def test_cookie_issues(header: str, issues: list[CookieIssue]) -> None:
    cookie = parse_set_cookie(header)
    assert cookie is not None
    assert cookie_issues(cookie) == issues


# --- Cookie verdicts -------------------------------------------------------------


def test_no_cookies_pass() -> None:
    outcome = evaluate_cookies([])
    assert (outcome.status, outcome.summary) == (
        Status.PASS,
        "No cookies are set on the home page.",
    )


@pytest.mark.parametrize(
    ("headers", "expected", "summary"),
    [
        (
            ["theme=dark; Secure; SameSite=Lax"],
            Status.PASS,
            "The only cookie set on the home page has Secure and SameSite.",
        ),
        (
            [
                "__Host-session=1; Path=/; Secure; HttpOnly; SameSite=Lax",
                "lang=en; Secure; SameSite=Lax",
            ],
            Status.PASS,
            "All 2 cookies set on the home page have Secure and SameSite, and session cookies "
            "have HttpOnly.",
        ),
        (
            ["theme=dark; SameSite=Lax"],
            Status.FAIL,
            "The only cookie set on the home page lacks the Secure flag.",
        ),
        (
            ["tracker=1; SameSite=None"],
            Status.FAIL,
            "The only cookie set on the home page uses SameSite=None without Secure.",
        ),
        (
            ["theme=dark; Secure"],
            Status.WARN,
            "The only cookie set on the home page has no SameSite attribute.",
        ),
        (
            ["sessionid=1; Secure; SameSite=Lax"],
            Status.WARN,
            "The only cookie set on the home page looks like a session cookie but lacks HttpOnly.",
        ),
        (
            [
                "a=1; SameSite=Lax",
                "b=1; Secure",
                "c=1",
                "PHPSESSID=1; Secure; SameSite=Lax",
            ],
            Status.FAIL,
            "Of 4 cookies set on the home page, 2 lack the Secure flag, 2 have no SameSite "
            "attribute and 1 looks like a session cookie but lacks HttpOnly.",
        ),
        (
            ["__Host-id=1; Secure; Domain=example.com; SameSite=Lax", "x=1; Secure; SameSite=Lax"],
            Status.WARN,
            "Of 2 cookies set on the home page, 1 breaks the rules of its __Host- or __Secure- "
            "name prefix.",
        ),
    ],
)
def test_cookie_verdicts(headers: list[str], expected: Status, summary: str) -> None:
    outcome = evaluate_cookies(headers)
    assert (outcome.status, outcome.summary) == (expected, summary)
    assert (outcome.remediation is None) == (expected is Status.PASS)


def test_cookie_evidence_lists_names_and_flags() -> None:
    outcome = evaluate_cookies(["sid=1; Secure; SameSite=Strict", "theme=dark; HttpOnly"])
    assert labels(outcome.evidence) == {
        "Cookie sid": "Secure, no HttpOnly, SameSite=Strict, session-like name",
        "Cookie theme": "no Secure, HttpOnly, no SameSite",
    }
    assert outcome.remediation is not None
    assert outcome.remediation.startswith(
        "Add Secure to every cookie, an explicit SameSite=Lax or Strict and HttpOnly to "
        "session cookies"
    )


@pytest.mark.parametrize(
    "header",
    [
        f"session={COOKIE_VALUE}",
        f'session="{COOKIE_VALUE}"; Secure',
        f"session={COOKIE_VALUE}; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly",
        f"{COOKIE_VALUE}; Path=/",
        f"__Host-auth={COOKIE_VALUE}; Domain=example.com",
        f"t={COOKIE_VALUE}; SameSite=None",
    ],
)
def test_cookie_values_never_appear(header: str) -> None:
    outcome = evaluate_cookies([header, f"other={COOKIE_VALUE}{COOKIE_VALUE}"])
    assert COOKIE_VALUE not in rendered(outcome)


def test_many_cookies_are_capped_in_evidence() -> None:
    headers = [f"c{i}=1; Secure; SameSite=Lax" for i in range(MAX_COOKIES_SHOWN + 3)]
    outcome = evaluate_cookies(headers)
    assert len(outcome.evidence) == MAX_COOKIES_SHOWN + 1
    assert labels(outcome.evidence)["More cookies"] == "3 not shown"


async def test_cookie_check_reads_every_set_cookie_header() -> None:
    page = response(
        HOME,
        headers=[
            ("Set-Cookie", "a=1; Secure; SameSite=Lax"),
            ("Content-Type", "text/html"),
            ("Set-Cookie", "b=2; SameSite=Lax"),
        ],
    )
    result = await run_check(COOKIES, make_context(fetcher=FakeFetcher(pages={HOME: page})))
    assert result.status is Status.FAIL
    assert result.summary == "Of 2 cookies set on the home page, 1 lacks the Secure flag."


async def test_cookie_check_fetch_error_is_inconclusive() -> None:
    error = FetchError(FetchErrorReason.TIMEOUT, "timed out")
    result = await run_check(COOKIES, make_context(fetcher=FakeFetcher(pages={HOME: error})))
    assert result.status is Status.INCONCLUSIVE
    assert result.summary == "The home page could not be fetched: the request timed out."


# --- CDN detection ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "providers"),
    [
        ({"Server": "cloudflare", "CF-RAY": "8a1b2c3d4e5f-FRA"}, ["Cloudflare"]),
        ({"cf-ray": "8a1b2c3d4e5f-FRA"}, ["Cloudflare"]),
        ({"X-Amz-Cf-Id": "abc==", "X-Cache": "Hit from cloudfront"}, ["Amazon CloudFront"]),
        ({"Via": "1.1 0a1b2c.cloudfront.net (CloudFront)"}, ["Amazon CloudFront"]),
        ({"X-Served-By": "cache-fra-eddf8230045-FRA", "Via": "1.1 varnish"}, ["Fastly"]),
        ({"X-Fastly-Request-ID": "abc"}, ["Fastly"]),
        ({"Via": "1.1 varnish"}, []),
        ({"Server": "AkamaiGHost"}, ["Akamai"]),
        ({"Akamai-GRN": "0.1234"}, ["Akamai"]),
        ({"X-Azure-Ref": "0abc"}, ["Azure Front Door"]),
        ({"X-Vercel-Id": "fra1::abc", "Server": "Vercel"}, ["Vercel"]),
        ({"X-NF-Request-ID": "01abc", "Server": "Netlify"}, ["Netlify"]),
        ({"Server": "Google Frontend"}, ["Google Front End"]),
        ({"X-Sucuri-ID": "11005"}, ["Sucuri"]),
        ({"X-Iinfo": "9-123-0 0NNN RT(1 2) q(0 0 0 -1) r(0 0) U6"}, ["Imperva"]),
        ({"X-CDN": "Imperva"}, ["Imperva"]),
        ({"cf-ray": "8a1b-FRA", "x-vercel-id": "fra1::abc"}, ["Cloudflare", "Vercel"]),
        ({"Server": "nginx/1.27.0", "X-Cache": "HIT"}, []),
        ({"Server": "Google Frontend-ish"}, []),
        ({}, []),
    ],
)
def test_detect_cdns(headers: dict[str, str], providers: list[str]) -> None:
    pairs = [(name.lower(), value) for name, value in headers.items()]
    assert [match.provider for match in detect_cdns(pairs)] == providers


def test_cdn_outcome_names_provider_and_signals() -> None:
    page = response(HOME, headers={"Server": "cloudflare", "CF-RAY": "8a1b-FRA"})
    outcome = evaluate_cdn(page)
    assert outcome.status is Status.INFO
    assert outcome.summary == "The home page is served through Cloudflare."
    assert labels(outcome.evidence) == {"Cloudflare": "server: cloudflare, cf-ray"}


def test_cdn_outcome_several_providers() -> None:
    page = response(HOME, headers={"cf-ray": "x", "x-vercel-id": "y"})
    assert evaluate_cdn(page).summary == "The home page is served through Cloudflare and Vercel."


def test_cdn_outcome_none_detected() -> None:
    outcome = evaluate_cdn(response(HOME, headers={"Server": "nginx"}))
    assert outcome.status is Status.INFO
    assert outcome.summary == "No CDN or edge network was detected from the response headers."


async def test_cdn_check() -> None:
    page = response(HOME, headers={"x-azure-ref": "0abc"})
    result = await run_check(CDN, make_context(fetcher=FakeFetcher(pages={HOME: page})))
    assert (result.status, result.points) == (Status.INFO, 0)
    error = FetchError(FetchErrorReason.CONNECT, "refused")
    result = await run_check(CDN, make_context(fetcher=FakeFetcher(pages={HOME: error})))
    assert result.status is Status.INCONCLUSIVE


# --- Privacy policy link ---------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "folded"),
    [
        ("KVKK Aydınlatma Metni", "kvkk aydinlatma metni"),
        ("KİŞİSEL VERİLERİN KORUNMASI", "kisisel verilerin korunmasi"),
        ("Datenschutzerklärung", "datenschutzerklarung"),
        ("Personvernerklæring", "personvernerklaering"),
        ("Politica de confidențialitate", "politica de confidentialitate"),
        ("Πολιτική Απορρήτου", "πολιτικη απορρητου"),
        ("/privacy_policy.html", "privacy policy html"),
    ],
)
def test_fold_text(text: str, folded: str) -> None:
    assert fold_text(text) == folded


def page_with(links: str) -> str:
    return f"<html><body><main>Hello</main><footer>{links}</footer></body></html>"


@pytest.mark.parametrize(
    ("html", "url", "text"),
    [
        ('<a href="/privacy">Privacy</a>', "https://example.com/privacy", "Privacy"),
        ('<a href="privacy-policy/">Legal</a>', "https://example.com/en/privacy-policy/", "Legal"),
        (
            '<a href="https://example.com/datenschutz#top">Datenschutz</a>',
            "https://example.com/datenschutz",
            "Datenschutz",
        ),
        ('<a href="/ds">Datenschutz&shy;erklärung</a>', "https://example.com/ds", None),
        (
            '<a href="/sayfa/12">KVKK Aydınlatma Metni</a>',
            "https://example.com/sayfa/12",
            "KVKK Aydınlatma Metni",
        ),
        (
            '<a href="/kisisel-verilerin-korunmasi">Yasal</a>',
            "https://example.com/kisisel-verilerin-korunmasi",
            "Yasal",
        ),
        (
            '<a href="/gizlilik-politikas%C4%B1">Gizlilik</a>',
            "https://example.com/gizlilik-politikas%C4%B1",
            "Gizlilik",
        ),
        (
            '<a href="/p/3"><span>Politique de</span> <b>confidentialité</b></a>',
            "https://example.com/p/3",
            "Politique de confidentialité",
        ),
        ('<a href="/p/4">Πολιτική απορρήτου</a>', "https://example.com/p/4", None),
        (
            '<a href="/p/5" aria-label="Privacy notice"><svg></svg></a>',
            "https://example.com/p/5",
            None,
        ),
        (
            '<a href="/p/6"><img src="x.png" alt="Polityka prywatności"></a>',
            "https://example.com/p/6",
            None,
        ),
        ('<a href="//cdn.example.com/gdpr.pdf">PDF</a>', "https://cdn.example.com/gdpr.pdf", "PDF"),
    ],
)
def test_find_privacy_links_match(html: str, url: str, text: str | None) -> None:
    links = find_privacy_links(page_with(html), "https://example.com/en/")
    assert [link.url for link in links] == [url]
    if text is not None:
        assert links[0].text == text


@pytest.mark.parametrize(
    "html",
    [
        '<a href="/about">About us</a><a href="/contact">Contact</a>',
        '<a href="/impressum">Impressum</a><a href="/terms">Terms of service</a>',
        '<a href="/urunler/aydinlatma">Aydınlatma</a>',
        '<a href="#privacy">Privacy</a>',
        '<a href="javascript:openPrivacy()">Privacy</a>',
        '<a href="mailto:privacy@example.com">privacy@example.com</a>',
        "<a>Privacy policy</a>",
        "<p>Read our privacy policy.</p>",
        "<script>var a = \"<a href='/privacy'>Privacy</a>\";</script>",
    ],
)
def test_find_privacy_links_no_match(html: str) -> None:
    assert find_privacy_links(page_with(html), HOME) == []


def test_find_privacy_links_uses_base_href() -> None:
    html = '<head><base href="https://static.example.com/site/"></head><a href="privacy">P</a>'
    links = find_privacy_links(html, HOME)
    assert [link.url for link in links] == ["https://static.example.com/site/privacy"]


def test_find_privacy_links_reports_what_matched() -> None:
    links = find_privacy_links(
        page_with(
            '<a href="/privacy">Privacy</a><a href="/x">Privacy</a><a href="/gdpr">Legal</a>'
        ),
        HOME,
    )
    assert [(link.text_match, link.path_match) for link in links] == [
        (True, True),
        (True, False),
        (False, True),
    ]


def html_page(body: str, url: str = HOME) -> HttpResponse:
    return response(url, headers={"Content-Type": "text/html; charset=utf-8"}, body=body)


def test_privacy_link_found() -> None:
    outcome = evaluate_privacy_policy(
        "example.com", html_page(page_with('<a href="/privacy-policy">Privacy Policy</a>'))
    )
    assert outcome.status is Status.INFO
    assert outcome.summary == (
        "The home page links to a privacy policy at https://example.com/privacy-policy."
    )
    assert labels(outcome.evidence) == {
        "Link": "https://example.com/privacy-policy",
        "Link text": "Privacy Policy",
        "Matched on": "link text and URL",
    }


def test_own_site_link_beats_earlier_external_link() -> None:
    body = page_with(
        '<a href="https://www.iubenda.com/privacy-policy/123">Privacy</a>'
        '<a href="https://www.example.com/legal">Privacy notice</a>'
    )
    outcome = evaluate_privacy_policy("example.com", html_page(body))
    assert outcome.summary == (
        "The home page links to a privacy policy at https://www.example.com/legal."
    )


def test_link_matching_text_and_path_is_preferred() -> None:
    body = page_with('<a href="/settings">Privacy settings</a><a href="/privacy">Privacy</a>')
    outcome = evaluate_privacy_policy("example.com", html_page(body))
    assert labels(outcome.evidence)["Link"] == "https://example.com/privacy"


def test_external_policy_is_reported_as_such() -> None:
    body = page_with('<a href="https://www.iubenda.com/privacy-policy/123">Privacy</a>')
    outcome = evaluate_privacy_policy("example.com", html_page(body))
    assert outcome.summary == (
        "The home page links to a privacy policy on another site at "
        "https://www.iubenda.com/privacy-policy/123."
    )


@pytest.mark.parametrize(
    ("domain", "final_url", "link"),
    [
        ("example.com", "https://www.example.com/", "https://www.example.com/privacy"),
        ("example.com", HOME, "https://legal.example.com/privacy"),
        ("shop.example.com", "https://shop.example.com/", "https://example.com/privacy"),
        ("example.com", "https://example.org/", "https://example.org/privacy"),
    ],
)
def test_own_hosts(domain: str, final_url: str, link: str) -> None:
    body = page_with(f'<a href="{link}">Privacy</a>')
    outcome = evaluate_privacy_policy(domain, html_page(body, url=final_url))
    assert "another site" not in outcome.summary


def test_widget_privacy_links_are_ignored() -> None:
    body = page_with(
        "This site is protected by reCAPTCHA and the Google "
        '<a href="https://policies.google.com/privacy">Privacy Policy</a> apply.'
    )
    outcome = evaluate_privacy_policy("example.com", html_page(body))
    assert outcome.summary == (
        "No privacy policy link was found in the home page HTML; links added by JavaScript "
        "are not seen."
    )


def test_no_link_on_a_truncated_page() -> None:
    page = replace(html_page(page_with('<a href="/about">About</a>')), truncated=True)
    outcome = evaluate_privacy_policy("example.com", page)
    assert outcome.status is Status.INFO
    assert "cut off at the size limit" in outcome.summary


def test_page_charset_is_honoured() -> None:
    body = page_with('<a href="/sayfa/7">Gizlilik Politikası</a>').encode("cp1254")
    page = HttpResponse(
        url=HOME,
        status=200,
        headers=(("content-type", "text/html; charset=windows-1254"),),
        body=body,
    )
    outcome = evaluate_privacy_policy("example.com", page)
    assert labels(outcome.evidence)["Link text"] == "Gizlilik Politikası"


@pytest.mark.parametrize(
    ("page", "expected", "summary"),
    [
        (
            response(HOME, status=403, headers={"cf-mitigated": "challenge"}),
            Status.INCONCLUSIVE,
            "The home page answered with a bot challenge, so its links could not be inspected.",
        ),
        (
            response(HOME, status=301),
            Status.INCONCLUSIVE,
            "The home page answered with HTTP 301, so its links could not be inspected.",
        ),
        (
            response(HOME, status=503),
            Status.INCONCLUSIVE,
            "The home page answered with HTTP 503, so its links could not be inspected.",
        ),
        (
            response(HOME, headers={"Content-Type": "application/json"}, body='{"privacy": 1}'),
            Status.INFO,
            "The home page is not an HTML document, so it has no links to inspect.",
        ),
    ],
)
def test_pages_without_inspectable_links(
    page: HttpResponse, expected: Status, summary: str
) -> None:
    outcome = evaluate_privacy_policy("example.com", page)
    assert (outcome.status, outcome.summary) == (expected, summary)


async def test_privacy_check_makes_no_extra_requests() -> None:
    page = html_page(page_with('<a href="/kvkk">KVKK</a>'))
    fetcher = FakeFetcher(pages={HOME: page})
    result = await run_check(PRIVACY_POLICY, make_context(fetcher=fetcher))
    assert fetcher.requests == [HOME]
    assert result.status is Status.INFO
    assert result.summary == "The home page links to a privacy policy at https://example.com/kvkk."


async def test_privacy_check_fetch_error_is_inconclusive() -> None:
    error = FetchError(FetchErrorReason.TLS, "certificate verify failed")
    result = await run_check(PRIVACY_POLICY, make_context(fetcher=FakeFetcher(pages={HOME: error})))
    assert result.status is Status.INCONCLUSIVE
