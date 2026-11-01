"""Checks on the home page response: cookie flags, CDN and privacy policy link."""

import codecs
import re
import unicodedata
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from html.parser import HTMLParser
from urllib.parse import unquote, urldefrag, urljoin, urlsplit

from webriskaudit.checks.base import Check, Outcome, evidence, redact_url
from webriskaudit.checks.homepage import is_bot_challenge, load_homepage, on_homepage
from webriskaudit.context import ScanContext
from webriskaudit.models import Category, Evidence, Reference, Status
from webriskaudit.net.types import HttpResponse


def _clip(value: str, limit: int = 300) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _join(items: Sequence[str]) -> str:
    """'a', 'a and b', 'a, b and c'."""
    return items[0] if len(items) == 1 else f"{', '.join(items[:-1])} and {items[-1]}"


# --- Cookies -----------------------------------------------------------------

MAX_COOKIES_SHOWN = 10

_SESSION_NAMES = frozenset({"phpsessid", "jsessionid", "connect.sid", "asp.net_sessionid"})
_SESSION_PARTS = ("sess", "sid", "auth", "token", "jwt", "login")
_SAME_SITE_VALUES = {"strict": "Strict", "lax": "Lax", "none": "None"}


@dataclass(frozen=True)
class SetCookie:
    """Name and security attributes of one Set-Cookie header. The value is never kept."""

    name: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    """Strict, Lax or None; None (the Python value) when absent or not recognized."""
    domain: str | None = None
    path: str | None = None


def parse_set_cookie(header: str) -> SetCookie | None:
    """Parse one Set-Cookie header the way browsers do (RFC 6265bis section 5.6).

    Attributes are matched case-insensitively and the last SameSite wins. The
    header is split on ";" only, so commas in Expires dates are harmless.
    Returns None for a header browsers ignore (empty name and value).
    """
    pair, _, attributes = header.partition(";")
    name, has_equals, value = pair.partition("=")
    if not has_equals:
        name, value = "", pair  # a nameless cookie, as browsers store it
    name = name.strip()
    if not name and not value.strip():
        return None

    secure = http_only = False
    same_site = domain = path = None
    for attribute in attributes.split(";"):
        key, _, raw = attribute.partition("=")
        key, raw = key.strip().lower(), raw.strip()
        if key == "secure":
            secure = True
        elif key == "httponly":
            http_only = True
        elif key == "samesite":
            same_site = _SAME_SITE_VALUES.get(raw.lower())
        elif key == "domain" and raw:
            domain = raw.removeprefix(".").lower()
        elif key == "path":
            path = raw if raw.startswith("/") else None
    return SetCookie(name, secure, http_only, same_site, domain, path)


def is_session_cookie(name: str) -> bool:
    """Heuristic: does the name look like a session or authentication cookie?"""
    lowered = name.lower()
    return lowered in _SESSION_NAMES or any(part in lowered for part in _SESSION_PARTS)


class CookieIssue(StrEnum):
    NO_SECURE = "no-secure"
    SAME_SITE_NONE_WITHOUT_SECURE = "samesite-none-without-secure"
    NO_SAME_SITE = "no-samesite"
    SESSION_WITHOUT_HTTP_ONLY = "session-without-httponly"
    PREFIX_RULES_BROKEN = "prefix-rules-broken"


# Status and summary phrases (one cookie, several cookies), most severe first.
_ISSUE_TEXT: dict[CookieIssue, tuple[Status, str, str]] = {
    CookieIssue.NO_SECURE: (Status.FAIL, "lacks the Secure flag", "lack the Secure flag"),
    CookieIssue.SAME_SITE_NONE_WITHOUT_SECURE: (
        Status.FAIL,
        "uses SameSite=None without Secure",
        "use SameSite=None without Secure",
    ),
    CookieIssue.NO_SAME_SITE: (
        Status.WARN,
        "has no SameSite attribute",
        "have no SameSite attribute",
    ),
    CookieIssue.SESSION_WITHOUT_HTTP_ONLY: (
        Status.WARN,
        "looks like a session cookie but lacks HttpOnly",
        "look like session cookies but lack HttpOnly",
    ),
    CookieIssue.PREFIX_RULES_BROKEN: (
        Status.WARN,
        "breaks the rules of its __Host- or __Secure- name prefix",
        "break the rules of their __Host- or __Secure- name prefix",
    ),
}


def _prefix_rules_broken(cookie: SetCookie) -> bool:
    # RFC 6265bis matches the prefixes case-insensitively; browsers drop such cookies.
    lowered = cookie.name.lower()
    if lowered.startswith("__host-"):
        return not (cookie.secure and cookie.domain is None and cookie.path == "/")
    return lowered.startswith("__secure-") and not cookie.secure


def cookie_issues(cookie: SetCookie) -> list[CookieIssue]:
    """Problems with one cookie's attributes, most severe first."""
    issues = []
    if not cookie.secure:
        none = cookie.same_site == "None"
        issues.append(CookieIssue.SAME_SITE_NONE_WITHOUT_SECURE if none else CookieIssue.NO_SECURE)
    if cookie.same_site is None:
        issues.append(CookieIssue.NO_SAME_SITE)
    if is_session_cookie(cookie.name) and not cookie.http_only:
        issues.append(CookieIssue.SESSION_WITHOUT_HTTP_ONLY)
    if _prefix_rules_broken(cookie):
        issues.append(CookieIssue.PREFIX_RULES_BROKEN)
    return issues


def _describe(cookie: SetCookie) -> Evidence:
    flags = [
        "Secure" if cookie.secure else "no Secure",
        "HttpOnly" if cookie.http_only else "no HttpOnly",
        f"SameSite={cookie.same_site}" if cookie.same_site else "no SameSite",
    ]
    if is_session_cookie(cookie.name):
        flags.append("session-like name")
    return evidence(f"Cookie {_clip(cookie.name, 80) or '(unnamed)'}", ", ".join(flags))


def _cookie_fix(found: set[CookieIssue]) -> str:
    needed = []
    if found & {CookieIssue.NO_SECURE, CookieIssue.SAME_SITE_NONE_WITHOUT_SECURE}:
        needed.append("Secure to every cookie")
    if CookieIssue.NO_SAME_SITE in found:
        needed.append("an explicit SameSite=Lax or Strict")
    if CookieIssue.SESSION_WITHOUT_HTTP_ONLY in found:
        needed.append("HttpOnly to session cookies")
    fix = []
    if needed:
        fix.append(
            f"Add {_join(needed)}, for example "
            "'Set-Cookie: __Host-session=...; Path=/; Secure; HttpOnly; SameSite=Lax'."
        )
    if CookieIssue.PREFIX_RULES_BROKEN in found:
        fix.append(
            "Set __Host- cookies with Secure, Path=/ and no Domain, and __Secure- with Secure."
        )
    return " ".join(fix)


def evaluate_cookies(set_cookie_headers: Sequence[str]) -> Outcome:
    """Verdict on the Set-Cookie headers of the home page. Values never appear in the output."""
    cookies = [cookie for h in set_cookie_headers if (cookie := parse_set_cookie(h))]
    if not cookies:
        return Outcome(Status.PASS, "No cookies are set on the home page.")

    per_cookie = [cookie_issues(cookie) for cookie in cookies]
    counts = Counter(issue for issues in per_cookie for issue in issues)
    details = [_describe(cookie) for cookie in cookies[:MAX_COOKIES_SHOWN]]
    if len(cookies) > MAX_COOKIES_SHOWN:
        details.append(evidence("More cookies", f"{len(cookies) - MAX_COOKIES_SHOWN} not shown"))

    total = len(cookies)
    if not counts:
        if total == 1:
            summary = "The only cookie set on the home page has Secure and SameSite"
        else:
            summary = f"All {total} cookies set on the home page have Secure and SameSite"
        if any(is_session_cookie(cookie.name) for cookie in cookies):
            summary += ", and session cookies have HttpOnly"
        return Outcome(Status.PASS, summary + ".", details)

    ordered = [issue for issue in _ISSUE_TEXT if issue in counts]
    failed = any(_ISSUE_TEXT[issue][0] is Status.FAIL for issue in ordered)
    status = Status.FAIL if failed else Status.WARN
    if total == 1:
        summary = "The only cookie set on the home page " + _join(
            [_ISSUE_TEXT[issue][1] for issue in ordered]
        )
    else:
        phrases = [
            f"{counts[issue]} {_ISSUE_TEXT[issue][1 if counts[issue] == 1 else 2]}"
            for issue in ordered
        ]
        summary = f"Of {total} cookies set on the home page, {_join(phrases)}"
    return Outcome(status, summary + ".", details, _cookie_fix(set(counts)))


def _evaluate_page_cookies(page: HttpResponse) -> Outcome:
    return evaluate_cookies(page.header_all("set-cookie"))


check_cookies = on_homepage(_evaluate_page_cookies)


# --- CDN ---------------------------------------------------------------------


@dataclass(frozen=True)
class _Signal:
    name: str
    """Regular expression that must match the whole lower-cased header name."""
    value: str | None = None
    """Regular expression searched case-insensitively in the value; None means presence."""

    def matches(self, name: str, value: str) -> bool:
        if not re.fullmatch(self.name, name):
            return False
        return self.value is None or re.search(self.value, value, re.IGNORECASE) is not None


_CDN_SIGNALS: tuple[tuple[str, tuple[_Signal, ...]], ...] = (
    ("Cloudflare", (_Signal("cf-ray"), _Signal("server", r"^cloudflare"))),
    (
        "Amazon CloudFront",
        (
            _Signal("x-amz-cf-id"),
            _Signal("x-amz-cf-pop"),
            _Signal("via", r"cloudfront"),
            _Signal("x-cache", r"cloudfront"),
        ),
    ),
    (
        "Fastly",
        (
            _Signal("x-fastly-request-id"),
            _Signal("x-served-by", r"^cache-"),
            _Signal("via", r"fastly"),
            _Signal("fastly-.*"),
        ),
    ),
    ("Akamai", (_Signal("server", r"^akamai"), _Signal("(x-)?akamai-.*"))),
    ("Azure Front Door", (_Signal("x-azure-ref"),)),
    ("Vercel", (_Signal("x-vercel-id"), _Signal("server", r"^vercel$"))),
    ("Netlify", (_Signal("x-nf-request-id"), _Signal("server", r"^netlify$"))),
    ("Google Front End", (_Signal("server", r"^google frontend$"),)),
    ("Sucuri", (_Signal("x-sucuri-id"), _Signal("server", r"^sucuri"))),
    ("Imperva", (_Signal("x-iinfo"), _Signal("x-cdn", r"imperva|incapsula"))),
)


@dataclass(frozen=True)
class CdnMatch:
    provider: str
    signals: tuple[str, ...]
    """The headers that gave it away, e.g. ``cf-ray`` or ``server: cloudflare``."""


def detect_cdns(headers: Sequence[tuple[str, str]]) -> list[CdnMatch]:
    """CDN or edge providers recognized from response headers, in table order."""
    found = []
    for provider, signals in _CDN_SIGNALS:
        seen: list[str] = []
        for name, value in headers:
            for signal in signals:
                if signal.matches(name.lower(), value):
                    shown = name if signal.value is None else f"{name}: {_clip(value.strip(), 80)}"
                    seen.append(shown)
                    break
        if seen:
            found.append(CdnMatch(provider, tuple(dict.fromkeys(seen))))
    return found


def evaluate_cdn(response: HttpResponse) -> Outcome:
    matches = detect_cdns(response.headers)
    if not matches:
        return Outcome(
            Status.INFO, "No CDN or edge network was detected from the response headers."
        )
    names = _join([match.provider for match in matches])
    details = [evidence(match.provider, ", ".join(match.signals)) for match in matches]
    return Outcome(Status.INFO, f"The home page is served through {names}.", details)


# An error or challenge page still shows which edge network answered.
check_cdn = on_homepage(evaluate_cdn, require_success=False)


# --- Privacy policy link -----------------------------------------------------

# Matched at the start of a word, after folding case and accents, against both
# the link text and the URL path. Languages follow the legacy scanner's list;
# imprint, terms and legal notice pages are left out, as they are not privacy
# policies.
PRIVACY_KEYWORDS: tuple[str, ...] = (
    # English, Italian (informativa privacy), Dutch (privacybeleid, privacyverklaring)
    "privacy",
    "data protection",
    # German
    "datenschutz",
    # French and Romanian (confidentialite, confidentialitate)
    "confidentialit",
    "vie privee",
    "donnees personnelles",
    # Spanish and Portuguese
    "privacidad",
    "proteccion de datos",
    "protecao de dados",
    # Polish
    "prywatnos",
    "ochrona danych",
    # Turkish
    "gizlilik",
    "kvkk",
    "kisisel veri",
    "aydinlatma metni",
    # Swedish
    "integritet",
    "personuppgift",
    # Danish
    "privatliv",
    "persondata",
    # Finnish
    "tietosuoja",
    # Norwegian
    "personvern",
    # Greek, transliterated in URLs and in Greek script
    "politiki aporritou",
    "prostasia dedomenon",
    "απορρητ",
    "προστασια δεδομενων",
    "προσωπικα δεδομενα",
    # Czech
    "osobnich udaju",
    # Hungarian
    "adatvedel",
    # Regulations
    "gdpr",
    "dsgvo",
    "rgpd",
)

# Characters that Unicode decomposition does not reduce to ASCII.
_FOLD = str.maketrans(
    {
        "\u0131": "i",  # Turkish dotless i
        "ø": "o",
        "æ": "ae",
        "ß": "ss",
        "ł": "l",
        "đ": "d",
        "œ": "oe",
    }
)


def fold_text(text: str) -> str:
    """Lower-case, strip accents and turn every run of non-word characters into a space."""
    decomposed = unicodedata.normalize("NFKD", text.lower().translate(_FOLD))
    stripped = "".join(char for char in decomposed if not unicodedata.combining(char))
    return re.sub(r"[\W_]+", " ", stripped).strip()


_PRIVACY_PATTERN = re.compile(
    r"(?<!\w)(?:" + "|".join(re.escape(fold_text(k)) for k in PRIVACY_KEYWORDS) + ")"
)

# Hosts whose privacy links come from embedded widgets (reCAPTCHA, hCaptcha,
# Turnstile, social embeds), not from the site's own policy.
_WIDGET_HOSTS = frozenset(
    {"google.com", "policies.google.com", "hcaptcha.com", "cloudflare.com", "facebook.com"}
)
_SKIPPED_SCHEMES = ("javascript:", "mailto:", "tel:", "data:")


@dataclass(frozen=True)
class PrivacyLink:
    url: str
    """Absolute URL, without fragment."""
    text: str
    """Link text with whitespace collapsed, including aria-label, title and image alt."""
    text_match: bool
    path_match: bool


class _LinkParser(HTMLParser):
    """Collects (href, text) of every <a href> and the first <base href>."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base: str | None = None
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if tag == "base" and self.base is None and values.get("href"):
            self.base = values["href"]
        elif tag == "a":
            self._finish()  # an unclosed <a> ends at the next one
            if "href" in values:
                self._href = values["href"]
                self._text = [values.get("aria-label", ""), values.get("title", "")]
        elif tag == "img" and self._href is not None:
            self._text.append(values.get("alt", ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._finish()

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def close(self) -> None:
        super().close()
        self._finish()

    def _finish(self) -> None:
        if self._href is not None:
            self.links.append((self._href, " ".join(" ".join(self._text).split())))
        self._href, self._text = None, []


def find_privacy_links(html: str, page_url: str) -> list[PrivacyLink]:
    """Links whose text or path matches a privacy keyword, in document order."""
    parser = _LinkParser()
    parser.feed(html)
    parser.close()
    base = urljoin(page_url, parser.base) if parser.base else page_url

    found = []
    for href, text in parser.links:
        href = href.strip()
        if not href or href.startswith("#") or href.lower().startswith(_SKIPPED_SCHEMES):
            continue
        url = urldefrag(urljoin(base, href)).url
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            continue
        text_match = bool(_PRIVACY_PATTERN.search(fold_text(text)))
        path_match = bool(
            _PRIVACY_PATTERN.search(fold_text(unquote(f"{parts.path} {parts.query}")))
        )
        if text_match or path_match:
            found.append(PrivacyLink(url, text, text_match, path_match))
    return found


def _bare(host: str) -> str:
    return host.lower().rstrip(".").removeprefix("www.")


def _is_own_host(host: str, sites: set[str]) -> bool:
    """Same host, its www counterpart, a subdomain or a parent domain of a scanned site."""
    host = _bare(host)
    return any(
        host == site or host.endswith(f".{site}") or (site.endswith(f".{host}") and "." in host)
        for site in sites
    )


def _pick(links: list[PrivacyLink], sites: set[str]) -> tuple[PrivacyLink, bool] | None:
    """Best candidate and whether it is on the site's own hosts."""
    ranked = []
    for index, link in enumerate(links):
        host = urlsplit(link.url).hostname or ""
        own = _is_own_host(host, sites)
        if not own and _bare(host) in _WIDGET_HOSTS:
            continue
        ranked.append((own, link.text_match and link.path_match, -index, link))
    if not ranked:
        return None
    own, _, _, link = max(ranked, key=lambda item: item[:3])
    return link, own


def _charset(response: HttpResponse) -> str:
    match = re.search(r"charset=[\"']?([\w.:-]+)", response.header("content-type") or "", re.I)
    if match:
        try:
            return codecs.lookup(match.group(1)).name
        except LookupError:
            pass
    return "utf-8"


def evaluate_privacy_policy(domain: str, response: HttpResponse) -> Outcome:
    """Look for a privacy policy link in the home page HTML. No extra requests are made."""
    if is_bot_challenge(response):
        return Outcome(
            Status.INCONCLUSIVE,
            "The home page answered with a bot challenge, so its links could not be inspected.",
        )
    if response.status >= 300:
        return Outcome(
            Status.INCONCLUSIVE,
            f"The home page answered with HTTP {response.status}, so its links could not be "
            "inspected.",
        )
    content_type = (response.header("content-type") or "").lower()
    if content_type and "html" not in content_type:
        return Outcome(
            Status.INFO,
            "The home page is not an HTML document, so it has no links to inspect.",
            [evidence("Content-Type", _clip(content_type, 100))],
        )

    html = response.body.decode(_charset(response), errors="replace")
    sites = {_bare(domain), _bare(urlsplit(response.url).hostname or domain)}
    choice = _pick(find_privacy_links(html, response.url), sites)
    if choice is None:
        where = (
            "the downloaded part of the home page HTML (it was cut off at the size limit)"
            if response.truncated
            else "the home page HTML"
        )
        return Outcome(
            Status.INFO,
            f"No privacy policy link was found in {where}; links added by JavaScript are not seen.",
        )

    link, own = choice
    sources = (("link text", link.text_match), ("URL", link.path_match))
    matched = _join([label for label, hit in sources if hit])
    shown = redact_url(link.url)
    details = [
        evidence("Link", _clip(shown)),
        evidence("Link text", _clip(link.text, 120) or "(none)"),
        evidence("Matched on", matched),
    ]
    where = "" if own else " on another site"
    return Outcome(
        Status.INFO,
        f"The home page links to a privacy policy{where} at {_clip(shown, 200)}.",
        details,
    )


async def check_privacy_policy(ctx: ScanContext) -> Outcome:
    # evaluate_privacy_policy judges challenge and error pages itself.
    page = await load_homepage(ctx, require_success=False)
    if isinstance(page, Outcome):
        return page
    return evaluate_privacy_policy(ctx.domain, page)


# --- Registry ----------------------------------------------------------------

COOKIES = Check(
    id="headers.cookies",
    title="Cookie security",
    category=Category.HEADERS,
    weight=5,
    run=check_cookies,
    references=(
        Reference(
            title="MDN: Set-Cookie",
            url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie",
        ),
        Reference(
            title="OWASP Session Management Cheat Sheet: Cookies",
            url="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies",
        ),
        Reference(
            title="RFC 6265: HTTP State Management Mechanism",
            url="https://www.rfc-editor.org/rfc/rfc6265.html",
        ),
    ),
)

CDN = Check(
    id="info.cdn",
    title="CDN / edge network",
    category=Category.INFO,
    weight=0,
    run=check_cdn,
)

PRIVACY_POLICY = Check(
    id="info.privacy_policy",
    title="Privacy policy link",
    category=Category.INFO,
    weight=0,
    run=check_privacy_policy,
)

CHECKS: tuple[Check, ...] = (COOKIES, CDN, PRIVACY_POLICY)
