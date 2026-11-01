"""Security headers of the home page.

HSTS (scored under transport), Content Security Policy, framing, MIME
sniffing, referrer policy and version disclosure, plus two informational
checks. Parsers follow the browser algorithms in the cited specifications, so
a header only counts when browsers would actually apply it.
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from html.parser import HTMLParser
from urllib.parse import urlsplit

from webriskaudit.checks.base import Check, Outcome, evidence, redact_url
from webriskaudit.checks.homepage import on_homepage
from webriskaudit.models import Category, Evidence, Reference, Status
from webriskaudit.net.types import HttpResponse

# --- Shared helpers ----------------------------------------------------------

_EVIDENCE_LIMIT = 300


def _truncate(value: str, limit: int = _EVIDENCE_LIMIT) -> str:
    value = value.strip()
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _join(items: Sequence[str]) -> str:
    """'a', 'a and b', 'a, b and c'."""
    if len(items) <= 1:
        return "".join(items)
    return f"{', '.join(items[:-1])} and {items[-1]}"


def _preview(items: Sequence[str], limit: int = 5) -> str:
    shown = ", ".join(items[:limit])
    return f"{shown} and {len(items) - limit} more" if len(items) > limit else shown


def _split_unquoted(value: str, separator: str) -> list[str]:
    """Split on ``separator`` wherever it is outside a double-quoted string."""
    parts: list[str] = []
    current: list[str] = []
    quoted = escaped = False
    for char in value:
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == separator and not quoted:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def split_header_values(values: Iterable[str]) -> list[str]:
    """Comma-separated elements of every line of a header, trimmed, empty ones dropped."""
    parts = (part.strip() for value in values for part in _split_unquoted(value, ","))
    return [part for part in parts if part]


# --- Strict-Transport-Security -----------------------------------------------

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days
_DAY = 86_400

_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')
_DIGITS = re.compile(r"[0-9]+")


@dataclass(frozen=True)
class Hsts:
    max_age: int
    include_subdomains: bool = False
    preload: bool = False


def _unquote(value: str) -> str:
    if _QUOTED.fullmatch(value):
        return re.sub(r"\\(.)", r"\1", value[1:-1])
    return value


def parse_hsts(value: str) -> Hsts:
    """Parse one Strict-Transport-Security value (RFC 6797 section 6.1).

    Directive names are case-insensitive and max-age may be quoted. Raises
    ValueError, with the reason, for a value that browsers ignore.
    """
    directives: dict[str, str | None] = {}
    for part in _split_unquoted(value, ";"):
        directive = part.strip()
        if not directive:
            continue
        name, has_value, raw = directive.partition("=")
        name, raw = name.strip().lower(), raw.strip()
        if not _TOKEN.fullmatch(name):
            raise ValueError(f"malformed directive {directive!r}")
        if name in directives:
            raise ValueError(f"the {name} directive appears more than once")
        if has_value and not (_TOKEN.fullmatch(raw) or _QUOTED.fullmatch(raw)):
            if "," in raw:
                raise ValueError("directives are separated by commas instead of semicolons")
            raise ValueError(f"malformed directive {directive!r}")
        directives[name] = _unquote(raw) if has_value else None
    if "max-age" not in directives:
        raise ValueError("the required max-age directive is missing")
    max_age = directives["max-age"]
    if max_age is None or not _DIGITS.fullmatch(max_age):
        raise ValueError(f"max-age is not a number of seconds ({max_age or 'empty'})")
    if directives.get("includesubdomains") is not None:
        raise ValueError("includeSubDomains does not take a value")
    return Hsts(
        # Browsers cap max-age anyway; the cap keeps absurd values cheap to convert.
        max_age=int(max_age) if len(max_age) <= 18 else 10**18,
        include_subdomains="includesubdomains" in directives,
        preload="preload" in directives,
    )


def _hsts_missing(source: HttpResponse, page: HttpResponse, found: list[Evidence]) -> Outcome:
    host, final_host = _host(source.url), _host(page.url)
    if source is page or host == final_host:
        return Outcome(
            Status.FAIL, "No Strict-Transport-Security header is sent over HTTPS.", found, _HSTS_FIX
        )
    found.append(evidence("Redirects to", redact_url(page.url)))
    if final_policy := page.header("strict-transport-security"):
        found.append(evidence(f"Policy of {_truncate(final_host, 80)}", _truncate(final_policy)))
    return Outcome(
        Status.FAIL,
        f"{host} redirects to {final_host} without sending Strict-Transport-Security; HSTS "
        f"applies per host, so browsers do not remember HTTPS for {host}.",
        found,
        f"{_HSTS_FIX} Send it on the HTTPS redirect from {host} too, not only on {final_host}.",
    )


def _days(seconds: int) -> str:
    days = seconds // _DAY
    if days == 0:
        return "less than a day"
    return "1 day" if days == 1 else f"{days} days"


_HSTS_FIX = (
    "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS "
    "response (leave out includeSubDomains until all subdomains serve HTTPS)."
)


def _host(url: str) -> str:
    return urlsplit(url).hostname or ""


def _valid_hsts(response: HttpResponse) -> bool:
    values = response.header_all("strict-transport-security")
    if not values:
        return False
    try:
        parse_hsts(values[0])
    except ValueError:
        return False
    return True


def hsts_source(page: HttpResponse) -> HttpResponse:
    """The response whose Strict-Transport-Security applies to the scanned host.

    Browsers keep HSTS per host and read it from every HTTPS response,
    redirects included, and the last valid header wins. The home page fetch
    starts at the scanned host, so only that host's own HTTPS responses count:
    a policy on www.example.com does not protect example.com.
    """
    chain = (*page.history, page)
    start = _host(chain[0].url)
    own = [r for r in chain if urlsplit(r.url).scheme == "https" and _host(r.url) == start]
    if not own:
        return page
    with_header = [r for r in own if r.header_all("strict-transport-security")]
    valid = [r for r in with_header if _valid_hsts(r)]
    return (valid or with_header or own)[-1]


def evaluate_hsts(page: HttpResponse) -> Outcome:
    if urlsplit(page.url).scheme != "https":
        return Outcome(
            Status.FAIL,
            "The home page ends up on plain HTTP, where browsers ignore Strict-Transport-Security.",
            [evidence("Final URL", redact_url(page.url))],
            "Serve the site over HTTPS without redirecting back to HTTP, then send "
            "Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        )
    source = hsts_source(page)
    found = [evidence("URL checked", redact_url(source.url))]
    values = source.header_all("strict-transport-security")
    if not values:
        return _hsts_missing(source, page, found)
    found.append(evidence("Header", _truncate(values[0])))
    if len(values) > 1:
        found.append(
            evidence(
                "Note",
                f"{len(values)} Strict-Transport-Security headers were sent; browsers use only "
                "the first (RFC 6797 section 8.1).",
            )
        )
    try:
        hsts = parse_hsts(values[0])
    except ValueError as exc:
        return Outcome(
            Status.FAIL,
            f"The Strict-Transport-Security header is invalid ({exc}), so browsers ignore it.",
            found,
            _HSTS_FIX,
        )
    found += [
        evidence("max-age", f"{hsts.max_age} seconds ({_days(hsts.max_age)})"),
        evidence("includeSubDomains", "yes" if hsts.include_subdomains else "no"),
        evidence("preload", "yes" if hsts.preload else "no"),
    ]
    if hsts.max_age == 0:
        return Outcome(
            Status.FAIL,
            "Strict-Transport-Security sets max-age=0, which tells browsers to drop the policy.",
            found,
            _HSTS_FIX,
        )
    if hsts.max_age < HSTS_MIN_MAX_AGE:
        return Outcome(
            Status.WARN,
            f"HSTS is enabled, but max-age is only {_days(hsts.max_age)} (under 180 days).",
            found,
            "Raise max-age to at least 15552000 (180 days); one year, max-age=31536000, is the "
            "common choice once HTTPS works everywhere.",
        )
    scope = ", including subdomains" if hsts.include_subdomains else ""
    return Outcome(Status.PASS, f"HSTS is enabled for {_days(hsts.max_age)}{scope}.", found)


# --- Content-Security-Policy -------------------------------------------------

CspPolicy = dict[str, tuple[str, ...]]
"""Directive name (lower-case) -> its values as sent."""

_ASCII_WHITESPACE = " \t\n\f\r"
_ASCII_WHITESPACE_RUN = re.compile(r"[ \t\n\f\r]+")
_NONCE_OR_HASH = re.compile(r"'(?:nonce|sha256|sha384|sha512)-[a-z0-9+/_=-]+'")
# "*", "https://*", "*:443": a host-source whose host is a bare wildcard.
_ANY_HOST_SOURCE = re.compile(r"(?:[a-z][a-z0-9+.-]*://)?\*(?::(?:[0-9]+|\*))?(?:/.*)?")
_ANY_HOST_SCHEMES = frozenset({"http:", "https:"})
# Browsers ignore these directives in a <meta> policy (CSP3 section 3.3).
_META_IGNORED = ("frame-ancestors", "report-uri", "sandbox")


def parse_csp_policy(serialized: str) -> CspPolicy:
    """Parse one serialized policy (CSP3 "parse a serialized CSP").

    Directive names are lower-cased; a repeated directive is ignored.
    """
    policy: CspPolicy = {}
    for token in serialized.split(";"):
        token = token.strip(_ASCII_WHITESPACE)
        if not token or not token.isascii():
            continue
        name, *values = _ASCII_WHITESPACE_RUN.split(token)
        policy.setdefault(name.lower(), tuple(values))
    return policy


def parse_csp(values: Iterable[str]) -> list[CspPolicy]:
    """Policies in Content-Security-Policy header values.

    Each header value may hold several comma-separated policies; empty
    policies are dropped (CSP3 "parse a serialized CSP list").
    """
    policies = (parse_csp_policy(part) for value in values for part in value.split(","))
    return [policy for policy in policies if policy]


class _MetaCspParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.contents: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta":
            return
        values = {name: value or "" for name, value in attrs}
        http_equiv = values.get("http-equiv", "").strip().lower()
        if http_equiv == "content-security-policy" and values.get("content", "").strip():
            self.contents.append(values["content"])


_HEAD_END = re.compile(r"</head\s*>|<body[\s/>]", re.IGNORECASE)


def find_meta_csp(html: str) -> list[str]:
    """Contents of <meta http-equiv="Content-Security-Policy"> elements in the document head."""
    end = _HEAD_END.search(html)
    parser = _MetaCspParser()
    parser.feed(html[: end.start()] if end else html)
    parser.close()
    return parser.contents


def meta_csp_policy(content: str) -> CspPolicy:
    """A <meta> policy without the directives browsers ignore there."""
    policy = parse_csp_policy(content)
    for name in _META_IGNORED:
        policy.pop(name, None)
    return policy


@dataclass(frozen=True)
class ScriptSources:
    """A source list of one policy, with the directive it came from."""

    directive: str
    sources: tuple[str, ...]

    def __str__(self) -> str:
        return " ".join((self.directive, *self.sources))


# CSP3 section 6.8.1 fallback lists: script elements, inline event handlers
# (attributes), and eval() (section 4.4, which reads script-src or default-src).
_ELEMENT_DIRECTIVES = ("script-src-elem", "script-src", "default-src")
_ATTRIBUTE_DIRECTIVES = ("script-src-attr", "script-src", "default-src")
_EVAL_DIRECTIVES = ("script-src", "default-src")


def _governing(policy: CspPolicy, directives: Sequence[str]) -> ScriptSources | None:
    return next((ScriptSources(d, policy[d]) for d in directives if d in policy), None)


class ScriptIssue(StrEnum):
    UNSAFE_INLINE = "'unsafe-inline'"
    UNSAFE_EVAL = "'unsafe-eval'"
    ANY_HOST = "any host (* or a bare http:/https:)"
    DATA_URL = "data: URLs"


_ISSUE_DETAILS: dict[ScriptIssue, str] = {
    ScriptIssue.UNSAFE_INLINE: "'unsafe-inline' lets injected inline scripts or event handlers run",
    ScriptIssue.UNSAFE_EVAL: "'unsafe-eval' allows eval() and similar string-to-code calls",
    ScriptIssue.ANY_HOST: "a wildcard or scheme-only source allows scripts from any host",
    ScriptIssue.DATA_URL: "data: allows scripts from data: URLs",
}


def _allows_any_host(source: str) -> bool:
    source = source.lower()
    return source in _ANY_HOST_SCHEMES or _ANY_HOST_SOURCE.fullmatch(source) is not None


def script_source_issues(sources: Iterable[str]) -> list[ScriptIssue]:
    """Weaknesses of one script source list, as a CSP Level 3 browser applies it.

    A nonce, a hash or 'strict-dynamic' makes browsers ignore 'unsafe-inline';
    'strict-dynamic' also makes them ignore host and scheme sources, which
    strict policies keep only as a fallback for older browsers.
    """
    lowered = {source.lower() for source in sources}
    strict_dynamic = "'strict-dynamic'" in lowered
    trusts_markup = strict_dynamic or any(_NONCE_OR_HASH.fullmatch(s) for s in lowered)
    issues = []
    if "'unsafe-inline'" in lowered and not trusts_markup:
        issues.append(ScriptIssue.UNSAFE_INLINE)
    if "'unsafe-eval'" in lowered:
        issues.append(ScriptIssue.UNSAFE_EVAL)
    if not strict_dynamic and any(_allows_any_host(source) for source in lowered):
        issues.append(ScriptIssue.ANY_HOST)
    if not strict_dynamic and "data:" in lowered:
        issues.append(ScriptIssue.DATA_URL)
    return issues


@dataclass(frozen=True)
class ScriptRestriction:
    """The source lists that govern scripts in one policy; None where nothing does."""

    elements: ScriptSources | None
    """<script> elements: script-src-elem, else script-src, else default-src."""
    attributes: ScriptSources | None
    """Inline event handlers: script-src-attr, else script-src, else default-src."""
    evaluation: ScriptSources | None
    """eval() and similar: script-src, else default-src."""

    def __str__(self) -> str:
        lists = (self.elements, self.attributes, self.evaluation)
        return "; ".join(str(s) for s in dict.fromkeys(s for s in lists if s is not None))

    def issues(self) -> set[ScriptIssue]:
        """Weaknesses of this policy.

        A missing list allows everything it would govern: with only
        script-src-elem, inline event handlers and eval() are unrestricted.
        """
        found: set[ScriptIssue] = set()
        if self.elements is None:
            found |= {ScriptIssue.UNSAFE_INLINE, ScriptIssue.ANY_HOST}
        else:
            found |= set(script_source_issues(self.elements.sources)) - {ScriptIssue.UNSAFE_EVAL}
        if self.attributes is None or ScriptIssue.UNSAFE_INLINE in script_source_issues(
            self.attributes.sources
        ):
            found.add(ScriptIssue.UNSAFE_INLINE)
        if self.evaluation is None or ScriptIssue.UNSAFE_EVAL in script_source_issues(
            self.evaluation.sources
        ):
            found.add(ScriptIssue.UNSAFE_EVAL)
        return found


def script_restriction(policy: CspPolicy) -> ScriptRestriction | None:
    """How ``policy`` restricts scripts, or None if no directive governs scripts at all."""
    restriction = ScriptRestriction(
        elements=_governing(policy, _ELEMENT_DIRECTIVES),
        attributes=_governing(policy, _ATTRIBUTE_DIRECTIVES),
        evaluation=_governing(policy, _EVAL_DIRECTIVES),
    )
    if restriction.elements is None and restriction.attributes is None:
        return None
    return restriction


def shared_script_issues(restrictions: Sequence[ScriptRestriction]) -> list[ScriptIssue]:
    """Weaknesses present in every restriction.

    A script must be allowed by every enforced policy, so a weakness in one
    policy is closed by any other policy that does not share it.
    """
    if not restrictions:
        return []
    common = set.intersection(*(r.issues() for r in restrictions))
    return [issue for issue in ScriptIssue if issue in common]


_CSP_FIX = (
    "Send a Content-Security-Policy header that limits scripts, e.g. script-src "
    "'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'. Roll it out "
    "with Content-Security-Policy-Report-Only first to find what it would block."
)


MAX_POLICIES_SHOWN = 3


def _listed(label: str, values: Sequence[str], noun: str) -> list[Evidence]:
    """One item per value, up to MAX_POLICIES_SHOWN, then a count of the rest."""
    items = [evidence(label, _truncate(value)) for value in values[:MAX_POLICIES_SHOWN]]
    if len(values) > MAX_POLICIES_SHOWN:
        items.append(evidence(f"More {noun}", f"{len(values) - MAX_POLICIES_SHOWN} not shown"))
    return items


def evaluate_csp(page: HttpResponse) -> Outcome:
    headers = [value for value in page.header_all("content-security-policy") if value.strip()]
    metas = find_meta_csp(page.text())
    policies = parse_csp(headers) + [p for c in metas if (p := meta_csp_policy(c))]
    found = _listed("Policy", headers, "policy headers")
    found += _listed("Policy (meta element)", metas, "meta policies")

    if not policies:
        report_only = page.header_all("content-security-policy-report-only")
        if any(value.strip() for value in report_only):
            return Outcome(
                Status.WARN,
                "Only a report-only Content Security Policy is sent, so browsers report "
                "violations but block nothing.",
                [evidence("Report-only policy", _truncate(report_only[0]))],
                "Once the report-only policy causes no unexpected reports, send it as "
                "Content-Security-Policy so browsers enforce it.",
            )
        return Outcome(
            Status.FAIL, "No Content Security Policy is enforced on the home page.", found, _CSP_FIX
        )

    restrictions = [r for policy in policies if (r := script_restriction(policy)) is not None]
    if not restrictions:
        found.append(evidence("Script sources", "not restricted"))
        return Outcome(
            Status.WARN,
            "The Content Security Policy does not restrict scripts: it has no script-src, "
            "script-src-elem, script-src-attr or default-src directive.",
            found,
            "Add a script-src directive, e.g. script-src 'nonce-{random}' 'strict-dynamic', or "
            "default-src 'self' as a baseline.",
        )

    found += _listed("Script sources", [str(r) for r in restrictions], "script restrictions")
    if len(restrictions) > 1:
        found.append(
            evidence(
                "Note",
                f"{len(restrictions)} policies restrict scripts; a script must be allowed by "
                "every one, so only weaknesses they share count.",
            )
        )
    issues = shared_script_issues(restrictions)
    if issues:
        found.append(evidence("Issues", "; ".join(_ISSUE_DETAILS[i] for i in issues)))
        return Outcome(
            Status.WARN,
            f"The Content Security Policy allows unsafe script sources: "
            f"{_join([str(i) for i in issues])}.",
            found,
            "Replace 'unsafe-inline' with nonces or hashes, drop 'unsafe-eval', and list "
            "specific hosts instead of * or bare schemes, e.g. script-src 'nonce-{random}' "
            "'strict-dynamic'.",
        )
    return Outcome(
        Status.PASS, "The Content Security Policy restricts scripts without unsafe sources.", found
    )


# --- Clickjacking ------------------------------------------------------------

_FRAMING_FIX = (
    "Send Content-Security-Policy: frame-ancestors 'self' (or 'none' if the site is never "
    "framed); X-Frame-Options: SAMEORIGIN additionally covers very old browsers."
)


def evaluate_clickjacking(page: HttpResponse) -> Outcome:
    # frame-ancestors only works from a header policy, never from <meta>.
    policies = parse_csp(page.header_all("content-security-policy"))
    ancestors = [p["frame-ancestors"] for p in policies if "frame-ancestors" in p]
    xfo = page.header_all("x-frame-options")

    if ancestors:
        found = [
            evidence("frame-ancestors", " ".join(a) or "(empty, same as 'none')") for a in ancestors
        ]
        if xfo:
            found.append(
                evidence(
                    "X-Frame-Options",
                    f"{_truncate(', '.join(xfo))} (ignored because frame-ancestors is set)",
                )
            )
        restrictive = [a for a in ancestors if not any(_allows_any_host(s) for s in a)]
        if not restrictive:
            return Outcome(
                Status.FAIL,
                "CSP frame-ancestors allows any site to frame the page.",
                found,
                _FRAMING_FIX,
            )
        allowed = " ".join(restrictive[0]) or "'none'"
        return Outcome(
            Status.PASS, f"CSP frame-ancestors limits who can frame the page ({allowed}).", found
        )

    found = [evidence("X-Frame-Options", _truncate(", ".join(xfo)))] if xfo else []
    # HTML's X-Frame-Options processing: any DENY or SAMEORIGIN among the values blocks.
    tokens = [token.lower() for token in split_header_values(xfo)]
    blocking = next((t for t in ("deny", "sameorigin") if t in tokens), None)
    if blocking:
        return Outcome(
            Status.PASS,
            f"X-Frame-Options is {blocking.upper()}, so other sites cannot frame the page.",
            found,
        )
    if any(token.startswith("allow-from") for token in tokens):
        return Outcome(
            Status.WARN,
            "X-Frame-Options uses the obsolete ALLOW-FROM, which modern browsers ignore.",
            found,
            "Replace ALLOW-FROM with Content-Security-Policy: frame-ancestors 'self' "
            "https://partner.example, listing the sites allowed to frame the page.",
        )
    if tokens:
        return Outcome(
            Status.FAIL,
            "X-Frame-Options has an unrecognized value, so it does not stop framing.",
            found,
            _FRAMING_FIX,
        )
    return Outcome(
        Status.FAIL,
        "Neither CSP frame-ancestors nor X-Frame-Options is set, so any site can frame the page.",
        found,
        _FRAMING_FIX,
    )


# --- X-Content-Type-Options --------------------------------------------------

_NOSNIFF_FIX = (
    "Send X-Content-Type-Options: nosniff on every response, together with a correct Content-Type."
)


def evaluate_content_type_options(page: HttpResponse) -> Outcome:
    # Fetch standard: only the first value counts.
    values = split_header_values(page.header_all("x-content-type-options"))
    if not values:
        return Outcome(Status.FAIL, "No X-Content-Type-Options header is sent.", [], _NOSNIFF_FIX)
    found = [evidence("X-Content-Type-Options", _truncate(", ".join(values)))]
    if values[0].lower() == "nosniff":
        return Outcome(Status.PASS, "X-Content-Type-Options is set to nosniff.", found)
    return Outcome(
        Status.FAIL,
        f"X-Content-Type-Options is {_truncate(values[0], 60)!r} instead of nosniff.",
        found,
        _NOSNIFF_FIX,
    )


# --- Referrer-Policy ---------------------------------------------------------

_STRICT_REFERRER = frozenset(
    {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
)
_LOOSE_REFERRER: dict[str, str] = {
    "origin": "sends the site's origin to every destination, even over plain HTTP",
    "origin-when-cross-origin": "sends the origin cross-site even over plain HTTP",
    "no-referrer-when-downgrade": "sends full URLs, path and query included, to other HTTPS sites",
}
_UNSAFE_REFERRER = "unsafe-url"
REFERRER_POLICIES = _STRICT_REFERRER | _LOOSE_REFERRER.keys() | {_UNSAFE_REFERRER}

_REFERRER_FIX = (
    "Send Referrer-Policy: strict-origin-when-cross-origin, or no-referrer or same-origin "
    "for stricter privacy."
)


def resolve_referrer_policy(values: Iterable[str]) -> str | None:
    """The policy browsers apply: the last recognized token, or None (W3C Referrer Policy 8.1)."""
    policy = None
    for token in split_header_values(values):
        if token.lower() in REFERRER_POLICIES:
            policy = token.lower()
    return policy


def evaluate_referrer_policy(page: HttpResponse) -> Outcome:
    values = page.header_all("referrer-policy")
    policy = resolve_referrer_policy(values)
    found = [evidence("Referrer-Policy", _truncate(", ".join(values)))] if values else []
    if policy is None:
        summary = (
            "Referrer-Policy has no recognized value, so browsers use their default "
            "(strict-origin-when-cross-origin)."
            if values
            else "No Referrer-Policy header is sent; browsers default to "
            "strict-origin-when-cross-origin, but the site states no policy."
        )
        return Outcome(Status.WARN, summary, found, _REFERRER_FIX)
    found.append(evidence("Effective policy", policy))
    if policy in _STRICT_REFERRER:
        return Outcome(Status.PASS, f"Referrer-Policy is {policy}.", found)
    if policy == _UNSAFE_REFERRER:
        return Outcome(
            Status.FAIL,
            "Referrer-Policy is unsafe-url, which sends full URLs, path and query included, to "
            "every site, even over plain HTTP.",
            found,
            _REFERRER_FIX,
        )
    return Outcome(
        Status.WARN,
        f"Referrer-Policy is {policy}, which {_LOOSE_REFERRER[policy]}.",
        found,
        _REFERRER_FIX,
    )


# --- Server version disclosure -----------------------------------------------

_VERSION = re.compile(r"[0-9]+\.[0-9]+")
_DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


def has_version(value: str) -> bool:
    """Whether a header value contains a version number such as 1.24."""
    return _VERSION.search(value) is not None


def evaluate_server_disclosure(page: HttpResponse) -> Outcome:
    present = [
        (name, value)
        for name in _DISCLOSURE_HEADERS
        for value in page.header_all(name)
        if value.strip()
    ]
    found = [evidence(name, _truncate(value)) for name, value in present]
    versioned = list(dict.fromkeys(name for name, value in present if has_version(value)))
    if versioned:
        summary = (
            f"The {versioned[0]} header reveals a software version."
            if len(versioned) == 1
            else f"The {_join(versioned)} headers reveal software versions."
        )
        return Outcome(
            Status.FAIL,
            summary,
            found,
            "Hide version numbers: server_tokens off; in nginx, ServerTokens Prod in Apache, "
            'expose_php = Off in PHP, and enableVersionHeader="false" for ASP.NET. Remove '
            "X-Powered-By entirely.",
        )
    powered_by = page.header("x-powered-by")
    if powered_by is not None and powered_by.strip():
        return Outcome(
            Status.WARN,
            f"X-Powered-By names the technology behind the site ({_truncate(powered_by, 60)}) "
            "without a version.",
            found,
            'Remove the X-Powered-By header (for example app.disable("x-powered-by") in '
            "Express); browsers do not use it.",
        )
    return Outcome(Status.PASS, "No software version numbers are exposed in server headers.", found)


# --- Permissions-Policy (informational) --------------------------------------

_EMPTY_ALLOWLIST = re.compile(r"\(\s*\)")


def parse_permissions_policy(values: Iterable[str]) -> dict[str, str]:
    """Feature -> allowlist from Permissions-Policy values (a structured-field dictionary).

    Parameters such as report-to are dropped, members without a value are
    skipped, and a repeated feature keeps its last allowlist.
    """
    features: dict[str, str] = {}
    for member in split_header_values(values):
        name, has_value, allowlist = member.partition("=")
        if has_value and name.strip():
            features[name.strip()] = _split_unquoted(allowlist, ";")[0].strip()
    return features


def evaluate_permissions_policy(page: HttpResponse) -> Outcome:
    values = page.header_all("permissions-policy")
    if not values:
        legacy = page.header("feature-policy") is not None
        note = " (only the older Feature-Policy header is sent)" if legacy else ""
        return Outcome(
            Status.INFO,
            f"Permissions-Policy is not set{note}.",
            [],
            "Optionally send Permissions-Policy to switch off browser features the site does not "
            "use, e.g. camera=(), microphone=(), geolocation=().",
        )
    features = parse_permissions_policy(values)
    disabled = [name for name, allow in features.items() if _EMPTY_ALLOWLIST.fullmatch(allow)]
    open_to_all = [name for name, allow in features.items() if allow == "*"]
    limited = [name for name in features if name not in disabled and name not in open_to_all]
    restricted = disabled + limited
    found = [evidence("Header", _truncate(", ".join(values)))]
    for label, names in (
        ("Disabled", disabled),
        ("Limited to listed origins", limited),
        ("Allowed for all origins", open_to_all),
    ):
        if names:
            found.append(evidence(label, _truncate(", ".join(names))))
    if not restricted:
        return Outcome(Status.INFO, "Permissions-Policy is set but restricts no features.", found)
    plural = "" if len(restricted) == 1 else "s"
    return Outcome(
        Status.INFO,
        f"Permissions-Policy restricts {len(restricted)} feature{plural}: {_preview(restricted)}.",
        found,
    )


# --- Deprecated headers (informational) --------------------------------------

_DEPRECATED_ADVICE: dict[str, str] = {
    "X-XSS-Protection": "Remove X-XSS-Protection or set it to 0: browsers dropped the XSS "
    "filter, which could itself be abused, and CSP replaces it.",
    "Expect-CT": "Remove Expect-CT: browsers enforce Certificate Transparency without it.",
    "Public-Key-Pins": "Remove Public-Key-Pins: browsers no longer support key pinning.",
    "Public-Key-Pins-Report-Only": "Remove Public-Key-Pins-Report-Only: browsers no longer "
    "support key pinning.",
}


def find_deprecated_headers(page: HttpResponse) -> list[tuple[str, str]]:
    """(name, value) of deprecated security headers the page still sends."""
    found = []
    for name in _DEPRECATED_ADVICE:
        for value in page.header_all(name):
            # X-XSS-Protection: 0 explicitly disables the old filter, as OWASP advises.
            disabled = name == "X-XSS-Protection" and value.split(";")[0].strip() == "0"
            if value.strip() and not disabled:
                found.append((name, value))
    return found


def evaluate_deprecated_headers(page: HttpResponse) -> Outcome:
    deprecated = find_deprecated_headers(page)
    if not deprecated:
        return Outcome(Status.INFO, "No deprecated security headers are sent.")
    names = list(dict.fromkeys(name for name, _ in deprecated))
    return Outcome(
        Status.INFO,
        f"Deprecated security headers are sent: {_join(names)}.",
        [evidence(name, _truncate(value)) for name, value in deprecated],
        " ".join(_DEPRECATED_ADVICE[name] for name in names),
    )


# --- Registry ----------------------------------------------------------------

_MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/"
_OWASP = "https://cheatsheetseries.owasp.org/cheatsheets/"


def _ref(title: str, url: str) -> Reference:
    return Reference(title=title, url=url)


_OWASP_HEADERS = _ref("OWASP HTTP Headers Cheat Sheet", _OWASP + "HTTP_Headers_Cheat_Sheet.html")

CHECKS: tuple[Check, ...] = (
    Check(
        "transport.hsts",
        "HTTP Strict Transport Security",
        Category.TRANSPORT,
        10,
        on_homepage(evaluate_hsts),
        (
            _ref(
                "RFC 6797: HTTP Strict Transport Security",
                "https://www.rfc-editor.org/rfc/rfc6797.html",
            ),
            _ref("MDN: Strict-Transport-Security", _MDN + "Strict-Transport-Security"),
            _ref(
                "OWASP HTTP Strict Transport Security Cheat Sheet",
                _OWASP + "HTTP_Strict_Transport_Security_Cheat_Sheet.html",
            ),
        ),
    ),
    Check(
        "headers.csp",
        "Content Security Policy",
        Category.HEADERS,
        10,
        on_homepage(evaluate_csp),
        (
            _ref("MDN: Content-Security-Policy", _MDN + "Content-Security-Policy"),
            _ref("MDN: CSP script-src", _MDN + "Content-Security-Policy/script-src"),
            _ref("W3C: Content Security Policy Level 3", "https://www.w3.org/TR/CSP3/"),
            _ref(
                "OWASP Content Security Policy Cheat Sheet",
                _OWASP + "Content_Security_Policy_Cheat_Sheet.html",
            ),
        ),
    ),
    Check(
        "headers.clickjacking",
        "Clickjacking protection",
        Category.HEADERS,
        5,
        on_homepage(evaluate_clickjacking),
        (
            _ref("MDN: CSP frame-ancestors", _MDN + "Content-Security-Policy/frame-ancestors"),
            _ref("MDN: X-Frame-Options", _MDN + "X-Frame-Options"),
            _ref(
                "OWASP Clickjacking Defense Cheat Sheet",
                _OWASP + "Clickjacking_Defense_Cheat_Sheet.html",
            ),
        ),
    ),
    Check(
        "headers.content_type_options",
        "X-Content-Type-Options",
        Category.HEADERS,
        5,
        on_homepage(evaluate_content_type_options),
        (_ref("MDN: X-Content-Type-Options", _MDN + "X-Content-Type-Options"), _OWASP_HEADERS),
    ),
    Check(
        "headers.referrer_policy",
        "Referrer-Policy",
        Category.HEADERS,
        5,
        on_homepage(evaluate_referrer_policy),
        (
            _ref("MDN: Referrer-Policy", _MDN + "Referrer-Policy"),
            _ref("W3C: Referrer Policy", "https://www.w3.org/TR/referrer-policy/"),
        ),
    ),
    Check(
        "headers.server_disclosure",
        "Server version disclosure",
        Category.HEADERS,
        5,
        on_homepage(evaluate_server_disclosure),
        (_ref("MDN: Server", _MDN + "Server"), _OWASP_HEADERS),
    ),
    Check(
        "info.permissions_policy",
        "Permissions-Policy",
        Category.INFO,
        0,
        on_homepage(evaluate_permissions_policy),
        (
            _ref("MDN: Permissions-Policy", _MDN + "Permissions-Policy"),
            _ref("W3C: Permissions Policy", "https://www.w3.org/TR/permissions-policy/"),
        ),
    ),
    Check(
        "info.deprecated_headers",
        "Deprecated headers",
        Category.INFO,
        0,
        on_homepage(evaluate_deprecated_headers),
        (
            _ref("MDN: X-XSS-Protection", _MDN + "X-XSS-Protection"),
            _ref("MDN: Expect-CT", _MDN + "Expect-CT"),
            _OWASP_HEADERS,
        ),
    ),
)
