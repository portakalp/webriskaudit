"""Email authentication checks: SPF, DMARC and DKIM, read from public DNS.

Parsing and evaluation are pure functions, so they are tested without DNS; the
check functions only look up TXT records and hand them over.
"""

import asyncio
import ipaddress
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from webriskaudit.checks.base import Check, Outcome, evidence
from webriskaudit.context import ScanContext
from webriskaudit.models import Category, Evidence, Reference, Status
from webriskaudit.net.types import DnsUnavailableError, NoAnswerError, NxDomainError, Resolver

EVIDENCE_LIMIT = 300

_SEVERITY = {Status.PASS: 0, Status.WARN: 1, Status.FAIL: 2}


def _truncate(value: str, limit: int = EVIDENCE_LIMIT) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


async def _txt(resolver: Resolver, name: str) -> list[str]:
    """TXT records of ``name``; a missing name or record type gives an empty list.

    Raises DnsUnavailableError.
    """
    try:
        return await resolver.txt(name)
    except (NxDomainError, NoAnswerError):
        return []


@dataclass(frozen=True)
class _Finding:
    status: Status
    summary: str
    remediation: str | None = None


def _combine(findings: Sequence[_Finding], items: list[Evidence]) -> Outcome:
    """The worst finding sets status and summary; every non-pass finding adds its fix."""
    worst = max(findings, key=lambda finding: _SEVERITY[finding.status])
    fixes = [f.remediation for f in findings if f.status is not Status.PASS and f.remediation]
    return Outcome(worst.status, worst.summary, items, " ".join(fixes) or None)


# --- SPF (RFC 7208) ------------------------------------------------------------

SPF_LOOKUP_LIMIT = 10
_LOOKUP_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists"})
_QUALIFIER_RESULTS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}

# RFC 7208 section 7.1: domain-spec = macro-string domain-end.
_MACRO_EXPAND = r"%\{[slodiphcrtv][0-9]*r?[-.+,/_=]*\}|%%|%_|%-"
_MACRO_LITERAL = r"[\x21-\x24\x26-\x7e]"
_MACRO_STRING = re.compile(rf"(?:{_MACRO_EXPAND}|{_MACRO_LITERAL})*", re.IGNORECASE)
_ENDS_WITH_MACRO = re.compile(
    rf"(?:{_MACRO_EXPAND}|{_MACRO_LITERAL})*(?:{_MACRO_EXPAND})", re.IGNORECASE
)
_DOMAIN_END = re.compile(r"\.([^.]+)\.?\Z")
_TOPLABEL = re.compile(r"[a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9-]*[a-z0-9]", re.IGNORECASE)

_MODIFIER = re.compile(r"([a-z][a-z0-9._-]*)=(.*)", re.IGNORECASE | re.DOTALL)
_MECHANISM = re.compile(r"([-+?~]?)([a-z0-9]+)(.*)", re.IGNORECASE | re.DOTALL)
_DUAL_CIDR = re.compile(r"(?::(.+?))?(?:/(0|[1-9][0-9]?))?(?://(0|[1-9][0-9]{0,2}))?", re.DOTALL)
_CIDR_LENGTH = re.compile(r"0|[1-9][0-9]{0,2}")


class SpfSyntaxError(ValueError):
    """A term that makes receivers return permerror (RFC 7208 sections 4.6.1 and 6)."""


@dataclass(frozen=True)
class SpfTerm:
    """One mechanism of an SPF record."""

    text: str
    """The term as written, e.g. ``~all``."""
    name: str
    """Lower-cased mechanism name, e.g. ``include``."""
    value: str = ""
    """What follows the name, without a leading ":", e.g. ``_spf.example.net`` or ``/24``."""
    qualifier: str = ""
    """``+``, ``-``, ``~`` or ``?`` as written; empty for an implicit ``+``."""


@dataclass(frozen=True)
class SpfRecord:
    """A syntactically valid SPF record."""

    mechanisms: tuple[SpfTerm, ...]
    redirect: str | None = None
    exp: str | None = None
    unknown_modifiers: tuple[str, ...] = ()
    """Unrecognized modifiers, which receivers ignore (RFC 7208 section 6)."""

    @property
    def all_term(self) -> SpfTerm | None:
        """The first ``all`` mechanism; evaluation never gets past it."""
        return next((term for term in self.mechanisms if term.name == "all"), None)

    @property
    def redirect_in_effect(self) -> bool:
        """A redirect is ignored when the record has an ``all`` mechanism (section 6.1)."""
        return self.redirect is not None and self.all_term is None

    @property
    def evaluated(self) -> tuple[SpfTerm, ...]:
        """Mechanisms up to and including the first ``all``.

        Receivers never test mechanisms after ``all`` (section 5.1), so they
        cause no DNS lookups.
        """
        end = next((i for i, term in enumerate(self.mechanisms) if term.name == "all"), None)
        return self.mechanisms if end is None else self.mechanisms[: end + 1]

    @property
    def lookup_count(self) -> int:
        """DNS-querying terms at the top level (section 4.6.4); includes are not expanded."""
        count = sum(1 for term in self.evaluated if term.name in _LOOKUP_MECHANISMS)
        return count + int(self.redirect_in_effect)


def is_spf_record(txt: str) -> bool:
    """True if a TXT record starts with ``v=spf1`` (any case) followed by a space or its end."""
    return txt[:6].lower() == "v=spf1" and txt[6:7] in ("", " ")


def _valid_domain_spec(spec: str) -> bool:
    if not _MACRO_STRING.fullmatch(spec):
        return False
    if _ENDS_WITH_MACRO.fullmatch(spec):
        return True
    end = _DOMAIN_END.search(spec)
    return end is not None and _TOPLABEL.fullmatch(end.group(1)) is not None


def _no_argument(rest: str) -> bool:
    return rest == ""


def _required_domain(rest: str) -> bool:
    return rest.startswith(":") and _valid_domain_spec(rest[1:])


def _optional_domain(rest: str) -> bool:
    return rest == "" or _required_domain(rest)


def _domain_and_cidr(rest: str) -> bool:
    match = _DUAL_CIDR.fullmatch(rest)
    if match is None:
        return False
    domain, ip4_length, ip6_length = match.groups()
    return (
        (domain is None or _valid_domain_spec(domain))
        and (ip4_length is None or int(ip4_length) <= 32)
        and (ip6_length is None or int(ip6_length) <= 128)
    )


def _network(rest: str, version: int) -> bool:
    if not rest.startswith(":"):
        return False
    address, slash, length = rest[1:].partition("/")
    max_length = 32 if version == 4 else 128
    if slash and not (_CIDR_LENGTH.fullmatch(length) and int(length) <= max_length):
        return False
    if "%" in address:  # zone ids are not part of the ip6 syntax
        return False
    try:
        return ipaddress.ip_address(address).version == version
    except ValueError:
        return False


_MECHANISM_SYNTAX: dict[str, Callable[[str], bool]] = {
    "all": _no_argument,
    "include": _required_domain,
    "exists": _required_domain,
    "a": _domain_and_cidr,
    "mx": _domain_and_cidr,
    "ptr": _optional_domain,
    "ip4": lambda rest: _network(rest, 4),
    "ip6": lambda rest: _network(rest, 6),
}


def _short(term: str) -> str:
    return _truncate(term, 60)


def _parse_mechanism(term: str) -> SpfTerm:
    match = _MECHANISM.fullmatch(term)
    if match is None:
        raise SpfSyntaxError(f'an invalid term "{_short(term)}"')
    qualifier, name, rest = match.group(1), match.group(2).lower(), match.group(3)
    syntax = _MECHANISM_SYNTAX.get(name)
    if syntax is None:
        raise SpfSyntaxError(f'an unknown mechanism "{_short(term)}"')
    if not syntax(rest):
        raise SpfSyntaxError(f'an invalid term "{_short(term)}"')
    return SpfTerm(term, name, rest.removeprefix(":"), qualifier)


def parse_spf(record: str) -> SpfRecord:
    """Parse an SPF record into its terms.

    Raises SpfSyntaxError for everything RFC 7208 turns into permerror: a record
    without the version, an unknown mechanism, a malformed term, or a repeated
    redirect or exp modifier. Unknown modifiers are kept aside, not rejected.
    """
    if not is_spf_record(record):
        raise SpfSyntaxError('no "v=spf1" version at the start')
    mechanisms: list[SpfTerm] = []
    modifiers: dict[str, str] = {}
    unknown: list[str] = []
    for term in record.split()[1:]:
        modifier = _MODIFIER.fullmatch(term)
        if modifier is None:
            mechanisms.append(_parse_mechanism(term))
            continue
        name, value = modifier.group(1).lower(), modifier.group(2)
        if name in ("redirect", "exp"):
            if name in modifiers:
                raise SpfSyntaxError(f"more than one {name} modifier")
            if not _valid_domain_spec(value):
                raise SpfSyntaxError(f'an invalid term "{_short(term)}"')
            modifiers[name] = value
        elif _MACRO_STRING.fullmatch(value):
            unknown.append(term)
        else:
            raise SpfSyntaxError(f'an invalid term "{_short(term)}"')
    return SpfRecord(
        mechanisms=tuple(mechanisms),
        redirect=modifiers.get("redirect"),
        exp=modifiers.get("exp"),
        unknown_modifiers=tuple(unknown),
    )


def _spf_all_finding(spf: SpfRecord) -> _Finding:
    term = spf.all_term
    if term is None:
        if spf.redirect is not None:
            return _Finding(
                Status.PASS,
                f"The SPF record delegates its policy to {spf.redirect} with a redirect modifier.",
            )
        return _Finding(
            Status.WARN,
            "The SPF record has no all mechanism or redirect, so mail from servers it does "
            "not list gets a neutral result.",
            'End the record with "-all" (or "~all" while testing), for example '
            '"v=spf1 include:_spf.example.net -all".',
        )
    qualifier = term.qualifier or "+"
    if qualifier == "-":
        return _Finding(
            Status.PASS,
            "The SPF record uses -all, so mail from servers it does not list fails SPF.",
        )
    if qualifier == "~":
        return _Finding(
            Status.PASS,
            "The SPF record uses ~all, so mail from servers it does not list gets a softfail "
            "result.",
        )
    if qualifier == "?":
        return _Finding(
            Status.WARN,
            "The SPF record uses ?all, so mail from servers it does not list gets a neutral "
            "result.",
            'Replace "?all" with "~all", or with "-all" once every legitimate sender is listed.',
        )
    return _Finding(
        Status.FAIL,
        f"The SPF record uses {term.text}, which authorizes every server on the internet to "
        "send mail for the domain.",
        f'Replace "{term.text}" with "-all" (or "~all" while testing) so only the listed servers '
        "are authorized.",
    )


def _spf_findings(spf: SpfRecord) -> list[_Finding]:
    findings = [_spf_all_finding(spf)]
    if spf.lookup_count > SPF_LOOKUP_LIMIT:
        findings.append(
            _Finding(
                Status.WARN,
                f"The SPF record has {spf.lookup_count} DNS-querying terms at the top level, "
                f"more than the {SPF_LOOKUP_LIMIT} RFC 7208 allows, so evaluation can end in a "
                "permanent error.",
                f"Bring include, a, mx, ptr, exists and redirect terms down to "
                f"{SPF_LOOKUP_LIMIT} or fewer, for example by replacing a and mx with ip4/ip6 "
                "ranges.",
            )
        )
    if any(term.name == "ptr" for term in spf.mechanisms):
        findings.append(
            _Finding(
                Status.WARN,
                "The SPF record uses the ptr mechanism, which RFC 7208 says should not be "
                "published.",
                "Replace ptr with ip4, ip6 or include terms for the servers that send the "
                "domain's mail.",
            )
        )
    return findings


def _spf_evidence(record: str, spf: SpfRecord) -> list[Evidence]:
    term = spf.all_term
    items = [
        evidence("Record", _truncate(record)),
        evidence(
            "all mechanism",
            f"{term.text} ({_QUALIFIER_RESULTS[term.qualifier or '+']})" if term else "none",
        ),
    ]
    if spf.redirect is not None:
        note = (
            "policy delegated, not expanded"
            if spf.redirect_in_effect
            else "ignored because the record has an all mechanism"
        )
        items.append(evidence("redirect", f"{spf.redirect} ({note})"))
    items.append(
        evidence(
            "DNS lookups at the top level",
            f"{spf.lookup_count} of {SPF_LOOKUP_LIMIT} (nested includes are not expanded)",
        )
    )
    if after_all := spf.mechanisms[len(spf.evaluated) :]:
        unused = " ".join(mechanism.text for mechanism in after_all)
        items.append(evidence("Never evaluated (after all)", _truncate(unused)))
    if spf.unknown_modifiers:
        ignored = ", ".join(spf.unknown_modifiers)
        items.append(evidence("Ignored unknown modifiers", _truncate(ignored)))
    return items


def evaluate_spf(txt_records: Sequence[str]) -> Outcome:
    """Verdict on a domain's TXT records: selection, syntax, all qualifier, lookups, ptr."""
    records = [txt for txt in txt_records if is_spf_record(txt)]
    if not records:
        items: list[Evidence] = []
        remediation = (
            "Publish one TXT record that lists the servers sending mail for the domain, for "
            'example "v=spf1 include:_spf.example.net -all", or "v=spf1 -all" if the domain '
            "sends no mail."
        )
        lookalike = next((txt for txt in txt_records if "v=spf1" in txt.lower()), None)
        if lookalike is not None:
            items.append(evidence("Ignored TXT record", _truncate(lookalike)))
            remediation += ' Receivers ignore a TXT record unless it starts with "v=spf1".'
        return Outcome(Status.FAIL, "The domain publishes no SPF record.", items, remediation)
    if len(records) > 1:
        return Outcome(
            Status.FAIL,
            f"The domain publishes {len(records)} SPF records, which receivers treat as a "
            "permanent error.",
            [evidence(f"SPF record {i}", _truncate(r)) for i, r in enumerate(records, 1)],
            "Merge them into a single TXT record that starts with v=spf1.",
        )
    record = records[0]
    try:
        spf = parse_spf(record)
    except SpfSyntaxError as exc:
        return Outcome(
            Status.FAIL,
            f"The SPF record has {exc}, which receivers treat as a permanent error.",
            [evidence("Record", _truncate(record))],
            "Fix or remove that term: one invalid term makes SPF evaluation fail with a "
            "permanent error for all mail.",
        )
    return _combine(_spf_findings(spf), _spf_evidence(record, spf))


async def check_spf(ctx: ScanContext) -> Outcome:
    try:
        records = await _txt(ctx.resolver, ctx.domain)
    except DnsUnavailableError:
        return Outcome(
            Status.INCONCLUSIVE, "The SPF record could not be looked up because DNS did not answer."
        )
    return evaluate_spf(records)


# --- DMARC (RFC 9989) ----------------------------------------------------------

DMARC_POLICIES = ("none", "quarantine", "reject")
DMARC_MAX_LABELS = 7
"""RFC 9989 section 4.10: a walk from a name of eight or more labels jumps to seven."""

_DMARC_LOOKALIKE = re.compile(r"\s*v\s*=\s*dmarc1\b", re.IGNORECASE)
_URI = re.compile(r"[a-z][a-z0-9+.-]*:\S+", re.IGNORECASE)


def parse_dmarc_tags(record: str) -> dict[str, str] | None:
    """Tags of a DMARC record, or None if the TXT record is not one.

    The first tag must be ``v=DMARC1`` with the value in exactly that case
    (RFC 9989 section 4.7). Keys are lower-cased and values trimmed; parts
    without "=" are skipped and the first of a repeated tag wins.
    """
    head, *rest = record.split(";")
    name, sep, version = head.partition("=")
    if not sep or name.strip().lower() != "v" or version.strip() != "DMARC1":
        return None
    tags = {"v": "DMARC1"}
    for part in rest:
        key, sep, value = part.partition("=")
        key = key.strip().lower()
        if sep and key:
            tags.setdefault(key, value.strip())
    return tags


def _policy_value(value: str | None) -> str | None:
    policy = (value or "").strip().lower()
    return policy if policy in DMARC_POLICIES else None


def _has_valid_rua(tags: Mapping[str, str]) -> bool:
    return any(_URI.fullmatch(uri.strip()) for uri in tags.get("rua", "").split(","))


def dmarc_policy_problem(tags: Mapping[str, str]) -> str | None:
    """Describe a missing or invalid p, or an invalid sp or np tag (RFC 9989 4.10.1)."""
    if "p" not in tags:
        return "no p tag"
    for key in ("p", "sp", "np"):
        if key in tags and _policy_value(tags[key]) is None:
            return f'an invalid {key} tag ("{_truncate(tags[key], 40)}")'
    return None


def effective_dmarc_policy(tags: Mapping[str, str], *, subdomain: bool) -> str | None:
    """The policy receivers apply, or None if they apply no DMARC processing.

    ``subdomain`` means the record was found at a parent of the scanned domain,
    which exists, so sp applies before p (np only covers non-existent names).
    With a missing or invalid p, or an invalid sp or np, RFC 9989 section 4.10.1
    has receivers act as if p=none when rua holds a valid URI, else skip DMARC.
    """
    if dmarc_policy_problem(tags) is not None:
        return "none" if _has_valid_rua(tags) else None
    return _policy_value(tags["sp"] if subdomain and "sp" in tags else tags["p"])


@dataclass(frozen=True)
class DmarcDiscovery:
    """What the DMARC tree walk found."""

    queried: tuple[str, ...]
    """Domains whose ``_dmarc`` name was queried, in order."""
    found_at: str | None = None
    """Domain whose ``_dmarc`` name holds DMARC records."""
    records: tuple[str, ...] = ()
    """DMARC records at that name."""
    ignored: tuple[str, ...] = ()
    """TXT records that look like DMARC but lack a valid ``v=DMARC1`` tag."""


def dmarc_lookup_names(domain: str) -> list[str]:
    """Domains whose ``_dmarc`` name the tree walk queries, starting with ``domain``.

    A simplified RFC 9989 section 4.10 walk: drop the leftmost label while at
    least two labels remain, jumping to seven labels from longer names.
    """
    labels = domain.split(".")
    shorter = range(min(len(labels) - 1, DMARC_MAX_LABELS), 1, -1)
    return [domain, *(".".join(labels[-count:]) for count in shorter)]


async def discover_dmarc(resolver: Resolver, domain: str) -> DmarcDiscovery:
    """Walk up from ``domain`` to the first name with DMARC records.

    Raises DnsUnavailableError if any lookup on the way gets no usable answer,
    since a missing record could not then be told apart from a failed lookup.
    """
    queried: list[str] = []
    ignored: list[str] = []
    for name in dmarc_lookup_names(domain):
        queried.append(name)
        txt = await _txt(resolver, f"_dmarc.{name}")
        records = tuple(record for record in txt if parse_dmarc_tags(record) is not None)
        if records:
            return DmarcDiscovery(tuple(queried), name, records)
        ignored += [record for record in txt if _DMARC_LOOKALIKE.match(record)]
    return DmarcDiscovery(tuple(queried), ignored=tuple(ignored))


def _dmarc_missing(domain: str, discovery: DmarcDiscovery) -> Outcome:
    where = "the domain" if len(discovery.queried) == 1 else "the domain or its parent domains"
    items = [evidence("Names queried", ", ".join(f"_dmarc.{n}" for n in discovery.queried))]
    remediation = (
        f'Publish a TXT record at _dmarc.{domain} such as "v=DMARC1; p=none; '
        f'rua=mailto:dmarc-reports@{domain}", then move to p=quarantine or p=reject once the '
        "reports show legitimate mail passes."
    )
    if discovery.ignored:
        items.append(evidence("Ignored TXT record", _truncate(discovery.ignored[0])))
        remediation += ' Receivers ignore a record unless it starts with "v=DMARC1;" exactly.'
    return Outcome(Status.FAIL, f"No DMARC record was found for {where}.", items, remediation)


def _dmarc_evidence(
    record: str, tags: Mapping[str, str], location: str, policy: str | None, source: str
) -> list[Evidence]:
    problem = dmarc_policy_problem(tags)
    if policy is None:
        applied = "no DMARC processing"
    elif problem is not None:
        applied = f"none (treated as p=none because of {problem})"
    else:
        applied = f"{policy} (from {source})"
    items = [
        evidence("Record", _truncate(record)),
        evidence("Found at", location),
        evidence("Effective policy", applied),
        evidence("Subdomain policy (sp)", _truncate(tags.get("sp", "not set"), 40)),
        evidence("Non-existent subdomain policy (np)", _truncate(tags.get("np", "not set"), 40)),
        evidence("Aggregate reports (rua)", "set" if _has_valid_rua(tags) else "not set"),
    ]
    for key, label in (("t", "Testing mode (t)"), ("pct", "Legacy pct")):
        if key in tags:
            items.append(evidence(label, _truncate(tags[key], 40)))
    return items


def _dmarc_verdict(
    tags: Mapping[str, str], policy: str | None, found_at: str, *, subdomain: bool
) -> tuple[Status, str, str | None]:
    record = f"The DMARC record of {found_at}" if subdomain else "The DMARC record"
    subject = f"The DMARC policy inherited from {found_at}" if subdomain else "The DMARC policy"
    example = f'"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{found_at}"'
    problem = dmarc_policy_problem(tags)
    if policy is None:
        summary = (
            f"{record} has {problem} and no valid rua address, so receivers apply no DMARC "
            "processing."
        )
        return Status.FAIL, summary, f"Set p to none, quarantine or reject, for example {example}."
    if problem is not None:
        summary = f"{record} has {problem}, so receivers treat it as p=none."
        return Status.WARN, summary, f"Set p to quarantine or reject, for example {example}."
    if policy == "none":
        target = (
            f"sp=quarantine and then sp=reject on {found_at}"
            if subdomain
            else ("p=quarantine and then p=reject")
        )
        return (
            Status.WARN,
            f"{subject} is none, so mail that fails authentication is only monitored.",
            f"Once the aggregate reports show legitimate mail passes, move to {target}.",
        )
    if tags.get("t", "").lower() == "y":
        # RFC 9989: t=y asks receivers for the next weaker policy.
        applied = "quarantine instead of reject" if policy == "reject" else "none instead"
        return (
            Status.WARN,
            f"{subject} is {policy} but in testing mode (t=y), so receivers apply {applied}.",
            "Remove t=y once the aggregate reports show legitimate mail passes.",
        )
    pct = tags.get("pct", "")
    if pct.isdigit() and int(pct) == 0:
        return (
            Status.WARN,
            f"{subject} is {policy} but pct=0, so receivers following the older RFC 7489 apply "
            "it to no messages.",
            "Remove pct=0; RFC 9989 replaced pct with t=y for testing.",
        )
    return (
        Status.PASS,
        f"{subject} is {policy}, so receivers are asked to {policy} mail that fails "
        "authentication.",
        None,
    )


def evaluate_dmarc(domain: str, discovery: DmarcDiscovery) -> Outcome:
    """Verdict on what the tree walk found for ``domain``."""
    parsed = [
        (record, tags)
        for record in discovery.records
        if (tags := parse_dmarc_tags(record)) is not None
    ]
    if discovery.found_at is None or not parsed:
        return _dmarc_missing(domain, discovery)
    location = f"_dmarc.{discovery.found_at}"
    if len(parsed) > 1:
        return Outcome(
            Status.FAIL,
            f"{len(parsed)} DMARC records are published at {location}, so receivers discard "
            "all of them.",
            [evidence(f"Record {i}", _truncate(record)) for i, (record, _) in enumerate(parsed, 1)],
            f"Keep exactly one TXT record starting with v=DMARC1 at {location}.",
        )
    record, tags = parsed[0]
    subdomain = discovery.found_at != domain
    policy = effective_dmarc_policy(tags, subdomain=subdomain)
    source = "sp" if subdomain and "sp" in tags else "p"
    if subdomain:
        location += f" (applies to {domain} as a subdomain)"
    status, summary, remediation = _dmarc_verdict(
        tags, policy, discovery.found_at, subdomain=subdomain
    )
    return Outcome(
        status, summary, _dmarc_evidence(record, tags, location, policy, source), remediation
    )


async def check_dmarc(ctx: ScanContext) -> Outcome:
    try:
        discovery = await discover_dmarc(ctx.resolver, ctx.domain)
    except DnsUnavailableError:
        return Outcome(
            Status.INCONCLUSIVE,
            "The DMARC record could not be looked up because DNS did not answer.",
        )
    return evaluate_dmarc(ctx.domain, discovery)


# --- DKIM (RFC 6376) -----------------------------------------------------------

DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "dkim",
    "mail",
    "smtp",
)

_DKIM_TAG_NAME = re.compile(r"[a-z][a-z0-9_]*", re.IGNORECASE)
_WHITESPACE = re.compile(r"\s+")


def parse_dkim_key(record: str) -> dict[str, str] | None:
    """Tags of a DKIM key record (RFC 6376 section 3.6.1), or None if it is not one.

    Tag names are case-sensitive and must not repeat (section 3.2); v=, when
    present, must come first and be DKIM1; p= is required and loses its
    whitespace. An empty p= means the key was revoked.
    """
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if not part.strip():
            continue
        name, sep, value = part.partition("=")
        name = name.strip()
        if not sep or not _DKIM_TAG_NAME.fullmatch(name) or name in tags:
            return None
        tags[name] = value.strip()
    if "v" in tags and (next(iter(tags)) != "v" or tags["v"] != "DKIM1"):
        return None
    if "p" not in tags:
        return None
    tags["p"] = _WHITESPACE.sub("", tags["p"])
    return tags


def evaluate_dkim(lookups: Mapping[str, Sequence[str] | None]) -> Outcome:
    """Verdict from the TXT records found per selector; None marks a failed lookup.

    Selectors cannot be listed, so not finding a key is inconclusive, never a fail.
    """
    keys: dict[str, str] = {}
    revoked: list[str] = []
    failed = [selector for selector, records in lookups.items() if records is None]
    for selector, records in lookups.items():
        parsed = [tags for txt in records or () if (tags := parse_dkim_key(txt)) is not None]
        active = [tags for tags in parsed if tags["p"]]
        if active:
            keys[selector] = active[0].get("k", "rsa").lower()
        elif parsed:
            revoked.append(selector)

    items: list[Evidence] = []
    if keys:
        found = ", ".join(f"{selector} ({key_type})" for selector, key_type in keys.items())
        items.append(evidence("Selectors found (key type)", found))
    if revoked:
        items.append(evidence("Revoked keys (empty p=)", ", ".join(revoked)))
    items.append(evidence("Selectors checked", ", ".join(lookups)))
    if failed:
        items.append(evidence("Lookups that failed", ", ".join(failed)))

    if keys:
        noun = "selector" if len(keys) == 1 else "selectors"
        summary = f"A DKIM public key is published under {noun} {', '.join(keys)}."
        return Outcome(Status.PASS, summary, items)
    if failed and len(failed) == len(lookups):
        summary = "The DKIM lookups failed because DNS did not answer."
    elif revoked:
        noun = "selector" if len(revoked) == 1 else "selectors"
        summary = (
            f"Only revoked DKIM keys (empty p=) were found, under {noun} {', '.join(revoked)}."
        )
    else:
        summary = (
            "No DKIM key under common selectors; selectors cannot be listed, so this does not "
            "prove DKIM is missing."
        )
    return Outcome(Status.INCONCLUSIVE, summary, items)


async def check_dkim(ctx: ScanContext) -> Outcome:
    names = [f"{selector}._domainkey.{ctx.domain}" for selector in DKIM_SELECTORS]
    results = await asyncio.gather(
        *(_txt(ctx.resolver, name) for name in names), return_exceptions=True
    )
    lookups: dict[str, list[str] | None] = {}
    for selector, result in zip(DKIM_SELECTORS, results, strict=True):
        if isinstance(result, DnsUnavailableError):
            lookups[selector] = None
        elif isinstance(result, BaseException):
            raise result
        else:
            lookups[selector] = result
    return evaluate_dkim(lookups)


# --- Registry ------------------------------------------------------------------

_RFC7208 = "https://www.rfc-editor.org/rfc/rfc7208.html"
_RFC9989 = "https://www.rfc-editor.org/rfc/rfc9989.html"

SPF_REFERENCES = (
    Reference(title="RFC 7208: Sender Policy Framework (SPF)", url=_RFC7208),
    Reference(
        title="RFC 7208, section 4.5: selecting the SPF record", url=f"{_RFC7208}#section-4.5"
    ),
    Reference(title="RFC 7208, section 4.6.4: DNS lookup limits", url=f"{_RFC7208}#section-4.6.4"),
    Reference(title='RFC 7208, section 5.5: "ptr" (do not use)', url=f"{_RFC7208}#section-5.5"),
)
DMARC_REFERENCES = (
    Reference(title="RFC 9989: DMARC", url=_RFC9989),
    Reference(
        title="RFC 9989, section 4.7: DMARC policy record format", url=f"{_RFC9989}#section-4.7"
    ),
    Reference(title="RFC 9989, section 4.10: DNS tree walk", url=f"{_RFC9989}#section-4.10"),
    Reference(
        title="RFC 9989, section 4.10.1: DMARC policy discovery", url=f"{_RFC9989}#section-4.10.1"
    ),
)
DKIM_REFERENCES = (
    Reference(
        title="RFC 6376 (DKIM), section 3.6.1: key record format",
        url="https://www.rfc-editor.org/rfc/rfc6376.html#section-3.6.1",
    ),
)

CHECKS: tuple[Check, ...] = (
    Check(
        id="email.spf",
        title="SPF record",
        category=Category.EMAIL,
        weight=10,
        run=check_spf,
        references=SPF_REFERENCES,
    ),
    Check(
        id="email.dmarc",
        title="DMARC policy",
        category=Category.EMAIL,
        weight=10,
        run=check_dmarc,
        references=DMARC_REFERENCES,
    ),
    Check(
        id="email.dkim",
        title="DKIM key",
        category=Category.EMAIL,
        weight=5,
        run=check_dkim,
        references=DKIM_REFERENCES,
    ),
)
