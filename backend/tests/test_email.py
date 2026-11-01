import re
from collections.abc import Sequence

import pytest

from webriskaudit.checks.base import Outcome, run_check
from webriskaudit.checks.email import (
    CHECKS,
    DKIM_SELECTORS,
    DmarcDiscovery,
    SpfSyntaxError,
    check_dkim,
    check_dmarc,
    check_spf,
    dmarc_lookup_names,
    dmarc_policy_problem,
    effective_dmarc_policy,
    evaluate_dkim,
    evaluate_dmarc,
    evaluate_spf,
    is_spf_record,
    parse_dkim_key,
    parse_dmarc_tags,
    parse_spf,
)
from webriskaudit.models import Category, Status
from webriskaudit.net.types import DnsUnavailableError, NxDomainError

from .fakes import DnsAnswer, FakeResolver, make_context

RUA = "rua=mailto:dmarc@example.com"
RSA_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt"
ED25519_KEY = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="


def includes(count: int) -> str:
    return " ".join(f"include:s{i}.example.net" for i in range(count))


def evidence_of(outcome: Outcome) -> dict[str, str]:
    return {item.label: item.value for item in outcome.evidence}


def dmarc_at(domain: str, *records: str, queried: Sequence[str] = ()) -> DmarcDiscovery:
    return DmarcDiscovery(tuple(queried) or (domain,), domain, records)


# --- SPF: record selection -----------------------------------------------------


@pytest.mark.parametrize(
    ("txt", "expected"),
    [
        ("v=spf1 -all", True),
        ("v=spf1", True),
        ("V=SPF1 MX -ALL", True),
        ("v=Spf1 include:_spf.example.net ~all", True),
        ("v=spf10 -all", False),
        ("v=spf1\t-all", False),
        (" v=spf1 -all", False),
        ("google-site-verification=abc v=spf1 -all", False),
        ("spf2.0/pra -all", False),
        ("", False),
    ],
)
def test_is_spf_record(txt: str, expected: bool) -> None:
    assert is_spf_record(txt) is expected


# --- SPF: parsing ---------------------------------------------------------------


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1",
        "v=spf1 -all",
        "v=spf1 a mx ip4:192.0.2.1 ip4:198.51.100.0/24 ip6:2001:db8::/32 ~all",
        "v=spf1 a:mail.example.com/28 mx:example.com//64 a/24//64 -all",
        "v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all",
        "v=spf1 include:example.com. -all",
        "v=spf1 exists:%{i}._spf.%{d} -all",
        "v=spf1 include:%{d2} -all",
        "v=spf1 ptr ptr:example.com ?all",
        "v=spf1 redirect=_spf.example.com",
        "v=spf1 -all exp=explain._spf.%{d}",
        "v=spf1 -all foo=bar",
        "v=spf1  mx   -all  ",
        "V=SPF1 MX Include:_SPF.Example.NET -ALL",
    ],
)
def test_parse_spf_accepts_valid_records(record: str) -> None:
    parse_spf(record)


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ("v=spf1 foo -all", 'unknown mechanism "foo"'),
        ("v=spf1 ip:192.0.2.1 -all", 'unknown mechanism "ip:192.0.2.1"'),
        ("v=spf1 include -all", 'invalid term "include"'),
        ("v=spf1 include: -all", 'invalid term "include:"'),
        ("v=spf1 include:192.0.2.1 -all", 'invalid term "include:192.0.2.1"'),
        ("v=spf1 include:localhost -all", 'invalid term "include:localhost"'),
        ("v=spf1 include:%{z}.example.com -all", "invalid term"),
        ("v=spf1 include:50%.example.com -all", "invalid term"),
        ("v=spf1 exists -all", 'invalid term "exists"'),
        ("v=spf1 all:example.com", 'invalid term "all:example.com"'),
        ("v=spf1 ip4:192.0.2.256 -all", "invalid term"),
        ("v=spf1 ip4:192.0.2.0/33 -all", "invalid term"),
        ("v=spf1 ip4:192.0.2.0/ -all", "invalid term"),
        ("v=spf1 ip4:2001:db8::1 -all", "invalid term"),
        ("v=spf1 ip6:2001:db8::/129 -all", "invalid term"),
        ("v=spf1 ip6:192.0.2.1 -all", "invalid term"),
        ("v=spf1 ip6:fe80::1%eth0 -all", "invalid term"),
        ("v=spf1 a/33 -all", 'invalid term "a/33"'),
        ("v=spf1 mx//129 -all", 'invalid term "mx//129"'),
        ("v=spf1 +-all", 'invalid term "+-all"'),
        ("v=spf1 - all", 'invalid term "-"'),
        ("v=spf1 redirect=a.example.com redirect=b.example.com", "more than one redirect"),
        ("v=spf1 -all exp=a.example.com exp=b.example.com", "more than one exp"),
        ("v=spf1 redirect=", 'invalid term "redirect="'),
        ("v=spf1 -all foo=%{z}", 'invalid term "foo=%{z}"'),
        ("include:example.com -all", 'no "v=spf1"'),
    ],
)
def test_parse_spf_rejects_what_receivers_permerror(record: str, message: str) -> None:
    with pytest.raises(SpfSyntaxError, match=re.escape(message)):
        parse_spf(record)


def test_parse_spf_terms() -> None:
    spf = parse_spf("v=spf1 MX a:mail.example.com/24 ~all redirect=x.example.com unknown=1")
    assert [(t.qualifier, t.name, t.value) for t in spf.mechanisms] == [
        ("", "mx", ""),
        ("", "a", "mail.example.com/24"),
        ("~", "all", ""),
    ]
    assert spf.all_term is not None
    assert spf.all_term.text == "~all"
    assert spf.redirect == "x.example.com"
    assert not spf.redirect_in_effect
    assert spf.unknown_modifiers == ("unknown=1",)
    assert spf.lookup_count == 2


@pytest.mark.parametrize(
    ("record", "count"),
    [
        ("v=spf1 -all", 0),
        ("v=spf1 ip4:192.0.2.1 ip6:2001:db8::1 -all", 0),
        ("v=spf1 a mx ptr exists:%{i}.example.com include:x.example.com -all", 5),
        ("v=spf1 mx redirect=_spf.example.com", 2),
        ("v=spf1 mx -all redirect=_spf.example.com", 1),
        (f"v=spf1 {includes(11)} -all", 11),
        # Terms after "all" are never evaluated (RFC 7208 section 5.1).
        (f"v=spf1 -all {includes(11)}", 0),
        ("v=spf1 mx ~all a include:x.example.com", 1),
    ],
)
def test_spf_lookup_count(record: str, count: int) -> None:
    assert parse_spf(record).lookup_count == count


def test_spf_terms_after_all_do_not_warn_about_lookups() -> None:
    outcome = evaluate_spf([f"v=spf1 -all {includes(11)}"])
    assert outcome.status is Status.PASS
    shown = {e.label: e.value for e in outcome.evidence}
    assert shown["DNS lookups at the top level"].startswith("0 of 10")
    assert shown["Never evaluated (after all)"].startswith("include:")


# --- SPF: verdicts ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("records", "status", "summary"),
    [
        (["v=spf1 include:_spf.example.net -all"], Status.PASS, "uses -all"),
        (["v=spf1 mx ~all"], Status.PASS, "softfail"),
        (["v=spf1 mx ?all"], Status.WARN, "uses ?all"),
        (["v=spf1 +all"], Status.FAIL, "uses +all, which authorizes every server"),
        (["v=spf1 all"], Status.FAIL, "uses all, which authorizes every server"),
        (["v=spf1 mx"], Status.WARN, "no all mechanism or redirect"),
        (["v=spf1"], Status.WARN, "neutral result"),
        (["v=spf1 redirect=_spf.example.net"], Status.PASS, "delegates its policy to _spf"),
        (["v=spf1 -all redirect=_spf.example.net"], Status.PASS, "uses -all"),
        (["v=spf1 -all +all"], Status.PASS, "uses -all"),
        (["v=spf1 -all", "v=spf1 mx -all"], Status.FAIL, "publishes 2 SPF records"),
        (["v=spf1 -all", "v=spf1 foo"], Status.FAIL, "publishes 2 SPF records"),
        (["v=spf1 mx foo -all"], Status.FAIL, 'unknown mechanism "foo"'),
        (["v=spf1 include -all"], Status.FAIL, "permanent error"),
        (["v=spf1 ptr -all"], Status.WARN, "ptr mechanism"),
        (["v=spf1 ptr:example.com ~all"], Status.WARN, "ptr mechanism"),
        ([f"v=spf1 {includes(11)} -all"], Status.WARN, "11 DNS-querying terms"),
        ([f"v=spf1 {includes(10)} -all"], Status.PASS, "uses -all"),
        ([f"v=spf1 {includes(10)} redirect=x.example.com"], Status.WARN, "11 DNS-querying"),
        ([f"v=spf1 {includes(10)} -all redirect=x.example.com"], Status.PASS, "uses -all"),
        (["V=SPF1 MX -ALL"], Status.PASS, "fails SPF"),
        (["v=SpF1 include:_spf.example.net ~ALL"], Status.PASS, "softfail"),
        (["v=spf1 ptr ?all"], Status.WARN, "uses ?all"),
        (["v=spf1 +all ptr"], Status.FAIL, "uses +all"),
        ([f"v=spf1 {includes(11)} +all"], Status.FAIL, "uses +all"),
        (["v=spf10 -all", "v=spf1 -all"], Status.PASS, "uses -all"),
        (["google-site-verification=abc", "v=spf1 mx -all"], Status.PASS, "uses -all"),
        (["google-site-verification=abc", "note v=spf1 -all"], Status.FAIL, "no SPF record"),
        ([" v=spf1 -all"], Status.FAIL, "no SPF record"),
        ([], Status.FAIL, "no SPF record"),
    ],
)
def test_evaluate_spf(records: list[str], status: Status, summary: str) -> None:
    outcome = evaluate_spf(records)
    assert outcome.status is status
    assert summary in outcome.summary
    assert (outcome.remediation is None) == (status is Status.PASS)


def test_spf_evidence_for_softfail() -> None:
    outcome = evaluate_spf(["v=spf1 include:_spf.example.net ~all"])
    assert evidence_of(outcome) == {
        "Record": "v=spf1 include:_spf.example.net ~all",
        "all mechanism": "~all (softfail)",
        "DNS lookups at the top level": "1 of 10 (nested includes are not expanded)",
    }


@pytest.mark.parametrize(
    ("record", "all_mechanism"),
    [
        ("v=spf1 -all", "-all (fail)"),
        ("v=spf1 ?all", "?all (neutral)"),
        ("v=spf1 +all", "+all (pass)"),
        ("v=spf1 all", "all (pass)"),
        ("v=spf1 mx", "none"),
    ],
)
def test_spf_evidence_names_the_all_result(record: str, all_mechanism: str) -> None:
    assert evidence_of(evaluate_spf([record]))["all mechanism"] == all_mechanism


def test_spf_redirect_is_reported_as_not_expanded() -> None:
    outcome = evaluate_spf(["v=spf1 redirect=_spf.example.net"])
    assert evidence_of(outcome)["redirect"] == "_spf.example.net (policy delegated, not expanded)"


def test_spf_redirect_next_to_all_is_reported_as_ignored() -> None:
    outcome = evaluate_spf(["v=spf1 -all redirect=_spf.example.net"])
    assert "ignored" in evidence_of(outcome)["redirect"]


def test_spf_unknown_modifiers_are_shown_but_not_penalized() -> None:
    outcome = evaluate_spf(["v=spf1 mx ip4=192.0.2.1 -all"])
    assert outcome.status is Status.PASS
    assert evidence_of(outcome)["Ignored unknown modifiers"] == "ip4=192.0.2.1"


def test_spf_several_warnings_all_get_a_fix() -> None:
    outcome = evaluate_spf([f"v=spf1 ptr {includes(11)} ?all"])
    assert outcome.status is Status.WARN
    assert outcome.remediation is not None
    for fix in ("?all", "10 or fewer", "Replace ptr"):
        assert fix in outcome.remediation


def test_spf_multiple_records_are_all_shown() -> None:
    outcome = evaluate_spf(["v=spf1 -all", "v=spf1 mx -all"])
    assert evidence_of(outcome) == {"SPF record 1": "v=spf1 -all", "SPF record 2": "v=spf1 mx -all"}


def test_spf_lookalike_record_is_shown_when_nothing_qualifies() -> None:
    outcome = evaluate_spf(["spf: v=spf1 -all"])
    assert evidence_of(outcome) == {"Ignored TXT record": "spf: v=spf1 -all"}
    assert outcome.remediation is not None
    assert 'starts with "v=spf1"' in outcome.remediation


def test_spf_evidence_is_truncated() -> None:
    record = f"v=spf1 {includes(40)} -all"
    outcome = evaluate_spf([record])
    assert len(evidence_of(outcome)["Record"]) <= 300


# --- SPF: check -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "status"),
    [
        (["v=spf1 mx -all"], Status.PASS),
        (["v=spf1 mx"], Status.WARN),
        (["some-verification=1"], Status.FAIL),
        (NxDomainError("example.com"), Status.FAIL),
        (DnsUnavailableError("timeout"), Status.INCONCLUSIVE),
    ],
)
async def test_check_spf(answer: DnsAnswer, status: Status) -> None:
    resolver = FakeResolver(txt_records={"example.com": answer})
    outcome = await check_spf(make_context(resolver=resolver))
    assert outcome.status is status
    assert resolver.queries == [("TXT", "example.com")]


async def test_check_spf_without_txt_records_fails() -> None:
    outcome = await check_spf(make_context())
    assert outcome.status is Status.FAIL
    assert outcome.summary == "The domain publishes no SPF record."


# --- DMARC: parsing ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("record", "tags"),
    [
        ("v=DMARC1; p=reject", {"v": "DMARC1", "p": "reject"}),
        ("v=DMARC1;p=quarantine;", {"v": "DMARC1", "p": "quarantine"}),
        (
            "v = DMARC1 ; P = Reject ; RUA = mailto:d@example.com",
            {"v": "DMARC1", "p": "Reject", "rua": "mailto:d@example.com"},
        ),
        ("V=DMARC1; p=none", {"v": "DMARC1", "p": "none"}),
        (
            "v=DMARC1; p=none; sp=reject; np=reject; t=y",
            {"v": "DMARC1", "p": "none", "sp": "reject", "np": "reject", "t": "y"},
        ),
        ("v=DMARC1; p=reject; p=none", {"v": "DMARC1", "p": "reject"}),
        ("v=DMARC1; junk; =x; p=reject", {"v": "DMARC1", "p": "reject"}),
        ("v=DMARC1", {"v": "DMARC1"}),
    ],
)
def test_parse_dmarc_tags(record: str, tags: dict[str, str]) -> None:
    assert parse_dmarc_tags(record) == tags


@pytest.mark.parametrize(
    "record",
    [
        "v=dmarc1; p=reject",
        "v=DMARC2; p=reject",
        "v=DMARC10; p=reject",
        "p=reject; v=DMARC1",
        "v=DMARC1 p=reject",
        "note: v=DMARC1; p=reject",
        "v=spf1 -all",
        "",
    ],
)
def test_parse_dmarc_tags_rejects_non_dmarc_records(record: str) -> None:
    assert parse_dmarc_tags(record) is None


@pytest.mark.parametrize(
    ("record", "subdomain", "policy"),
    [
        ("v=DMARC1; p=reject", False, "reject"),
        ("v=DMARC1; p=quarantine", False, "quarantine"),
        ("v=DMARC1; p=none", False, "none"),
        ("v=DMARC1; p=REJECT", False, "reject"),
        ("v=DMARC1; p=none; sp=reject", False, "none"),
        ("v=DMARC1; p=none; sp=reject", True, "reject"),
        ("v=DMARC1; p=reject; sp=none", True, "none"),
        ("v=DMARC1; p=reject", True, "reject"),
        ("v=DMARC1; p=none; np=reject", True, "none"),
        ("v=DMARC1; p=reject; np=none", True, "reject"),
        (f"v=DMARC1; {RUA}", False, "none"),
        ("v=DMARC1", False, None),
        (f"v=DMARC1; p=rejected; {RUA}", False, "none"),
        ("v=DMARC1; p=rejected", False, None),
        ("v=DMARC1; p=", False, None),
        ("v=DMARC1; p=reject; sp=strict", False, None),
        (f"v=DMARC1; p=reject; np=; {RUA}", True, "none"),
        ("v=DMARC1; rua=not-a-uri", False, None),
        ("v=DMARC1; rua=mailto:a@example.com, https://reports.example.net/x", False, "none"),
    ],
)
def test_effective_dmarc_policy(record: str, subdomain: bool, policy: str | None) -> None:
    tags = parse_dmarc_tags(record)
    assert tags is not None
    assert effective_dmarc_policy(tags, subdomain=subdomain) == policy


@pytest.mark.parametrize(
    ("record", "problem"),
    [
        ("v=DMARC1; p=reject; sp=none; np=quarantine", None),
        ("v=DMARC1", "no p tag"),
        ("v=DMARC1; p=block", 'an invalid p tag ("block")'),
        ("v=DMARC1; p=reject; sp=yes", 'an invalid sp tag ("yes")'),
        ("v=DMARC1; p=reject; np=", 'an invalid np tag ("")'),
    ],
)
def test_dmarc_policy_problem(record: str, problem: str | None) -> None:
    tags = parse_dmarc_tags(record)
    assert tags is not None
    assert dmarc_policy_problem(tags) == problem


# --- DMARC: verdicts ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("record", "status", "summary"),
    [
        ("v=DMARC1; p=reject", Status.PASS, "The DMARC policy is reject"),
        (f"v=DMARC1; p=quarantine; {RUA}", Status.PASS, "is quarantine"),
        ("v=DMARC1; p=none", Status.WARN, "only monitored"),
        ("v=DMARC1; p=none; sp=reject", Status.WARN, "is none"),
        ("v=DMARC1; sp=reject; p=none", Status.WARN, "is none"),
        ("v=DMARC1; p=none; sp=quarantine; np=reject", Status.WARN, "is none"),
        # RFC 9989: t=y asks for the next weaker policy, not for no policy.
        (
            "v=DMARC1; p=reject; t=y",
            Status.WARN,
            "is reject but in testing mode (t=y), so receivers apply quarantine instead of reject.",
        ),
        (
            "v=DMARC1; p=quarantine; t=Y",
            Status.WARN,
            "is quarantine but in testing mode (t=y), so receivers apply none instead.",
        ),
        ("v=DMARC1; p=reject; t=n", Status.PASS, "is reject"),
        ("v=DMARC1; p=none; t=y", Status.WARN, "is none"),
        ("v=DMARC1; p=reject; pct=0", Status.WARN, "pct=0"),
        ("v=DMARC1; p=reject; pct=100", Status.PASS, "is reject"),
        (f"v=DMARC1; {RUA}", Status.WARN, "has no p tag, so receivers treat it as p=none"),
        ("v=DMARC1", Status.FAIL, "no p tag and no valid rua address"),
        ("v=DMARC1; p=rejectt", Status.FAIL, 'invalid p tag ("rejectt")'),
        ("v=DMARC1; p=reject; sp=bogus", Status.FAIL, "invalid sp tag"),
        (f"v=DMARC1; p=reject; sp=bogus; {RUA}", Status.WARN, "invalid sp tag"),
        ("v=DMARC1;p=REJECT", Status.PASS, "is reject"),
        ("  v = DMARC1 ;  p = quarantine ; ", Status.PASS, "is quarantine"),
        (f"V=DMARC1; P=Reject; {RUA.upper()}", Status.PASS, "is reject"),
    ],
)
def test_evaluate_dmarc(record: str, status: Status, summary: str) -> None:
    outcome = evaluate_dmarc("example.com", dmarc_at("example.com", record))
    assert outcome.status is status
    assert summary in outcome.summary
    assert (outcome.remediation is None) == (status is Status.PASS)


def test_dmarc_evidence() -> None:
    outcome = evaluate_dmarc("example.com", dmarc_at("example.com", f"v=DMARC1; p=reject; {RUA}"))
    assert evidence_of(outcome) == {
        "Record": f"v=DMARC1; p=reject; {RUA}",
        "Found at": "_dmarc.example.com",
        "Effective policy": "reject (from p)",
        "Subdomain policy (sp)": "not set",
        "Non-existent subdomain policy (np)": "not set",
        "Aggregate reports (rua)": "set",
    }


def test_dmarc_evidence_shows_testing_and_legacy_tags() -> None:
    outcome = evaluate_dmarc(
        "example.com", dmarc_at("example.com", "v=DMARC1; p=reject; sp=none; t=y; pct=50")
    )
    evidence = evidence_of(outcome)
    assert evidence["Subdomain policy (sp)"] == "none"
    assert evidence["Testing mode (t)"] == "y"
    assert evidence["Legacy pct"] == "50"
    assert evidence["Aggregate reports (rua)"] == "not set"


@pytest.mark.parametrize(
    ("record", "effective"),
    [
        ("v=DMARC1", "no DMARC processing"),
        (f"v=DMARC1; {RUA}", "none (treated as p=none because of no p tag)"),
    ],
)
def test_dmarc_evidence_for_missing_policy(record: str, effective: str) -> None:
    outcome = evaluate_dmarc("example.com", dmarc_at("example.com", record))
    assert evidence_of(outcome)["Effective policy"] == effective


def test_duplicate_dmarc_records_fail() -> None:
    discovery = dmarc_at("example.com", "v=DMARC1; p=reject", "v=DMARC1; p=none")
    outcome = evaluate_dmarc("example.com", discovery)
    assert outcome.status is Status.FAIL
    assert outcome.summary.startswith("2 DMARC records are published at _dmarc.example.com")
    assert list(evidence_of(outcome)) == ["Record 1", "Record 2"]


@pytest.mark.parametrize(
    ("record", "status", "effective"),
    [
        ("v=DMARC1; p=none; sp=reject", Status.PASS, "reject (from sp)"),
        ("v=DMARC1; p=reject", Status.PASS, "reject (from p)"),
        ("v=DMARC1; p=quarantine; sp=none", Status.WARN, "none (from sp)"),
        ("v=DMARC1; p=none; np=reject", Status.WARN, "none (from p)"),
        ("v=DMARC1; p=reject; sp=reject; t=y", Status.WARN, "reject (from sp)"),
    ],
)
def test_dmarc_inherited_from_parent(record: str, status: Status, effective: str) -> None:
    discovery = dmarc_at("example.com", record, queried=("www.example.com", "example.com"))
    outcome = evaluate_dmarc("www.example.com", discovery)
    assert outcome.status is status
    assert outcome.summary.startswith("The DMARC policy inherited from example.com")
    evidence = evidence_of(outcome)
    assert evidence["Effective policy"] == effective
    assert evidence["Found at"] == "_dmarc.example.com (applies to www.example.com as a subdomain)"


def test_dmarc_inherited_none_suggests_sp() -> None:
    discovery = dmarc_at("example.com", "v=DMARC1; p=none", queried=("www.example.com",))
    outcome = evaluate_dmarc("www.example.com", discovery)
    assert outcome.remediation is not None
    assert "sp=quarantine" in outcome.remediation


@pytest.mark.parametrize(
    ("queried", "summary"),
    [
        (("example.com",), "No DMARC record was found for the domain."),
        (
            ("www.example.com", "example.com"),
            "No DMARC record was found for the domain or its parent domains.",
        ),
    ],
)
def test_missing_dmarc_fails(queried: tuple[str, ...], summary: str) -> None:
    outcome = evaluate_dmarc(queried[0], DmarcDiscovery(queried))
    assert outcome.status is Status.FAIL
    assert outcome.summary == summary
    assert evidence_of(outcome)["Names queried"] == ", ".join(f"_dmarc.{n}" for n in queried)


def test_missing_dmarc_shows_ignored_lookalike() -> None:
    discovery = DmarcDiscovery(("example.com",), ignored=("v=dmarc1; p=reject",))
    outcome = evaluate_dmarc("example.com", discovery)
    assert evidence_of(outcome)["Ignored TXT record"] == "v=dmarc1; p=reject"
    assert outcome.remediation is not None
    assert '"v=DMARC1;" exactly' in outcome.remediation


# --- DMARC: tree walk ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("domain", "names"),
    [
        ("example.com", ["example.com"]),
        ("www.example.com", ["www.example.com", "example.com"]),
        (
            "a.b.example.co.uk",
            ["a.b.example.co.uk", "b.example.co.uk", "example.co.uk", "co.uk"],
        ),
        (
            "a.b.c.d.e.f.example.com",
            [
                "a.b.c.d.e.f.example.com",
                "b.c.d.e.f.example.com",
                "c.d.e.f.example.com",
                "d.e.f.example.com",
                "e.f.example.com",
                "f.example.com",
                "example.com",
            ],
        ),
        (
            "a.b.c.d.e.f.g.h.example.com",
            [
                "a.b.c.d.e.f.g.h.example.com",
                "d.e.f.g.h.example.com",
                "e.f.g.h.example.com",
                "f.g.h.example.com",
                "g.h.example.com",
                "h.example.com",
                "example.com",
            ],
        ),
    ],
)
def test_dmarc_lookup_names(domain: str, names: list[str]) -> None:
    assert dmarc_lookup_names(domain) == names


def test_dmarc_walk_never_exceeds_eight_queries() -> None:
    domain = ".".join(f"l{i}" for i in range(30)) + ".example.com"
    assert len(dmarc_lookup_names(domain)) <= 8


async def test_check_dmarc_reads_the_domain_record() -> None:
    resolver = FakeResolver(
        txt_records={"_dmarc.example.com": ["some-verification=1", f"v=DMARC1; p=reject; {RUA}"]}
    )
    outcome = await check_dmarc(make_context(resolver=resolver))
    assert outcome.status is Status.PASS
    assert resolver.queries == [("TXT", "_dmarc.example.com")]


async def test_check_dmarc_walks_up_to_the_organizational_domain() -> None:
    resolver = FakeResolver(
        txt_records={
            "_dmarc.mail.shop.example.com": NxDomainError("_dmarc.mail.shop.example.com"),
            "_dmarc.example.com": ["v=DMARC1; p=none; sp=reject"],
        }
    )
    outcome = await check_dmarc(make_context("mail.shop.example.com", resolver=resolver))
    assert outcome.status is Status.PASS
    assert "inherited from example.com is reject" in outcome.summary
    assert resolver.queries == [
        ("TXT", "_dmarc.mail.shop.example.com"),
        ("TXT", "_dmarc.shop.example.com"),
        ("TXT", "_dmarc.example.com"),
    ]


async def test_check_dmarc_stops_at_the_first_record_found() -> None:
    resolver = FakeResolver(
        txt_records={
            "_dmarc.shop.example.com": ["v=DMARC1; p=none"],
            "_dmarc.example.com": ["v=DMARC1; p=reject"],
        }
    )
    outcome = await check_dmarc(make_context("mail.shop.example.com", resolver=resolver))
    assert outcome.status is Status.WARN
    assert "inherited from shop.example.com is none" in outcome.summary
    assert ("TXT", "_dmarc.example.com") not in resolver.queries


async def test_check_dmarc_duplicates_at_the_domain_fail_without_walking() -> None:
    resolver = FakeResolver(
        txt_records={
            "_dmarc.www.example.com": ["v=DMARC1; p=reject", "v=DMARC1; p=quarantine"],
            "_dmarc.example.com": ["v=DMARC1; p=reject"],
        }
    )
    outcome = await check_dmarc(make_context("www.example.com", resolver=resolver))
    assert outcome.status is Status.FAIL
    assert len(resolver.queries) == 1


async def test_check_dmarc_not_found_anywhere_fails() -> None:
    resolver = FakeResolver()
    outcome = await check_dmarc(make_context("www.example.com", resolver=resolver))
    assert outcome.status is Status.FAIL
    assert len(resolver.queries) == 2


async def test_check_dmarc_reports_an_ignored_lookalike() -> None:
    resolver = FakeResolver(txt_records={"_dmarc.example.com": ["v=dmarc1; p=reject"]})
    outcome = await check_dmarc(make_context(resolver=resolver))
    assert outcome.status is Status.FAIL
    assert evidence_of(outcome)["Ignored TXT record"] == "v=dmarc1; p=reject"


@pytest.mark.parametrize(
    "unavailable",
    ["_dmarc.www.example.com", "_dmarc.example.com"],
)
async def test_check_dmarc_dns_unavailable_is_inconclusive(unavailable: str) -> None:
    resolver = FakeResolver(txt_records={unavailable: DnsUnavailableError("SERVFAIL")})
    outcome = await check_dmarc(make_context("www.example.com", resolver=resolver))
    assert outcome.status is Status.INCONCLUSIVE
    assert outcome.summary == "The DMARC record could not be looked up because DNS did not answer."
    assert resolver.queries[-1] == ("TXT", unavailable)


# --- DKIM ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("record", "tags"),
    [
        (f"v=DKIM1; k=rsa; p={RSA_KEY}", {"v": "DKIM1", "k": "rsa", "p": RSA_KEY}),
        (f"k=ed25519; p={ED25519_KEY}", {"k": "ed25519", "p": ED25519_KEY}),
        ("p=MIGf MA0G\tCSqG", {"p": "MIGfMA0GCSqG"}),
        ("v=DKIM1; p=", {"v": "DKIM1", "p": ""}),
        ("v=DKIM1; h=sha256; p=abc;", {"v": "DKIM1", "h": "sha256", "p": "abc"}),
    ],
)
def test_parse_dkim_key(record: str, tags: dict[str, str]) -> None:
    assert parse_dkim_key(record) == tags


@pytest.mark.parametrize(
    "record",
    [
        "v=DKIM2; p=abc",
        "v=dkim1; p=abc",
        "k=rsa; v=DKIM1; p=abc",
        "v=DKIM1; k=rsa",
        "P=abc",
        "p=abc; p=def",
        "v=spf1 -all",
        "v=DKIM1; p=abc; garbage",
        "",
    ],
)
def test_parse_dkim_key_rejects_non_keys(record: str) -> None:
    assert parse_dkim_key(record) is None


def dkim_lookups(**found: list[str] | None) -> dict[str, list[str] | None]:
    lookups: dict[str, list[str] | None] = {selector: [] for selector in DKIM_SELECTORS}
    lookups.update(found)
    return lookups


@pytest.mark.parametrize(
    ("lookups", "status", "summary"),
    [
        (
            dkim_lookups(google=[f"v=DKIM1; k=rsa; p={RSA_KEY}"]),
            Status.PASS,
            "A DKIM public key is published under selector google.",
        ),
        (
            dkim_lookups(
                selector1=[f"v=DKIM1; p={RSA_KEY}"], selector2=[f"k=ed25519; p={ED25519_KEY}"]
            ),
            Status.PASS,
            "A DKIM public key is published under selectors selector1, selector2.",
        ),
        (
            dkim_lookups(s1=["v=DKIM1; p="], s2=[f"v=DKIM1; p={RSA_KEY}"]),
            Status.PASS,
            "A DKIM public key is published under selector s2.",
        ),
        (
            dkim_lookups(s1=["v=DKIM1; p="]),
            Status.INCONCLUSIVE,
            "Only revoked DKIM keys (empty p=) were found, under selector s1.",
        ),
        (
            dkim_lookups(),
            Status.INCONCLUSIVE,
            "No DKIM key under common selectors; selectors cannot be listed, so this does not "
            "prove DKIM is missing.",
        ),
        (
            dkim_lookups(default=["v=spf1 -all"], mail=["some-verification=1"]),
            Status.INCONCLUSIVE,
            "No DKIM key under common selectors",
        ),
        (
            dict.fromkeys(DKIM_SELECTORS),
            Status.INCONCLUSIVE,
            "The DKIM lookups failed because DNS did not answer.",
        ),
        (
            dkim_lookups(default=None, k1=None),
            Status.INCONCLUSIVE,
            "No DKIM key under common selectors",
        ),
        (
            dkim_lookups(default=None, k1=[f"p={RSA_KEY}"]),
            Status.PASS,
            "under selector k1.",
        ),
    ],
)
def test_evaluate_dkim(lookups: dict[str, list[str] | None], status: Status, summary: str) -> None:
    outcome = evaluate_dkim(lookups)
    assert outcome.status is status
    assert summary in outcome.summary
    assert outcome.remediation is None


def test_dkim_evidence() -> None:
    outcome = evaluate_dkim(
        dkim_lookups(
            google=[f"v=DKIM1; p={RSA_KEY}"],
            k2=[f"k=ED25519; p={ED25519_KEY}"],
            s1=["v=DKIM1; p="],
            smtp=None,
        )
    )
    evidence = evidence_of(outcome)
    assert evidence["Selectors found (key type)"] == "google (rsa), k2 (ed25519)"
    assert evidence["Revoked keys (empty p=)"] == "s1"
    assert evidence["Selectors checked"] == ", ".join(DKIM_SELECTORS)
    assert evidence["Lookups that failed"] == "smtp"


async def test_check_dkim_queries_every_selector() -> None:
    resolver = FakeResolver(txt_records={"google._domainkey.example.com": [f"p={RSA_KEY}"]})
    outcome = await check_dkim(make_context(resolver=resolver))
    assert outcome.status is Status.PASS
    assert sorted(resolver.queries) == sorted(
        ("TXT", f"{selector}._domainkey.example.com") for selector in DKIM_SELECTORS
    )


async def test_check_dkim_all_lookups_unavailable() -> None:
    resolver = FakeResolver(
        txt_records={
            f"{selector}._domainkey.example.com": DnsUnavailableError("timeout")
            for selector in DKIM_SELECTORS
        }
    )
    outcome = await check_dkim(make_context(resolver=resolver))
    assert outcome.status is Status.INCONCLUSIVE
    assert "DNS did not answer" in outcome.summary


async def test_check_dkim_nothing_found_is_inconclusive() -> None:
    outcome = await check_dkim(make_context())
    assert outcome.status is Status.INCONCLUSIVE
    assert outcome.summary.startswith("No DKIM key under common selectors")


class BrokenResolver(FakeResolver):
    async def txt(self, name: str) -> list[str]:
        raise RuntimeError("resolver bug")


async def test_check_dkim_unexpected_error_becomes_inconclusive() -> None:
    dkim = next(check for check in CHECKS if check.id == "email.dkim")
    result = await run_check(dkim, make_context(resolver=BrokenResolver()))
    assert result.status is Status.INCONCLUSIVE


# --- Registry ------------------------------------------------------------------------


def test_registry() -> None:
    assert [(c.id, c.title, c.category, c.weight) for c in CHECKS] == [
        ("email.spf", "SPF record", Category.EMAIL, 10),
        ("email.dmarc", "DMARC policy", Category.EMAIL, 10),
        ("email.dkim", "DKIM key", Category.EMAIL, 5),
    ]
    for check in CHECKS:
        assert check.references
        assert all(
            ref.url.startswith("https://www.rfc-editor.org/rfc/") for ref in check.references
        )


async def test_run_check_scores_email_checks() -> None:
    resolver = FakeResolver(
        txt_records={
            "example.com": ["v=spf1 mx ?all"],
            "_dmarc.example.com": ["v=DMARC1; p=reject"],
        }
    )
    ctx = make_context(resolver=resolver)
    results = {check.id: await run_check(check, ctx) for check in CHECKS}
    assert results["email.spf"].status is Status.WARN
    assert results["email.spf"].points == 5.0
    assert results["email.dmarc"].points == 10.0
    assert results["email.dkim"].status is Status.INCONCLUSIVE
    assert results["email.dkim"].points == 0.0
    assert results["email.dmarc"].references[0].url == "https://www.rfc-editor.org/rfc/rfc9989.html"
