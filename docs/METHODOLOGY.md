# Methodology

This document describes what WebRiskAudit checks, how each check reaches its
verdict and how the verdicts become a score. It describes methodology version
`2026-11` (scanner version `2.0.0`). The rules below are taken from the
code in `backend/src/webriskaudit/`; where this document and the code
disagree, the code is right and this document has a bug.

## Purpose and scope

WebRiskAudit gives a quick, evidence-backed read on the externally visible
security configuration of one domain: email authentication (SPF, DMARC,
DKIM), HTTPS and TLS, and the HTTP security headers of the home page.

It is deliberately limited:

- **Passive checks only.** A scan reads public DNS records, makes one TLS
  handshake on port 443 and sends two ordinary `GET` requests
  (`http://<domain>/` and `https://<domain>/`, each following up to 5
  redirects). It does not probe paths, ports or vulnerabilities, does not
  retry, and identifies itself with the User-Agent
  `WebRiskAudit/<version> (+https://github.com/portakalp/webriskaudit)`.
  See [ADR 0001](adr/0001-passive-checks-only.md).
- **One vantage point.** Results describe what the scanner's own network sees
  at the time of the scan. Geo-dependent answers, WAF rules or IPv6-only
  hosts can look different from elsewhere.
- **Configuration, not security.** A high score means the checked
  configuration follows current recommendations. It says nothing about
  application vulnerabilities, patch levels or anything else a passive scan
  cannot see.

## How a scan runs

1. **Input.** The input is reduced to a host name: a scheme (`http` or
   `https` only), userinfo, port, path, query, fragment and a trailing dot are
   removed, the name is lower-cased and converted to its IDNA A-label form.
   `www.` is kept: the host is scanned as given. IP addresses (including
   numeric forms such as `127.1` or `0x7f.1`), single-label names, names longer
   than 253 characters, labels that are not 1-63 letters, digits or hyphens
   (or that start or end with a hyphen), invalid `xn--` labels and names under
   the special-use TLDs `alt`, `arpa`, `corp`, `example`, `home`,
   `internal`, `invalid`, `local`, `localhost`, `mail`, `onion` and `test` are
   refused (`net/domain.py`).
2. **Pre-check.** The A and AAAA records are looked up (`scanner.py`):
   - NXDOMAIN: the scan is refused (`domain-not-found`).
   - No A or AAAA record: the scan continues without addresses. The email
     checks run; every check that needs a web server is inconclusive.
   - DNS gives no usable answer, or the lookup runs past the scan deadline:
     the scan is refused (`dns-unavailable`).
   - Any address that is not globally routable: the scan is refused
     (`non-public-target`).
3. **Checks.** All 16 checks run concurrently against a shared context. The
   two HTTP fetches are made once per scan and shared by every check that
   reads them.
4. **Time limits.** Each check has 30 seconds from its start, and the whole
   scan has 45 seconds counted from before the pre-check (both configurable,
   see `backend/.env.example`). A check still running when either runs out is
   reported as inconclusive: "The check did not finish within N seconds and
   timed out." Inside the checks, each DNS query is limited to 5 seconds, each
   HTTP fetch to 10 seconds in total (DNS, redirects and body included) and
   the TLS handshake to 10 seconds.
5. **Failures.** A check that raises an unexpected exception is reported as
   inconclusive ("The check failed unexpectedly.") and the exception is logged
   on the server.

The API serves a report from an in-memory cache for 10 minutes after a scan,
so a repeated request within that time returns the earlier result.

## Statuses

Every check ends in exactly one status:

| Status         | Meaning                                                                                                          | Points        |
| -------------- | ---------------------------------------------------------------------------------------------------------------- | ------------- |
| `pass`         | The configuration meets the check's rule.                                                                        | the weight    |
| `warn`         | Present but weaker than recommended, not enforced (monitoring or testing mode), or not stated.                   | half          |
| `fail`         | Missing, invalid (ignored by receivers or browsers), or unsafe.                                                  | 0             |
| `inconclusive` | No verdict could be reached. See below.                                                                          | not counted   |
| `info`         | Result of an informational check (weight 0). Describes what was found and never affects the score.               | not counted   |

A check is **inconclusive** when the scanner cannot tell whether the domain
meets the rule: DNS did not answer, the server could not be reached or timed
out in a way that may be the scanner's fault, the home page was a bot
challenge or an HTTP error page, the domain has no web server, the check
timed out or failed unexpectedly, or (DKIM only) absence cannot be proven.
Inconclusive results neither earn nor cost points and are counted under
coverage instead. See [ADR 0002](adr/0002-explicit-inconclusive-results.md).

The runner enforces the split between scored and informational checks
(`checks/base.py`): a scored check can return `pass`, `warn`, `fail` or
`inconclusive`; an informational check can return `info` or `inconclusive`.

## Scoring

The scoring code is `backend/src/webriskaudit/scoring.py`.

- Points per check: `pass` earns the weight, `warn` half the weight, every
  other status 0.
- A **completed** check is a scored check (weight above 0) with status `pass`,
  `warn` or `fail`.
- **Score** = `round(100 * points of completed checks / weight of completed checks)`,
  using Python's `round()`.
- **Minimum coverage.** If the completed checks carry less than half of the
  total scored weight (less than 45 of 90 points), the report has no score
  and no grade (`score` and `grade` are `null`). Exactly half is enough.
- **Coverage** reports `scored` (completed scored checks), `inconclusive`
  (scored checks without a verdict) and `total` (all scored checks, 12).
  Informational checks are not part of coverage.
- **Category scores** (email, transport, headers) use the same formula over
  the category's completed checks. A category with no completed check has
  `score: null`. Category scores are reported even when the overall score is
  not. The informational category has no score.

| Grade | Score  |
| ----- | ------ |
| A     | 90-100 |
| B     | 75-89  |
| C     | 60-74  |
| D     | 45-59  |
| F     | 0-44   |

Examples:

- webriskaudit.com on 1 November 2026: 11 scored checks pass and
  `headers.csp` (weight 10) warns, so 85 of 90 points: score 94, grade A. The
  headers category has 30 of 35 points: 86.
- A mail-only domain without A/AAAA records: only the email checks (25 of 90
  points) complete, so there is no overall score; the email category is still
  scored.
- A site whose home page answers with a bot challenge: HSTS and the six
  header checks (45 points) are inconclusive, the other 45 points complete, so
  the report is scored over those 45 points.

## Checks

| ID                             | Title                          | Category  | Weight |
| ------------------------------ | ------------------------------ | --------- | -----: |
| `email.spf`                    | SPF record                     | email     |     10 |
| `email.dmarc`                  | DMARC policy                   | email     |     10 |
| `email.dkim`                   | DKIM key                       | email     |      5 |
| `transport.tls_certificate`    | TLS certificate                | transport |     15 |
| `transport.https_redirect`     | HTTP to HTTPS redirect         | transport |      5 |
| `transport.hsts`               | HTTP Strict Transport Security | transport |     10 |
| `headers.csp`                  | Content Security Policy        | headers   |     10 |
| `headers.clickjacking`         | Clickjacking protection        | headers   |      5 |
| `headers.content_type_options` | X-Content-Type-Options         | headers   |      5 |
| `headers.referrer_policy`      | Referrer-Policy                | headers   |      5 |
| `headers.cookies`              | Cookie security                | headers   |      5 |
| `headers.server_disclosure`    | Server version disclosure      | headers   |      5 |
| `info.cdn`                     | CDN / edge network             | info      |      0 |
| `info.privacy_policy`          | Privacy policy link            | info      |      0 |
| `info.permissions_policy`      | Permissions-Policy             | info      |      0 |
| `info.deprecated_headers`      | Deprecated headers             | info      |      0 |

Scored weight: email 25, transport 30, headers 35, total 90. Reports list the
checks in this order (`checks/__init__.py`).

Where a check combines several findings, the most severe one (fail, then
warn, then pass) sets the status and the summary, and the remediation lists
the fix for every finding that is not a pass. Cookie values are never
included.

Reports are cached and shown to anyone who scans the same domain, so the
runner bounds what a check can report (`checks/base.py`): at most 20
evidence items per check (the last one counts the items left out), labels
cut to 100 characters, values to 300 and summaries to 500. URLs in evidence
keep only the scheme, host and path: credentials are dropped, and query
strings, fragments and `;` path parameters, which can carry session ids or
tokens, are replaced by `...`.

### Email checks

The email checks read TXT records only (`checks/email.py`). For every lookup,
NXDOMAIN and "no TXT records" both mean "nothing published"; a lookup without
a usable answer (timeout, SERVFAIL, no reachable nameserver) is a DNS failure.

#### `email.spf`: SPF record

Reads the TXT records at `<domain>`. A TXT record is an SPF record when it
starts with `v=spf1` (any case) followed by a space or the end of the record.

| Condition                                                                         | Status       |
| --------------------------------------------------------------------------------- | ------------ |
| DNS failure                                                                       | inconclusive |
| No SPF record                                                                     | fail         |
| More than one SPF record (RFC 7208 section 4.5: permerror)                        | fail         |
| A syntax error that makes receivers return permerror (see below)                  | fail         |
| `+all` or a bare `all`                                                            | fail         |
| `?all`                                                                            | warn         |
| No `all` mechanism and no `redirect=` (the default result is neutral)             | warn         |
| More than 10 DNS-querying terms at the top level (RFC 7208 section 4.6.4)          | warn         |
| A `ptr` mechanism (RFC 7208 section 5.5: should not be used)                      | warn         |
| `-all`, `~all` (softfail), or no `all` but a `redirect=` (delegated, not expanded) | pass         |

The last five rows are separate findings; the worst one wins.

- **Syntax.** A record fails as a permanent error when it contains an unknown
  mechanism, a mechanism with an invalid argument, a repeated `redirect` or
  `exp` modifier, or a modifier whose value is not a valid macro string.
  Arguments are checked against RFC 7208: `all` takes none; `include` and
  `exists` need `:<domain-spec>`; `a` and `mx` take an optional domain-spec
  and `/n` (at most 32) and `//n` (at most 128) prefix lengths; `ptr` takes an
  optional domain-spec; `ip4` and `ip6` need an address of that version with
  an optional prefix length. A domain-spec must be a valid macro string that
  ends in a macro expansion or in a valid top-level label (section 7.1).
  Unknown modifiers are ignored, as receivers ignore them (section 6), and are
  listed in the evidence.
- **The `all` mechanism.** The first `all` decides, because evaluation never
  passes it. When a record has an `all` mechanism, its `redirect` is ignored
  (section 6.1).
- **Lookup count.** `include`, `a`, `mx`, `ptr` and `exists` terms are counted,
  plus `redirect` when it is in effect. Only mechanisms up to the first `all`
  are counted, since evaluation never passes it (section 5.1). Includes and
  redirects are not followed, so lookups inside them are not counted.
- **Evidence.** The record; the `all` mechanism and its result (pass, fail,
  softfail or neutral) or "none"; the redirect target and whether it is in
  effect; "DNS lookups at the top level: N of 10 (nested includes are not
  expanded)"; the mechanisms after the first `all`, as "Never evaluated
  (after all)"; ignored unknown modifiers. When no SPF record is found but a TXT
  record contains `v=spf1` elsewhere, that record is shown as ignored.

References: [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html),
[section 4.5](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.5),
[section 4.6.4](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.6.4),
[section 5.5](https://www.rfc-editor.org/rfc/rfc7208.html#section-5.5).

#### `email.dmarc`: DMARC policy

**Discovery.** The check queries TXT at `_dmarc.<domain>`. If no DMARC record
is there, it walks up the tree (a simplified RFC 9989 section 4.10 walk): it
removes the leftmost label while at least two labels remain, and from a name
with eight or more labels it jumps straight to its seven-label ancestor. So
at most seven names are queried. The walk stops at the first name with a
DMARC record. For example, `a.b.example.co.uk` queries `a.b.example.co.uk`,
`b.example.co.uk`, `example.co.uk` and `co.uk`, in that order.

A TXT record is a DMARC record when its first tag is `v=DMARC1`: the tag name
is case-insensitive and may be surrounded by spaces, the value must be
exactly `DMARC1` (RFC 9989 section 4.7). Tags are split on `;` and then on the
first `=`; keys are case-insensitive, values are trimmed, parts without `=`
are skipped and the first of a repeated tag wins. Values are never
substring-matched.

**Applicable policy.** For a record at the scanned domain, `p` applies. For a
record found at a parent, the scanned domain is an existing subdomain, so
`sp` applies, falling back to `p`. `np` covers only non-existent subdomains,
so it is shown but not applied.

**Missing or invalid policy.** When `p` is missing, or `p`, `sp` or `np` has a
value other than `none`, `quarantine` or `reject` (any case), RFC 9989
section 4.10.1 has receivers act as if `p=none` was published if `rua` holds
at least one syntactically valid URI, and apply no DMARC processing
otherwise.

Rules, in order:

| Condition                                                                     | Status       |
| ----------------------------------------------------------------------------- | ------------ |
| DNS failure on any query of the walk                                          | inconclusive |
| No DMARC record at the domain or any parent queried                           | fail         |
| More than one DMARC record at the name where one was found                    | fail         |
| Missing or invalid policy and no valid `rua`: no DMARC processing             | fail         |
| Missing or invalid policy with a valid `rua`: treated as `p=none`             | warn         |
| Applicable policy `none` (monitoring only)                                    | warn         |
| Applicable policy `quarantine` or `reject` with `t=y` (testing mode)          | warn         |
| Applicable policy `quarantine` or `reject` with `pct=0` (legacy RFC 7489 tag) | warn         |
| Applicable policy `quarantine` or `reject`                                    | pass         |

A DNS failure anywhere in the walk is inconclusive because a missing record
cannot then be told apart from a failed lookup.

Evidence: the record, where it was found (and that it applies to the scanned
domain as a subdomain), the effective policy and which tag it came from,
`sp`, `np`, whether `rua` is set, and `t` and `pct` when present. When nothing
is found: the names queried, and a TXT record that looks like DMARC but does
not start with `v=DMARC1` exactly.

References: [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html),
[section 4.7](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.7),
[section 4.10](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10),
[section 4.10.1](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10.1).

#### `email.dkim`: DKIM key

DKIM selectors cannot be listed, so the check queries TXT at
`<selector>._domainkey.<domain>` for 11 common selectors, concurrently:
`default`, `google`, `selector1`, `selector2`, `k1`, `k2`, `s1`, `s2`, `dkim`,
`mail` and `smtp`.

A TXT record is a key record (RFC 6376 section 3.6.1) when every non-empty
part is `tag=value` with a valid tag name, no tag repeats (tag names are
case-sensitive), `v`, if present, comes first and is `DKIM1`, and a `p` tag
is present. Whitespace inside `p` is removed; an empty `p` means the key was
revoked. Other TXT records are ignored.

| Condition                                                         | Status       |
| ----------------------------------------------------------------- | ------------ |
| At least one selector has a key with a non-empty `p`              | pass         |
| Every lookup failed                                               | inconclusive |
| Only revoked keys (empty `p`) were found                          | inconclusive |
| No key under any of the selectors                                 | inconclusive |

This check never fails. The summary for the last row reads: "No DKIM key
under common selectors; selectors cannot be listed, so this does not prove
DKIM is missing."

Evidence: the selectors with a key and the key type (`k=`, default `rsa`),
selectors with revoked keys, the selectors checked, and the lookups that
failed.

References: [RFC 6376, section 3.6.1](https://www.rfc-editor.org/rfc/rfc6376.html#section-3.6.1).

### Transport checks

#### `transport.tls_certificate`: TLS certificate

Without A/AAAA records the check is inconclusive. Otherwise the scanner
resolves the domain again, requires every address to be public, and makes
one TLS handshake with port 443 of the first IPv4 address (the first IPv6
address if there is none), sending the domain as SNI (`net/tls.py`). The
client is Python's default TLS context with the
[certifi](https://pypi.org/project/certifi/) CA bundle: the chain and the
host name are verified, and TLS 1.2 is the lowest version offered.

No completed handshake:

| Condition                                                                         | Status       |
| --------------------------------------------------------------------------------- | ------------ |
| Connection refused, domain has only IPv6 addresses                                | inconclusive |
| Connection refused (nothing listens on port 443)                                  | fail         |
| Connection reset or aborted, or host or network unreachable                       | inconclusive |
| Handshake failed for another reason than certificate verification                 | fail         |
| Handshake timed out                                                               | inconclusive |
| Address not public, DNS lookup failed, or no TLS session was set up               | inconclusive |

A refused connection to an IPv6-only host is not counted because the scanner
itself may lack IPv6 connectivity. A reset or an unreachable host is not
counted either: a filter in front of the scanner or the network on the way
can cause it, so it does not show that there is no HTTPS service. A
handshake failure (for example a server that only offers TLS 1.0 or 1.1, or
plain HTTP on port 443) is a fail because a browser's default client would
fail the same way.

Completed handshake:

| Condition                                                                                    | Status       |
| -------------------------------------------------------------------------------------------- | ------------ |
| Certificate verification failed (untrusted chain, wrong host name, expired, ...)             | fail         |
| Verified, but the validity dates were not reported                                           | inconclusive |
| Expired, or less than 7 days left (or less than a sixth of the lifetime, if that is shorter) | fail         |
| Less than a quarter of the lifetime (`notAfter - notBefore`) left: renewal is overdue        | warn         |
| Negotiated protocol SSLv2, SSLv3, TLSv1 or TLSv1.1                                           | warn         |
| Otherwise                                                                                    | pass         |

ACME clients usually renew with a third of the lifetime left, so a
certificate below a quarter has missed its renewal. The fail threshold is 7
days, or a sixth of the lifetime when that is shorter (half the third at
which ACME clients renew), so short-lived certificates are not failed for
being short-lived: a 160-hour certificate fails below about 27 hours left.
Certificates valid for 42 days or more keep the 7-day threshold. The last
three rows are separate findings; the worst one wins. In practice an expired
certificate already fails verification, and the protocol row cannot fire
because TLS 1.2 is the minimum the client offers.

Evidence: the verification error, issuer ("Organization (Common Name)"),
valid from and until (ISO 8601, UTC), days left, the lifetime (in days, or
in hours under a week), the negotiated protocol, and up to 5 DNS names from
the subject alternative names.

References:
[OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html),
[RFC 8996: Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996.html),
[Let's Encrypt integration guide](https://letsencrypt.org/docs/integration-guide/).

#### `transport.https_redirect`: HTTP to HTTPS redirect

Without A/AAAA records the check is inconclusive. Otherwise it fetches
`http://<domain>/` through the guarded fetcher (see the
[threat model](THREAT_MODEL.md)), following up to 5 redirects.

The request failed:

| Condition                                                                                | Status       |
| ---------------------------------------------------------------------------------------- | ------------ |
| The first request was refused: nothing listens on port 80, nothing is served over HTTP   | pass         |
| The first request was refused, but the domain has only IPv6 addresses                    | inconclusive |
| A redirect target refused the connection                                                 | inconclusive |
| A connection was reset or aborted, or the host or network was unreachable                | inconclusive |
| Timeout, blocked target, unresolvable redirect target, TLS failure on a redirect target, too many redirects or a malformed response | inconclusive |

Only a refused connection shows that port 80 is closed. A reset or an
unreachable host can come from a filter or the network on the way, so it
does not show whether anything is served over plain HTTP.

A response arrived:

| Condition                                                                                         | Status |
| ------------------------------------------------------------------------------------------------- | ------ |
| The final URL is `http://`: content is served over plain HTTP                                     | fail   |
| HTTPS is reached only after one or more further plain HTTP hops                                   | warn   |
| The first redirect goes to HTTPS on another host than the domain or its `www.`/apex counterpart   | warn   |
| The first redirect goes straight to HTTPS on the same host or its `www.`/apex counterpart         | pass   |

The `www.`/apex counterpart of `example.com` is `www.example.com`, and the
other way round. A redirect to another host is a warn because browsers can
only pick up HSTS for the scanned host when it redirects to itself first.

Evidence: the request and the redirect chain; the final status when content
is served over HTTP; the request and the error when the request failed, and
the URL that failed when a redirect target refused the connection.

References:
[RFC 6797, section 7.2](https://www.rfc-editor.org/rfc/rfc6797.html#section-7.2),
[OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).

#### `transport.hsts`: HTTP Strict Transport Security

Follows the [home page rules](#home-page-checks). Browsers keep HSTS per
host and read it from every HTTPS response, redirects included, so the header
is read from the scanned host's own HTTPS responses in the redirect chain of
`https://<domain>/`. When several of them send it, the last valid header
wins. A policy on another host does not count: a policy on `www.example.com`
does not protect `example.com`.

| Condition                                                                                            | Status |
| ---------------------------------------------------------------------------------------------------- | ------ |
| The final URL is `http://` (browsers ignore HSTS there)                                              | fail   |
| No `Strict-Transport-Security` header                                                                | fail   |
| The scanned host redirects to another host without sending the header (the summary names both hosts) | fail   |
| The first header is invalid, so browsers ignore it                                                   | fail   |
| `max-age=0` (tells browsers to drop the policy)                                                      | fail   |
| `max-age` below 15552000 seconds (180 days)                                                          | warn   |
| Otherwise                                                                                            | pass   |

Within one response, only the first `Strict-Transport-Security` header is used
(RFC 6797 section 8.1); additional ones are noted in the evidence. Directives
are separated by `;` and their names are case-insensitive; values are tokens
or quoted strings, so `max-age="31536000"` is accepted. The header is invalid
when a directive is malformed or repeated, directives are separated by commas,
`max-age` is missing or not a number of seconds, or `includeSubDomains` has a
value. `includeSubDomains` and `preload` are reported but do not change the
verdict.

Evidence: the URL checked, the header, `max-age` in seconds and days,
`includeSubDomains` and `preload`. When the scanned host redirects to another
host without the header: the URL it redirects to ("Redirects to") and the
policy that host sends, if any ("Policy of <host>").

References: [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797.html),
[MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security),
[OWASP HTTP Strict Transport Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html).

### Home page checks

`transport.hsts`, the six `headers.*` checks and the four `info.*` checks
read the response to one shared `GET https://<domain>/` that follows up to 5
redirects. Except for HSTS (see above), only the final response is
inspected; other headers and cookies on redirect responses are not seen. At
most 1 MB of the decoded body is kept.

Shared rules (`checks/homepage.py`):

| Condition                                                                                    | Status       |
| -------------------------------------------------------------------------------------------- | ------------ |
| The domain has no A/AAAA record                                                              | inconclusive |
| The fetch failed (blocked target, timeout, connection or TLS failure, unresolvable redirect, too many redirects, malformed response) | inconclusive |
| The response is a bot challenge: Cloudflare (`cf-mitigated: challenge`) or AWS WAF (`x-amzn-waf-action: challenge` or `captcha`) | inconclusive |
| The final status is 400 or higher                                                            | inconclusive |

The last two rows exist because the headers of a WAF block page, a challenge
or a proxy error page are probably not the site's own. They apply to HSTS,
the six header checks, `info.permissions_policy` and
`info.deprecated_headers`. `info.cdn` applies only the first two rows (an
error or challenge page still shows which edge network answered), and
`info.privacy_policy` has its own rules.

#### `headers.csp`: Content Security Policy

Policies are collected from every non-empty `Content-Security-Policy` header
(each header may hold several comma-separated policies) and from
`<meta http-equiv="Content-Security-Policy">` elements in the document head.
From a meta policy, `frame-ancestors`, `report-uri` and `sandbox` are
dropped, because browsers ignore them there. Each policy is parsed as CSP
Level 3 does: directives are split on `;`, names lower-cased, the first of a
repeated directive wins.

Each policy governs scripts through three source lists, with the fallbacks
of CSP Level 3 (section 6.8.1):

- `<script>` elements: `script-src-elem`, else `script-src`, else
  `default-src`;
- inline event handlers (attributes): `script-src-attr`, else `script-src`,
  else `default-src`;
- `eval()` and similar calls: `script-src`, else `default-src`.

A list that is missing allows everything it would govern: without an element
list, inline scripts and scripts from any host are allowed; without an
attribute list, inline event handlers (`'unsafe-inline'`); without an eval
list, `'unsafe-eval'`. The element list is checked for every weakness below
except `'unsafe-eval'`, the attribute list only for `'unsafe-inline'`, and the
eval list only for `'unsafe-eval'`.

A source list has these weaknesses:

- `'unsafe-inline'`, unless the list also contains a nonce, a hash
  (`'sha256-...'`, `'sha384-...'`, `'sha512-...'`) or `'strict-dynamic'`, which make
  browsers ignore it;
- `'unsafe-eval'`;
- a source that allows any host: `*`, a wildcard host with any scheme, port or
  path (`https://*`, `*:443`), or a bare `http:` or `https:`; unless
  `'strict-dynamic'` is present, which makes browsers ignore host and scheme
  sources;
- `data:`, unless `'strict-dynamic'` is present.

A script must be allowed by every enforced policy, so a weakness only counts
when every policy that restricts scripts has it.

| Condition                                                                         | Status |
| --------------------------------------------------------------------------------- | ------ |
| No enforced policy, but a non-empty `Content-Security-Policy-Report-Only`         | warn   |
| No enforced policy                                                                | fail   |
| No policy has `script-src`, `script-src-elem`, `script-src-attr` or `default-src` | warn   |
| Every script-restricting policy shares at least one weakness                      | warn   |
| Otherwise                                                                         | pass   |

Evidence: the policies (header and meta), the script source lists of each
policy that restricts scripts, a note when several policies restrict
scripts, and the weaknesses found. Up to 3 policy headers, 3 meta policies
and 3 script restrictions are shown, plus a count of any beyond that.

References:
[MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy),
[MDN: CSP script-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src),
[W3C: Content Security Policy Level 3](https://www.w3.org/TR/CSP3/),
[OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).

#### `headers.clickjacking`: Clickjacking protection

`frame-ancestors` is read from `Content-Security-Policy` headers only (it has
no effect in a meta policy). When any enforced policy has it,
`X-Frame-Options` is ignored, as browsers do.

| Condition                                                                                                    | Status |
| ------------------------------------------------------------------------------------------------------------ | ------ |
| Every `frame-ancestors` directive allows any host (`*`, a wildcard host, or a bare `http:`/`https:`)        | fail   |
| At least one `frame-ancestors` directive is restrictive (an empty one counts as `'none'`)                  | pass   |
| No `frame-ancestors`; `X-Frame-Options` contains `DENY` or `SAMEORIGIN` (any case, any of its values)      | pass   |
| No `frame-ancestors`; `X-Frame-Options` is `ALLOW-FROM ...` (obsolete, ignored by browsers)                   | warn   |
| No `frame-ancestors`; `X-Frame-Options` has another value                                                   | fail   |
| Neither is set                                                                                              | fail   |

Evidence: the `frame-ancestors` values and `X-Frame-Options` (marked as
ignored when `frame-ancestors` is set).

References:
[MDN: CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors),
[MDN: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options),
[OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html).

#### `headers.content_type_options`: X-Content-Type-Options

The values of all `X-Content-Type-Options` headers are split on commas; only
the first value counts, as in the Fetch standard.

| Condition                                       | Status |
| ----------------------------------------------- | ------ |
| First value is `nosniff` (any case, trimmed)    | pass   |
| Missing, or another value                       | fail   |

References:
[MDN: X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options),
[OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).

#### `headers.referrer_policy`: Referrer-Policy

The values of all `Referrer-Policy` headers are split on commas; the last
recognized token (any case) is the policy browsers apply (W3C Referrer
Policy, section 8.1).

| Effective policy                                                                         | Status |
| ---------------------------------------------------------------------------------------- | ------ |
| `no-referrer`, `same-origin`, `strict-origin`, `strict-origin-when-cross-origin`         | pass   |
| `origin`, `origin-when-cross-origin`, `no-referrer-when-downgrade`                       | warn   |
| `unsafe-url`                                                                             | fail   |
| No header, or no recognized token                                                        | warn   |

A missing header is a warn, not a fail: browsers default to
`strict-origin-when-cross-origin`, but the site does not state a policy.

References:
[MDN: Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy),
[W3C: Referrer Policy](https://www.w3.org/TR/referrer-policy/).

#### `headers.cookies`: Cookie security

Reads the `Set-Cookie` headers of the final home page response
(`checks/site.py`). Each header is parsed as browsers do (RFC 6265bis): the
name is the part before the first `=` of the first `;`-separated part,
attributes match case-insensitively, the last `SameSite` wins, and a
`SameSite` value other than `Strict`, `Lax` or `None` counts as absent.
Headers with an empty name and value are ignored. Cookie values are never
stored or reported.

A cookie is **session-like** when its name is `PHPSESSID`, `JSESSIONID`,
`connect.sid` or `ASP.NET_SessionId`, or contains `sess`, `sid`, `auth`,
`token`, `jwt` or `login` (any case).

| Condition (on any cookie)                                                                      | Status |
| ---------------------------------------------------------------------------------------------- | ------ |
| No `Secure`, including `SameSite=None` without `Secure`                                        | fail   |
| No (valid) `SameSite`                                                                          | warn   |
| A session-like cookie without `HttpOnly`                                                       | warn   |
| A `__Host-` cookie without `Secure`, with `Domain` or with a `Path` other than `/`; a `__Secure-` cookie without `Secure` | warn   |
| No cookies set                                                                                 | pass   |
| Every cookie passes the rules above                                                            | pass   |

The worst issue across all cookies sets the status. Evidence: for up to 10
cookies, the name (cut to 80 characters) and its flags (`Secure`, `HttpOnly`,
`SameSite`, session-like name), plus the number of cookies not shown.

References:
[MDN: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie),
[OWASP Session Management Cheat Sheet: Cookies](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies),
[RFC 6265](https://www.rfc-editor.org/rfc/rfc6265.html).

#### `headers.server_disclosure`: Server version disclosure

| Condition                                                                                              | Status |
| ------------------------------------------------------------------------------------------------------ | ------ |
| A version number (digits, a dot, digits) in `Server`, `X-Powered-By`, `X-AspNet-Version` or `X-AspNetMvc-Version` | fail   |
| `X-Powered-By` is present without a version                                                            | warn   |
| Otherwise (a bare product name such as `nginx` or `cloudflare` is fine)                                | pass   |

Evidence: every non-empty value of the four headers.

References: [MDN: Server](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Server),
[OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).

### Informational checks

Informational checks have weight 0 and report `info`. They are inconclusive
when the home page cannot be used, under the rules above.

#### `info.cdn`: CDN / edge network

Recognizes edge networks from the final response headers (header names are
matched in full, values searched case-insensitively). Several providers can
be reported.

| Provider          | Signals                                                                                 |
| ----------------- | --------------------------------------------------------------------------------------- |
| Cloudflare        | `cf-ray`; `server` starting with `cloudflare`                                           |
| Amazon CloudFront | `x-amz-cf-id`; `x-amz-cf-pop`; `via` or `x-cache` containing `cloudfront`              |
| Fastly            | `x-fastly-request-id`; `x-served-by` starting with `cache-`; `via` containing `fastly`; any `fastly-*` header |
| Akamai            | `server` starting with `akamai`; any `akamai-*` or `x-akamai-*` header                 |
| Azure Front Door  | `x-azure-ref`                                                                           |
| Vercel            | `x-vercel-id`; `server: vercel`                                                         |
| Netlify           | `x-nf-request-id`; `server: netlify`                                                    |
| Google Front End  | `server: Google Frontend`                                                               |
| Sucuri            | `x-sucuri-id`; `server` starting with `sucuri`                                          |
| Imperva           | `x-iinfo`; `x-cdn` containing `imperva` or `incapsula`                                  |

The summary names the providers, or says that none was detected from the
response headers. Evidence lists the headers that matched. This check has no
references.

#### `info.privacy_policy`: Privacy policy link

Looks for a link to a privacy policy in the home page HTML. No other page is
requested.

| Condition                                                    | Status       |
| ------------------------------------------------------------ | ------------ |
| No A/AAAA record, or the fetch failed                        | inconclusive |
| Bot challenge, or a final status of 300 or higher            | inconclusive |
| `Content-Type` present and not HTML                          | info         |
| A link was found, or not                                     | info         |

The body is decoded with the charset from `Content-Type` (default UTF-8) and
parsed with Python's `html.parser`. Every `<a href>` is collected with its
text, `aria-label`, `title` and the `alt` text of images inside it; a
`<base href>` is honoured. Fragment-only links, `javascript:`, `mailto:`,
`tel:`, `data:` and non-HTTP(S) links are skipped. A link matches when its
text, or its URL path and query, contains a keyword at the start of a word,
after case and accents are folded.

Keywords cover English, German, French, Spanish, Italian, Dutch,
Portuguese, Polish, Turkish (including `kvkk` and `aydinlatma metni`),
Swedish, Danish, Finnish, Norwegian, Romanian, Greek (in Greek script and
transliterated), Czech and Hungarian, plus `gdpr`, `dsgvo` and `rgpd`.
Imprint, terms and legal notice pages are not counted as privacy policies.

When several links match, links on the site's own hosts (the scanned host,
the final host, their `www.` forms, subdomains and parent domains) win, then
links that match on both text and URL, then the first in the document.
Links to `google.com`, `policies.google.com`, `hcaptcha.com`,
`cloudflare.com` and `facebook.com` are skipped unless they are the site's
own, because they come from embedded widgets.

The summary gives the absolute URL found (noting when it is on another site)
or says that no link was found in the home page HTML, and that links added by
JavaScript are not seen. Evidence: the link, its text and whether it matched
on the text, the URL or both. This check has no references.

#### `info.permissions_policy`: Permissions-Policy

The header is read as a structured-field dictionary: members are split on
commas, each `feature=allowlist` member is kept with its parameters dropped,
members without a value are skipped and a repeated feature keeps its last
allowlist. A feature is **disabled** with `()`, **allowed for all origins**
with `*`, and **limited** with any other allowlist.

- Header missing: "Permissions-Policy is not set" (noting when only the
  older `Feature-Policy` header is sent), with optional advice.
- Present: the number of restricted (disabled or limited) features and the
  first five of them, or that it restricts none. Evidence lists the three
  groups.

References:
[MDN: Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy),
[W3C: Permissions Policy](https://www.w3.org/TR/permissions-policy/).

#### `info.deprecated_headers`: Deprecated headers

Lists these headers when they are sent with a non-empty value, with advice
for each:

- `X-XSS-Protection`, unless its value before the first `;` is `0` (OWASP
  recommends removing it or sending `0`);
- `Expect-CT`;
- `Public-Key-Pins` and `Public-Key-Pins-Report-Only`.

Otherwise: "No deprecated security headers are sent."

References:
[MDN: X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection),
[MDN: Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Expect-CT),
[OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).

## Methodology versioning

Every report carries two versions, both defined in
`backend/src/webriskaudit/__init__.py`:

- `methodology_version` (`METHODOLOGY_VERSION`, currently `2026-11`, a year
  and month). As the comment next to it states, it is bumped whenever the
  checks, their weights or the grade bands change, so that two reports with
  the same methodology version are comparable. A change to a verdict rule changes what a check reports, so
  it is a change to the checks.
- `scanner_version` (the package version, currently `2.0.0`). It changes
  with any release, including changes that do not affect results.

Scores from different methodology versions should not be compared directly.
This document describes one methodology version; when it changes, the
document changes with it.

## Known limitations

**Email**

- DKIM selectors cannot be listed. Only the 11 common selectors are tried,
  so "no key found" is inconclusive, never a fail, and a key under another
  selector is not seen.
- The DMARC tree walk is simplified. It stops at the first name that
  publishes a record and does not apply RFC 9989's `psd=` rules for finding
  the organizational domain. `rua` is only checked for URI syntax (it decides
  the missing-policy rule and is reported as set or not set); report
  destinations are not verified.
- SPF `include` and `redirect` targets are not fetched, so the 10-lookup
  limit is counted on the top-level record only, nested records are not
  checked for syntax, and the limit of two void lookups (RFC 7208 section
  4.6.4) is not checked.

**Web**

- Only the home page is inspected, and apart from HSTS only its final
  response. Other headers and cookies sent on redirect responses are not
  seen: when `https://example.com/` redirects to `https://www.example.com/`,
  the header and cookie results describe `www.example.com`. HSTS is the
  exception: it is read from `example.com`'s own responses, because a policy
  on `www.example.com` does not protect `example.com`. Cookies set by
  JavaScript and links or meta tags added by JavaScript are not seen.
- A bot challenge or an HTTP error on the home page makes the header checks
  inconclusive. Only Cloudflare's and AWS WAF's challenge markers are
  recognized; another provider's block page with a 2xx status is scored as
  if it were the site.
- CSP is judged on script restrictions only. `'unsafe-hashes'`,
  `'wasm-unsafe-eval'` and directives such as `object-src` or `base-uri` are
  not evaluated.
- The session-cookie rule and the version-number pattern are heuristics.
  Other places that reveal software (`Via`, generator meta tags) are not
  checked.
- CDN detection relies on identifying headers; a provider that adds none is
  not detected.

**TLS**

- One handshake is made. Cipher suites and other protocol versions are not
  enumerated, and revocation (OCSP, CRL) and Certificate Transparency are not
  checked.
- TLS 1.2 is the lowest version the client offers, so a server that only
  offers TLS 1.0 or 1.1 fails the handshake (and the check) instead of
  getting the "deprecated protocol" warning.
- Missing intermediate certificates are not fetched (no AIA fetching), so a
  server that does not send its full chain fails verification, even though
  some browsers would recover.

**Vantage point and timing**

- Results reflect the scanner's network at one moment. A WAF that blocks the
  scanner makes checks inconclusive; geo-dependent answers are not seen.
- Connections go to the first IPv4 address (IPv6 only when there is none).
  Other addresses of the same name are not checked. Failed connections to
  IPv6-only hosts are inconclusive, since the scanner may lack IPv6.
- Reports are cached for up to 10 minutes, so a fix made right after a scan
  shows up only after the cache entry expires.

**Scoring**

- Inconclusive checks are left out of the score. A site that blocks the
  scanner's home page request removes 45 points of header checks from its
  denominator and is scored on the rest; coverage shows this, and the score
  is withheld only when less than half of the weight completes.
- Weights express this project's judgement of relative importance. They are
  not derived from a risk model.
