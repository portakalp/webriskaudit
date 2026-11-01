# 2. Explicit inconclusive results

Date: 2026-11-01

## Status

Accepted

## Context

Checks fail to reach a verdict for reasons unrelated to the domain's
configuration: DNS times out, a server drops the connection, a WAF answers
with a challenge page, the scanner has no IPv6 route, or the domain has no
web server at all.

v1 resolved these cases with a rule its code called "benefit of the doubt":
a timeout or error earned the check's full points (and some checks reported
`"assumed": true`). A domain that does not exist scored 75 out of 100,
because nearly every check errored and was then credited. Other v1 results
were reported without being measured: the cookie-consent check awarded
points whenever a privacy policy was found, and `data_leak_safe` was always
true. A failed scan returned `200` with zeroed results.

A score that rewards errors cannot be trusted, and a security tool that
overstates what it observed is worse than none.

## Decision

- Every check reports one of five statuses: `pass`, `warn`, `fail`,
  `inconclusive` or `info`. `inconclusive` means no verdict was reached, and
  the summary says why (DNS did not answer, the request timed out, the home
  page was a bot challenge or an HTTP error, the domain has no A/AAAA record,
  the check timed out or failed unexpectedly).
- Inconclusive checks neither earn nor cost points: the score is points
  earned over the weight of the checks that completed. The report states
  coverage (completed, inconclusive and total scored checks).
- When the completed checks carry less than half of the total scored weight,
  the report has no score and no grade (`null`), so a few passing checks
  cannot read as an A.
- A check returns inconclusive whenever the cause may be on the scanner's
  side, not only on errors: a failed connection to an IPv6-only host, a
  refused connection to a redirect target, a missing DKIM key under the
  guessed selectors (absence cannot be proven), and the headers of a
  challenge or error page (they are probably not the site's own).
- Before any check runs, the scan is refused outright for a domain that does
  not exist (NXDOMAIN), resolves to a non-public address, or gets no usable
  DNS answer. Those are API errors, not reports.
- An unexpected exception in a check becomes an inconclusive result; the
  scan still completes.

## Consequences

- A report never claims more than the scan observed, and the evidence and
  summary of an inconclusive check explain what went wrong.
- Scores are computed over different denominators. Two reports can both
  score 100 with different coverage, so the frontend must show coverage next
  to the score.
- A site can remove checks from its score by blocking the scanner: a bot
  challenge on the home page takes 45 of the 90 points out of the
  denominator. The 50% rule limits this (blocking every web check leaves no
  score), and coverage makes it visible, but it is not prevented.
- The frontend and API clients must handle `score: null`, `grade: null` and
  category scores of `null`.
- Deciding between `fail` and `inconclusive` is part of each check's rules and
  is documented per check in [METHODOLOGY.md](../METHODOLOGY.md).
