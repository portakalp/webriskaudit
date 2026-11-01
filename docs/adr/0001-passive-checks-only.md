# 1. Passive checks only

Date: 2026-11-01

## Status

Accepted

## Context

WebRiskAudit is public: anyone can point it at any domain, and the owner of
that domain has not asked to be scanned. What the scanner sends is therefore
traffic that a third party receives from a stranger.

v1 went well beyond reading public information. To find a privacy policy it
walked a list of 48 guessed paths on the target (`/privacy`, `/datenschutz`,
`/impressum`, `/kvkk`, ...). Each request was retried up to three times with
exponential backoff whenever it saw a 403 or the word "cloudflare", with a
Chrome User-Agent, explicitly "to bypass Cloudflare blocks". It also looked
the site's IP address up in DNS blocklists and scored the presence of a WAF.
One scan could send dozens of requests to a site and work around the bot
protection its owner had chosen.

v2 is a non-commercial, open-source tool and the owner's portfolio project.
It has to be safe to run against any domain and honest about what it does.

## Decision

The scanner only observes what a browser or a mail server sees during normal
use:

- DNS: A/AAAA of the domain; TXT at the domain (SPF), at `_dmarc.<domain>`
  and up to six parent names (DMARC), and at 11 common DKIM selector names.
- One TLS handshake on port 443.
- `GET http://<domain>/` and `GET https://<domain>/`, each following up to 5
  redirects, with at most 1 MB of each body kept.

Nothing else: no other paths, ports or methods, no request bodies, no
retries, no brute forcing, no exploitation. The scanner identifies itself as
`WebRiskAudit/<version> (+https://github.com/portakalp/webriskaudit)` and does
not try to get past bot protection: a challenge page makes the affected
checks inconclusive instead.

A check that would need more than this budget is not added unless this
decision is revisited.

## Consequences

- The footprint of a scan is small, fixed and documented (README, "Request
  footprint"), so it can be stated plainly in the responsible-use policy and
  the amplification risk stays low (see the threat model).
- Some things cannot be checked. DKIM selectors can only be guessed, so a
  missing key is never a fail. The privacy policy is found only through links
  on the home page. Headers and cookies come from the home page only. TLS is
  judged from one handshake, so protocol versions and cipher suites are not
  enumerated. Sites behind bot protection get inconclusive header checks.
- The v1 checks that did not fit were dropped: the guessed privacy paths, the
  DNS blocklist lookup (which in v1 could not report a listing anyway, because
  an attribute error was swallowed as "clean"), and the scored WAF detection.
  CDN detection remains as an informational check without points. The v1
  cookie-consent and data-leak results, which were never measured, had
  already been removed.
- Results describe one vantage point at one moment; the scanner does not
  retry from elsewhere.
