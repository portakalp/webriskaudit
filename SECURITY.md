# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on this repository
([private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).
Do not open a public issue for security problems. If the button is
missing, open an issue that only asks for a private contact, without
details.

Include what you found, how to reproduce it, and the impact you expect.
I aim to acknowledge reports within 7 days.

## Scope

- The scanner and API in `backend/` and its deployment at
  https://api.webriskaudit.com
- The website in `frontend/` and its deployment at https://webriskaudit.com
- The deployment configuration in `infra/`, `deploy/` and
  `.github/workflows/`

Out of scope: findings that the scanner reports about third-party domains.
Those belong to the owners of those domains.

## Supported versions

Only the latest commit on `main` is supported.

## Scanner traffic

The hosted scanner makes requests to the domains that its users enter. If
you run a site and see this traffic:

- **User-Agent.** Every HTTP request sends
  `WebRiskAudit/<version> (+https://github.com/portakalp/webriskaudit)`,
  for example `WebRiskAudit/2.0.0 (+https://github.com/portakalp/webriskaudit)`.
  The TLS handshake that reads the certificate carries no User-Agent.
- **Source address.** All of the hosted scanner's traffic leaves from one
  static IPv4 address, a Cloud NAT address in Google Cloud (europe-west1).
  The address is in use (the hosted API has been deployed since 2026-11-03),
  but it is not listed here yet.
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) ("Finding the NAT address")
  describes how it is looked up. Copies of the code that others run use
  their own addresses.
- **What a scan requests.** A TLS handshake on port 443 to read the
  certificate and one `GET` request each for `http://<domain>/` and
  `https://<domain>/`, following at most 5 redirects that the site sends, on
  ports 80 and 443 only; each HTTPS request makes its own TLS handshake.
  Nothing else is requested. DNS lookups go through the public resolvers `1.1.1.1`
  and `9.9.9.10`, so your name servers see those resolvers, not the
  scanner's address. A domain's report is cached for 10 minutes, so a site
  is normally fetched at most once in 10 minutes, however many people ask.
- **Blocking it.** You can block the address or the User-Agent. The scanner
  does not retry requests or change its address or User-Agent. The email
  checks use DNS only and are not affected. For the other checks, the
  report depends on how the block answers:
  - **Dropping** packets from the address: the requests time out, and the
    TLS, redirect and header checks are reported as inconclusive and do
    not count towards the score.
  - **Rejecting** connections from the address, for example with a TCP
    reset: the scanner cannot tell this from a closed port, so the TLS
    certificate check fails ("No HTTPS service answered on port 443"), the
    HTTP to HTTPS redirect check passes ("Port 80 is closed") and the
    header checks are inconclusive.
  - **Answering the User-Agent with an error status** (400 or higher): the
    header and cookie checks are inconclusive. The TLS check is not
    affected, since the handshake carries no User-Agent. On port 80, an
    error page served over plain HTTP fails the redirect check; a block
    that first redirects to HTTPS does not.

  So drop rather than reject, and keep the redirect to HTTPS in front of a
  User-Agent block; otherwise the report scores the block, not the site.
- **Reporting a problem or asking to be excluded.** Open an issue on this
  repository, or, if you would rather not name your domain in public, use
  private vulnerability reporting as above. Give the domain and, for a
  problem, the time and what you saw. I aim to answer within 7 days. The
  scanner has no exclusion list yet, so until a requested exclusion is in
  place, blocking the address or the User-Agent as described above is the
  immediate way to opt out.

## Responsible use

WebRiskAudit performs passive checks only: DNS lookups, a TLS handshake
and a small number of ordinary HTTP `GET` requests. It does not attempt
exploitation, brute forcing or port scanning. Only scan domains you own
or are authorised to assess.
