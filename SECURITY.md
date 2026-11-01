# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on this repository
([private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).
Do not open a public issue for security problems.

Include what you found, how to reproduce it, and the impact you expect.
I aim to acknowledge reports within 7 days.

## Scope

- The scanner and API in `backend/`
- The website in `frontend/` and its deployment at https://webriskaudit.com

Out of scope: findings that the scanner reports about third-party domains.
Those belong to the owners of those domains.

## Supported versions

Only the latest commit on `main` is supported.

## Responsible use

WebRiskAudit performs passive checks only: DNS lookups, a TLS handshake
and a small number of ordinary HTTP `GET` requests. It does not attempt
exploitation, brute forcing or port scanning. Only scan domains you own
or are authorised to assess.
