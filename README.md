# WebRiskAudit

An open-source, passive security scanner for domains. Enter a domain and get a
quick read on its email authentication (SPF, DKIM, DMARC), TLS certificate,
HTTP security headers and a few related signals, scored out of 100.

> **Status: v2 rebuild in progress.** v1 was a commercial MVP. This repository
> is being rebuilt in the open as a non-commercial project. See
> [Project history](#project-history) and the [roadmap](#roadmap). Until the
> items under [Known limitations](#known-limitations) are fixed, treat results
> as rough heuristics.

Live site: https://webriskaudit.com. The scanner API is offline during the
rebuild.

## What it checks

| Area       | Check                                                                    | Points |
| ---------- | ------------------------------------------------------------------------ | -----: |
| Email      | SPF record published                                                     |     10 |
| Email      | DMARC policy is `quarantine` or `reject`                                 |     10 |
| Email      | DKIM key found under a common selector                                   |      5 |
| Email      | Web server IP not listed on DNS blocklists                               |     10 |
| Server     | TLS certificate valid with more than 30 days left                        |     10 |
| Server     | CDN / WAF detected in front of the site                                  |     10 |
| Server     | `Server` header does not disclose the software                           |     10 |
| Server     | Security headers: HSTS, CSP, X-Frame-Options, Permissions-Policy, Referrer-Policy (5 each; 4 or more earn the full 20) |     20 |
| Compliance | Privacy policy reachable                                                 |     10 |

The total (95) is normalized to a 0-100 score: 80 and above is `SECURE`,
50-79 `MODERATE`, below 50 `CRITICAL`.

Every check is passive: DNS lookups, one TLS handshake, a `GET` for the home
page and `GET` requests for up to about 50 common privacy-policy paths,
stopping at the first one found. Requests identify themselves with the
User-Agent `WebRiskAudit/2.1.0 (+https://github.com/portakalp/webriskaudit)`.
Nothing is exploited, brute forced or port scanned. A scan takes about 30-60
seconds.

## Known limitations

These are real flaws found in the v1 scanner. They are the first things v2
fixes, each with tests.

- **Errors count as passes.** When a check times out, fails or has no data to
  read (for example a domain with no TXT records at all), most checks award
  full points ("benefit of the doubt"), so a domain that does not exist can
  still score well. v2 reports these checks as inconclusive.
- **DMARC parsing** uses substring matching, so `p=none; sp=reject` is read as
  `p=reject`.
- **The DNS blocklist check** cannot report a listing because of an attribute
  error that is swallowed as "clean".
- **DKIM** is only looked up under a short list of common selectors, so "not
  found" is not proof that DKIM is missing.
- **The API is not hardened against SSRF** yet: it fetches whatever host it is
  given and follows redirects. Do not expose it publicly until the guarded
  fetch layer lands.

## Repository layout

```
backend/    FastAPI service and the scanner (SecurityAuditor.py)
frontend/   Next.js static site served at webriskaudit.com
```

## Running locally

Backend (Python 3.12):

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Interactive API docs are at http://localhost:8000/docs. Browser origins
allowed by CORS come from `ALLOWED_ORIGINS` (see
[`backend/.env.example`](backend/.env.example)); the default covers
`http://localhost:3000` and `https://webriskaudit.com`.

If every TLS check fails locally on macOS with the python.org installer, run
its `Install Certificates.command` so Python can verify certificates.

Frontend (Node.js 22, pnpm):

```bash
cd frontend
cp .env.example .env.local
pnpm install
pnpm dev
```

Then open http://localhost:3000. Without a running API the site shows an
error state and offers an example report with illustrative values.

## API

```bash
curl -s -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com"}'
```

| Method | Path        | Description                                  |
| ------ | ----------- | -------------------------------------------- |
| `POST` | `/api/scan` | Scan a domain and return the scored report   |
| `GET`  | `/health`   | Liveness check                               |
| `GET`  | `/docs`     | OpenAPI documentation                        |

A failed scan returns `502` with a generic message, and invalid input returns
FastAPI's default `422`. The API keeps no database or scan history; its
application logs record each scanned domain and the URLs requested.

## Roadmap

- Guarded fetch layer: hostname validation, public-IP-only resolution, pinned
  connections and re-validated redirects
- Pass / fail / inconclusive results instead of benefit-of-the-doubt scoring
- Standards-based parsers (RFC 7208 SPF, RFC 9989 DMARC, RFC 6376 DKIM) with
  table-driven tests
- CI (ruff, mypy, pytest, ESLint, TypeScript), pinned dependencies and
  Docker Compose
- Explainable reports: evidence, why it matters and how to fix it, for every
  check

## Project history

v1 (December 2025 to June 2026) was the MVP of a small security-audit service:
visitors entered an email address and a domain, got a short report, and were
offered paid audit packages. I no longer offer that service, so v2 removes the
lead capture, pricing, booking and analytics, and turns the scanner into an
open-source tool. Rebuilding it also exposed the flaws listed under
[Known limitations](#known-limitations).

The final v1 code is tagged [`v1.0.0`](../../tree/v1.0.0). Its earlier history
was not imported because it contained a hardcoded credential.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability and for the
responsible-use policy. Only scan domains you own or are authorised to assess.

## License

[MIT](LICENSE) © Taha Gökalp Bakar
