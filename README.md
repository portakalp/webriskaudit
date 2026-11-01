# WebRiskAudit

An open-source, passive security scanner for domains. Enter a domain and get a
read on its email authentication (SPF, DMARC, DKIM), HTTPS and TLS setup and
HTTP security headers, scored out of 100. Every verdict comes with the
evidence it was based on, how to fix it, and references to the standard
behind it.

> **Status: v2 rebuild in progress.** v1 was a commercial MVP. This repository
> is being rebuilt in the open as a non-commercial project. The v2 scanner
> engine, the API and the website's v2 report view are in place; deploying
> them is the next step. See [Project history](#project-history), the
> [known limitations](#known-limitations) and the [roadmap](#roadmap).

Live site: https://webriskaudit.com. The scanner API is offline during the
rebuild.

## What it checks

| ID                             | Check                                                                                                                            | Category  | Weight |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- | --------- | -----: |
| `email.spf`                    | One valid SPF record (RFC 7208) ending in `-all` or `~all`, within 10 DNS-querying terms, without `ptr`                          | Email     |     10 |
| `email.dmarc`                  | DMARC policy (RFC 9989) of `quarantine` or `reject`, on the domain or inherited from a parent, not in testing mode               | Email     |     10 |
| `email.dkim`                   | A DKIM public key under one of 11 common selectors                                                                               | Email     |      5 |
| `transport.tls_certificate`    | The certificate on port 443 is trusted and matches the host, is not about to expire and its renewal is not overdue               | Transport |     15 |
| `transport.https_redirect`     | `http://` redirects straight to HTTPS (or port 80 is closed)                                                                     | Transport |      5 |
| `transport.hsts`               | `Strict-Transport-Security` with a `max-age` of at least 180 days                                                                | Transport |     10 |
| `headers.csp`                  | An enforced Content Security Policy that restricts scripts without `'unsafe-inline'`, `'unsafe-eval'`, wildcards or bare schemes | Headers   |     10 |
| `headers.clickjacking`         | CSP `frame-ancestors`, or `X-Frame-Options: DENY` / `SAMEORIGIN`                                                                 | Headers   |      5 |
| `headers.content_type_options` | `X-Content-Type-Options: nosniff`                                                                                                | Headers   |      5 |
| `headers.referrer_policy`      | A stated `Referrer-Policy` of `no-referrer`, `same-origin`, `strict-origin` or `strict-origin-when-cross-origin`                 | Headers   |      5 |
| `headers.cookies`              | Cookies set by the home page have `Secure` and `SameSite`, and session-like cookies `HttpOnly`                                   | Headers   |      5 |
| `headers.server_disclosure`    | No version numbers in `Server`, `X-Powered-By`, `X-AspNet-Version` or `X-AspNetMvc-Version`                                      | Headers   |      5 |
| `info.cdn`                     | CDN or edge network, recognized from response headers                                                                            | Info      |      0 |
| `info.privacy_policy`          | A privacy policy link on the home page (keywords in 17 languages)                                                                | Info      |      0 |
| `info.permissions_policy`      | Which browser features `Permissions-Policy` restricts                                                                            | Info      |      0 |
| `info.deprecated_headers`      | `X-XSS-Protection` (other than `0`), `Expect-CT`, `Public-Key-Pins` and `Public-Key-Pins-Report-Only`                            | Info      |      0 |

The scored checks add up to 90 points.

### Statuses and scoring

Each check ends in one of five statuses:

- **pass** earns the check's full weight, **warn** half of it, **fail** none.
- **inconclusive** means the check could not reach a verdict: DNS did not
  answer, the server could not be reached or timed out, the home page was an
  error or bot-challenge page, or the domain has no web server. It neither
  earns nor costs points and is reported under coverage instead.
- **info** is used by the informational checks, which have no weight.

The score is the points earned divided by the weight of the scored checks that
reached a verdict, as a percentage; each category gets its own score the same
way. Coverage reports how many scored checks reached a verdict. When those
checks carry less than half of the 90 points, the report has no score or
grade, so a handful of passing checks cannot read as an A.

| Grade | Score  |
| ----- | ------ |
| A     | 90-100 |
| B     | 75-89  |
| C     | 60-74  |
| D     | 45-59  |
| F     | 0-44   |

Before any check runs, the input is normalized (a URL is reduced to its host;
`www.` is kept) and resolved. IP addresses, single-label and special-use
names (`localhost`, `.local`, `.internal`, `.invalid`, `.test`, `.onion`, ...)
are refused, and so are names that do not exist (NXDOMAIN) or resolve to a
non-public address. A domain without A/AAAA records is still scanned: the
email checks run and the web checks are inconclusive.

[docs/METHODOLOGY.md](docs/METHODOLOGY.md) explains every verdict rule and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) how the scanner protects itself
and the sites it scans.

### Request footprint

All checks are passive. A scan makes:

- **DNS lookups:** A and AAAA for the domain; TXT at the domain (SPF), at
  `_dmarc.<domain>` and, if nothing is there, at up to six parent names
  (DMARC); TXT at 11 `<selector>._domainkey.<domain>` names (DKIM); and A/AAAA
  again before every HTTP request and the TLS handshake.
- **One TLS handshake** on port 443 to read the certificate.
- **Two `GET` requests**, for `http://<domain>/` and `https://<domain>/`, each
  following up to 5 redirects. The HTTPS requests make their own handshakes.
  No other paths are requested, and at most 1 MB of each body is kept.

Requests only go to public IP addresses on the default ports, every redirect
is checked again before it is followed, and the User-Agent is
`WebRiskAudit/<version> (+https://github.com/portakalp/webriskaudit)`. Nothing
is exploited, brute forced or port scanned. A scan typically takes a few
seconds at most and is cut off after 45 seconds; when the scanner is busy, a
new scan may first wait up to 30 seconds for a free slot.

## Known limitations

- **DKIM selectors cannot be listed.** Only 11 common selectors are tried, so
  "no key found" is inconclusive, never a fail.
- **The DMARC tree walk is simplified.** It stops at the first name that
  publishes a record and does not apply RFC 9989's `psd=` rules for choosing
  the organizational domain.
- **SPF includes are not expanded.** The 10-lookup limit is counted on the
  top-level record only, so a record that exceeds it through nested
  `include:` terms is not flagged.
- **Headers come from the home page only.** Other pages are not fetched, and
  headers or cookies sent only on redirect responses are not seen, except
  HSTS: it is read from the scanned host's own HTTPS responses, redirects
  included, since a policy on `www.example.com` does not cover `example.com`.
  Links and
  meta tags added by JavaScript are not seen either.
- **One vantage point.** Results show what the scanner's network sees; a WAF
  that blocks it makes the header checks inconclusive. Connections go to the
  first IPv4 address (IPv6 only if there is none), and failed connections to
  IPv6-only hosts are inconclusive, since the scanner may lack IPv6.
- **TLS is checked through one handshake.** Trust, host name, expiry and the
  negotiated protocol are checked; cipher suites and other protocol versions
  are not enumerated. A server that only offers TLS 1.0 or 1.1 fails the
  handshake and the check.
- **Abuse controls are per process.** The rate limit and report cache live in
  memory, so they reset on restart and are not shared between workers.

## Repository layout

```
backend/      FastAPI service and the scanner package (src/webriskaudit)
frontend/     Next.js static site served at webriskaudit.com
docs/         Methodology, threat model, deployment runbook, decisions (docs/adr/)
infra/gcp/    Terraform for the API's Google Cloud project (docs/DEPLOYMENT.md)
deploy/       Cloud Run service spec and the egress firewall check
compose.yaml  Local Docker stack: the site and the API
Makefile      Common tasks; run "make" to list them
```

## Running locally

With Docker, `make up` (or `docker compose up --build`) builds both images and
starts the site on http://localhost:3000 and the API on
http://localhost:8000, bound to 127.0.0.1; `make down` stops them. `make help`
lists the other tasks (install, lint, typecheck, test, openapi, dev servers).

Backend (Python 3.12, [uv](https://docs.astral.sh/uv/)):

```bash
cd backend
uv sync
uv run uvicorn webriskaudit.api:app --reload --port 8000 --no-proxy-headers --ws none
```

The two flags match the Docker image: uvicorn trusts no `X-Forwarded-For`
header and has no WebSocket support. Interactive API docs are at
http://localhost:8000/docs unless `API_DOCS_ENABLED=false`. Settings are read
from environment variables, listed with their defaults in
[`backend/.env.example`](backend/.env.example). Certificates are verified
against the [certifi](https://pypi.org/project/certifi/) CA bundle, so no
system certificate setup is needed.

Tests and checks (the same as CI):

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run python scripts/export_openapi.py   # regenerate openapi.json after API changes
```

Tests never leave the machine: fakes stand in for DNS, HTTP and TLS, and
sockets are disabled during the test run, except loopback (`127.0.0.1`) for
the tests that check SNI and certificate verification over real TLS.

Frontend (Node.js 22, pnpm):

```bash
cd frontend
cp .env.example .env.local
pnpm install
pnpm dev
```

Then open http://localhost:3000. Without a running API the site shows an
error state and offers an example report with illustrative values.

Frontend checks (the same as CI):

```bash
pnpm lint
pnpm exec tsc --noEmit
pnpm test    # vitest
pnpm build   # static export into out/
```

The API's TypeScript types (`frontend/lib/api-types.ts`) are generated from
`backend/openapi.json`. After an API change, run `make openapi`, which runs
`scripts/export_openapi.py` in `backend/` and `pnpm gen:api` in `frontend/`.

### Deployment notes

- The API image (`backend/Dockerfile`) runs uvicorn with
  `--no-proxy-headers`, so `X-Forwarded-For` is never read. Behind a proxy,
  set `ORIGIN_AUTH_SECRETS` and have the proxy send one of the secrets in an
  `X-Origin-Auth` header on every request; every route except `GET /` and
  `GET /health` then answers 403 without it. Set `CLIENT_IP_HEADER` to the
  header in which the proxy passes the client's address (`CF-Connecting-IP`
  behind Cloudflare), so the rate limits see the real client address.
  [ADR 0006](docs/adr/0006-client-ip-behind-cloudflare.md) explains why, and
  lists the Cloudflare settings this depends on.
- Set `API_DOCS_ENABLED=false` in production: `/docs` and `/redoc` load
  scripts from a CDN. [`backend/openapi.json`](backend/openapi.json)
  documents the API either way.
- The site's API URL (`NEXT_PUBLIC_API_URL`) is inlined at build time, and the
  site's Content Security Policy must allow its origin in `connect-src`, or
  the browser blocks every scan. For Cloudflare Pages, set
  `NEXT_PUBLIC_API_URL=https://api.webriskaudit.com` in the build settings,
  the origin that [`frontend/public/_headers`](frontend/public/_headers)
  allows, and change both together. The Docker image fills in `connect-src`
  from its build argument.

## API

```bash
curl -s -X POST http://localhost:8000/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com"}'
```

| Method | Path            | Description                                         |
| ------ | --------------- | --------------------------------------------------- |
| `POST` | `/api/v1/scan`  | Scan a domain and return the report                 |
| `GET`  | `/health`       | Liveness check                                      |
| `GET`  | `/`             | Service name and version                            |
| `GET`  | `/docs`         | Interactive docs; off with `API_DOCS_ENABLED=false` |

The OpenAPI document is committed as
[`backend/openapi.json`](backend/openapi.json), together with the TypeScript
types generated from it (`frontend/lib/api-types.ts`). CI fails when either
is missing from the commit or drifts from the code.

A report contains the domain, `scanned_at`, `duration_ms`, `score` and
`grade` (both `null` without enough coverage), `coverage`, per-category
scores, and one entry per check with its `status`, `points`, `summary`,
`evidence`, `remediation` and `references`. Evidence never includes cookie
values.

Errors are [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html) problem
details (`application/problem+json`) with `type`, `title`, `status` and
`detail`. Problem types are `https://webriskaudit.com/problems/<slug>`:

| Status | Slug                | When                                                        |
| -----: | ------------------- | ----------------------------------------------------------- |
|    422 | `invalid-domain`    | The input is not a public domain name                       |
|    422 | `invalid-request`   | The body is not `{"domain": "<string>"}`                    |
|    422 | `domain-not-found`  | The domain does not exist (NXDOMAIN)                        |
|    422 | `non-public-target` | The domain resolves to a private or reserved address        |
|    400 | `invalid-client-ip` | No valid client address in the proxy's `CLIENT_IP_HEADER`   |
|    403 | `forbidden`         | The request did not come through the proxy (origin auth)    |
|    413 | `request-too-large` | The request body is larger than 8 kB                        |
|    429 | `rate-limited`      | Too many new scans; `Retry-After` gives the wait in seconds |
|    500 | `internal-error`    | Unexpected failure (no internal details are returned)       |
|    502 | `dns-unavailable`   | DNS gave no usable answer for the domain                    |
|    503 | `scanner-busy`      | No room for a new scan right now; see `Retry-After`         |

Abuse controls (defaults, configurable in `.env.example`): request bodies over
8 kB are refused; each client (an IPv4 address or an IPv6 /64 network) may
start 10 new scans per 10 minutes, one at a time, and all clients together 600;
a domain's report is cached for 10 minutes and cached reports do not count
against the limits; concurrent requests for the same domain share one scan; at
most 4 scans run at once and at most 16 more wait, each for up to 30 seconds,
after which the API answers 503; and a waiting scan is dropped when its client
disconnects. Every check reports at most 20 evidence items, so a hostile site
cannot inflate the report. The client is the TCP peer, or behind a proxy the
address in `CLIENT_IP_HEADER`, accepted only with origin authentication (see
the deployment notes).

The scanner resolves names with the host's resolvers unless `DNS_NAMESERVERS`
lists others. On cloud hosts whose resolver also answers for private zones
(for example an AWS VPC with private hosted zones), set it to public
resolvers: otherwise the API's answers reveal which internal names exist, and
the email checks would show their TXT records.

The API keeps no database or scan history. It writes one JSON log line per
scan request (domain, outcome, cache use, score, grade, coverage and
duration), never logs client IP addresses or request bodies, and switches off
uvicorn's access log, which would record client addresses. The image also
turns off uvicorn's WebSocket support, which would log the client address and
path of every WebSocket handshake.

## Roadmap

- Deploy v2: the static site, and the API at `api.webriskaudit.com`
- A hash-based Content Security Policy for the site, without
  `'unsafe-inline'` in `script-src`
- Narrow the known limitations where it can be done passively, starting with
  expanding SPF includes to count nested lookups

## Project history

v1 (December 2025 to June 2026) was the MVP of a small security-audit service:
visitors entered an email address and a domain, got a short report, and were
offered paid audit packages. I no longer offer that service, so v2 removes the
lead capture, pricing, booking and analytics, and turns the scanner into an
open-source tool.

Rebuilding it also exposed flaws in the v1 scanner, which v2 fixes with
tests:

- Errors counted as passes ("benefit of the doubt"), so a domain that does
  not exist scored 75/100. v2 refuses such domains and reports checks that
  cannot reach a verdict as inconclusive.
- DMARC was parsed by substring matching, so `p=none; sp=reject` read as
  `p=reject`.
- The DNS blocklist check could not report a listing, because an attribute
  error was swallowed as "clean". v2 drops the check, and no longer scores
  the mere presence of a CDN or WAF.
- The API fetched whatever host it was given and followed redirects without
  checking them, with no protection against server-side request forgery.

The final v1 code is tagged [`v1.0.0`](../../tree/v1.0.0). Its earlier history
was not imported because it contained a hardcoded credential.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability and for the
responsible-use policy. Only scan domains you own or are authorised to assess.

## License

[MIT](LICENSE) © Taha Gökalp Bakar
