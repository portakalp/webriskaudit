# Scan triage: Semgrep (SAST) and OWASP ZAP (DAST)

Date: 2026-11-12. Scanned: `main` at `d8cc7d7`, then this branch after each
fix. First SAST and DAST run on the project; every finding has a decision
below. Raw output: the `semgrep-sarif` artifact of the CI job and the ZAP
reports next to this file.

| Tool             | Reported     | False positive | Fixed | Accepted | Informational |
| ---------------- | ------------ | -------------: | ----: | -------: | ------------: |
| Semgrep 1.185.0  | 5 (one rule) |              0 |     5 |        0 |             0 |
| ZAP 2.17.0, site | 3 alerts     |              1 |     0 |        1 |             1 |
| ZAP 2.17.0, API  | 2 alerts     |              0 |     1 |        0 |             1 |

Semgrep reported nothing in the application code (Python or TypeScript).

## 1. SAST: Semgrep

Semgrep Community Edition 1.185.0 from PyPI, no account, registry rules as
downloaded on the scan date. The CI job `SAST (Semgrep)` runs the same scan on
every pull request and on `main` and fails on any finding:

```bash
uvx semgrep@1.185.0 scan --metrics=off --error \
  --config p/python --config p/typescript --config p/owasp-top-ten \
  --config p/github-actions --config semgrep/ --sarif-output semgrep.sarif .
```

571 rules loaded (569 registry, 2 project), 337 applied to 127 files. Skipped:
23 test files on Semgrep's default ignore list (`backend/tests/`,
`frontend/test/`, `infra/gcp/tests/`) and one file over 1 MB; one line of
`frontend/components/ScanWorkflow.test.tsx` did not parse.

`p/owasp-top-ten` reported 5 findings, all from one rule (S1). `p/python`,
`p/typescript`, `p/github-actions` and the project rules reported nothing.
Run once and not in CI: `p/react`, `p/dockerfile`, `p/terraform` and
`p/security-audit`, also nothing.

**S1. `dependabot-missing-cooldown`, medium, `.github/dependabot.yml`, once
per ecosystem (5). True positive, fixed in `eae9e2c`.** Dependabot proposed a
version on the day it was published, so a malicious or broken release could
reach a pull request before it was withdrawn (CWE-829). Each ecosystem now
has `cooldown: default-days: 7`; security updates are not delayed. Re-scan: 0
findings.

**Project rules.** `http-client-outside-net` and `raw-socket-outside-net`
encode [ADR 0004](../adr/0004-guarded-network-layer.md): under `backend/src`,
only `webriskaudit/net/`, which holds the SSRF guards, may import an HTTP
client or use sockets and dnspython. `semgrep --test semgrep/` passes. As a
control, a temporary file in `checks/` importing `socket` and `httpx` made
both rules fire. They match import statements, so an import built at run time
(`importlib`) gets past them.

## 2. DAST: OWASP ZAP, passive scans of the local stack

ZAP 2.17.0, image `ghcr.io/zaproxy/zaproxy:stable` at digest
`sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af`.
The only target was this project's own stack from `compose.yaml` on the
developer's machine. Production and third-party hosts were not scanned, and no
active scan was run: ZAP requested pages and read the answers.

The stack ran with [compose.scan.yaml](compose.scan.yaml): no host ports, and
an internal network with no route to the internet (checked: `1.1.1.1` is
unreachable and outside names do not resolve). The API's job is to connect to
the domain it is given, so the scanner must not be able to make it contact
someone else. ZAP therefore used the rules shipped in the image; the "network
failures" in the reports are its own update and telemetry calls (the log of
the site run and the OpenAPI run has no other errors).

```bash
docker compose -f compose.yaml -f docs/security/compose.scan.yaml up --build --detach --wait
zap() { docker run --rm --network webriskaudit_default -v "$OUT:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable "$@"; }
zap zap-baseline.py -t http://web:8080 -w zap-web-baseline.md
zap zap-baseline.py -t http://api:8000 -w zap-api-baseline.md
zap zap-api-scan.py -t http://api:8000/openapi.json -f openapi -S -w zap-api-openapi.md
```

`$OUT` was a scratch directory; the reports were copied from it. The baseline
runs also wrote a JSON copy (`-J`), which is not committed.

| Run                               | URLs | Alerts | Report                                     |
| --------------------------------- | ---: | -----: | ------------------------------------------ |
| Site, baseline                    |   27 |      3 | [zap-web-baseline.md](zap-web-baseline.md) |
| API, baseline                     |    3 |      1 | [zap-api-baseline.md](zap-api-baseline.md) |
| API, from `openapi.json`, passive |    7 |      2 | [zap-api-openapi.md](zap-api-openapi.md)   |

A JSON API has no links to follow, so the baseline spider saw 3 URLs. The
third run imports the OpenAPI file and requests each operation once; `-S`
skips the active scan. Its PASS list still names active rules that never ran,
so no PASS count is quoted here.

**D1. Application Error Disclosure (90022), medium, `/privacy-policy`. False
positive.** The evidence is the text "Error Report": the page says that scan
data "can also be kept for up to 30 days by Google Cloud's Error Reporting".
The page is static and shows no error output.

**D2. CSP: style-src unsafe-inline (10055), medium, all 5 HTML responses.
True, accepted.** `style-src` keeps `'unsafe-inline'` because the React code
sets `style` attributes (a score bar's width, for example), which hashes do
not cover. An inline style cannot run script, and abusing it needs HTML
injection first; the site is a static export that renders report strings as
text. `script-src` has no `'unsafe-inline'`. Possible follow-up, after testing
in browsers: `style-src 'self'; style-src-attr 'unsafe-inline'`.

**D3. Modern Web Application (10109), informational, `/64` (a 404). No
action.** ZAP notes that the page loads scripts and has no links: a hint to
use its browser-based spider, not a weakness.

**D4. X-Content-Type-Options Header Missing (10021), low, API (`/`,
`/health`, `/openapi.json`). True positive, fixed in `76d3f9d`.** The site
sent `nosniff`; the API did not. A small middleware now adds it to every API
response, with tests. Both API runs were repeated after the fix and no longer
report it ([zap-api-openapi-after-fix.md](zap-api-openapi-after-fix.md)).

**D5. Client Error response code (100000), informational, `POST
/api/v1/scan`. Expected, no action.** ZAP's generated request body is not a
valid domain, so the API refuses it with 422. The API log has that one request
as `invalid-domain`; no scan was started.

## 3. What these scans do not show

- Nothing was attacked: no injection or fuzzing against the API. ZAP's active
  API scan against the same isolated stack is the next step.
- ZAP's spider does not run JavaScript, so the path a visitor takes (form, API
  call, report on screen) was not exercised.
- The stack was local, over plain HTTP, without Cloudflare, the load balancer
  or origin authentication.
- Semgrep Community Edition looks at one function at a time, so a flaw that
  only shows across functions or files is not reported.
