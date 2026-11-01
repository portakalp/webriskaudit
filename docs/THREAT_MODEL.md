# Threat model

This document covers the v2 scanner API (`backend/`) and the static website
(`frontend/`) as of 1 November 2026. It lists what needs protecting, who might
attack it, what the code does about it today, and what the deployment has to
add. File references are relative to `backend/src/webriskaudit/`.

## What the service is

WebRiskAudit takes a domain name from anyone on the internet and makes
network requests to that domain on their behalf: DNS lookups, one TLS
handshake and two HTTP `GET` request chains. It returns a report and keeps no
database. Anyone can call the API; there are no accounts.

An API that fetches URLs chosen by strangers is a server-side request forgery
(SSRF) and traffic amplification risk by design, so most of this document is
about the network layer.

```
  Visitor's browser
     |  static files                         POST /api/v1/scan {"domain": "..."}
     v                                          |
  Static host + Cloudflare (frontend/out)       v
                                             Cloudflare and the platform's proxy
                                               (set X-Origin-Auth, CF-Connecting-IP)
                                                |
                                                v
                                             uvicorn + FastAPI (api.py)
                                               origin auth, client address, body limit,
                                               rate limits, cache, scan queue
                                                |
                                                v
                                             Scanner (scanner.py) -> 16 checks
                                                |  ScanContext: resolver, fetcher, TLS probe
                  +-----------------------------+-----------------------------+
                  v                             v                             v
             DnsResolver                  GuardedFetcher                   TlsProbe
             (net/dns.py)                 (net/http.py)                  (net/tls.py)
                  |                             |                             |
                  v                             v                             v
          recursive resolver        scanned host and any public       scanned host,
          (DNS_NAMESERVERS,         host its redirects point to,      port 443
          else resolv.conf)         ports 80 and 443
```

## Assets

1. **The API host's network position.** Whatever the API process can reach
   that the internet cannot: private networks, the hosting platform's
   internal services, cloud metadata endpoints (`169.254.169.254`), services
   on localhost.
2. **Availability of the API**: CPU, memory, open connections and the scan
   slots (4 by default).
3. **Third parties and the scanner's reputation.** The scanner must not
   become a way to send traffic at someone else, and its IP address should
   not end up on blocklists.
4. **Honest reports.** A report must not claim more than the scan observed.
5. **Visitors' privacy**: their IP addresses and the domains they scan.
6. **The operator's logs**: they should be trustworthy and free of visitor
   data.

There are no user accounts, passwords, API keys or databases in the backend.
Its settings are limits, allowed origins and the DNS resolvers to query.

## Trust boundaries

| Boundary                    | What crosses it                         | Trust                                                                                                         |
| --------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Browser to static site      | Static files                            | No server code runs for the site ([ADR 0005](adr/0005-static-frontend-export.md)).                             |
| Client to API               | JSON body, client address, `Origin`     | Untrusted. CORS decides which web pages may read responses; it does not stop other clients.                    |
| API to DNS                  | Queries and answers                     | The resolver is trusted to resolve, but answers for the scanned domain come from whoever controls that domain: any address, any TXT content. |
| API to scanned hosts        | Status, headers, redirects, body, certificate, timing | Untrusted. Redirects may point anywhere; bodies may be huge, slow or compressed.                  |
| API to logs and platform    | Log lines                               | Must not carry client addresses or attacker-controlled line breaks.                                           |
| API response to browser     | Report JSON                             | Contains strings chosen by the scanned domain (header values, records, URLs).                                 |

## Adversaries

- **A1, internal reach (SSRF).** Wants the API to connect to internal
  addresses: directly (`127.0.0.1`, `localhost`, `[::1]`, `0x7f.1`), through
  their own domain's DNS (an A record of `10.0.0.5`, an AAAA record of
  `::ffff:127.0.0.1`), through redirects (`Location: http://169.254.169.254/`),
  or through DNS rebinding (a public address at the check, a private one at
  the connection).
- **A2, amplifier.** Wants to use the scanner to send traffic at a third
  party, or to hide behind the scanner's address.
- **A3, resource exhaustion.** Wants to exhaust the API with many scans, slow
  or endless targets, decompression bombs or large request bodies.
- **A4, log injection.** Wants to forge or break log lines with line breaks or
  control characters, or make the logs record visitor data.
- **A5, hostile target.** Controls a scanned domain and returns hostile
  content: malformed responses, markup aimed at whoever views the report.
- **A6, report manipulation.** Wants a misleading report, for example by
  serving the scanner something other than what visitors get.

## Mitigations as implemented

### SSRF and internal reach (A1)

1. **Input validation** (`net/domain.py`). The input is reduced to a host name
   and refused when it is an IP literal in any form (dotted, bracketed IPv6,
   or a last label that is a decimal or `0x` number, which URL parsers treat
   as IPv4), a single-label name, a name under a special-use TLD (`alt`,
   `arpa`, `corp`, `example`, `home`, `internal`, `invalid`, `local`,
   `localhost`, `mail`, `onion`, `test`), not valid LDH/IDNA, longer than 253
   characters, or not an `http`/`https` URL. The host is taken after the last
   `@` and before the first `/`, `\`, `?` or `#`, as browsers do, to avoid
   parser differences.
2. **Public-address test** (`net/addresses.py`). An address is public only if
   it is outside explicit tables: for IPv4, `0.0.0.0/8`, private ranges,
   `100.64.0.0/10`, loopback, `169.254.0.0/16`, `192.0.0.0/24`, documentation
   and benchmarking ranges, `192.88.99.0/24`, multicast and `240.0.0.0/4`;
   for IPv6, anything outside `2000::/3`, plus `2001::/23`, `2001:db8::/32` and
   `3fff::/20`. IPv6 addresses that carry an IPv4 address (IPv4-mapped,
   IPv4-compatible, NAT64 `64:ff9b::/96`, 6to4 and Teredo) are judged by the
   embedded IPv4 addresses. Addresses with a zone index are refused. The code
   does not rely on `ipaddress.is_global`, whose answers differ between Python
   versions.
3. **Pre-check** (`scanner.py`). A domain is only scanned when every A and
   AAAA address is public; otherwise the request is refused with
   `non-public-target` before any check runs.
4. **Every hop checked again** (`net/http.py`). Before each request, including
   each redirect: the scheme must be `http` or `https`, the port must be the
   scheme's default, the URL must not contain credentials, the host must pass
   the input validation above, and the name is resolved again. If the answer
   is empty or any address is not public, the hop is refused (`BLOCKED`).
5. **Address pinning with SNI** (`net/http.py`). The request goes to one of
   the addresses that were just checked (the first IPv4, else the first
   IPv6), with the host name in the `Host` header. For HTTPS the host name is
   passed as httpx's `sni_hostname` extension, which httpcore uses for SNI and
   for certificate host name verification, so the certificate is checked
   against the name, not the address. Certificates are verified against
   certifi's CA bundle. Because the connection uses the checked address, a
   DNS answer that changes between the check and the connection (rebinding)
   cannot move it.
6. **Manual redirects** (`net/http.py`). The client never follows redirects
   itself. Only 301, 302, 303, 307 and 308 with a `Location` are followed, at
   most 5 times, relative locations are resolved against the current URL,
   and each target goes through steps 4 and 5.
7. **TLS probe** (`net/tls.py`). Only port 443; the same validation, public
   address check and pinning, with the host name as `server_hostname`.
8. **No other way out.** Checks do not open sockets; they only use the
   resolver, fetcher and TLS prober in `ScanContext`. The HTTP client ignores
   proxy environment variables (`trust_env=False`) and does not retry. Tests
   run with sockets disabled (`pytest-socket`) except loopback (`127.0.0.1`)
   for the real-TLS tests, so a check that bypassed the network layer would
   fail its tests, and nothing leaves the machine.

### Traffic at third parties (A2)

1. **Fixed request budget per scan.** One TLS handshake on port 443 and two
   `GET` chains (`http://<domain>/` and `https://<domain>/`) of at most 6
   requests each (the first request and 5 redirects). No other paths, ports
   or methods, no request bodies and no retries. DNS: A/AAAA for the
   pre-check, one TXT for SPF, up to 7 TXT for DMARC, 11 TXT for DKIM, and
   A/AAAA again before every HTTP hop and the TLS probe.
2. **Rate limits on new scans** (`ratelimit.py`, `api.py`). Per client (an
   IPv4 address, or an IPv6 /64 network, since one subscriber usually holds
   a whole /64): 10 new scans per 10 minutes as a sliding window, and one
   new scan running or waiting at a time (`429`). For all clients together:
   600 new scans per window (`503 scanner-busy`), a backstop against clients
   with many addresses. At most 10 000 client keys are tracked; past that
   the least recently active one is forgotten.
3. **Cache and coalescing** (`cache.py`). A host name's report is served from
   memory for 10 minutes, and concurrent requests for the same host share one
   running scan, so a host is scanned at most once per 10 minutes per
   process, however many clients ask.
4. **Concurrency cap.** At most 4 scans run at once and at most 16 more wait
   for a slot (`api.py`), which bounds the scanner's total outgoing
   activity.
5. **Identification.** The User-Agent names the project and links to the
   repository, so a target can identify and block the scanner.
   [SECURITY.md](../SECURITY.md) states the responsible-use policy.

### Exhausting the API (A3)

1. **Cheap refusals first.** A request body over 8 KiB is refused with `413
   request-too-large` before the app reads it, whether the size is declared
   in `Content-Length` or only seen while streaming (`BodySizeLimit` in
   `api.py`). A `domain` longer than 2048 characters or not a valid domain
   is refused before rate limiting, DNS or any other work.
2. **Rate limits on new scans only.** Cache hits and requests that join a
   running scan do not count. A refused request is not recorded, so retrying
   early does not extend the wait. `429` and `503` responses carry
   `Retry-After`. Expired client entries and cached reports are swept at
   the start of every request, health checks included (`Sweeper` in
   `api.py`).
3. **Bounded queue.** At most 4 scans run; at most 16 more wait for a slot,
   each for up to 30 seconds. Beyond that, or when the wait runs out, the API
   answers `503 scanner-busy` with `Retry-After`.
4. **Time limits.** DNS: 5 seconds per query. HTTP: 10 seconds per fetch
   chain, covering DNS, redirects and the body; body reading stops at 90% of
   that budget so the status and headers survive a slow body. TLS: 10
   seconds. Each check: 30 seconds. Each scan: 45 seconds; checks still
   running then are inconclusive.
5. **Body limits** (`net/http.py`). At most 1 MB of decoded body is kept per
   final response; bodies of redirect responses are not read. Only `gzip` and
   `deflate` are offered, and the decoder never inflates more than the
   remaining limit, so a decompression bomb stops at 1 MB. Reading also stops
   after 2 MB of raw bytes. Stacked or unknown codings are not decoded.
6. **Bounded memory.** The cache holds at most 1024 reports and each rate
   limiter at most 10 000 client keys. Parsers work on bounded input (TXT
   records, headers, a 1 MB body), and each check reports at most 20
   evidence items, with labels cut to 100 characters, values to 300 and
   summaries to 500 (`checks/base.py`).
7. **Disconnects.** A scan that is still waiting for a slot is cancelled once
   its last client disconnects, so it neither holds a queue place nor runs
   for nobody. A scan that has started finishes and is cached, so cancelling
   and retrying does not start a second scan; the retry joins the first one
   or gets the cached report.

### Hostile targets (A5)

1. A check that raises an unexpected exception becomes inconclusive and the
   other checks continue (`checks/base.py`).
2. HTML is parsed with Python's `html.parser`: no scripts run and no
   subresources are fetched.
3. Cookie values are dropped while parsing and never reach the report or the
   logs. URLs in evidence keep only scheme, host and path (`redact_url` in
   `checks/base.py`): query strings, fragments and `;` path parameters can
   carry session ids or tokens, and a cached report is shown to anyone who
   scans the same domain.
4. Report fields contain strings the scanned domain chose: header values, DNS
   records, URLs, certificate names. The frontend must render them as text
   (React escapes text by default; `dangerouslySetInnerHTML` must not be used
   for report data). The privacy-policy URL is only reported for `http` and
   `https` links. Reference URLs come from the code, not from the target.

### Logs (A4)

1. **JSON lines** (`logs.py`). Every record is one `json.dumps` object, so line
   breaks and control characters in any value are escaped and cannot start a
   new log line or forge fields.
2. **What is logged.** One line per scan request: outcome, the normalized
   domain, cache use (`miss`, `hit` or `coalesced`), score, grade, coverage and
   duration. The normalized domain is lower-case ASCII letters, digits,
   hyphens and dots only. The raw input of an invalid request, request
   bodies and client addresses are never logged.
3. **uvicorn's access log is switched off** at startup, because it would
   record client addresses. The image also runs uvicorn with `--ws none`:
   its WebSocket support logs the client address and raw path of every
   handshake, outside the access log. An upgrade request is then plain HTTP
   and goes through origin authentication like any other.
4. Exceptions inside checks and unexpected errors are logged with their
   tracebacks, on the server only.

### Errors (information disclosure)

1. Errors are RFC 9457 problem details with fixed type URIs
   (`https://webriskaudit.com/problems/<slug>`) and fixed or generated
   messages (`api.py`).
2. Unexpected errors return `500 internal-error` with a generic detail; the
   exception goes to the log only.
3. Invalid request bodies return up to three field locations and validation
   messages, not the submitted values.
4. Unknown routes and wrong methods also return problem details, with
   `type: about:blank`. A refused CORS preflight gets the CORS middleware's
   plain-text `400`.
5. DNS error messages do not include resolver addresses (`net/dns.py`).

### Browsers on other sites

CORS allows only the origins in `ALLOWED_ORIGINS` (default
`http://localhost:3000` and `https://webriskaudit.com`), without credentials,
for `GET` and `POST` with a `Content-Type` header, and exposes `Retry-After`.
The API uses no cookies or other ambient credentials, so a page on another
site has nothing to borrow; it could only start scans the same way any
client can.

### Misleading reports (A6)

1. A check that cannot reach a verdict says so (`inconclusive`) instead of
   guessing, and the score is withheld when less than half of the weight
   completes ([ADR 0002](adr/0002-explicit-inconclusive-results.md)).
2. Domains that do not exist are refused instead of scored.
3. Bot challenge and HTTP error pages are not scored as the site's headers.
4. Failed scans are not cached.

A domain owner can still serve the scanner something different from what
visitors get, for example by User-Agent or source address. Any external scan
has this limit; the report describes what the scanner saw.

### Supply chain

CI pins GitHub Actions to commit SHAs, runs with a read-only token, installs
from lockfiles (`uv sync --locked`, `pnpm install --frozen-lockfile`), audits
dependencies (`pip-audit`, `pnpm audit`), scans for secrets (gitleaks) and
builds both Docker images without pushing them. The Dockerfiles pin their
base images by tag and digest. Dependabot proposes updates for the npm and uv
dependencies, the GitHub Actions and the Docker base images. The v1 history
was not imported because it contained a hardcoded credential.

## Data kept

| Data                                   | Where                                       | How long                                                                                                                                                           |
| -------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Client address (IPv4, or the IPv6 /64) | Rate limiter and scan queue, process memory | While it has hits in the window or a new scan waiting or running; removed by a sweep after the hits expire; lost on restart. Never logged or persisted by the app. |
| Scanned domain and report              | Cache, process memory                       | 10 minutes (at most 1024 reports); lost on restart.                                                                                                                |
| Scanned domain                         | Application log (stderr)                    | As long as the hosting platform keeps logs.                                                                                                                        |

There is no database, no account, no cookie and no analytics. See
[ADR 0003](adr/0003-no-personal-data.md).

## Residual risks

1. **Defence in depth for SSRF depends on the deployment.** The address checks
   are code; a bug in them, in a library, or a range missing from the tables
   would expose the internal network unless the network itself blocks it.
2. **Split-horizon DNS.** Unless `DNS_NAMESERVERS` is set, the scanner uses
   the resolvers in `/etc/resolv.conf`. If those serve internal zones,
   internal names that resolve to private addresses are refused, but the
   difference between `domain-not-found` and `non-public-target` tells a
   caller which internal names exist, and the TXT records of internal names
   without A/AAAA records appear in the email checks. Mitigation: set
   `DNS_NAMESERVERS` to public resolvers; when it is set, `resolv.conf` is
   not read at all.
3. **Waiting scans hold connections.** Up to 16 scans can wait for a slot,
   each for up to 30 seconds, before the 45-second scan deadline starts, so
   a request can take about 75 seconds and keep its connection open that
   long. The queue is bounded and a waiting scan is dropped when its client
   disconnects, so this costs memory and connections, not scans.
4. **Rate limiting is per client key and per process.** Clients with a /48
   or larger IPv6 allocation, or many IPv4 addresses, can rotate keys; the
   global limit of 600 new scans per window bounds the total. The limits,
   cache and queue are in memory: they reset on restart and multiply with
   the number of workers or instances.
5. **The cache key is the host name.** Varying subdomains of a victim with
   wildcard DNS bypasses the cache; the rate limits and the scan queue still
   apply.
6. **No authentication.** The API is public by design; abuse controls are
   the only barrier.
7. **Logs record scanned domains.** A domain can identify a person (for
   example a personal domain). Retention is set by the hosting platform.
8. **Report strings are attacker-controlled** and safe only as long as the
   frontend keeps rendering them as text.

## What the deployment must add

1. **Egress firewall.** Allow outbound TCP 80 and 443 and DNS to the
   configured resolver only. Deny private, link-local, metadata, loopback and
   other non-public ranges (IPv4 and IPv6) at the network level, as a second
   layer behind the code.
2. **A public recursive resolver** without internal zones: set
   `DNS_NAMESERVERS` (for example `1.1.1.1,9.9.9.10`; Quad9's `9.9.9.9`
   filters domains, which then look nonexistent), or make sure the
   container's `/etc/resolv.conf` points to such a resolver.
3. **Origin authentication and the client address.** Behind a proxy, set
   `ORIGIN_AUTH_SECRETS` and `CLIENT_IP_HEADER` (`CF-Connecting-IP` behind
   Cloudflare), and have the proxy set `X-Origin-Auth` to one of the secrets
   on every request ([ADR 0006](adr/0006-client-ip-behind-cloudflare.md)).
   Every route except `GET /` and `GET /health` then answers 403 without the
   secret, so a request that skips the proxy cannot choose its own client
   address. Without this, every client shares the proxy's address and one
   rate limit. uvicorn's `--proxy-headers` is no substitute: the proxies
   append to a client-supplied `X-Forwarded-For`, so with
   `--forwarded-allow-ips="*"` each request can pick its own rate limit key.
   The image runs uvicorn with `--no-proxy-headers`.
4. **One process.** Run one worker per instance and one instance, or accept
   that every limit multiplies with the number of processes. Deploys and
   restarts reset the limits and the cache.
5. **Proxy limits.** Cap the request body size at the proxy too (a few
   kilobytes is enough), and set request and header timeouts and a
   connection limit. Allow requests to stay open for about 75 seconds (queue
   wait plus scan deadline).
6. **Settings.** Set `ALLOWED_ORIGINS` to the real site origin, and keep
   `RATE_LIMIT_SCANS`, `GLOBAL_RATE_LIMIT_SCANS` and `CACHE_TTL_SECONDS`
   above 0 in production (0 turns those controls off). Invalid values stop
   the app at startup.
7. **Log retention.** Keep application logs and the platform's own access
   logs (which do contain client addresses) for a short, stated period, in
   line with the site's privacy note.
8. **Updates.** CA trust comes from certifi, not the system store, so keep
   dependencies current (Dependabot, `uv lock --upgrade`).
