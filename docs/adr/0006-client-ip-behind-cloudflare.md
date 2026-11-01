# 6. Client IP behind Cloudflare

Date: 2026-11-01

## Status

Accepted

## Context

The per-client rate limits key on the client's address: an IPv4 address as
is, an IPv6 address by its /64 network ([ADR 0003](0003-no-personal-data.md)).
In production the API sits behind two proxies: Cloudflare (a proxied DNS
record for `api.webriskaudit.com`) and a Google Cloud global external
Application Load Balancer in front of Cloud Run. The TCP peer the application
sees is a Google front end, so keying on the peer would put every visitor
into one rate limit.

The usual fix, uvicorn's `--proxy-headers` with `FORWARDED_ALLOW_IPS`, does
not work here:

- With `--forwarded-allow-ips="*"`, uvicorn (0.54) takes the leftmost entry
  of `X-Forwarded-For`, which is whatever the client sent. Cloudflare appends
  to an existing `X-Forwarded-For` instead of replacing it, and so does the
  load balancer (`<supplied-value>,<client-ip>,<load-balancer-ip>`). Every
  request could pick its own rate limit key.
- With a list of trusted networks, uvicorn takes the first untrusted entry
  from the right. That needs the Google front-end ranges, the load
  balancer's address and every Cloudflare range, kept up to date, and it
  still trusts a header that anyone can send.
- The load balancer has a public address. A request sent straight to it
  skips Cloudflare and can carry any header, including `CF-Connecting-IP`.
- Allowing only Cloudflare's address ranges does not help either: a
  Cloudflare Worker on another account can send requests from those ranges
  to a non-Cloudflare destination (the load balancer's address) and set
  `CF-Connecting-IP` itself, as Cloudflare's documentation of the header
  states.

Cloudflare puts the visitor's address in `CF-Connecting-IP`, a single
address that it sets on every request it forwards. The header can be trusted
only if the API knows the request came through our zone.

## Decision

- **Origin authentication.** A Cloudflare Transform Rule (Modify Request
  Header, *Set static*) adds `X-Origin-Auth: <secret>` to every request for
  `api.webriskaudit.com`. The API reads the accepted values from
  `ORIGIN_AUTH_SECRETS` (comma-separated, each at least 32 visible ASCII
  characters). A pure ASGI middleware, outermost apart from the sweep of
  expired rate limit entries and cached reports (which reads nothing from
  the request), compares the header with every secret using
  `hmac.compare_digest` and answers 403 (`forbidden` problem details)
  unless exactly one header matches one of them. Only `GET /health` (the
  platform's probes reach the container directly) and `GET /` (service
  information) are exempt.
- **Client address.** With origin authentication on, the client is the
  value of `CLIENT_IP_HEADER` (`CF-Connecting-IP`). It must be one header
  holding one IP address (checked with `ipaddress`); otherwise a scan
  request gets 400 (`invalid-client-ip`). The address is then keyed as
  before, an IPv4-mapped IPv6 address counting as its IPv4 address.
- `CLIENT_IP_HEADER` without `ORIGIN_AUTH_SECRETS`, or the other way round,
  is refused at startup.
- **Without origin authentication** (local runs, Docker Compose), the client
  is the TCP peer, as before.
- uvicorn runs with `--no-proxy-headers`, and nothing reads
  `X-Forwarded-For`. `FORWARDED_ALLOW_IPS` is gone from the image.
- uvicorn also runs with `--ws none`, so an upgrade request is plain HTTP
  and gets the same 403. With WebSocket support on, uvicorn logs the client
  address and raw path of every handshake, even a refused one. The
  middleware also closes any WebSocket connection, since no route takes one.
- **Rotation.** Two secrets can be accepted at once: deploy `old,new`, switch
  the Cloudflare rule to `new`, then deploy `new` alone.
- The scan log line records `client_ip_source` (`header` or `peer`), never
  the address. The secret never appears in logs, error messages or the
  settings' `repr`.

Cloudflare settings this depends on, which live in the dashboard and not in
the code:

- **Pseudo IPv4: Off.** In *Overwrite Headers* mode Cloudflare replaces
  `CF-Connecting-IP` with a Class E IPv4 address hashed from the visitor's
  IPv6 address. Every IPv6 address would become its own IPv4 key, so a
  client with a /64 would get a fresh limit for each address it uses. *Add
  Header* mode only adds `CF-Pseudo-IPv4` and is harmless, but has no use
  here.
- **Remove visitor IP headers: Off.** That Managed Transform drops
  `CF-Connecting-IP`, and every scan would get 400.
- The Transform Rule must *set* the header, so that a value sent by the
  client is replaced.

## Consequences

- A request that does not pass through Cloudflare gets 403 on every route
  except `/health` and `/`. If the Transform Rule is removed or the secrets
  no longer match, the API fails closed; the deploy smoke test sees it.
- The secret is one more thing to store (Secret Manager), rotate (yearly)
  and keep out of the repository, Terraform state and logs.
- Requests that Cloudflare Workers on other zones send to the API arrive
  with `CF-Connecting-IP: 2a06:98c0:3600::103`, Cloudflare's address for
  cross-zone Worker subrequests. They all share one rate limit
  (`2a06:98c0:3600::/64`). The site calls the API from the browser, so this
  only affects third parties calling the API from a Worker, and it errs on
  the strict side.
- The header name is a setting, so another proxy (another CDN, or a host
  that sets its own client header) needs a configuration change, not a code
  change; it still needs origin authentication.
- Cloudflare documents Authenticated Origin Pulls (mutual TLS from its edge
  to the origin) as the way to prove traffic comes from a zone. It would
  need client certificate validation on the load balancer. The shared
  secret is checked by the application itself and works on any host; mutual
  TLS can be added later without changing the application.
