# 3. No personal data

Date: 2026-11-01

## Status

Accepted

## Context

v1 was the lead-generation funnel of a paid audit service. A scan required an
email address next to the domain. The API stored both in a SQL database
(`Lead` and `Scan` tables, linked by `lead_id`), and the website loaded Google
Analytics and Vercel Analytics, showed a cookie banner for them, and embedded
Calendly for booking calls. CORS allowed every origin with credentials.

None of this serves a non-commercial scanner. Personal data that is not
collected cannot leak, does not need a retention policy and does not need
consent. The project also has to keep its privacy note true without
maintaining infrastructure for it.

## Decision

- The API accepts only a domain: `POST /api/v1/scan` with
  `{"domain": "<string>"}`. There are no accounts, no email field, no
  cookies and no database.
- Reports are kept only in an in-memory cache (at most 1024 of them), to
  absorb repeated requests: served for 10 minutes and dropped with the next
  request after that. There is no scan history.
- The client's IP address is used only by the in-memory rate limiter, which
  keys an IPv4 address as is and an IPv6 address by its /64 network. The key
  is also held while that client's new scan waits or runs, to allow one at a
  time. It is never logged or written anywhere. It is forgotten with the
  first request of any kind after its last hit leaves the window, or when
  the process restarts.
- The application logs one JSON line per scan request with the normalized
  domain, outcome, cache use, score, grade, coverage, timings and whether
  the client address came from a proxy header or the TCP peer. It never
  logs client addresses, request bodies or the raw input of an invalid
  request, and it switches off uvicorn's access log, which would record
  client addresses.
- Evidence never contains cookie values; the cookie parser drops them.
- The website has no analytics, no tracking, no cookies and no third-party
  scripts.

## Consequences

- There is nothing to breach, export or delete on request, and the privacy
  note can say so.
- There are no shareable report links or scan history; a report exists only
  in the visitor's browser. Adding either would need a new decision.
- Abuse cannot be traced back to a client from the application's own data.
  Abuse controls have to work without identity: per-address rate limits in
  memory, a cache and a concurrency cap.
- The rate limit and cache reset on restart and are not shared between
  processes.
- Some personal data is still processed outside the application's control:
  the hosting platform and Cloudflare see client addresses and keep their own
  logs, and a scanned domain can itself identify a person (a personal
  domain). The privacy note has to describe these. Log retention is set in
  the deployment: in production the platform's request logs, which hold
  client addresses, are not stored, application logs are kept for 14 days
  ([ADR 0007](0007-api-on-cloud-run.md)), and Error Reporting keeps
  unexpected errors, which name the domain, for up to 30 days.
