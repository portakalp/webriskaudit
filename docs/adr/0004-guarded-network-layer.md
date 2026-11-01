# 4. Guarded network layer

Date: 2026-11-01

## Status

Accepted

## Context

The API connects to hosts named by anonymous users, and to whatever those
hosts redirect to. Without guards this is server-side request forgery: a user
can make the API connect to `127.0.0.1`, to private networks, or to the cloud
metadata endpoint `169.254.169.254`, either directly or through a domain
whose DNS points there, a redirect, or a DNS answer that changes between a
check and the connection (DNS rebinding).

v1 had no such protection. Checks called `requests.get(..., allow_redirects=True)`,
`socket.gethostbyname` and `socket.create_connection((domain, 443))` directly
on the user's input, so the operating system resolved and connected to
whatever the name pointed at, and redirects were followed without being
checked. Each check opened its own connections, so there was no single place
to enforce a rule.

## Decision

All network access goes through three interfaces in `net/types.py`
(`Resolver`, `Fetcher`, `TlsProber`), handed to the checks in a
`ScanContext`. Checks never open sockets. The real implementations:

- `normalize_domain` (`net/domain.py`) turns input into a lower-case A-label
  host name and refuses IP literals in any notation, single-label and
  special-use names, and invalid labels.
- `is_public_address` (`net/addresses.py`) decides from explicit tables
  whether an address is globally routable, judging IPv6 forms that embed an
  IPv4 address by that address. It does not use `ipaddress.is_global`.
- `GuardedFetcher` (`net/http.py`), for every hop including each redirect:
  only `http`/`https` on the default port and without credentials; the host
  must pass `normalize_domain`; the name is resolved and every address must
  be public; the connection is pinned to one checked address, with the host
  name in the `Host` header and, for HTTPS, as SNI and for certificate
  verification (httpx's `sni_hostname` extension, certifi's CA bundle).
  Redirects (301, 302, 303, 307, 308) are followed manually, at most 5, and
  each target is checked again. One `get()` has an overall deadline of 10
  seconds; at most 1 MB of decoded body is kept, with a bounded gzip/deflate
  decoder; proxy environment variables are ignored and nothing is retried.
- `TlsProbe` (`net/tls.py`): port 443 only, the same validation and pinning,
  the host name as `server_hostname`, a 10-second limit.
- `DnsResolver` (`net/dns.py`): dnspython with a 5-second limit per query,
  mapped onto three error types (`NxDomainError`, `NoAnswerError`,
  `DnsUnavailableError`).
- The scanner refuses a domain whose own addresses are not all public before
  any check runs.

Tests use in-memory fakes of the three interfaces and run with sockets
disabled (`pytest-socket`), except loopback (`127.0.0.1`) for the real-TLS
tests in `tests/test_tls_loopback.py`; nothing leaves the machine.

## Consequences

- SSRF protection lives in one small, tested layer instead of in every check,
  and new checks get it for free as long as they use the context.
- Every hop costs a DNS lookup, and every request opens a new connection
  (no pooling), which makes a scan slightly slower.
- Some real sites cannot be inspected: redirects to non-default ports or IP
  literals are blocked, and such checks become inconclusive. Only the first
  IPv4 address is contacted (the first IPv6 address only when there is no
  IPv4).
- Certificate verification depends on httpcore honouring `sni_hostname` for
  host name checks. `tests/test_tls_loopback.py` verifies this over real TLS
  on `127.0.0.1`, with certificates from a throwaway CA (trustme): the
  fetcher and the TLS probe send the host name as SNI and verify the
  certificate against it, a certificate for another name or only for the
  pinned IP address is refused, and only CAs in the certifi bundle are
  trusted.
- The code is the first layer, not the only one. The deployment must still
  block non-public egress at the network level, use a resolver without
  internal zones, and run behind a correctly configured proxy (see
  [THREAT_MODEL.md](../THREAT_MODEL.md)).
