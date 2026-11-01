"""HTTPS and TLS checks: the certificate on port 443 and the plain HTTP redirect.

HSTS also belongs to the transport category but lives in the headers module,
since it is read from the home page response like the other headers.
"""

from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from webriskaudit.checks.base import Check, Outcome, evidence, redact_url
from webriskaudit.checks.homepage import NO_WEB_SERVER
from webriskaudit.context import ScanContext
from webriskaudit.models import Category, Evidence, Reference, Status
from webriskaudit.net.types import (
    FetchError,
    FetchErrorReason,
    HttpResponse,
    TlsProbeError,
    TlsProbeResult,
)

EXPIRY_FAIL_DAYS = 7
# Short-lived certificates (Let's Encrypt's 160-hour profile) never have 7
# days left, so the fail floor is a sixth of the lifetime when that is
# shorter: half the third at which ACME clients renew. Certificates valid for
# 42 days or more keep the 7-day floor.
EXPIRY_FAIL_SHARE = 1 / 6
# ACME clients renew with a third of the lifetime left, so a certificate
# below a quarter has missed its renewal.
RENEWAL_OVERDUE_SHARE = 0.25
OUTDATED_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})
MAX_NAMES_SHOWN = 5

_SEVERITY = {Status.PASS: 0, Status.WARN: 1, Status.FAIL: 2}

_IPV6_ONLY_NOTE = (
    "the domain only has IPv6 addresses and the scanner may lack IPv6 connectivity, so this is "
    "not counted"
)

_UNTRUSTED_FIX = (
    "Install a certificate from a publicly trusted CA (for example Let's Encrypt) that covers "
    "this host name, and serve the full chain including intermediate certificates."
)
_RENEW_FIX = (
    "Renew the certificate now and make sure automated renewal (your ACME client's timer or "
    "cron job) is running."
)
_PROTOCOL_FIX = (
    "Disable TLS 1.0 and 1.1 and offer TLS 1.2 and 1.3, for example "
    "'ssl_protocols TLSv1.2 TLSv1.3;' in nginx."
)
_NO_HTTPS_FIX = (
    "Serve the site over HTTPS on port 443 with a certificate from a publicly trusted CA such as "
    "Let's Encrypt."
)
_HANDSHAKE_FIX = (
    "Make port 443 offer TLS 1.2 or 1.3 with a certificate for this host name, and test it with "
    "'openssl s_client -connect <host>:443 -servername <host>'."
)
_REDIRECT_FIX = (
    "Answer every plain HTTP request with a 301 or 308 redirect to the same URL on HTTPS, for "
    "example 'return 301 https://$host$request_uri;' in nginx."
)


def _clip(value: str, limit: int = 300) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def is_ipv6_only(addresses: tuple[str, ...]) -> bool:
    """True when every address is IPv6, so a failed connection may be the scanner's own."""
    return bool(addresses) and all(":" in address for address in addresses)


# --- TLS certificate ---------------------------------------------------------


def _utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def _iso(moment: datetime) -> str:
    return _utc(moment).strftime("%Y-%m-%dT%H:%M:%SZ")


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def _lifetime(lifetime: timedelta) -> str:
    """'90 days', or '160 hours' for a lifetime under a week."""
    if lifetime < timedelta(days=7):
        return _plural(round(lifetime / timedelta(hours=1)), "hour")
    return _plural(round(lifetime / timedelta(days=1)), "day")


def _time_left(remaining: timedelta) -> str:
    if remaining.days:
        return _plural(remaining.days, "day")
    hours = int(remaining / timedelta(hours=1))
    return _plural(hours, "hour") if hours else "less than an hour"


def _certificate_evidence(result: TlsProbeResult, now: datetime) -> list[Evidence]:
    items = []
    if result.issuer:
        items.append(evidence("Issuer", _clip(result.issuer)))
    if result.not_before:
        items.append(evidence("Valid from", _iso(result.not_before)))
    if result.not_after:
        items.append(evidence("Valid until", _iso(result.not_after)))
        items.append(evidence("Days left", (_utc(result.not_after) - _utc(now)).days))
    if result.not_before and result.not_after:
        lifetime = _utc(result.not_after) - _utc(result.not_before)
        items.append(evidence("Lifetime", _lifetime(lifetime)))
    if result.protocol:
        items.append(evidence("Protocol", result.protocol))
    if names := result.subject_alt_names:
        shown = ", ".join(names[:MAX_NAMES_SHOWN])
        if len(names) > MAX_NAMES_SHOWN:
            shown += f" and {len(names) - MAX_NAMES_SHOWN} more"
        items.append(evidence("Names", _clip(shown)))
    return items


_Finding = tuple[Status, str, str]
"""Status, summary sentence and remediation of one problem."""


def _validity_finding(
    not_before: datetime | None, not_after: datetime, now: datetime
) -> _Finding | None:
    """Expiry or overdue renewal; None when the dates are fine.

    The fail floor is 7 days, or a sixth of the lifetime when that is shorter,
    so a short-lived certificate is not failed for being short-lived.
    """
    not_after = _utc(not_after)
    remaining = not_after - _utc(now)
    if remaining <= timedelta(0):
        return Status.FAIL, f"The certificate expired on {_iso(not_after)}.", _RENEW_FIX
    lifetime = None if not_before is None else not_after - _utc(not_before)
    fail_below = timedelta(days=EXPIRY_FAIL_DAYS)
    if lifetime is not None and lifetime > timedelta(0):
        fail_below = min(fail_below, lifetime * EXPIRY_FAIL_SHARE)
    if remaining < fail_below:
        return Status.FAIL, f"The certificate expires in {_time_left(remaining)}.", _RENEW_FIX
    if lifetime is None:
        return None
    if remaining < lifetime * RENEWAL_OVERDUE_SHARE:
        total = _lifetime(lifetime)
        return (
            Status.WARN,
            f"The certificate has {_time_left(remaining)} of its {total} left, so renewal is "
            "overdue.",
            _RENEW_FIX,
        )
    return None


def evaluate_certificate(result: TlsProbeResult, now: datetime) -> Outcome:
    """Verdict on a completed TLS handshake; ``now`` is passed in for deterministic tests."""
    details = _certificate_evidence(result, now)
    if not result.verified:
        reason = (result.error or "unknown verification error").rstrip(".")
        return Outcome(
            Status.FAIL,
            f"The certificate on port 443 is not trusted: {_clip(reason, 200)}.",
            [evidence("Verification error", _clip(reason)), *details],
            _UNTRUSTED_FIX,
        )
    if result.not_after is None:
        return Outcome(
            Status.INCONCLUSIVE,
            "The TLS handshake succeeded but the certificate's validity dates were not reported.",
            details,
        )

    findings: list[_Finding] = []
    if validity := _validity_finding(result.not_before, result.not_after, now):
        findings.append(validity)
    if result.protocol in OUTDATED_PROTOCOLS:
        findings.append(
            (
                Status.WARN,
                f"The server negotiated {result.protocol}, which is deprecated.",
                _PROTOCOL_FIX,
            )
        )
    if not findings:
        issuer = f" from {result.issuer}" if result.issuer else ""
        days = (_utc(result.not_after) - _utc(now)).days
        return Outcome(
            Status.PASS,
            f"The certificate{issuer} is trusted and valid for {_plural(days, 'more day')}.",
            details,
        )

    findings.sort(key=lambda finding: _SEVERITY[finding[0]], reverse=True)
    if len(findings) > 1:
        details.append(evidence("Issues", " ".join(summary for _, summary, _ in findings)))
    return Outcome(
        findings[0][0],
        findings[0][1],
        details,
        " ".join(dict.fromkeys(fix for _, _, fix in findings)),
    )


def evaluate_probe_error(error: TlsProbeError, *, ipv6_only: bool = False) -> Outcome:
    """Verdict when no TLS handshake completed on port 443."""
    detail = [evidence("Error", _clip(str(error)))]
    match error.reason:
        case FetchErrorReason.CONNECT if ipv6_only:
            summary = f"No connection to port 443 could be made, but {_IPV6_ONLY_NOTE}."
        case FetchErrorReason.CONNECT:
            return Outcome(
                Status.FAIL, "No HTTPS service answered on port 443.", detail, _NO_HTTPS_FIX
            )
        case FetchErrorReason.TLS:
            # A default client context could not complete a handshake: browsers
            # would fail the same way (e.g. a TLS 1.0-only server, HTTP on 443).
            return Outcome(
                Status.FAIL, "The TLS handshake on port 443 failed.", detail, _HANDSHAKE_FIX
            )
        case FetchErrorReason.NETWORK:
            summary = (
                "The connection to port 443 was reset or the host was unreachable, which does "
                "not show whether an HTTPS service runs there."
            )
        case FetchErrorReason.TIMEOUT:
            summary = "The TLS handshake on port 443 timed out."
        case FetchErrorReason.BLOCKED:
            summary = "The TLS probe was blocked because the target address is not public."
        case _:
            summary = f"The TLS probe on port 443 failed ({error.reason})."
    return Outcome(Status.INCONCLUSIVE, summary, detail)


async def check_tls_certificate(ctx: ScanContext) -> Outcome:
    if not ctx.addresses:
        return NO_WEB_SERVER
    try:
        result = await ctx.tls.probe(ctx.domain, 443)
    except TlsProbeError as error:
        return evaluate_probe_error(error, ipv6_only=is_ipv6_only(ctx.addresses))
    return evaluate_certificate(result, datetime.now(UTC))


# --- HTTP to HTTPS redirect --------------------------------------------------


def is_same_site_host(host: str, domain: str) -> bool:
    """True for the scanned host itself or its www/apex counterpart."""
    host, domain = host.lower().rstrip("."), domain.lower().rstrip(".")
    return host in (domain, f"www.{domain}") or f"www.{host}" == domain


def evaluate_redirect(domain: str, response: HttpResponse) -> Outcome:
    """Verdict on the response to ``http://<domain>/`` after redirects."""
    chain = (*response.redirects, response.url)
    details = [evidence("Redirect chain", _clip(" -> ".join(redact_url(url) for url in chain)))]
    if urlsplit(response.url).scheme != "https":
        details.append(evidence("Final status", response.status))
        return Outcome(
            Status.FAIL,
            f"http://{domain}/ is served over plain HTTP (status {response.status}) "
            "instead of redirecting to HTTPS.",
            details,
            _REDIRECT_FIX,
        )

    targets = chain[1:] or chain
    plain_hops = sum(urlsplit(url).scheme == "http" for url in targets)
    if plain_hops:
        return Outcome(
            Status.WARN,
            f"The redirect from http://{domain}/ passes through "
            f"{_plural(plain_hops, 'more plain HTTP hop')} before reaching HTTPS.",
            details,
            f"Redirect http://{domain}/ straight to https://{domain}/ with a 301 or 308, so the "
            "first response already moves the browser to HTTPS.",
        )

    first_host = urlsplit(targets[0]).hostname or ""
    if not is_same_site_host(first_host, domain):
        return Outcome(
            Status.WARN,
            f"http://{domain}/ redirects straight to HTTPS, but on another host ({first_host}).",
            details,
            f"Redirect http://{domain}/ to https://{domain}/ first and move to other hosts from "
            "there, so browsers can pick up HSTS for this host.",
        )
    return Outcome(
        Status.PASS,
        f"http://{domain}/ redirects straight to HTTPS on {first_host}.",
        details,
    )


_REDIRECT_ERRORS = {
    FetchErrorReason.TIMEOUT: "The plain HTTP request timed out.",
    FetchErrorReason.NETWORK: (
        "The plain HTTP connection was reset or the host was unreachable, so it is unknown "
        "whether anything is served over plain HTTP."
    ),
    FetchErrorReason.BLOCKED: (
        "The plain HTTP request was blocked because it or a redirect pointed at a non-public "
        "address, a non-default port or an unsupported scheme."
    ),
    FetchErrorReason.DNS: "A redirect target of the plain HTTP request did not resolve.",
    FetchErrorReason.TLS: "The plain HTTP request was redirected to an HTTPS host that failed TLS.",
    FetchErrorReason.TOO_MANY_REDIRECTS: "The plain HTTP request was redirected too many times.",
    FetchErrorReason.PROTOCOL: "The server sent a malformed response to the plain HTTP request.",
}


def evaluate_redirect_error(domain: str, error: FetchError, *, ipv6_only: bool = False) -> Outcome:
    """Verdict when ``http://<domain>/`` could not be fetched.

    A refused connection only means "port 80 is closed" when it was the first
    request that failed, not a redirect target. A reset or unreachable host
    (NETWORK) proves nothing either way and is inconclusive.
    """
    request = f"http://{domain}/"
    detail = [evidence("Request", request), evidence("Error", _clip(str(error)))]
    if error.reason is FetchErrorReason.CONNECT:
        if error.url is not None and error.url != request:
            detail.append(evidence("Failed URL", _clip(redact_url(error.url))))
            return Outcome(
                Status.INCONCLUSIVE,
                "A redirect target of the plain HTTP request could not be reached.",
                detail,
            )
        if ipv6_only:
            return Outcome(
                Status.INCONCLUSIVE,
                f"No connection to port 80 could be made, but {_IPV6_ONLY_NOTE}.",
                detail,
            )
        return Outcome(
            Status.PASS, "Port 80 is closed, so nothing is served over plain HTTP.", detail
        )
    summary = _REDIRECT_ERRORS.get(error.reason, f"The plain HTTP request failed ({error.reason}).")
    return Outcome(Status.INCONCLUSIVE, summary, detail)


async def check_https_redirect(ctx: ScanContext) -> Outcome:
    if not ctx.addresses:
        return NO_WEB_SERVER
    try:
        response = await ctx.fetch(f"http://{ctx.domain}/")
    except FetchError as error:
        return evaluate_redirect_error(ctx.domain, error, ipv6_only=is_ipv6_only(ctx.addresses))
    return evaluate_redirect(ctx.domain, response)


# --- Registry ----------------------------------------------------------------

_OWASP_TLS = Reference(
    title="OWASP Transport Layer Security Cheat Sheet",
    url="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
)

TLS_CERTIFICATE = Check(
    id="transport.tls_certificate",
    title="TLS certificate",
    category=Category.TRANSPORT,
    weight=15,
    run=check_tls_certificate,
    references=(
        _OWASP_TLS,
        Reference(
            title="RFC 8996: Deprecating TLS 1.0 and TLS 1.1",
            url="https://www.rfc-editor.org/rfc/rfc8996.html",
        ),
        Reference(
            title="Let's Encrypt integration guide: when to renew",
            url="https://letsencrypt.org/docs/integration-guide/",
        ),
    ),
)

HTTPS_REDIRECT = Check(
    id="transport.https_redirect",
    title="HTTP to HTTPS redirect",
    category=Category.TRANSPORT,
    weight=5,
    run=check_https_redirect,
    references=(
        Reference(
            title="RFC 6797 section 7.2: HSTS hosts redirect plain HTTP requests",
            url="https://www.rfc-editor.org/rfc/rfc6797.html#section-7.2",
        ),
        _OWASP_TLS,
    ),
)

CHECKS: tuple[Check, ...] = (TLS_CERTIFICATE, HTTPS_REDIRECT)
