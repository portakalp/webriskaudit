"""Registry of every check, in the order reports list them."""

from webriskaudit.checks import email, headers, site, transport
from webriskaudit.checks.base import Check

DISPLAY_ORDER: tuple[str, ...] = (
    "email.spf",
    "email.dmarc",
    "email.dkim",
    "transport.tls_certificate",
    "transport.https_redirect",
    "transport.hsts",
    "headers.csp",
    "headers.clickjacking",
    "headers.content_type_options",
    "headers.referrer_policy",
    "headers.cookies",
    "headers.server_disclosure",
    "info.cdn",
    "info.privacy_policy",
    "info.permissions_policy",
    "info.deprecated_headers",
)


def _registry() -> tuple[Check, ...]:
    modules = (email, transport, headers, site)
    by_id = {check.id: check for module in modules for check in module.CHECKS}
    if sorted(by_id) != sorted(DISPLAY_ORDER):
        raise RuntimeError("DISPLAY_ORDER does not list exactly the checks the modules define")
    return tuple(by_id[check_id] for check_id in DISPLAY_ORDER)


ALL_CHECKS: tuple[Check, ...] = _registry()
