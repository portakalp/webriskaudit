from webriskaudit.checks import ALL_CHECKS, DISPLAY_ORDER, email, headers, site, transport
from webriskaudit.models import Category

SPEC_ORDER = [
    ("email.spf", Category.EMAIL, 10),
    ("email.dmarc", Category.EMAIL, 10),
    ("email.dkim", Category.EMAIL, 5),
    ("transport.tls_certificate", Category.TRANSPORT, 15),
    ("transport.https_redirect", Category.TRANSPORT, 5),
    ("transport.hsts", Category.TRANSPORT, 10),
    ("headers.csp", Category.HEADERS, 10),
    ("headers.clickjacking", Category.HEADERS, 5),
    ("headers.content_type_options", Category.HEADERS, 5),
    ("headers.referrer_policy", Category.HEADERS, 5),
    ("headers.cookies", Category.HEADERS, 5),
    ("headers.server_disclosure", Category.HEADERS, 5),
    ("info.cdn", Category.INFO, 0),
    ("info.privacy_policy", Category.INFO, 0),
    ("info.permissions_policy", Category.INFO, 0),
    ("info.deprecated_headers", Category.INFO, 0),
]


def test_registry_matches_the_specification() -> None:
    assert [(c.id, c.category, c.weight) for c in ALL_CHECKS] == SPEC_ORDER
    assert list(DISPLAY_ORDER) == [check_id for check_id, _, _ in SPEC_ORDER]


def test_ids_are_unique_across_modules() -> None:
    ids = [c.id for module in (email, transport, headers, site) for c in module.CHECKS]
    assert len(ids) == len(set(ids)) == len(ALL_CHECKS)


def test_scored_weights_sum_to_90() -> None:
    assert sum(c.weight for c in ALL_CHECKS) == 90


def test_informational_checks_have_weight_0_and_no_others_do() -> None:
    for check in ALL_CHECKS:
        assert (check.category is Category.INFO) == (check.weight == 0), check.id


def test_id_prefix_matches_category() -> None:
    for check in ALL_CHECKS:
        assert check.id.split(".")[0] == check.category.value, check.id


def test_scored_checks_cite_references() -> None:
    for check in ALL_CHECKS:
        if check.weight:
            assert check.references, check.id
            assert all(ref.url.startswith("https://") for ref in check.references)
