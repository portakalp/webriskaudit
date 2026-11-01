import json
import logging
import sys

import pytest

from webriskaudit.logs import JsonFormatter
from webriskaudit.settings import DEFAULT_ALLOWED_ORIGINS, Settings, SettingsError


def test_defaults_without_environment() -> None:
    assert Settings.from_env({}) == Settings()
    assert Settings().allowed_origins == DEFAULT_ALLOWED_ORIGINS


def test_values_from_environment() -> None:
    settings = Settings.from_env(
        {
            "ALLOWED_ORIGINS": " https://a.example , https://b.example/ ,, ",
            "RATE_LIMIT_SCANS": "0",
            "RATE_LIMIT_WINDOW_SECONDS": "60",
            "CACHE_TTL_SECONDS": "0",
            "MAX_CONCURRENT_SCANS": "8",
            "SCAN_DEADLINE_SECONDS": "20.5",
            "CHECK_TIMEOUT_SECONDS": "10",
            "GLOBAL_RATE_LIMIT_SCANS": "100",
            "MAX_QUEUED_SCANS": "0",
            "QUEUE_TIMEOUT_SECONDS": "5",
            "DNS_NAMESERVERS": " 1.1.1.1, 2606:4700:4700::1111 ,",
        }
    )
    assert settings == Settings(
        allowed_origins=("https://a.example", "https://b.example"),
        rate_limit_scans=0,
        rate_limit_window=60.0,
        global_rate_limit_scans=100,
        cache_ttl=0.0,
        max_concurrent_scans=8,
        max_queued_scans=0,
        queue_timeout=5.0,
        scan_deadline=20.5,
        check_timeout=10.0,
        dns_nameservers=("1.1.1.1", "2606:4700:4700::1111"),
    )


def test_empty_origin_list_allows_no_browser_origin() -> None:
    assert Settings.from_env({"ALLOWED_ORIGINS": ""}).allowed_origins == ()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("RATE_LIMIT_SCANS", "ten"),
        ("RATE_LIMIT_SCANS", "1.5"),
        ("RATE_LIMIT_SCANS", "-1"),
        ("MAX_CONCURRENT_SCANS", "0"),
        ("SCAN_DEADLINE_SECONDS", "0"),
        ("CACHE_TTL_SECONDS", "-5"),
        ("QUEUE_TIMEOUT_SECONDS", "0"),
        ("MAX_QUEUED_SCANS", "-1"),
        ("DNS_NAMESERVERS", "dns.google"),
        ("DNS_NAMESERVERS", "1.1.1.1,https://dns.example/"),
    ],
)
def test_invalid_values_are_refused(name: str, value: str) -> None:
    with pytest.raises(SettingsError, match=name):
        Settings.from_env({name: value})


SECRET = "s" * 32
HEADER = "CF-Connecting-IP"


def test_origin_auth_is_off_by_default() -> None:
    settings = Settings()
    assert (settings.origin_auth_enabled, settings.client_ip_header) == (False, None)


def test_origin_auth_from_environment() -> None:
    settings = Settings.from_env(
        {"ORIGIN_AUTH_SECRETS": f" {SECRET} , {'n' * 64} ,", "CLIENT_IP_HEADER": f" {HEADER} "}
    )
    assert settings.origin_auth_secrets == (SECRET, "n" * 64)
    assert settings.client_ip_header == HEADER
    assert settings.origin_auth_enabled
    assert SECRET not in repr(settings)


@pytest.mark.parametrize(
    ("env", "message"),
    [
        (
            {"ORIGIN_AUTH_SECRETS": "s" * 31, "CLIENT_IP_HEADER": HEADER},
            "entry 1 must be at least 32",
        ),
        ({"ORIGIN_AUTH_SECRETS": f"{SECRET},{'t' * 8}", "CLIENT_IP_HEADER": HEADER}, "entry 2"),
        ({"ORIGIN_AUTH_SECRETS": "s" * 16 + " " + "s" * 16, "CLIENT_IP_HEADER": HEADER}, "entry 1"),
        ({"ORIGIN_AUTH_SECRETS": "ş" * 32, "CLIENT_IP_HEADER": HEADER}, "entry 1"),
        ({"ORIGIN_AUTH_SECRETS": SECRET}, "ORIGIN_AUTH_SECRETS needs CLIENT_IP_HEADER"),
        ({"ORIGIN_AUTH_SECRETS": SECRET, "CLIENT_IP_HEADER": " "}, "needs CLIENT_IP_HEADER"),
        ({"CLIENT_IP_HEADER": HEADER}, "CLIENT_IP_HEADER needs ORIGIN_AUTH_SECRETS"),
        ({"ORIGIN_AUTH_SECRETS": SECRET, "CLIENT_IP_HEADER": "CF Connecting IP"}, "header name"),
        ({"ORIGIN_AUTH_SECRETS": SECRET, "CLIENT_IP_HEADER": "CF-Connecting-IP:"}, "header name"),
    ],
)
def test_invalid_origin_auth_is_refused(env: dict[str, str], message: str) -> None:
    with pytest.raises(SettingsError, match=message) as error:
        Settings.from_env(env)
    assert "sss" not in str(error.value)  # the message never contains a secret
    assert "ttt" not in str(error.value)


def test_origin_auth_is_checked_when_built_directly() -> None:
    with pytest.raises(SettingsError, match="entry 1"):
        Settings(origin_auth_secrets=("short",), client_ip_header=HEADER)
    with pytest.raises(SettingsError, match="needs ORIGIN_AUTH_SECRETS"):
        Settings(client_ip_header=HEADER)


def test_json_formatter_merges_fields_and_exceptions() -> None:
    record = logging.LogRecord("webriskaudit.api", logging.INFO, __file__, 1, "scan", (), None)
    record.fields = {"domain": "example.com", "score": 87}
    line = json.loads(JsonFormatter().format(record))
    assert line["message"] == "scan"
    assert (line["level"], line["logger"]) == ("info", "webriskaudit.api")
    assert (line["domain"], line["score"]) == ("example.com", 87)
    assert line["time"].endswith("+00:00")

    try:
        raise RuntimeError("boom")
    except RuntimeError:
        error = logging.LogRecord(
            "webriskaudit", logging.ERROR, __file__, 1, "failed", (), sys.exc_info()
        )
    assert "RuntimeError: boom" in json.loads(JsonFormatter().format(error))["exception"]
