"""The API image's start command and healthcheck, read from the Dockerfile."""

import json
import re
import shlex
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from uvicorn.main import main as uvicorn_main

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"


def start_options(env: dict[str, str]) -> dict[str, Any]:
    """uvicorn's options from the Dockerfile's CMD, with ``env`` as the container environment."""
    match = re.search(r"^CMD (\[.*\])$", DOCKERFILE.read_text(encoding="utf-8"), re.MULTILINE)
    assert match is not None
    shell, flag, script = json.loads(match.group(1))
    assert (shell, flag) == ("/bin/sh", "-c")
    # ${NAME:-default} as the shell expands it: the default when unset or empty.
    expanded = re.sub(r"\$\{(\w+):-([^}]*)\}", lambda m: env.get(m[1]) or m[2], script)
    command, program, *args = shlex.split(expanded)
    assert (command, program) == ("exec", "uvicorn")
    with uvicorn_main.make_context("uvicorn", args) as context:
        return dict(context.params)


def test_image_runs_one_worker_without_trusting_forwarded_headers() -> None:
    options = start_options({})
    assert options["app"] == "webriskaudit.api:app"
    assert options["host"] == "0.0.0.0"  # noqa: S104 (a container listens on every interface)
    assert options["workers"] == 1
    assert options["proxy_headers"] is False
    assert options["forwarded_allow_ips"] is None
    assert "FORWARDED_ALLOW_IPS" not in DOCKERFILE.read_text(encoding="utf-8")


def test_image_turns_websocket_support_off() -> None:
    # uvicorn would log the address and path of each handshake; upgrades now reach OriginAuth.
    assert start_options({})["ws"] == "none"


def test_image_start_command_defaults() -> None:
    options = start_options({})
    assert options["port"] == 8000
    assert options["access_log"] is False
    assert options["timeout_graceful_shutdown"] == 8


def test_image_start_command_reads_the_platform_port() -> None:
    options = start_options({"PORT": "8080", "GRACEFUL_SHUTDOWN_SECONDS": "5"})
    assert (options["port"], options["timeout_graceful_shutdown"]) == (8080, 5)


@pytest.mark.parametrize("env", [{}, {"PORT": ""}, {"PORT": "8080"}])
def test_healthcheck_calls_the_port_the_server_listens_on(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    match = re.search(r"^HEALTHCHECK .*\\\n\s+CMD (\[.*\])$", DOCKERFILE.read_text("utf-8"), re.M)
    assert match is not None
    program, flag, code = json.loads(match.group(1))
    assert (program, flag) == ("python", "-c")
    urls: list[str] = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout: urls.append(url))
    monkeypatch.delenv("PORT", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    exec(code, {})  # noqa: S102 (the Dockerfile's own healthcheck, with urlopen replaced)
    assert urls == [f"http://127.0.0.1:{start_options(env)['port']}/health"]


def test_image_records_its_revision() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    runtime = text[text.index("AS runtime") :]
    assert 'ARG REVISION=""' in runtime
    assert 'ENV WEBRISKAUDIT_REVISION="${REVISION}"' in runtime
    assert 'org.opencontainers.image.revision="${REVISION}"' in runtime
    assert 'org.opencontainers.image.source="https://github.com/portakalp/webriskaudit"' in runtime
