"""The API image's start command, parsed the way uvicorn parses it."""

import json
import re
import shlex
from pathlib import Path
from typing import Any

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


def test_image_runs_the_api_without_trusting_forwarded_headers() -> None:
    options = start_options({})
    assert options["app"] == "webriskaudit.api:app"
    assert options["host"] == "0.0.0.0"  # noqa: S104 (a container listens on every interface)
    assert options["proxy_headers"] is False
    assert options["forwarded_allow_ips"] is None
    assert options["workers"] is None
    assert "FORWARDED_ALLOW_IPS" not in DOCKERFILE.read_text(encoding="utf-8")
