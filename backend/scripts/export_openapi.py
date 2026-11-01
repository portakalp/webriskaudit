"""Write the API's OpenAPI document to backend/openapi.json.

Run from backend/ with "uv run python scripts/export_openapi.py". The output is
deterministic (sorted keys, two-space indent, trailing newline), so CI fails on
drift with "git diff --exit-code openapi.json".
"""

import json
from pathlib import Path

from webriskaudit.api import create_app
from webriskaudit.models import ScanReport
from webriskaudit.settings import Settings

OUTPUT = Path(__file__).resolve().parent.parent / "openapi.json"


async def _never_called(domain: str) -> ScanReport:
    raise NotImplementedError


def render() -> str:
    """The OpenAPI document as written to disk; independent of the environment."""
    schema = create_app(settings=Settings(), scan=_never_called).openapi()
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main() -> None:
    OUTPUT.write_text(render(), encoding="utf-8")
    print(f"Wrote {OUTPUT.name}")


if __name__ == "__main__":
    main()
