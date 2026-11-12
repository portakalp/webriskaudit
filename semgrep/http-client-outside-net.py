# Test file for http-client-outside-net.yaml (run: semgrep test semgrep/).
# "ruleid" marks a line the rule must report, "ok" a line it must not.

# ruleid: http-client-outside-net
import httpx

# ruleid: http-client-outside-net
import httpx as client

# ruleid: http-client-outside-net
from httpx import AsyncClient

# ruleid: http-client-outside-net
import requests

# ruleid: http-client-outside-net
import urllib.request

# ruleid: http-client-outside-net
from urllib.request import urlopen

# ruleid: http-client-outside-net
from urllib import request

# ruleid: http-client-outside-net
import http.client

# ok: http-client-outside-net
from urllib.parse import urlsplit

# ok: http-client-outside-net
from http import HTTPStatus

# ok: http-client-outside-net
from webriskaudit.net.types import Fetcher


async def good(fetcher: Fetcher) -> int:
    # ok: http-client-outside-net
    response = await fetcher.get("https://example.com/")
    return response.status
