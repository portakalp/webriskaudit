# Test file for raw-socket-outside-net.yaml (run: semgrep test semgrep/).
# "ruleid" marks a line the rule must report, "ok" a line it must not.
import asyncio

# ruleid: raw-socket-outside-net
import socket

# ruleid: raw-socket-outside-net
from socket import create_connection

# ruleid: raw-socket-outside-net
import dns.resolver

# ruleid: raw-socket-outside-net
import dns.asyncresolver

# ruleid: raw-socket-outside-net
from dns import resolver

# ruleid: raw-socket-outside-net
from dns.resolver import Resolver

# ok: raw-socket-outside-net
from webriskaudit.net.types import Resolver as GuardedResolver


async def bad(address: str) -> None:
    # ruleid: raw-socket-outside-net
    await asyncio.open_connection(address, 443)


async def good(resolver: GuardedResolver, name: str) -> list[str]:
    # ok: raw-socket-outside-net
    return await resolver.addresses(name)
