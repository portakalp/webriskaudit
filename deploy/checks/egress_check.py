"""One-off proof of the API's egress firewall, run as a Cloud Run job.

The job (deploy/cloudrun/egress-check-job.yaml) runs in the same subnet, with
the same network tag and service account as the API. Expected:

- allowed: DNS over UDP and TCP to 1.1.1.1 and 9.9.9.10; TCP 80 and 443 to
  webriskaudit.com;
- blocked: DNS to a resolver that is not on the allow-list (8.8.8.8), another
  port on webriskaudit.com (8443, where Cloudflare listens), any IPv6
  connection (the subnet is IPv4-only and the firewall rules cover IPv4
  only);
- unreachable: private addresses. This does not test the priority-900 deny
  rule: nothing in the VPC uses them and the default internet gateway does
  not deliver to them, so they are dropped without that rule too, and VPC
  firewall rules logging, which could show the rule matching, is not
  available for Direct VPC egress;
- the metadata server must not answer a request without Metadata-Flavor.

It contacts only webriskaudit.com, the two allowed resolvers (1.1.1.1 also
over IPv6), 8.8.8.8 and private or link-local addresses. It uses the
standard library only and does not use the system resolver. Prints one JSON
line per check and a summary; exits 1 if any result differs from the
expectation.
"""

import errno
import json
import os
import secrets
import socket
import ssl
import struct
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from functools import partial

SITE = "webriskaudit.com"
ALLOWED_RESOLVERS = ("1.1.1.1", "9.9.9.10")
BLOCKED_RESOLVER = "8.8.8.8"
BLOCKED_PORT = 8443
PRIVATE_TARGETS = ("10.0.0.1", "172.16.0.1", "192.168.0.1")
IPV6_TARGET = "2606:4700:4700::1111"  # 1.1.1.1's IPv6 address; it listens on 443
METADATA = "169.254.169.254"
TIMEOUT = 3.0
USER_AGENT = "webriskaudit-egress-check"

TYPE_A = 1
TYPE_TXT = 16
CLASS_IN = 1
CLASS_CH = 3


class BlockedError(Exception):
    """No answer within the timeout, or the connection was refused or unroutable."""


UNREACHABLE = {errno.EHOSTUNREACH, errno.ENETUNREACH}
NO_IPV6 = {errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT}


def connect(address: str, port: int) -> socket.socket:
    """TCP connection; BlockedError when the firewall drops or rejects it."""
    try:
        return socket.create_connection((address, port), timeout=TIMEOUT)
    except (TimeoutError, ConnectionRefusedError) as exc:
        raise BlockedError(type(exc).__name__) from exc
    except OSError as exc:
        if exc.errno in UNREACHABLE:
            raise BlockedError(os.strerror(exc.errno)) from exc
        raise


@dataclass(frozen=True)
class Result:
    check: str
    target: str
    expect: str
    result: str
    detail: str

    @property
    def ok(self) -> bool:
        return self.expect == self.result


# --- DNS ---------------------------------------------------------------------


def dns_query(name: str, qtype: int, qclass: int) -> tuple[int, bytes]:
    """Query ID and wire-format query with recursion desired."""
    qid = secrets.randbits(16)
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split("."))
    return qid, header + labels + b"\x00" + struct.pack("!HH", qtype, qclass)


def skip_name(msg: bytes, offset: int) -> int:
    while True:
        length = msg[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def parse_answers(msg: bytes, qid: int, qtype: int) -> list[bytes]:
    """RDATA of the answers of type qtype. Raises ValueError on a bad reply."""
    try:
        return _parse_answers(msg, qid, qtype)
    except (struct.error, IndexError) as exc:
        raise ValueError(f"malformed reply: {exc}") from exc


def _parse_answers(msg: bytes, qid: int, qtype: int) -> list[bytes]:
    rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", msg[:12])
    if rid != qid:
        raise ValueError("reply ID does not match")
    if flags & 0x000F:
        raise ValueError(f"rcode {flags & 0x000F}")
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(msg, offset) + 4
    answers = []
    for _ in range(ancount):
        offset = skip_name(msg, offset)
        rtype, _, _, rdlength = struct.unpack("!HHIH", msg[offset : offset + 10])
        offset += 10
        if rtype == qtype:
            answers.append(msg[offset : offset + rdlength])
        offset += rdlength
    return answers


def resolve(server: str, transport: str, name: str, qtype: int, qclass: int) -> list[bytes]:
    qid, query = dns_query(name, qtype, qclass)
    if transport == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT)
            try:
                sock.sendto(query, (server, 53))
                reply, _ = sock.recvfrom(4096)
            except (TimeoutError, ConnectionRefusedError) as exc:
                raise BlockedError(type(exc).__name__) from exc
    else:
        with connect(server, 53) as sock:
            sock.settimeout(TIMEOUT)
            try:
                sock.sendall(struct.pack("!H", len(query)) + query)
                size = struct.unpack("!H", recv_exactly(sock, 2))[0]
                reply = recv_exactly(sock, size)
            except TimeoutError as exc:
                raise BlockedError("no reply") from exc
    return parse_answers(reply, qid, qtype)


def recv_exactly(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ValueError("connection closed early")
        data += chunk
    return data


def resolve_a(server: str, transport: str, name: str) -> list[str]:
    return [socket.inet_ntoa(r) for r in resolve(server, transport, name, TYPE_A, CLASS_IN)]


def egress_address() -> str:
    """Our public address as 1.1.1.1 sees it (whoami.cloudflare, CHAOS TXT)."""
    answers = resolve(ALLOWED_RESOLVERS[0], "udp", "whoami.cloudflare", TYPE_TXT, CLASS_CH)
    if not answers:
        raise ValueError("no TXT answer")
    rdata = answers[0]
    return rdata[1 : 1 + rdata[0]].decode("ascii")


# --- TCP and HTTP --------------------------------------------------------------


def tcp_connect(address: str, port: int) -> str:
    with connect(address, port):
        return "connected"


def ipv6_probe() -> str:
    """TCP 443 over IPv6; no IPv6 address or no IPv6 support counts as blocked."""
    try:
        return tcp_connect(IPV6_TARGET, 443)
    except OSError as exc:
        if exc.errno in NO_IPV6:
            raise BlockedError(os.strerror(exc.errno)) from exc
        raise


def http_status(address: str, port: int, host: str, path: str, *, tls: bool) -> int:
    """Status code of a GET to address:port with the given Host header."""
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    with connect(address, port) as raw:
        sock: socket.socket = raw
        if tls:
            sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        sock.sendall(request)
        status_line = sock.recv(64).split(b"\r\n", 1)[0].decode("ascii", "replace")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ValueError(f"not an HTTP reply: {status_line!r}")
    return int(parts[1])


# --- Checks ----------------------------------------------------------------------


def run(check: str, target: str, expect: str, probe: Callable[[], str]) -> Result:
    """Run probe: returning means allowed, BlockedError means blocked, else error."""
    try:
        detail = probe()
        outcome = "allowed"
    except BlockedError as exc:
        detail, outcome = str(exc), "blocked"
    except (OSError, ValueError) as exc:
        detail, outcome = f"{type(exc).__name__}: {exc}", "error"
    return Result(check, target, expect, outcome, detail)


def dns_probe(server: str, transport: str) -> str:
    return ", ".join(resolve_a(server, transport, SITE))


def http_probe(address: str, port: int, tls: bool) -> str:
    return f"status {http_status(address, port, SITE, '/', tls=tls)}"


def checks(site_address: str | None) -> list[Result]:
    results = []
    for server in (*ALLOWED_RESOLVERS, BLOCKED_RESOLVER):
        expect = "blocked" if server == BLOCKED_RESOLVER else "allowed"
        for transport in ("udp", "tcp"):
            target = f"{server}:53/{transport}"
            results.append(run("dns", target, expect, partial(dns_probe, server, transport)))

    if site_address is not None:
        for port, tls in ((80, False), (443, True)):
            target = f"{SITE} ({site_address}):{port}"
            probe = partial(http_probe, site_address, port, tls)
            results.append(run("https" if tls else "http", target, "allowed", probe))
        target = f"{SITE} ({site_address}):{BLOCKED_PORT}"
        results.append(
            run("tcp", target, "blocked", partial(tcp_connect, site_address, BLOCKED_PORT))
        )

    results.append(run("ipv6", f"[{IPV6_TARGET}]:443", "blocked", ipv6_probe))

    for address in PRIVATE_TARGETS:
        probe = partial(tcp_connect, address, 80)
        results.append(run("private", f"{address}:80", "blocked", probe))
    return results


def metadata_check() -> Result:
    """The metadata server may be reachable (it is for VMs), but must refuse
    a request without the Metadata-Flavor header."""
    target = f"{METADATA}:80"
    try:
        status = http_status(
            METADATA, 80, "metadata.google.internal", "/computeMetadata/v1/", tls=False
        )
    except BlockedError as exc:
        return Result("metadata", target, "refused", "refused", f"blocked: {exc}")
    except (OSError, ValueError) as exc:
        return Result("metadata", target, "refused", "error", f"{type(exc).__name__}: {exc}")
    result = "allowed" if 200 <= status < 300 else "refused"
    return Result("metadata", target, "refused", result, f"reachable, status {status}")


def egress_check() -> Result:
    expected = os.environ.get("EXPECTED_EGRESS_IP", "").strip()
    try:
        seen = egress_address()
    except BlockedError as exc:
        return Result("egress-ip", "whoami.cloudflare", expected or "any", "error", str(exc))
    except (OSError, ValueError) as exc:
        return Result("egress-ip", "whoami.cloudflare", expected or "any", "error", repr(exc))
    if not expected:
        return Result("egress-ip", "whoami.cloudflare", "any", "any", seen)
    return Result("egress-ip", "whoami.cloudflare", expected, seen, seen)


def main() -> int:
    try:
        site_address: str | None = resolve_a(ALLOWED_RESOLVERS[0], "udp", SITE)[0]
    except (BlockedError, OSError, ValueError, IndexError):
        site_address = None

    results = [*checks(site_address), metadata_check(), egress_check()]
    for result in results:
        print(json.dumps({**asdict(result), "ok": result.ok}), flush=True)
    failed = [r for r in results if not r.ok]
    if site_address is None:
        failed.append(Result("setup", SITE, "resolved", "error", "could not resolve"))
    print(
        json.dumps(
            {
                "message": "egress-check summary",
                "checks": len(results),
                "failed": len(failed),
                "ok": not failed,
            }
        ),
        flush=True,
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
