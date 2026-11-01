"""Decide whether an IP address is on the public internet.

The tables are explicit instead of relying on ``ipaddress.is_global``, whose
answers (especially for IPv4-mapped IPv6) have changed between Python releases.
"""

import ipaddress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

_BLOCKED_V4 = tuple(
    IPv4Network(net)
    for net in (
        "0.0.0.0/8",  # "this network"
        "10.0.0.0/8",  # private
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, cloud metadata services
        "172.16.0.0/12",  # private
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation (TEST-NET-1)
        "192.88.99.0/24",  # deprecated 6to4 relay anycast
        "192.168.0.0/16",  # private
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # documentation (TEST-NET-2)
        "203.0.113.0/24",  # documentation (TEST-NET-3)
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, incl. limited broadcast
    )
)

_GLOBAL_UNICAST_V6 = IPv6Network("2000::/3")
# Inside 2000::/3 but not reachable web hosts. Teredo (2001::/32) is part of
# 2001::/23 but is unwrapped and judged by its embedded addresses first.
_BLOCKED_V6 = tuple(
    IPv6Network(net)
    for net in (
        "2001::/23",  # IETF protocol assignments (benchmarking, ORCHID, ...)
        "2001:db8::/32",  # documentation
        "3fff::/20",  # documentation (RFC 9637)
    )
)
_IPV4_COMPATIBLE = IPv6Network("::/96")
_NAT64 = IPv6Network("64:ff9b::/96")


def is_public_address(ip: str) -> bool:
    """True if ``ip`` is a globally routable unicast address. Unparsable input is not."""
    if "%" in ip:  # a zone index only makes sense for non-global addresses
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(address, IPv4Address):
        return _is_public_v4(address)
    embedded = _embedded_ipv4(address)
    if embedded is not None:
        return all(_is_public_v4(inner) for inner in embedded)
    return address in _GLOBAL_UNICAST_V6 and not any(address in net for net in _BLOCKED_V6)


def _is_public_v4(address: IPv4Address) -> bool:
    return not any(address in net for net in _BLOCKED_V4)


def _embedded_ipv4(address: IPv6Address) -> tuple[IPv4Address, ...] | None:
    """IPv4 addresses an IPv6 address carries and would be routed towards, if any."""
    if address.ipv4_mapped is not None:
        return (address.ipv4_mapped,)
    if address in _NAT64 or address in _IPV4_COMPATIBLE:
        return (IPv4Address(int(address) & 0xFFFFFFFF),)
    if address.sixtofour is not None:
        return (address.sixtofour,)
    if address.teredo is not None:
        return address.teredo  # (server, client)
    return None


def pick_address(addresses: list[str]) -> str:
    """The address to connect to: the first IPv4 one, which every deployment can
    reach, else the first one. ``addresses`` must not be empty."""
    return next((address for address in addresses if ":" not in address), addresses[0])
