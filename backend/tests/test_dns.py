"""DnsResolver with a stub below dnspython's resolution logic, so no packet is sent."""

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

import dns.exception
import dns.message
import dns.nameserver
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from webriskaudit.net.dns import DEFAULT_LIFETIME, DnsResolver
from webriskaudit.net.types import DnsUnavailableError, NoAnswerError, NxDomainError

FIRST = "192.0.2.53"
SECOND = "198.51.100.53"
SERVERS = (FIRST, SECOND)

# dnspython pauses 0.1 s and 0.2 s between UDP rounds, so TCP starts after 0.3 s. The 0.2 s
# left is for a busy machine, where a pause can run 0.2 s over; with less the tests flake.
QUICK = 0.5

RECORDS = {
    dns.rdatatype.A: "203.0.113.7",
    dns.rdatatype.AAAA: "2001:db8::7",
    dns.rdatatype.TXT: '"v=spf1 -all"',
}

Server = Callable[[dns.message.QueryMessage, float], Awaitable[dns.message.Message]]


async def answers(request: dns.message.QueryMessage, _: float) -> dns.message.Message:
    question = request.question[0]
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(question.name, 60, "IN", question.rdtype, RECORDS[question.rdtype])
    )
    return dns.message.from_wire(response.to_wire())


async def no_data(request: dns.message.QueryMessage, _: float) -> dns.message.Message:
    return dns.message.make_response(request)


async def nxdomain(request: dns.message.QueryMessage, _: float) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.NXDOMAIN)
    return response


async def servfail(request: dns.message.QueryMessage, _: float) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.SERVFAIL)
    return response


async def lost(_: dns.message.QueryMessage, __: float) -> dns.message.Message:
    """Times out at once, which keeps the tests fast; ``silent`` waits like a real one."""
    raise dns.exception.Timeout


async def silent(_: dns.message.QueryMessage, limit: float) -> dns.message.Message:
    await asyncio.sleep(limit)
    raise dns.exception.Timeout


async def stuck(_: dns.message.QueryMessage, __: float) -> dns.message.Message:
    await asyncio.sleep(3600)
    raise AssertionError("not reached")


Network = Mapping[tuple[str, str], Server]
Query = tuple[str, str]


@pytest.fixture
def queries() -> list[Query]:
    return []


@pytest.fixture
def timeouts() -> list[float]:
    return []


@pytest.fixture
def network(
    monkeypatch: pytest.MonkeyPatch, queries: list[Query], timeouts: list[float]
) -> Callable[[Network], None]:
    """Installs a network: what each (nameserver, transport) does with a query."""

    def install(servers: Network) -> None:
        async def async_query(
            nameserver: dns.nameserver.Do53Nameserver,
            request: dns.message.QueryMessage,
            **options: Any,
        ) -> dns.message.Message:
            address = nameserver.answer_nameserver()
            transport = "tcp" if options["max_size"] else "udp"
            queries.append((address, transport))
            timeouts.append(options["timeout"])
            return await servers[address, transport](request, options["timeout"])

        monkeypatch.setattr(dns.nameserver.Do53Nameserver, "async_query", async_query)

    return install


Install = Callable[[Network], None]


def everywhere(server: Server) -> Network:
    return {(address, transport): server for address in SERVERS for transport in ("udp", "tcp")}


async def test_udp_answer_needs_no_tcp(network: Install, queries: list[Query]) -> None:
    network(everywhere(answers))
    resolver = DnsResolver(nameservers=SERVERS)
    assert await resolver.txt("example.com") == ["v=spf1 -all"]
    assert queries == [(FIRST, "udp")]


async def test_second_nameserver_answers_when_the_first_times_out_on_udp(
    network: Install, queries: list[Query]
) -> None:
    network({**everywhere(answers), (FIRST, "udp"): lost})
    resolver = DnsResolver(nameservers=SERVERS)
    assert await resolver.txt("example.com") == ["v=spf1 -all"]
    assert queries == [(FIRST, "udp"), (SECOND, "udp")]


async def test_udp_timeout_is_retried_over_tcp(network: Install, queries: list[Query]) -> None:
    network({**everywhere(lost), (FIRST, "tcp"): answers})
    resolver = DnsResolver(lifetime=QUICK, nameservers=SERVERS)
    assert await resolver.txt("example.com") == ["v=spf1 -all"]
    assert queries[-1] == (FIRST, "tcp")
    assert set(queries[:-1]) == {(FIRST, "udp"), (SECOND, "udp")}


async def test_a_dead_first_nameserver_leaves_the_second_its_tcp_turn(
    network: Install, queries: list[Query]
) -> None:
    # The case measured in production if 1.1.1.1 failed: UDP to 9.9.9.10 is lost, TCP is not.
    network({**everywhere(silent), (SECOND, "tcp"): answers})
    resolver = DnsResolver(lifetime=1.2, nameservers=SERVERS)
    assert await resolver.txt("example.com") == ["v=spf1 -all"]
    assert queries == [(FIRST, "udp"), (SECOND, "udp"), (FIRST, "tcp"), (SECOND, "tcp")]


async def test_addresses_fall_back_per_record_type(network: Install) -> None:
    network({**everywhere(lost), (FIRST, "tcp"): answers})
    resolver = DnsResolver(lifetime=QUICK, nameservers=SERVERS)
    assert sorted(await resolver.addresses("example.com")) == ["2001:db8::7", "203.0.113.7"]


@pytest.mark.parametrize(("server", "error"), [(nxdomain, NxDomainError), (no_data, NoAnswerError)])
async def test_final_answers_are_not_retried(
    network: Install, queries: list[Query], server: Server, error: type[Exception]
) -> None:
    network(everywhere(server))
    with pytest.raises(error):
        await DnsResolver(nameservers=SERVERS).txt("example.com")
    assert queries == [(FIRST, "udp")]


@pytest.mark.parametrize(("server", "error"), [(nxdomain, NxDomainError), (no_data, NoAnswerError)])
async def test_final_answers_over_tcp_are_kept(
    network: Install, queries: list[Query], server: Server, error: type[Exception]
) -> None:
    network({**everywhere(lost), (FIRST, "tcp"): server})
    with pytest.raises(error):
        await DnsResolver(lifetime=QUICK, nameservers=SERVERS).txt("example.com")
    assert queries[-1] == (FIRST, "tcp")
    assert queries.count((FIRST, "tcp")) == 1


async def test_servfail_from_every_nameserver_is_not_a_timeout(
    network: Install, queries: list[Query]
) -> None:
    network(everywhere(servfail))
    with pytest.raises(DnsUnavailableError, match="failed"):
        await DnsResolver(nameservers=SERVERS).txt("example.com")
    assert queries == [(FIRST, "udp"), (SECOND, "udp")]


async def test_timeouts_on_both_transports_are_a_generic_error(
    network: Install, queries: list[Query]
) -> None:
    network(everywhere(silent))
    resolver = DnsResolver(lifetime=1.2, nameservers=SERVERS)
    with pytest.raises(DnsUnavailableError) as caught:
        await resolver.txt("example.com")
    assert queries == [(FIRST, "udp"), (SECOND, "udp"), (FIRST, "tcp"), (SECOND, "tcp")]
    assert str(caught.value) == "DNS lookup for example.com timed out"


async def test_an_attempt_that_ignores_its_timeout_cannot_outlast_the_lifetime(
    network: Install,
) -> None:
    network({**everywhere(lost), (FIRST, "tcp"): stuck})
    resolver = DnsResolver(lifetime=QUICK, nameservers=SERVERS)
    loop = asyncio.get_running_loop()
    started = loop.time()
    with pytest.raises(DnsUnavailableError) as caught:
        await resolver.txt("example.com")
    assert loop.time() - started < 1
    assert str(caught.value) == "DNS lookup for example.com timed out"


async def test_cancelling_a_lookup_is_not_turned_into_a_dns_error(network: Install) -> None:
    network(everywhere(stuck))
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.01):
            await DnsResolver(nameservers=SERVERS).txt("example.com")


@pytest.mark.parametrize(
    ("servers", "expected"),
    [((FIRST,), DEFAULT_LIFETIME / 2), (SERVERS, DEFAULT_LIFETIME / 4)],
)
async def test_each_nameserver_gets_an_equal_part_of_the_udp_half(
    network: Install, timeouts: list[float], servers: tuple[str, ...], expected: float
) -> None:
    network(everywhere(answers))
    await DnsResolver(nameservers=servers).txt("example.com")
    assert timeouts == pytest.approx([expected], abs=0.01)
