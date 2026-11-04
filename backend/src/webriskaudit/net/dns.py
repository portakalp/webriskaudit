"""DNS lookups with dnspython, mapped onto the foundation's error types."""

import asyncio
from collections.abc import Iterable, Sequence

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdtypes.txtbase
import dns.resolver

from webriskaudit.net.types import DnsError, DnsUnavailableError, NoAnswerError, NxDomainError

DEFAULT_LIFETIME = 5.0


class DnsResolver:
    """Resolver backed by ``dns.asyncresolver`` with a per-query time limit.

    A lookup that times out over UDP is retried over TCP within the same
    limit; dnspython only does that for truncated replies. UDP gets the first
    half of the limit and TCP the rest. Each half is shared evenly between
    the nameservers, so one that hangs still leaves the others a turn on both
    transports. With 5 seconds and two nameservers an attempt gets 1.25
    seconds, enough for one retransmitted TCP SYN.

    Uses the system's nameservers unless ``nameservers`` is given; then the
    system configuration is not read at all.
    """

    def __init__(
        self, *, lifetime: float = DEFAULT_LIFETIME, nameservers: Sequence[str] | None = None
    ) -> None:
        self._resolver = dns.asyncresolver.Resolver(configure=not nameservers)
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._lifetime = lifetime
        self._udp_lifetime = lifetime / 2
        self._resolver.timeout = self._udp_lifetime / len(self._resolver.nameservers)

    @property
    def nameservers(self) -> tuple[str, ...]:
        """The nameservers this resolver queries."""
        return tuple(str(server) for server in self._resolver.nameservers)

    async def txt(self, name: str) -> list[str]:
        answer = await self._resolve(name, "TXT")
        return [
            decode_txt(rdata.strings)
            for rdata in answer
            if isinstance(rdata, dns.rdtypes.txtbase.TXTBase)
        ]

    async def addresses(self, name: str) -> list[str]:
        ipv4, ipv6 = await asyncio.gather(
            self._addresses(name, "A"), self._addresses(name, "AAAA"), return_exceptions=True
        )
        return merge_address_answers(name, ipv4, ipv6)

    async def _addresses(self, name: str, rdtype: str) -> list[str]:
        answer = await self._resolve(name, rdtype)
        return [rdata.to_text() for rdata in answer]

    async def _resolve(self, name: str, rdtype: str) -> dns.resolver.Answer:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._lifetime
        try:
            # Not dnspython's lifetime alone: it sleeps between rounds of
            # nameservers before it looks at the clock, so it can run over.
            async with asyncio.timeout_at(deadline):
                try:
                    return await self._resolver.resolve(
                        name, rdtype, search=False, lifetime=self._udp_lifetime
                    )
                except dns.exception.Timeout:
                    return await self._resolver.resolve(
                        name, rdtype, tcp=True, search=False, lifetime=deadline - loop.time()
                    )
        except TimeoutError:
            raise DnsUnavailableError(f"DNS lookup for {name} timed out") from None
        except dns.exception.DNSException as exc:
            raise dns_error(exc, name) from exc


def decode_txt(strings: Iterable[bytes]) -> str:
    """Join a TXT record's character-strings and decode them as UTF-8."""
    return b"".join(strings).decode("utf-8", errors="replace")


def dns_error(exc: dns.exception.DNSException, name: str) -> DnsError:
    """Map a dnspython exception. Messages stay generic: no resolver addresses."""
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return NxDomainError(f"{name} does not exist")
    if isinstance(exc, dns.resolver.NoAnswer):
        return NoAnswerError(f"{name} has no records of the requested type")
    if isinstance(exc, dns.name.NameTooLong | dns.name.LabelTooLong | dns.name.EmptyLabel):
        return NxDomainError(f"{name} is not a valid DNS name")
    if isinstance(exc, dns.exception.Timeout):
        return DnsUnavailableError(f"DNS lookup for {name} timed out")
    return DnsUnavailableError(f"DNS lookup for {name} failed")


def merge_address_answers(name: str, *answers: list[str] | BaseException) -> list[str]:
    """Combine the A and AAAA outcomes: any addresses win, else the most telling error."""
    for answer in answers:
        if isinstance(answer, BaseException) and not isinstance(answer, DnsError):
            raise answer
    found = [address for answer in answers if isinstance(answer, list) for address in answer]
    if found:
        return found
    if all(isinstance(answer, NxDomainError) for answer in answers):
        raise NxDomainError(f"{name} does not exist")
    if all(isinstance(answer, list | NxDomainError | NoAnswerError) for answer in answers):
        raise NoAnswerError(f"{name} has no A or AAAA records")
    raise DnsUnavailableError(f"DNS lookup for {name} failed")
