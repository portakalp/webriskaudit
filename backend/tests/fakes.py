"""In-memory stand-ins for DNS, HTTP and TLS, so tests never touch the network."""

from dataclasses import dataclass, field

from webriskaudit.context import ScanContext
from webriskaudit.net.types import (
    DnsError,
    FetchError,
    FetchErrorReason,
    HttpResponse,
    NoAnswerError,
    NxDomainError,
    TlsProbeError,
    TlsProbeResult,
)

DnsAnswer = list[str] | DnsError


@dataclass
class FakeResolver:
    """Answers from dicts. Unknown TXT names have no records; unknown hosts do not exist."""

    txt_records: dict[str, DnsAnswer] = field(default_factory=dict)
    address_records: dict[str, DnsAnswer] = field(default_factory=dict)
    queries: list[tuple[str, str]] = field(default_factory=list)

    async def txt(self, name: str) -> list[str]:
        self.queries.append(("TXT", name))
        return _answer(self.txt_records.get(name, NoAnswerError(name)))

    async def addresses(self, name: str) -> list[str]:
        self.queries.append(("A/AAAA", name))
        return _answer(self.address_records.get(name, NxDomainError(name)))


def _answer(answer: DnsAnswer) -> list[str]:
    if isinstance(answer, DnsError):
        raise answer
    return list(answer)


@dataclass
class FakeFetcher:
    """Serves canned responses by URL; unknown URLs fail to connect."""

    pages: dict[str, HttpResponse | FetchError] = field(default_factory=dict)
    requests: list[str] = field(default_factory=list)

    async def get(self, url: str) -> HttpResponse:
        self.requests.append(url)
        page = self.pages.get(url)
        if page is None:
            raise FetchError(FetchErrorReason.CONNECT, f"no fake page for {url}")
        if isinstance(page, FetchError):
            raise page
        return page


@dataclass
class FakeTlsProber:
    result: TlsProbeResult | TlsProbeError
    probes: list[tuple[str, int]] = field(default_factory=list)

    async def probe(self, host: str, port: int = 443) -> TlsProbeResult:
        self.probes.append((host, port))
        if isinstance(self.result, TlsProbeError):
            raise self.result
        return self.result


def response(
    url: str,
    status: int = 200,
    headers: dict[str, str] | list[tuple[str, str]] | None = None,
    body: str = "",
    redirects: tuple[str, ...] = (),
) -> HttpResponse:
    """Build an HttpResponse; header names are lower-cased like the real fetcher does."""
    pairs = list(headers.items()) if isinstance(headers, dict) else list(headers or [])
    return HttpResponse(
        url=url,
        status=status,
        headers=tuple((name.lower(), value) for name, value in pairs),
        body=body.encode(),
        redirects=redirects,
    )


def make_context(
    domain: str = "example.com",
    *,
    addresses: tuple[str, ...] = ("93.184.215.14",),
    resolver: FakeResolver | None = None,
    fetcher: FakeFetcher | None = None,
    tls: FakeTlsProber | None = None,
) -> ScanContext:
    return ScanContext(
        domain=domain,
        addresses=addresses,
        resolver=resolver or FakeResolver(),
        fetcher=fetcher or FakeFetcher(),
        tls=tls or FakeTlsProber(TlsProbeResult(verified=True)),
    )
