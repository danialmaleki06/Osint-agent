"""HTTPS transport for public registries on a selected local interface."""

import ssl
from ipaddress import IPv4Address
from time import monotonic

import httpx

from osint_mcp.config import settings

_DNS_URL = "https://8.8.8.8/resolve"
_DNS_NAME = "dns.google"
_REGISTRY_HOSTS = frozenset({
    "bo.nalog.gov.ru",
    "egrul.nalog.ru",
    "fedresurs.ru",
    "pub.fsa.gov.ru",
    "proverki.gov.ru",
    "reestr.digital.gov.ru",
    "rmsp.nalog.ru",
    "suggestions.dadata.ru",
})
_addresses: dict[tuple[str, str], tuple[float, str]] = {}


async def resolve_public_ipv4(host: str, bind: str) -> str:
    key = (bind, host)
    cached = _addresses.get(key)
    if cached and cached[0] > monotonic():
        return cached[1]

    # The numeric URL avoids DNS interception by a local TUN profile.
    # SNI and the Host header keep the resolver's certificate and origin checks.
    transport = httpx.AsyncHTTPTransport(local_address=bind)
    async with httpx.AsyncClient(transport=transport, timeout=3, trust_env=False) as dns:
        response = await dns.get(
            _DNS_URL,
            params={"name": host, "type": "A"},
            headers={"Host": _DNS_NAME},
            extensions={"sni_hostname": _DNS_NAME},
        )
    response.raise_for_status()
    payload = response.json()
    answers = payload.get("Answer") if isinstance(payload, dict) and payload.get("Status") == 0 else None
    if isinstance(answers, list):
        for answer in answers:
            if not isinstance(answer, dict) or answer.get("type") != 1:
                continue
            try:
                address = IPv4Address(answer.get("data"))
            except ValueError:
                continue
            if address.is_global and not address.is_multicast:
                ttl = answer.get("TTL")
                if isinstance(ttl, int) and ttl > 0:
                    _addresses[key] = (monotonic() + min(ttl, 300), str(address))
                return str(address)
    raise ValueError("DNS не вернул публичный IPv4-адрес реестра")


class _DirectRegistryTransport(httpx.AsyncBaseTransport):
    def __init__(self, bind: str, verify: bool | ssl.SSLContext) -> None:
        self._bind = bind
        self._verify = verify
        self._origins: dict[str, httpx.AsyncHTTPTransport] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if request.url.scheme != "https" or host not in _REGISTRY_HOSTS or request.url.port:
            raise httpx.ConnectError("Прямой маршрут доступен только для HTTPS реестров", request=request)
        try:
            address = await resolve_public_ipv4(host, self._bind)
        except (httpx.HTTPError, ValueError) as exc:
            raise httpx.ConnectError(f"Не удалось разрешить DNS реестра {host}: {exc}", request=request) from exc

        # Keep pools separate by hostname even when two registries share an IP.
        if host not in self._origins:
            self._origins[host] = httpx.AsyncHTTPTransport(
                local_address=self._bind, verify=self._verify,
            )
        routed = httpx.Request(
            request.method,
            request.url.copy_with(host=address),
            headers=request.headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": host},
        )
        return await self._origins[host].handle_async_request(routed)

    async def aclose(self) -> None:
        for transport in self._origins.values():
            await transport.aclose()


def registry_client(
    *, timeout: float, headers: dict[str, str], verify: bool | ssl.SSLContext = True,
) -> httpx.AsyncClient:
    proxy = settings.registry_proxy_url
    bind = settings.registry_bind_ipv4
    if proxy or bind is None:
        return httpx.AsyncClient(timeout=timeout, headers=headers, proxy=proxy, verify=verify)
    return httpx.AsyncClient(
        timeout=timeout,
        headers=headers,
        transport=_DirectRegistryTransport(str(bind), verify),
        trust_env=False,
    )
