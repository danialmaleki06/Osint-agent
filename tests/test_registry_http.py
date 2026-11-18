from ipaddress import IPv4Address

import httpx
import pytest
import respx

from osint_mcp.config import settings
from osint_mcp.context.registry_http import registry_client


@respx.mock
async def test_registry_direct_keeps_hostname_for_tls_and_http(monkeypatch):
    monkeypatch.setattr(settings, "registry_bind_ipv4", IPv4Address("192.0.2.12"))
    monkeypatch.setattr(settings, "registry_proxy_url", None)
    dns = respx.get("https://8.8.8.8/resolve", params={
        "name": "bo.nalog.gov.ru", "type": "A",
    }).respond(json={"Status": 0, "Answer": [{"type": 1, "data": "213.24.64.194", "TTL": 120}]})
    registry = respx.get("https://213.24.64.194/").respond(text="registry")

    async with registry_client(timeout=5, headers={}) as client:
        response = await client.get("https://bo.nalog.gov.ru/")
        await client.get("https://bo.nalog.gov.ru/")

    assert response.url.host == "bo.nalog.gov.ru"
    assert registry.calls.last.request.headers["Host"] == "bo.nalog.gov.ru"
    assert registry.calls.last.request.extensions["sni_hostname"] == "bo.nalog.gov.ru"
    assert dns.calls.last.request.extensions["sni_hostname"] == "dns.google"
    assert dns.call_count == 1


@respx.mock
async def test_registry_direct_rejects_nonpublic_dns_answer(monkeypatch):
    monkeypatch.setattr(settings, "registry_bind_ipv4", IPv4Address("192.0.2.13"))
    monkeypatch.setattr(settings, "registry_proxy_url", None)
    respx.get("https://8.8.8.8/resolve").respond(
        json={"Status": 0, "Answer": [{"type": 1, "data": "198.18.4.100", "TTL": 60}]}
    )

    async with registry_client(timeout=5, headers={}) as client:
        with pytest.raises(httpx.ConnectError, match="публичный IPv4"):
            await client.get("https://bo.nalog.gov.ru/")
