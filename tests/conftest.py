import pytest

from osint_mcp.config import settings


@pytest.fixture(autouse=True)
def use_default_registry_route(monkeypatch):
    """Keep mocked HTTP tests independent of the developer's local network."""
    monkeypatch.setattr(settings, "registry_bind_ipv4", None)
    monkeypatch.setattr(settings, "registry_proxy_url", None)
