import pytest

from osint_mcp.config import settings


@pytest.fixture(autouse=True)
def use_default_registry_route(monkeypatch):
    """Keep mocked HTTP tests independent of the developer's local network."""
    monkeypatch.setattr(settings, "registry_bind_ipv4", None)
    monkeypatch.setattr(settings, "registry_proxy_url", None)
    monkeypatch.setattr(settings, "yandex_search_api_key", "")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "")
    monkeypatch.setattr(settings, "yandex_search_mode", "fallback")


@pytest.fixture(autouse=True)
def isolated_search_cache():
    from osint_mcp.tools.web_search_source import clear_search_cache

    clear_search_cache()
    yield
    clear_search_cache()
