"""Тесты сводной проверки лимитов провайдеров (check_all_limits и MCP-инструмент)."""

from unittest.mock import AsyncMock

import pytest

from osint_mcp import keys as keys_mod
from osint_mcp.config import settings
from osint_mcp.context.dadata import DaDataSource
from osint_mcp.models import ProvidersLimitsReport
from osint_mcp.server import check_provider_limits
from osint_mcp.tools.quota import check_all_limits

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _clean_pools():
    keys_mod.dadata.reset()
    keys_mod.checko.reset()
    yield
    keys_mod.dadata.reset()
    keys_mod.checko.reset()


async def test_check_all_limits_structure(monkeypatch):
    """Метод возвращает структурированный отчёт по всем провайдерам."""
    monkeypatch.setattr(settings, "dadata_api_key", "mock-dadata-key")
    monkeypatch.setattr(settings, "dadata_secret_key", "mock-secret-key")
    monkeypatch.setattr(settings, "checko_api_key", "mock-checko-key")
    monkeypatch.setattr(settings, "apicloud_key", "mock-apicloud-key")
    monkeypatch.setattr(settings, "hh_app_token", "mock-hh-token")

    mock_source = DaDataSource()
    mock_source.get_quota = AsyncMock(return_value={
        "findById/party": {"used": 12, "remaining": 9988},
        "suggest/party": {"used": 50, "remaining": 9950},
    })

    report = await check_all_limits(mock_source)

    assert isinstance(report, ProvidersLimitsReport)
    prov_map = {p.provider: p for p in report.providers}

    assert "dadata" in prov_map
    assert "checko" in prov_map
    assert "apicloud" in prov_map
    assert "hh" in prov_map
    assert "open_registries" in prov_map

    # DaData
    dadata = prov_map["dadata"]
    assert dadata.status == "ok"
    assert dadata.keys_total == 1
    assert dadata.keys_active == 1
    assert "findById/party" in dadata.methods
    assert dadata.methods["findById/party"].remaining == 9988

    # Open registries
    assert prov_map["open_registries"].status == "unlimited"

    # Нет алертов при хорошем остатке
    assert len(report.alerts) == 0


async def test_check_all_limits_without_secret_key(monkeypatch):
    """Без секретного ключа DaData статус остаётся ok, но выводится понятное пояснение."""
    monkeypatch.setattr(settings, "dadata_api_key", "mock-dadata-key")
    monkeypatch.setattr(settings, "dadata_secret_key", "")

    mock_source = DaDataSource()
    report = await check_all_limits(mock_source)
    prov_map = {p.provider: p for p in report.providers}

    assert prov_map["dadata"].status == "ok"
    assert "DADATA_SECRET_KEY" in (prov_map["dadata"].error or "")


async def test_check_all_limits_low_quota_alert(monkeypatch):
    """При остатке квоты <= 10 формируется предупреждение."""
    monkeypatch.setattr(settings, "dadata_api_key", "mock-dadata-key")
    monkeypatch.setattr(settings, "dadata_secret_key", "mock-secret-key")
    monkeypatch.setattr(settings, "checko_api_key", "mock-checko-key")

    mock_source = DaDataSource()
    mock_source.get_quota = AsyncMock(return_value={
        "findById/brand": {"used": 95, "remaining": 5},
    })

    report = await check_all_limits(mock_source)
    assert any("findById/brand" in alert and "мало" in alert for alert in report.alerts)


async def test_check_all_limits_quota_exhausted_alert(monkeypatch):
    """При нулевом остатке квоты формируется предупреждение об исчерпании."""
    monkeypatch.setattr(settings, "dadata_api_key", "mock-dadata-key")
    monkeypatch.setattr(settings, "dadata_secret_key", "mock-secret-key")
    monkeypatch.setattr(settings, "checko_api_key", "mock-checko-key")

    mock_source = DaDataSource()
    mock_source.get_quota = AsyncMock(return_value={
        "suggest/party": {"used": 10000, "remaining": 0},
    })

    report = await check_all_limits(mock_source)
    assert any("suggest/party" in alert and "исчерпана" in alert for alert in report.alerts)


async def test_check_all_limits_handles_dadata_error(monkeypatch):
    """Если запрос статистики падает, провайдер помечается warning и не роняет сервер."""
    monkeypatch.setattr(settings, "dadata_api_key", "mock-dadata-key")
    monkeypatch.setattr(settings, "dadata_secret_key", "mock-secret-key")

    mock_source = DaDataSource()
    mock_source.get_quota = AsyncMock(side_effect=RuntimeError("Connection timeout"))

    report = await check_all_limits(mock_source)
    prov_map = {p.provider: p for p in report.providers}
    assert prov_map["dadata"].status == "warning"
    assert "Connection timeout" in prov_map["dadata"].error


async def test_check_all_limits_keys_exhausted(monkeypatch):
    """Если все ключи в пуле помечены как exhausted, выводится статус exhausted."""
    monkeypatch.setattr(settings, "dadata_api_key", "key1")
    keys_mod.dadata.mark_exhausted("key1", "Limit reached")

    mock_source = DaDataSource()
    report = await check_all_limits(mock_source)
    prov_map = {p.provider: p for p in report.providers}

    assert prov_map["dadata"].status == "exhausted"
    assert any("DaData" in alert and "исчерпаны" in alert for alert in report.alerts)


async def test_mcp_tool_check_provider_limits(monkeypatch):
    """MCP-инструмент успешно вызывается и возвращает ProvidersLimitsReport."""
    monkeypatch.setattr(settings, "dadata_api_key", "test-key")
    monkeypatch.setattr(settings, "dadata_secret_key", "test-secret")
    monkeypatch.setattr(settings, "checko_api_key", "test-checko")

    # Переопределяем get_quota у глобального _source в server
    from osint_mcp import server
    server._source.get_quota = AsyncMock(return_value={
        "findById/party": {"used": 1, "remaining": 9999}
    })

    result = await check_provider_limits()
    assert isinstance(result, ProvidersLimitsReport)
    assert len(result.providers) == 5
