"""Тесты сводной проверки лимитов провайдеров (check_all_limits и MCP-инструмент)."""

from unittest.mock import AsyncMock

import pytest

from osint_mcp import keys as keys_mod
from osint_mcp import ledger
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
    ledger.reset()
    yield
    keys_mod.dadata.reset()
    keys_mod.checko.reset()
    ledger.reset()


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
    assert len(result.providers) == 15
    assert result.summary["всего_провайдеров"] == 15


async def test_check_all_limits_concrete_numbers(monkeypatch):
    """Проверка расчёта конкретных цифр: ёмкости пулов, остатков и запаса проверок компаний."""
    monkeypatch.setattr(settings, "dadata_api_key", "mock-dadata-key")
    monkeypatch.setattr(settings, "dadata_secret_key", "mock-secret-key")
    monkeypatch.setattr(settings, "checko_api_keys", "key1,key2,key3")
    monkeypatch.setattr(settings, "hh_app_token", "mock-hh-token")

    mock_source = DaDataSource()
    mock_source.get_quota = AsyncMock(return_value={
        "findById/party": {"used": 100, "remaining": 9900},
    })

    report = await check_all_limits(mock_source)
    prov_map = {p.provider: p for p in report.providers}

    # Checko (3 ключа по 100 запросов = 300 запросов емкость)
    checko = prov_map["checko"]
    assert checko.keys_total == 3
    assert checko.keys_active == 3
    assert checko.daily_limit_per_key == 100
    assert checko.pool_daily_capacity == 300
    assert checko.estimated_remaining_requests == 300
    assert checko.cost_per_company_requests == 10
    assert checko.estimated_companies_remaining == 30

    # DaData
    dadata = prov_map["dadata"]
    assert dadata.daily_limit_per_key == 10000
    assert dadata.pool_daily_capacity == 10000
    assert dadata.estimated_companies_remaining > 0

    # HeadHunter
    hh = prov_map["hh"]
    assert hh.daily_limit_per_key == 5000
    assert hh.pool_daily_capacity == 5000
    assert hh.estimated_companies_remaining == 2500

    # Государственные реестры (безлимитные)
    for reg_id in ["bo_nalog", "egrul", "rmsp", "fedresurs", "fsa", "software_registry", "customs"]:
        assert reg_id in prov_map
        assert prov_map[reg_id].status == "unlimited"
        assert prov_map[reg_id].category == "official_registry"

    # OSINT источники
    for osint_id in ["geo_reviews", "reputation_fiascos", "site_infrastructure"]:
        assert osint_id in prov_map
        assert prov_map[osint_id].status == "unlimited"
        assert prov_map[osint_id].category == "osint_web"

    # Сводка summary
    assert report.summary["всего_провайдеров"] == 15
    assert report.summary["активных_ключей_всего"] >= 4
    assert report.summary["суммарная_суточная_емкость_запросов"] == 15300
    assert report.summary["расчетный_запас_полных_проверок_компаний"] == 30
    assert report.summary["узкое_горлышко_квоты"] == "Checko API"
