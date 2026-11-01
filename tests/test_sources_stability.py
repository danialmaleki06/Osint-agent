"""Тесты стабильности источников данных и прозрачности fallback-механизмов.

Проверяют:
1. Корректную нормализацию URL и протоколов в inspect_site_content (домены без схемы, переход на http).
2. Отсутствие скрытых падений при одновременном отказе всех эшелонов источников (DaData + Checko + ЕГРЮЛ).
3. Прозрачность и фиксацию fallback в coverage_note и диагностических gap.
4. Отсутствие скрытых сетевых запросов при синхронной оценке репутационных инцидентов.
5. Корректность слияния финансовых данных ГИР БО и Checko.
"""

import httpx
import pytest
import respx
from unittest.mock import AsyncMock, patch

from osint_mcp.config import settings
from osint_mcp.context.bo_nalog import FinancialYear, merge_financial_years
from osint_mcp.context.reputation_fiascos import evaluate_fiascos_findings
from osint_mcp.context.site import inspect_site_content
from osint_mcp.models import (
    CompanyContext,
    ContextResult,
    SourceResult,
    Fact,
)
from osint_mcp.tools.context_builder import build_company_context
from osint_mcp.tools.risk import collect_risk_facts


pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@respx.mock
async def test_inspect_site_content_normalizes_raw_domain():
    """Домен без протокола (например, 'bpmsoft.ru') автоматически дополняется https://."""
    respx.get("https://bpmsoft.ru").mock(
        return_value=httpx.Response(
            200,
            text='<html><head><meta name="description" content="Платформа"></head><body><h1>BPMSoft CRM</h1><script src="https://mc.yandex.ru/watch/12345678"></script></body></html>',
        )
    )

    h1, tech, err = await inspect_site_content("bpmsoft.ru")

    assert err is None
    assert h1 == "BPMSoft CRM"
    assert tech is not None
    assert "Яндекс.Метрика" in tech.analytics
    assert "12345678" in tech.tracker_ids.get("yandex_metrika", [])


@respx.mock
async def test_inspect_site_content_falls_back_to_http_on_connect_error():
    """Если https:// недоступен, inspect_site_content пробует http://."""
    respx.get("https://old-corp.ru").mock(side_effect=httpx.ConnectError("Connection refused"))
    respx.get("http://old-corp.ru").mock(
        return_value=httpx.Response(
            200,
            text="<html><h1>Старый корпоративный сайт</h1></html>",
        )
    )

    h1, tech, err = await inspect_site_content("old-corp.ru")

    assert err is None
    assert h1 == "Старый корпоративный сайт"


@respx.mock
async def test_inspect_site_content_handles_both_protocols_failing():
    """Когда и https, и http не отвечают, возвращается честная диагностическая ошибка, а не краш."""
    respx.get("https://down.ru").mock(side_effect=httpx.ConnectError("Connection refused"))
    respx.get("http://down.ru").mock(side_effect=httpx.ConnectError("Connection refused"))

    h1, tech, err = await inspect_site_content("down.ru")

    assert h1 is None
    assert tech is None
    assert err is not None
    assert "сайт недоступен" in err


@respx.mock
async def test_context_builder_all_three_tiers_fail_cleanly():
    """Если DaData, Checko и ЕГРЮЛ одновременно недоступны, возвращается unavailable с перечислением всех трёх причин без UnboundLocalError."""
    # 1. DaData 503
    respx.post(f"{settings.dadata_base_url}/findById/party").mock(
        return_value=httpx.Response(503)
    )
    # 2. Checko 403
    respx.get(url__regex=rf"{settings.checko_base_url}/.*").mock(
        return_value=httpx.Response(403, json={"meta": {"status": "fail", "message": "Лимит исчерпан"}})
    )
    # 3. ЕГРЮЛ сервис падает
    with patch("osint_mcp.context.egrul.EgrulSource.get_card", AsyncMock(return_value=(None, "Сервис ЕГРЮЛ недоступен: 502 Bad Gateway"))):
        res = await build_company_context("7724744134")

    assert res.status == "unavailable"
    assert res.context is None
    assert "DaData:" in res.reason
    assert "Checko:" in res.reason
    assert "ЕГРЮЛ:" in res.reason


def test_evaluate_fiascos_findings_is_fully_offline():
    """Синхронная оценка репутационных находок не делает сетевых запросов даже при ссылках без дат."""
    hits = [
        {
            "url": "https://nonexistent-domain-123456789.org/news/leak",
            "title": "Банк: Утечка клиентских данных",
            "snippet": "Хакеры опубликовали дамп базы клиентов Банк на хакерском форуме.",
        }
    ]

    # Должен отработать мгновенно и офлайн без падений сети
    profile = evaluate_fiascos_findings(
        inn="7707083893",
        company_name="ООО Банк",
        brand="Банк",
        raw_hits=hits,
    )

    assert profile.total_signals == 1
    assert len(profile.incidents) == 1
    assert profile.incidents[0].category.value == "cyber_data_breach"


def test_merge_financial_years_preserves_primary_and_fills_fallback():
    """Слияние финансов Checko и ГИР БО корректно объединяет данные разных лет."""
    checko_years = [
        FinancialYear(year=2024, revenue=500_000.0, profit=100_000.0),
        FinancialYear(year=2023, revenue=400_000.0, profit=80_000.0),
    ]
    bo_years = [
        FinancialYear(year=2023, revenue=400_000.0, assets=300_000.0, report_url="https://bo.nalog.gov.ru/pdf/1"),
        FinancialYear(year=2022, revenue=300_000.0, assets=200_000.0, report_url="https://bo.nalog.gov.ru/pdf/2"),
    ]

    merged = merge_financial_years(primary=checko_years, fallback=bo_years)

    assert len(merged) == 3
    y2024 = next(y for y in merged if y.year == 2024)
    y2023 = next(y for y in merged if y.year == 2023)
    y2022 = next(y for y in merged if y.year == 2022)

    assert y2024.revenue == 500_000.0
    # В 2023 году: выручка и прибыль от Checko, активы и ссылка дополнены из ГИР БО
    assert y2023.revenue == 400_000.0
    assert y2023.profit == 80_000.0
    assert y2023.assets == 300_000.0
    assert y2023.report_url == "https://bo.nalog.gov.ru/pdf/1"
    # 2022 год подтянут из ГИР БО
    assert y2022.revenue == 300_000.0


@pytest.mark.asyncio
async def test_collect_risk_facts_fallback_transparency():
    """Когда Checko недоступен, а ApiCloud подменяет направление, в coverage_note четко зафиксирован fallback."""
    mock_checko = AsyncMock()
    mock_checko.check_registry_flags.return_value = SourceResult(source="checko.registry_flags", status="unavailable", reason="Лимит")
    mock_checko.check_arbitration.return_value = SourceResult(source="checko.arbitration", status="unavailable", reason="Лимит")
    mock_checko.check_enforcement.return_value = SourceResult(source="checko.enforcement", status="unavailable", reason="Лимит")
    mock_checko.check_inspections.return_value = SourceResult(source="checko.inspections", status="unavailable", reason="Лимит")
    mock_checko.check_procurement.return_value = SourceResult(source="checko.procurement", status="unavailable", reason="Лимит")

    backup_res = [
        SourceResult(source="apicloud.enforcement", status="ok", facts=[]),
        SourceResult(source="apicloud.arbitration", status="ok", facts=[]),
    ]

    with patch("osint_mcp.tools.risk._backup_checks", AsyncMock(return_value=backup_res)), \
         patch("osint_mcp.context.fedresurs.FedresursSource.check_commercial_facts", AsyncMock(return_value=SourceResult(source="fedresurs.commercial", status="ok", facts=[]))), \
         patch("osint_mcp.context.fsa.FsaSource.check_certificates", AsyncMock(return_value=SourceResult(source="fsa.certificates", status="ok", facts=[]))), \
         patch("osint_mcp.context.software_registry.SoftwareRegistrySource.check_software_registry", AsyncMock(return_value=SourceResult(source="software_registry", status="ok", facts=[]))):

        collection = await collect_risk_facts(inn="7724744134", source=mock_checko)

    assert "api-cloud" in collection.coverage_note
    assert "apicloud.enforcement" in [r.source for r in collection.results]
    assert "apicloud.arbitration" in [r.source for r in collection.results]
