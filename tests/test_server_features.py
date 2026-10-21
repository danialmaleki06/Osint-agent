import pytest
from unittest.mock import AsyncMock, patch

from osint_mcp.models import CompanyContext, ContextResult, HiringInfo, RiskCollection
from osint_mcp.server import generate_full_dossier


@pytest.mark.asyncio
async def test_generate_full_dossier_query_guard():
    ctx = CompanyContext(
        inn="1655065057",
        name_legal='УПРАВЛЕНИЕ ФЕДЕРАЛЬНОЙ СЛУЖБЫ ПО НАДЗОРУ В СФЕРЕ ЗАЩИТЫ ПРАВ ПОТРЕБИТЕЛЕЙ ПО РТ',
        name_short='УПРАВЛЕНИЕ РОСПОТРЕБНАДЗОРА ПО РЕСПУБЛИКЕ ТАТАРСТАН',
    )
    ctx_res = ContextResult(status="ok", context=ctx)
    risk_col = RiskCollection(inn="1655065057", results=[], facts=[])

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)), \
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[])):
        
        # Передаем несоответствующее название через expected_name
        res = await generate_full_dossier(
            inn="1655065057",
            detail="brief",
            expected_name="ООО «ПСО «Казань»",
        )

        assert "расхождение_запроса" in res
        disc = res["расхождение_запроса"]
        assert disc["критичность"] == "high"
        assert "КРИТИЧЕСКОЕ РАСХОЖДЕНИЕ" in disc["предупреждение"]

        # Проверяем, что предупреждение попало в score.warnings
        assert any("КРИТИЧЕСКОЕ РАСХОЖДЕНИЕ" in w for w in res.get("warnings", []))


@pytest.mark.asyncio
async def test_generate_full_dossier_query_guard_embedded_string():
    ctx = CompanyContext(
        inn="1655065057",
        name_legal='УПРАВЛЕНИЕ ФЕДЕРАЛЬНОЙ СЛУЖБЫ ПО НАДЗОРУ В СФЕРЕ ЗАЩИТЫ ПРАВ ПОТРЕБИТЕЛЕЙ ПО РТ',
        name_short='УПРАВЛЕНИЕ РОСПОТРЕБНАДЗОРА ПО РЕСПУБЛИКЕ ТАТАРСТАН',
    )
    ctx_res = ContextResult(status="ok", context=ctx)
    risk_col = RiskCollection(inn="1655065057", results=[], facts=[])

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)), \
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[])):
        
        # Передаем строку содержащую и название и ИНН прямо в поле inn
        res = await generate_full_dossier(
            inn="ООО «ПСО «Казань» (ИНН 1655065057)",
            detail="brief",
        )

        assert "расхождение_запроса" in res
        disc = res["расхождение_запроса"]
        assert disc["критичность"] == "high"
        assert any("КРИТИЧЕСКОЕ РАСХОЖДЕНИЕ" in w for w in res.get("warnings", []))


@pytest.mark.asyncio
async def test_generate_full_dossier_hr_hub():
    ctx = CompanyContext(
        inn="7743001840",
        name_legal='ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "ВК"',
        name_short='ООО "ВК"',
        brand="VK",
        size_category="large",
        hiring=HiringInfo(open_vacancies=0),
    )
    ctx_res = ContextResult(status="ok", context=ctx)
    risk_col = RiskCollection(inn="7743001840", results=[], facts=[])

    mock_hub = {
        "обнаружен": True,
        "бренд": "VK",
        "наименование_хаба": "VK",
        "employer_id": "15478",
        "вакансий_в_хабе": 159,
        "пояснение": "Найм консолидирован в централизованном HR-хабе.",
    }

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)), \
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[])), \
         patch("osint_mcp.tools.hr_hub.detect_corporate_hr_hub", AsyncMock(return_value=mock_hub)):
        
        res = await generate_full_dossier(inn="7743001840", detail="full")

        assert "кадровый_хаб_холдинга" in res
        assert res["кадровый_хаб_холдинга"]["employer_id"] == "15478"
        assert res["кадровый_хаб_холдинга"]["вакансий_в_хабе"] == 159


@pytest.mark.asyncio
async def test_get_verdict_query_guard_and_dirty_inn():
    from osint_mcp.server import get_verdict
    from osint_mcp.models import SourceResult

    ctx = CompanyContext(
        inn="1655065057",
        name_legal='УПРАВЛЕНИЕ ФЕДЕРАЛЬНОЙ СЛУЖБЫ ПО НАДЗОРУ В СФЕРЕ ЗАЩИТЫ ПРАВ ПОТРЕБИТЕЛЕЙ ПО РТ',
        name_short='УПРАВЛЕНИЕ РОСПОТРЕБНАДЗОРА ПО РЕСПУБЛИКЕ ТАТАРСТАН',
    )
    ctx_res = ContextResult(status="ok", context=ctx)
    risk_col = RiskCollection(
        inn="1655065057",
        results=[SourceResult(source="checko", status="ok")],
        sources_ok=1,
        facts=[],
    )

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)):

        res = await get_verdict(inn="ООО «ПСО «Казань» (ИНН 1655065057)")

        assert res.inn == "1655065057"
        assert res.verdict.floored is True
        assert res.verdict.floor_criterion == "query_name_mismatch"
        assert res.verdict.label == "рискованно"
        assert any("ВНИМАНИЕ: Запрошена организация «ООО «ПСО «Казань»" in w for w in res.warnings)


@pytest.mark.asyncio
async def test_check_companies_batch_dirty_inn_and_discrepancy():
    from osint_mcp.server import check_companies_batch
    from osint_mcp.models import SourceResult

    ctx = CompanyContext(
        inn="1655065057",
        name_legal='УПРАВЛЕНИЕ РОСПОТРЕБНАДЗОРА',
        employees=150,
        revenue_latest=500_000_000,
        hiring=HiringInfo(open_vacancies=3),
    )
    ctx_res = ContextResult(status="ok", context=ctx)
    risk_col = RiskCollection(
        inn="1655065057",
        results=[SourceResult(source="checko", status="ok")],
        sources_ok=1,
        facts=[],
    )

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)):

        batch_res = await check_companies_batch(
            inns=["ООО «ПСО «Казань» (ИНН 1655065057)"]
        )

        assert batch_res["проверено"] == 1
        item = batch_res["результаты"][0]
        assert item["inn"] == "1655065057"
        assert item["вердикт"] == "рискованно"
        assert any("ВНИМАНИЕ: Запрошена" in w for w in item.get("warnings", []))
        assert "кадры" in item
        assert item["кадры"]["штат_фнс"] == 150
        assert item["кадры"]["вакансий"] == 3


def test_check_coverage_dirty_inn():
    from osint_mcp import ledger
    from osint_mcp.server import check_coverage

    ledger.reset()
    ledger.set_subject("7724744134")
    ledger.record("checko", "company", "ok")

    rep = check_coverage("ООО «БПМСофт» (ИНН 7724744134)")
    assert rep.inn == "7724744134"
    assert rep.checked is True
    assert rep.total_requests == 1
    ledger.reset()

