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
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[])), \
         patch("osint_mcp.server._checko.check_affiliations", AsyncMock(return_value=(None, None))), \
         patch("osint_mcp.server._build_customs_facts", return_value=[]), \
         patch("osint_mcp.server._build_geo_reviews_facts", return_value=[]), \
         patch("osint_mcp.context.site.inspect_site_content", AsyncMock(return_value=(None, None, "no site"))):
        
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
         patch("osint_mcp.server._checko.check_affiliations", AsyncMock(return_value=(None, None))), \
         patch("osint_mcp.server._build_customs_facts", return_value=[]), \
         patch("osint_mcp.server._build_geo_reviews_facts", return_value=[]), \
         patch("osint_mcp.context.site.inspect_site_content", AsyncMock(return_value=(None, None, "no site"))), \
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



@pytest.mark.asyncio
async def test_get_company_report_clean_user_mode():
    from osint_mcp.server import get_company_report
    from osint_mcp.models import SourceResult

    ctx = CompanyContext(
        inn="7707083893",
        name_legal="ПАО СБЕРБАНК",
        name_short="СБЕРБАНК",
    )
    ctx_res = ContextResult(status="ok", context=ctx, reason="Технический сбой дополнительного источника")
    risk_col = RiskCollection(
        inn="7707083893",
        results=[
            SourceResult(source="checko.arbitration", status="ok"),
            SourceResult(source="fedresurs", status="unavailable", reason="451 Unavailable"),
        ],
        sources_ok=1,
        coverage_note="Недоступны источники: fedresurs",
        facts=[],
    )

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)), \
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[])), \
         patch("osint_mcp.server._checko.check_affiliations", AsyncMock(return_value=(None, None))), \
         patch("osint_mcp.server._build_customs_facts", return_value=[]), \
         patch("osint_mcp.server._build_geo_reviews_facts", return_value=[]), \
         patch("osint_mcp.context.site.inspect_site_content", AsyncMock(return_value=(None, None, "no site"))):

        # В обычном пользовательском режиме (debug=False по умолчанию)
        user_rep = await get_company_report(inn="7707083893", detail="full", debug=False)
        assert "что_не_собралось" not in user_rep
        assert "источники" not in user_rep
        assert "_диагностика_разработчика" not in user_rep
        # В кратких рисках нет строки "охват: ..."
        assert not any("охват:" in line for line in user_rep.get("риски_кратко", []))

        # В режиме разработчика (debug=True)
        dev_rep = await get_company_report(inn="7707083893", detail="full", debug=True)
        assert "что_не_собралось" in dev_rep
        assert "источники" in dev_rep
        assert "_диагностика_разработчика" in dev_rep
        diag = dev_rep["_диагностика_разработчика"]
        assert "отказы_источников" in diag
        assert diag["отказы_источников"][0]["source"] == "fedresurs"
        assert diag["отказы_источников"][0]["reason"] == "451 Unavailable"
        assert any("охват:" in line for line in dev_rep.get("риски_кратко", []))


@pytest.mark.asyncio
async def test_generate_full_dossier_debug_flag_propagation():
    from osint_mcp.server import generate_full_dossier
    from osint_mcp.models import SourceResult

    ctx = CompanyContext(inn="7707083893", name_legal="ПАО СБЕРБАНК")
    ctx_res = ContextResult(status="ok", context=ctx, reason="Таймаут")
    risk_col = RiskCollection(
        inn="7707083893",
        results=[SourceResult(source="fsa", status="unavailable", reason="Timeout")],
        coverage_note="Недоступны источники: fsa",
        facts=[],
    )

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)), \
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[])):

        dossier_user = await generate_full_dossier(inn="7707083893", debug=False)
        assert "_диагностика_разработчика" not in dossier_user
        assert "что_не_собралось" not in dossier_user

        dossier_dev = await generate_full_dossier(inn="7707083893", debug=True)
        assert "_диагностика_разработчика" in dossier_dev
        assert "что_не_собралось" in dossier_dev


@pytest.mark.asyncio
async def test_check_companies_batch_debug_flag():
    from osint_mcp.server import check_companies_batch
    from osint_mcp.models import SourceResult

    ctx = CompanyContext(inn="7707083893", name_legal="ПАО СБЕРБАНК")
    ctx_res = ContextResult(status="ok", context=ctx, reason="Таймаут")
    risk_col = RiskCollection(
        inn="7707083893",
        results=[SourceResult(source="fsa", status="unavailable", reason="Timeout")],
        coverage_note="Недоступны источники: fsa",
        facts=[],
    )

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)):

        res_user = await check_companies_batch(inns=["7707083893"], debug=False)
        item_user = res_user["результаты"][0]
        assert "что_не_собралось" not in item_user
        assert "охват" not in item_user

        res_dev = await check_companies_batch(inns=["7707083893"], debug=True)
        item_dev = res_dev["результаты"][0]
        assert "что_не_собралось" in item_dev


@pytest.mark.asyncio
async def test_get_company_report_fiascos_in_warnings():
    from osint_mcp.server import get_company_report
    from osint_mcp.scoring.models import PendingFact
    from datetime import datetime, timezone

    ctx = CompanyContext(
        inn="7736207543",
        name_legal="ООО Яндекс",
        name_short="Яндекс",
    )
    ctx_res = ContextResult(status="ok", context=ctx)
    risk_col = RiskCollection(inn="7736207543", results=[], sources_ok=1, facts=[])
    fiasco = PendingFact(
        fact_id="F-1",
        kind="fiasco_disaster_incident",
        statement="[РБК] [08.10.2026] Атака дронов на дата-центр компании в Сасово: пожар локализован | Вывод: операционный риск",
        source_url="https://rbc.ru",
        found_by="reputation_fiascos_engine",
        found_at=datetime.now(timezone.utc),
    )

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)), \
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[fiasco])), \
         patch("osint_mcp.server._checko.check_affiliations", AsyncMock(return_value=(None, None))), \
         patch("osint_mcp.server._build_customs_facts", return_value=[]), \
         patch("osint_mcp.server._build_geo_reviews_facts", return_value=[]), \
         patch("osint_mcp.context.site.inspect_site_content", AsyncMock(return_value=(None, None, "no site"))):

        res = await get_company_report(inn="7736207543")
        assert "warnings" in res
        assert any("Репутационный риск / инцидент в СМИ" in w for w in res["warnings"])
        assert any("08.10.2026" in w and "Атака дронов" in w for w in res["warnings"])
