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
