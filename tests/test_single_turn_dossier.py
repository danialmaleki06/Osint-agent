import pytest
from unittest.mock import AsyncMock, patch

from osint_mcp.models import Candidate, CompanyContext, ContextResult, RiskCollection, ResolveResult
from osint_mcp.server import generate_full_dossier, mcp, resolve_company, PRIMARY_TOOLS, GRANULAR_TOOLS


@pytest.mark.asyncio
async def test_generate_full_dossier_direct_inn():
    """Проверка прямого вызова с ИНН — ровно один вызов формирует досье со всеми секциями."""
    ctx = CompanyContext(
        inn="7707083893",
        name_legal="ПАО СБЕРБАНК",
        name_short="СБЕРБАНК",
        brand="Сбер",
        brand_domain="sberbank.ru",
        address_full="г. Москва, ул. Вавилова, д. 19",
    )
    ctx_res = ContextResult(status="ok", context=ctx)
    risk_col = RiskCollection(inn="7707083893", results=[], facts=[])

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)), \
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[])), \
         patch("osint_mcp.server._checko.check_affiliations", AsyncMock(return_value=(None, None))), \
         patch("osint_mcp.context.customs.build_customs_facts", return_value=[]), \
         patch("osint_mcp.context.geo_reviews.build_geo_reviews_facts", return_value=[]), \
         patch("osint_mcp.context.site.inspect_site_content", AsyncMock(return_value=(None, None, "no site"))):

        res = await generate_full_dossier(inn="7707083893", detail="full")

        assert res["inn"] == "7707083893"
        assert "карточка" in res
        assert "вердикт" in res
        assert "score" in res


@pytest.mark.asyncio
async def test_generate_full_dossier_name_auto_resolution():
    """Если передано наименование компании вместо ИНН, generate_full_dossier автоматически разрешает его."""
    resolve_result = ResolveResult(
        query="Вайлдберриз",
        status="ok",
        confidence="high",
        total_found=1,
        candidates=[
            Candidate(
                inn="7721546864",
                name="ООО ВАЙЛДБЕРРИЗ",
                status="Действующая организация",
            )
        ],
    )

    ctx = CompanyContext(inn="7721546864", name_legal="ООО ВАЙЛДБЕРРИЗ", name_short="Вайлдберриз")
    ctx_res = ContextResult(status="ok", context=ctx)
    risk_col = RiskCollection(inn="7721546864", results=[], facts=[])

    with patch("osint_mcp.server._source.resolve", AsyncMock(return_value=resolve_result)), \
         patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)), \
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[])):

        res = await generate_full_dossier(inn="Вайлдберриз", detail="brief")

        assert res["inn"] == "7721546864"
        assert res["карточка"]["наименование"] == "ООО ВАЙЛДБЕРРИЗ"


@pytest.mark.asyncio
async def test_generate_full_dossier_ambiguous_name_returns_candidates():
    """Если передано неоднозначное название, возвращаются кандидаты для уточнения."""
    resolve_result = ResolveResult(
        query="Ромашка",
        status="ok",
        confidence="low",
        total_found=2,
        candidates=[
            Candidate(inn="7701000001", name="ООО РОМАШКА 1", status="Действующая"),
            Candidate(inn="7701000002", name="ООО РОМАШКА 2", status="Действующая"),
        ],
    )

    with patch("osint_mcp.server._source.resolve", AsyncMock(return_value=resolve_result)):
        res = await generate_full_dossier(inn="Ромашка")

        assert res["status"] == "multiple_candidates"
        assert len(res["candidates"]) == 2
        assert "Уточните" in res["hint"]


def test_tool_exposure_control():
    """Проверяем, что в базовом режиме регистрируются только 11 главных инструментов."""
    tools = list(mcp._tool_manager._tools.keys())
    assert "generate_full_dossier" in tools
    assert "resolve_company" in tools
    assert "check_companies_batch" in tools
    assert "health_check" in tools
    # Низкоуровневые инструменты не должны быть выставлены в MCP
    assert "get_company_context" not in tools
    assert "collect_risk_facts" not in tools
    assert "get_verdict" not in tools
    assert "check_customs_ved" not in tools
    assert "check_geo_reviews" not in tools
    assert "check_shared_analytics" not in tools
    assert "check_affiliations" not in tools
    assert len(tools) == len(PRIMARY_TOOLS)
