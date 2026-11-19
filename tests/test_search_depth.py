from unittest.mock import Mock
from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("detail,expected", [("brief", 2), ("standard", 4), ("full", 6)])
async def test_reputation_reduces_actual_search_calls(monkeypatch, detail, expected):
    from osint_mcp.context import reputation_fiascos

    search = Mock(return_value=[])
    monkeypatch.setattr(reputation_fiascos, "search_web", search)
    await reputation_fiascos.async_build_reputation_fiasco_facts(
        "7724744134", "БПМСОФТ", brand="BPMSoft", detail=detail)
    assert search.call_count == expected


@pytest.mark.parametrize("detail,maximum", [("brief", 1), ("standard", 4), ("full", 9)])
async def test_media_search_count_depends_on_detail(monkeypatch, detail, maximum):
    from osint_mcp.context import news_media

    search = Mock(return_value=[])
    monkeypatch.setattr(news_media, "search_news", search)
    result = await news_media.fetch_company_media_presence(
        "7724744134", "БПМСОФТ", brand="BPMSoft", director_fio="Баранов Денис Валентинович", detail=detail)
    assert 0 < search.call_count <= maximum
    assert result["поисковых_запросов"] == search.call_count
    if detail == "full":
        assert search.call_count == len(news_media.build_media_queries("БПМСОФТ", "BPMSoft", "Баранов Денис Валентинович"))


@pytest.mark.parametrize("detail,expected,news_count", [("brief", 0, 0), ("standard", 1, 2), ("full", 2, 5)])
async def test_competitor_discovery_and_news_share_detail_limits(monkeypatch, detail, expected, news_count):
    from osint_mcp.context import competitors

    search = Mock(return_value=[])
    monkeypatch.setattr(competitors, "search_web", search)
    news = Mock(return_value=[])
    monkeypatch.setattr(competitors, "search_news", news)
    monkeypatch.setattr(competitors, "_match_cluster_peers", lambda **kw: (None, []))
    monkeypatch.setattr(competitors, "_extract_competitor_names_from_text",
                        lambda *a: ["Alpha", "Beta", "Gamma", "Delta", "Epsilon"])
    result = await competitors.fetch_company_competitors("Example", detail=detail)
    assert search.call_count == expected
    assert news.call_count == news_count
    if detail == "brief":
        assert "не запускались" in result["примечание"]


async def test_brief_known_competitors_do_not_claim_their_news_was_checked(monkeypatch):
    from osint_mcp.context import competitors

    search = Mock(side_effect=AssertionError("Brief must not search competitors"))
    monkeypatch.setattr(competitors, "search_web", search)
    result = await competitors.fetch_company_competitors("БПМСОФТ", brand="BPMSoft", detail="brief")
    assert result["конкуренты"]
    assert all("не запускался" in item["последняя_новость"] for item in result["конкуренты"])


@pytest.mark.parametrize("detail,web_count,rss_count", [("brief", 2, 1), ("standard", 4, 4)])
async def test_dossier_passes_detail_to_real_search_collectors(monkeypatch, detail, web_count, rss_count):
    from osint_mcp import server
    from osint_mcp.context import reputation_fiascos, competitors, news_media
    from osint_mcp.models import CompanyContext, ContextResult, RiskCollection

    ctx = CompanyContext(inn="7724744134", name_legal="БПМСОФТ", name_short="БПМСОФТ",
                         brand="BPMSoft", brand_domain="bpmsoft.ru")
    monkeypatch.setattr(server, "_build_context", AsyncMock(return_value=ContextResult(status="ok", context=ctx)))
    monkeypatch.setattr(server, "_collect_risk_facts", AsyncMock(return_value=RiskCollection(inn=ctx.inn, results=[], facts=[])))
    monkeypatch.setattr(server, "_quarantine", SimpleNamespace(confirmed_facts=lambda inn: [], add=lambda *a: 0))
    monkeypatch.setattr("osint_mcp.tools.hr_hub.detect_corporate_hr_hub", AsyncMock(return_value=None))
    rep_search, competitor_search, rss_search = Mock(return_value=[]), Mock(return_value=[]), Mock(return_value=[])
    monkeypatch.setattr(reputation_fiascos, "search_web", rep_search)
    monkeypatch.setattr(competitors, "search_web", competitor_search)
    monkeypatch.setattr(competitors, "search_news", Mock(return_value=[]))
    monkeypatch.setattr(news_media, "search_news", rss_search)
    result = await server.generate_full_dossier(ctx.inn, detail=detail)
    assert rep_search.call_count + competitor_search.call_count == web_count
    assert rss_search.call_count == rss_count
    assert result["глубина_веб_поиска"]["репутационных_контуров"] == rep_search.call_count
