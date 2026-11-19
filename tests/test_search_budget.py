import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
import respx

from osint_mcp.config import settings
from osint_mcp.tools.search_budget import SearchBudget, SearchBudgetExceeded, search_budget
from osint_mcp.tools.web_search_source import YANDEX_SEARCH_URL, SearchUnavailable, search_web


@pytest.fixture
def paid(monkeypatch):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    monkeypatch.setattr(settings, "yandex_search_mode", "primary")


def empty_response():
    return {"rawData": base64.b64encode(b'<yandexsearch><response><found>0</found></response></yandexsearch>').decode()}


def test_budget_is_atomic_across_threads():
    budget = SearchBudget(4)
    def attempt(_):
        try:
            budget.reserve(0.488)
            return True
        except SearchBudgetExceeded:
            return False
    with ThreadPoolExecutor(max_workers=20) as executor:
        assert sum(executor.map(attempt, range(100))) == 8
    assert budget.snapshot() == {"лимит_руб": 4, "верхняя_оценка_расхода_руб": 3.904,
                                 "http_попыток": 8, "отклонено_по_бюджету": 92}


@respx.mock
async def test_dossier_budget_is_shared_by_async_workers(paid):
    route = respx.post(YANDEX_SEARCH_URL).respond(json=empty_response())
    with search_budget(4) as budget:
        results = await asyncio.gather(*(
            asyncio.to_thread(search_web, f"query {i}", raise_on_unavailable=True) for i in range(30)
        ), return_exceptions=True)
    assert route.call_count == 8
    assert sum(isinstance(result, SearchUnavailable) for result in results) == 22
    assert budget.snapshot()["верхняя_оценка_расхода_руб"] == 3.904


@respx.mock
def test_retry_is_blocked_before_an_extra_http_attempt(paid):
    route = respx.post(YANDEX_SEARCH_URL).respond(502)
    with search_budget(0.5) as budget:
        with pytest.raises(SearchUnavailable, match="лимит"):
            search_web("query", raise_on_unavailable=True)
    assert route.call_count == 1
    assert budget.snapshot()["http_попыток"] == 1


@respx.mock
def test_malformed_paid_responses_still_use_budget(paid):
    route = respx.post(YANDEX_SEARCH_URL).respond(json={"rawData": "broken"})
    with search_budget(0.5) as budget:
        for _ in range(2):
            with pytest.raises(SearchUnavailable):
                search_web("query", raise_on_unavailable=True)
    assert route.call_count == 1 and budget.snapshot()["отклонено_по_бюджету"] == 1


@respx.mock
def test_cache_does_not_reserve_money(paid):
    route = respx.post(YANDEX_SEARCH_URL).respond(json=empty_response())
    with search_budget(4):
        search_web("query", raise_on_unavailable=True)
    with search_budget(0) as budget:
        assert search_web("query", raise_on_unavailable=True) == []
    assert route.call_count == 1 and budget.snapshot()["http_попыток"] == 0


@respx.mock
async def test_concurrent_dossiers_have_independent_budgets(paid):
    route = respx.post(YANDEX_SEARCH_URL).respond(json=empty_response())
    async def dossier(prefix):
        with search_budget(0.5) as budget:
            await asyncio.gather(*(
                asyncio.to_thread(search_web, f"{prefix}-{i}", raise_on_unavailable=True) for i in range(3)
            ), return_exceptions=True)
            return budget.snapshot()
    first, second = await asyncio.gather(dossier("one"), dossier("two"))
    assert route.call_count == 2
    assert first["http_попыток"] == second["http_попыток"] == 1


@respx.mock
def test_lost_response_consumes_a_budget_slot(paid):
    route = respx.post(YANDEX_SEARCH_URL).mock(side_effect=httpx.ReadTimeout("lost response"))
    with search_budget(0.5):
        with pytest.raises(SearchUnavailable, match="лимит"):
            search_web("query", raise_on_unavailable=True)
    assert route.call_count == 1


@respx.mock
async def test_report_wrapper_limits_the_entire_dossier(monkeypatch, paid):
    from osint_mcp import server

    route = respx.post(YANDEX_SEARCH_URL).respond(json=empty_response())
    async def assemble(**kwargs):
        from osint_mcp.tools.search_budget import yandex_search_stage
        with yandex_search_stage("reputation"):
            await asyncio.gather(*(
                asyncio.to_thread(search_web, f"query-{i}", raise_on_unavailable=True) for i in range(20)
            ), return_exceptions=True)
        return {"inn": kwargs["inn"]}
    monkeypatch.setattr(server, "_assemble_company_report", assemble)
    result = await server.get_company_report("7724744134")
    assert route.call_count == result["бюджет_Яндекса"]["http_попыток"] == 8
    assert result["бюджет_Яндекса"]["верхняя_оценка_расхода_руб"] == 3.904
    assert result["бюджет_Яндекса"]["отклонено_по_бюджету"] == 12
    assert any("бюджет" in message for message in result["warnings"])


async def test_dossier_preserves_search_priority(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from osint_mcp import server
    from osint_mcp.models import CompanyContext, ContextResult, RiskCollection, SiteTechInfo

    phases = []
    def phase(name):
        def run(*a, **kw):
            phases.append(name)
            return []
        return run
    ctx = CompanyContext(inn="7724744134", name_legal="БПМСОФТ", name_short="БПМСОФТ",
                         brand="BPMSoft", brand_domain="bpmsoft.ru", address_full="Москва")
    monkeypatch.setattr(server, "_build_context", AsyncMock(return_value=ContextResult(status="ok", context=ctx)))
    monkeypatch.setattr(server, "_collect_risk_facts", AsyncMock(return_value=RiskCollection(inn=ctx.inn, results=[], facts=[])))
    monkeypatch.setattr(server, "_quarantine", SimpleNamespace(confirmed_facts=lambda inn: [], add=lambda *a: 0))
    monkeypatch.setattr("osint_mcp.tools.hr_hub.detect_corporate_hr_hub", AsyncMock(return_value=None))
    monkeypatch.setattr(server._checko, "check_affiliations", AsyncMock(return_value=(None, None)))
    monkeypatch.setattr(server, "_fetch_company_media_presence", AsyncMock(return_value={}))
    monkeypatch.setattr(server, "_inspect_site_content", AsyncMock(return_value=(None, SiteTechInfo(tracker_ids={"yandex_metrika": ["12345678"]}), None)))
    monkeypatch.setattr(server, "_async_build_reputation_fiasco_facts", AsyncMock(side_effect=phase("reputation")))
    monkeypatch.setattr(server, "_build_geo_reviews_facts", phase("geo"))
    monkeypatch.setattr(server, "_build_customs_facts", phase("customs"))
    monkeypatch.setattr(server, "_build_analytics_affiliation_facts", phase("analytics"))
    monkeypatch.setattr(server, "_fetch_company_competitors", AsyncMock(side_effect=phase("competitors")))
    await server.generate_full_dossier(ctx.inn, detail="full")
    assert phases == ["reputation", "geo", "customs", "analytics", "competitors"]


@pytest.mark.parametrize("fail_one", [False, True])
@respx.mock
async def test_site_discovery_cannot_spend_reputation_minimum(monkeypatch, paid, fail_one):
    """Exercise real paid fallback and real reputation queries within a dossier."""
    import json
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from osint_mcp import server
    from osint_mcp.models import CompanyContext, ContextResult, RiskCollection, SiteTechInfo
    from osint_mcp.context.reputation_fiascos import build_fiasco_queries
    from osint_mcp.tools.web_search_source import SEARCH_URL

    monkeypatch.setattr(settings, "yandex_search_mode", "fallback")
    respx.post(SEARCH_URL).respond(202)
    respx.get(url__startswith="https://search.yahoo.com/").respond(500)
    attempted = []
    def respond(request):
        query = json.loads(request.content)["query"]["queryText"]
        attempted.append(query)
        if fail_one and "датацентр пожар" in query:
            return httpx.Response(503)
        return httpx.Response(200, json=empty_response())
    route = respx.post(YANDEX_SEARCH_URL).mock(side_effect=respond)
    ctx = CompanyContext(inn="7724744134", name_legal="БПМСОФТ", name_short="БПМСОФТ",
                         brand="BPMSoft", brand_domain="bpmsoft.ru")
    async def context(*args):
        # Simulate multiple candidate queries and their paid retries before reputation.
        for i in range(3):
            await asyncio.to_thread(search_web, f"site-discovery-{i}", raise_on_unavailable=False)
        return ContextResult(status="ok", context=ctx)
    monkeypatch.setattr(server, "_build_context", context)
    monkeypatch.setattr(server, "_collect_risk_facts", AsyncMock(return_value=RiskCollection(inn=ctx.inn, results=[], facts=[])))
    monkeypatch.setattr(server, "_quarantine", SimpleNamespace(confirmed_facts=lambda inn: [], add=lambda *args: 0))
    monkeypatch.setattr("osint_mcp.tools.hr_hub.detect_corporate_hr_hub", AsyncMock(return_value=None))
    monkeypatch.setattr(server._checko, "check_affiliations", AsyncMock(return_value=(None, None)))
    monkeypatch.setattr(server, "_fetch_company_media_presence", AsyncMock(return_value={}))
    monkeypatch.setattr(server, "_fetch_company_competitors", AsyncMock(return_value=None))
    monkeypatch.setattr(server, "_inspect_site_content", AsyncMock(return_value=(None, SiteTechInfo(), None)))
    result = await server.generate_full_dossier(ctx.inn, detail="full")
    required = {queries[0] for queries in build_fiasco_queries(ctx.name_short, ctx.brand, ctx.brand_domain, inn=ctx.inn).values()}
    reputation = [query for query in attempted if not query.startswith("site-discovery-")]
    assert len(reputation) == 6
    assert set(reputation) <= required
    assert route.call_count == 8
    assert result["бюджет_Яндекса"]["верхняя_оценка_расхода_руб"] == 3.904
    coverage = result["проверка_репутации"]
    assert coverage["направлений_с_ответом"] == (5 if fail_one else 6)
    assert coverage["статус"] == ("partial" if fail_one else "ok")
    if fail_one:
        assert "disasters" in coverage["неполные_направления"]
        assert any("Репутационная проверка неполная" in warning for warning in result["warnings"])


def test_unused_protected_slots_return_to_optional_search():
    from osint_mcp.tools.search_budget import protect_yandex_attempts, reserve_yandex_attempt, yandex_search_stage
    with search_budget(4) as budget, protect_yandex_attempts("reputation", 6):
        reserve_yandex_attempt()
        reserve_yandex_attempt()
        with pytest.raises(SearchBudgetExceeded):
            reserve_yandex_attempt()
        with yandex_search_stage("reputation"):
            pass  # All reputation queries were free or cached.
        for _ in range(6):
            reserve_yandex_attempt()
    assert budget.attempts == 8


async def test_reputation_failure_is_not_a_clean_empty_result(monkeypatch):
    from unittest.mock import Mock
    from osint_mcp.context import reputation_fiascos
    monkeypatch.setattr(reputation_fiascos, "search_web", Mock(side_effect=SearchUnavailable("offline")))
    facts = await reputation_fiascos.async_build_reputation_fiasco_facts("7724744134", "БПМСОФТ", detail="full")
    assert not facts
    assert facts.coverage["статус"] == "unavailable"
    assert len(facts.coverage["неполные_направления"]) == 6
