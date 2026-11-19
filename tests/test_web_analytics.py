"""Тесты для анализа веб-аналитики, поиска связанных доменов и скрытых холдингов."""

import pytest


def test_one_failed_tracker_keeps_other_tracker_results(monkeypatch):
    from osint_mcp.context import web_analytics
    from osint_mcp.tools.web_search_source import SearchUnavailable

    def search(tracker_type, tracker_id, **kwargs):
        if tracker_id == "broken":
            raise SearchUnavailable("provider unavailable")
        return web_analytics.SharedTrackerHit(tracker_type, tracker_id, ["related.example"], True,
                                              "Shared tracker", ["https://related.example"])
    monkeypatch.setattr(web_analytics, "search_domains_sharing_tracker", search)
    facts = web_analytics.build_analytics_affiliation_facts("company.example",
        {"yandex_metrika": ["working", "broken"]}, "7724744134")
    assert len(facts) == 1 and facts.partial_reason


def test_all_failed_trackers_are_unavailable(monkeypatch):
    from osint_mcp.context import web_analytics
    from osint_mcp.tools.web_search_source import SearchUnavailable

    def fail(**kwargs):
        raise SearchUnavailable("provider unavailable")
    monkeypatch.setattr(web_analytics, "search_domains_sharing_tracker", fail)
    with pytest.raises(SearchUnavailable):
        web_analytics.build_analytics_affiliation_facts("company.example", {"yandex_metrika": ["broken"]}, "7724744134")
from types import SimpleNamespace
from unittest.mock import patch

from osint_mcp.context.web_analytics import (
    clean_domain,
    search_domains_sharing_tracker,
    build_analytics_affiliation_facts,
)
from osint_mcp.scoring import score_company
from osint_mcp.models import ExtFact


def test_clean_domain():
    assert clean_domain("https://sub.company.ru/page?query=1") == "sub.company.ru"
    assert clean_domain("http://www.main-corp.com/path") == "main-corp.com"
    assert clean_domain("partner.io") == "partner.io"
    assert clean_domain("not_a_domain") is None
    assert clean_domain(None) is None


def test_search_domains_sharing_tracker_probable_holding():
    """Тест обнаружения скрытой группы/холдинга по единому коду аналитики."""
    fake_hits = [
        {"url": "https://holding-parent.ru/about", "snippet": "ym(98765432)"},
        {"url": "https://store-sister.ru/catalog", "snippet": "ym(98765432)"},
        {"url": "https://developer-portal.ru/", "snippet": "ym(98765432)"},
        {"url": "https://unrelated.example/", "snippet": "ym(198765432)"},
    ]

    with patch("osint_mcp.context.web_analytics.search_web", return_value=fake_hits):
        hit = search_domains_sharing_tracker(
            tracker_type="yandex_metrika",
            tracker_id="98765432",
            current_domain="little-subsidiary.ru",
        )

        assert hit.tracker_type == "yandex_metrika"
        assert hit.tracker_id == "98765432"
        assert len(hit.shared_domains) == 3
        assert "holding-parent.ru" in hit.shared_domains
        assert "store-sister.ru" in hit.shared_domains
        assert hit.is_probable_holding is True
        assert "скрытый холдинг" in hit.interpretation or "общими бизнес-активами" in hit.interpretation


def test_search_domains_sharing_tracker_agency_false_positive():
    """Тест отсеивания ложных срабатываний: счетчик веб-студии на 20+ клиентах."""
    fake_hits = [
        {"url": f"https://client-{i}.ru/", "snippet": "ym(11223344)"} for i in range(22)
    ]

    with patch("osint_mcp.context.web_analytics.search_web", return_value=fake_hits):
        hit = search_domains_sharing_tracker(
            tracker_type="yandex_metrika",
            tracker_id="11223344",
            current_domain="my-client.ru",
        )

        assert len(hit.shared_domains) == 22
        assert hit.is_probable_holding is False
        assert "веб-студии" in hit.interpretation or "ложное срабатывание" in hit.interpretation


def test_build_analytics_affiliation_facts_quarantine_payload():
    """Тест генерации PendingFact со структурированным описанием для агента."""
    fake_hits = [
        {"url": "https://federal-bank.ru/service", "snippet": "ym(55667788)"},
        {"url": "https://fin-leasing.ru/offers", "snippet": "ym(55667788)"},
    ]

    with patch("osint_mcp.context.web_analytics.search_web", return_value=fake_hits):
        facts = build_analytics_affiliation_facts(
            domain="small-fintech.ru",
            tracker_ids={"yandex_metrika": ["55667788"]},
            subject_inn="7701234567",
        )

        assert len(facts) == 1
        fact = facts[0]
        assert fact.kind == "affiliate_domain_signal"
        assert "federal-bank.ru" in fact.statement
        assert fact.found_by == "shared_web_analytics"
        assert fact.payload["tracker_id"] == "55667788"
        assert fact.payload["shared_domains"] == ["federal-bank.ru", "fin-leasing.ru"]


def test_affiliate_network_scoring_rule():
    """Тест учета факта цифрового холдинга в скоринге по правилу из scoring.yaml."""
    from datetime import datetime, timezone

    fact = ExtFact(
        fact_id="WEBANALYTICS-YM-55667788",
        kind="affiliate_domain_signal",
        statement="Обнаружена связанная сеть доменов по коду аналитики yandex_metrika (55667788): federal-bank.ru, fin-leasing.ru.",
        source_url="https://small-fintech.ru",
        source_type="web_analytics",
        trust="reference",
        retrieved_at=datetime.now(timezone.utc),
        payload={"is_probable_holding": True},
    )

    res = score_company(facts=[fact])
    matched_names = [m.criterion for m in res.matched]
    assert "affiliate_network_detected" in matched_names
    assert any("Цифровая аффилированность" in m.reason for m in res.matched if m.reason)


async def test_shared_analytics_returns_and_stores_a_positive_hit(monkeypatch, tmp_path):
    from osint_mcp import server
    from osint_mcp.tools.quarantine import QuarantineStore

    async def inspect(_):
        return None, SimpleNamespace(tracker_ids={"yandex_metrika": ["55667788"]}), None

    monkeypatch.setattr(server, "_inspect_site_content", inspect)
    store = QuarantineStore(tmp_path / "quarantine.db")
    monkeypatch.setattr(server, "_quarantine", store)
    with patch("osint_mcp.context.web_analytics.search_web", return_value=[
        {"url": "https://example.org/", "snippet": "ym(55667788)"},
    ]):
        report = await server.check_shared_analytics("7724744134", "https://example.com/")

    assert report["networks_found"] == 1
    assert report["shared_networks"][0]["tracker_id"] == "55667788"
    [pending] = store.list_pending("7724744134")
    assert pending.payload["tracker_id"] == "55667788"
    store.close()
