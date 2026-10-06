"""Тесты для анализа веб-аналитики, поиска связанных доменов и скрытых холдингов."""

import pytest
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
        {"url": "https://holding-parent.ru/about", "title": "Головная компания"},
        {"url": "https://store-sister.ru/catalog", "title": "Интернет-магазин сети"},
        {"url": "https://developer-portal.ru/", "title": "Строительный портал"},
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
        {"url": f"https://client-{i}.ru/"} for i in range(22)
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
        {"url": "https://federal-bank.ru/service"},
        {"url": "https://fin-leasing.ru/offers"},
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
