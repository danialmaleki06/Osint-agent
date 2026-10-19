"""Тесты для модуля выявления репутационных факапов, неплатежей и операционных сбоев."""

from unittest.mock import patch
import pytest

from osint_mcp.context.reputation_fiascos import (
    FiascoPlatform,
    FiascoCategory,
    build_fiasco_queries,
    classify_fiasco_text,
    evaluate_fiascos_findings,
    build_reputation_fiasco_facts,
)
from osint_mcp.scoring.models import PendingFact


def test_build_fiasco_queries():
    """Проверка генерации поисковых запросов по всем 5 целевым платформам."""
    queries = build_fiasco_queries(
        company_name="ООО «Ромашка Софт»",
        brand="Ромашка",
        domain="romashka.ru",
    )

    assert FiascoPlatform.VC_RU in queries
    assert FiascoPlatform.HABR in queries
    assert FiascoPlatform.PIKABU in queries
    assert FiascoPlatform.BLACKLISTS in queries
    assert FiascoPlatform.DEV_COMMUNITY in queries

    # Проверяем наличие доменов целевых ресурсов
    vc_q = " ".join(queries[FiascoPlatform.VC_RU])
    assert "site:vc.ru" in vc_q
    assert "приёмная" in vc_q

    habr_q = " ".join(queries[FiascoPlatform.HABR])
    assert "site:habr.com" in habr_q
    assert "постмортем" in habr_q

    pika_q = " ".join(queries[FiascoPlatform.PIKABU])
    assert "site:pikabu.ru" in pika_q

    bl_q = " ".join(queries[FiascoPlatform.BLACKLISTS])
    assert "antijob" in bl_q or "pravda-sotrudnikov" in bl_q

    dev_q = " ".join(queries[FiascoPlatform.DEV_COMMUNITY])
    assert "github.com" in dev_q or "gitlab.com" in dev_q


def test_classify_fiasco_payment_default():
    """Тест классификации риска неплатежей и затягивания актов."""
    text = "Компания ООО Ромашка не заплатили за этап разработки и не подписывают акты уже 4 месяца."
    cat, markers, severity, advice = classify_fiasco_text(FiascoPlatform.VC_RU, text)

    assert cat == FiascoCategory.PAYMENT_DEFAULT
    assert "не заплатили" in markers or "не подписывают акты" in markers
    assert severity == "critical"
    assert "100% предоплату" in advice


def test_classify_fiasco_tech_incident():
    """Тест классификации технологической аварии на Хабре."""
    text = "Наш постмортем: почему упал прод и произошла потеря данных клиентов на 2 дня."
    cat, markers, severity, advice = classify_fiasco_text(FiascoPlatform.HABR, text)

    assert cat == FiascoCategory.TECH_INCIDENT
    assert "постмортем" in markers or "упал прод" in markers
    assert severity == "high"
    assert "Архитектурные риски" in advice


def test_classify_fiasco_employer_fraud():
    """Тест классификации черных списков работодателей и токсичного менеджмента."""
    text = "Не выплатили расчет при увольнении, серая зп, жуткая текучка, директор самодур."
    cat, markers, severity, advice = classify_fiasco_text(FiascoPlatform.BLACKLISTS, text)

    assert cat == FiascoCategory.EMPLOYER_FRAUD
    assert "не выплатили расчет" in markers or "серая зп" in markers
    assert severity == "moderate"
    assert "текучки ЛПР" in advice


def test_evaluate_fiascos_findings():
    """Тест агрегации сырых находок в структурированный профиль рисков."""
    raw_hits = [
        {
            "url": "https://vc.ru/claim/12345-ne-platyat-podryadchikam",
            "title": "ООО Ромашка не платят подрядчикам за дизайн",
            "snippet": "Задержка оплаты превысила полгода, досудебная претензия направлена.",
        },
        {
            "url": "https://habr.com/ru/post/555555/",
            "title": "Разбор аварии кластера в Ромашке",
            "snippet": "Сбой базы данных привел к простою сервиса на 18 часов.",
        },
        {
            "url": "https://antijob.top/black_list/id999",
            "title": "Черный список работодателей: Ромашка",
            "snippet": "Кидалово на финальный расчет, не советую работать.",
        },
    ]

    profile = evaluate_fiascos_findings("7701122334", "Ромашка", raw_hits)

    assert profile.total_signals == 3
    assert len(profile.incidents) == 3
    assert "vc_ru" in profile.platforms_covered
    assert "habr" in profile.platforms_covered
    assert "blacklists" in profile.platforms_covered
    assert "ВЫСОКИЙ КОММЕРЧЕСКИЙ РИСК" in profile.primary_commercial_risk
    assert len(profile.recommended_countermeasures) >= 2


@patch("osint_mcp.context.reputation_fiascos.search_web")
def test_build_reputation_fiasco_facts(mock_search):
    """Тест создания фактов PendingFact для шины карантина."""
    mock_search.return_value = [
        {
            "url": "https://vc.ru/claim/777",
            "title": "Сорван проект интеграции CRM",
            "snippet": "Заказчик отказался подписывать акты, немотивированный отказ.",
        }
    ]

    facts = build_reputation_fiasco_facts(
        inn="7724744134",
        company_name="ООО БПМСОФТ",
        brand="BPMSoft",
        platforms=["vc_ru"],
    )

    assert len(facts) >= 1
    f = facts[0]
    assert isinstance(f, PendingFact)
    assert f.trust == "mention"
    assert f.found_by == "reputation_fiascos_engine"
    assert "https://vc.ru" in f.source_url
    assert "FIASCO-" in f.fact_id
