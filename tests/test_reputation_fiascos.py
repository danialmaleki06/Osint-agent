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
    extract_incident_date,
)
from osint_mcp.scoring.models import PendingFact


def test_extract_incident_date():
    """Тест извлечения дат публикаций и инцидентов из URL и текста."""
    # Извлечение из URL (РБК: /DD/MM/YYYY/)
    assert extract_incident_date(
        "https://www.rbc.ru/technology_and_media/08/10/2026/6ac729745ecb179a64305301",
        "Пожар в Сасово",
        "Атака БПЛА",
    ) == "08.10.2026"

    # Извлечение из URL (Ведомости: /YYYY/MM/DD/)
    assert extract_incident_date(
        "https://www.vedomosti.ru/technology/articles/2026/10/08/1235289-chto-izvestno",
        "Атака БПЛА",
        "ЦОД остановлен",
    ) == "08.10.2026"

    # Извлечение из текста с русским месяцем
    assert extract_incident_date(
        "https://dzen.ru/a/asezNYwtABJA3Be0",
        "Атака на ЦОД",
        "В ночь на 8 октября 2026 года произошел инцидент",
    ) == "08.10.2026"

    # Извлечение из текста (утечка)
    assert extract_incident_date(
        "https://habr.com/ru/news/654039/",
        "Утечка базы",
        "1 марта служба безопасности рассказала о сливе... 2022 год",
    ) == "01.03.2022"

    # Извлечение формы предложного падежа месяца и года: "в марте 2022 года"
    assert extract_incident_date(
        "https://example.com/leak",
        "Утечка данных",
        "В марте 2022 года была зафиксирована компрометация базы",
    ) == "03.2022"

    # Извлечение при наличии даты и месяца и года в разных частях сниппета
    assert extract_incident_date(
        "https://example.com/incident",
        "Инцидент 2023",
        "26 января хакеры слили исходники",
    ) == "26.01.2023"


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

    # Проверяем наличие ключевых маркеров целевых ресурсов
    vc_q = " ".join(queries[FiascoPlatform.VC_RU])
    assert "vc.ru" in vc_q
    assert "приёмная" in vc_q

    habr_q = " ".join(queries[FiascoPlatform.HABR])
    assert "habr" in habr_q
    assert "сбой" in habr_q or "утечка" in habr_q

    pika_q = " ".join(queries[FiascoPlatform.PIKABU])
    assert "pikabu" in pika_q

    bl_q = " ".join(queries[FiascoPlatform.BLACKLISTS])
    assert "antijob" in bl_q or "правда сотрудников" in bl_q

    dev_q = " ".join(queries[FiascoPlatform.DEV_COMMUNITY])
    assert "github" in dev_q or "gitlab" in dev_q


def test_classify_fiasco_disaster_incident():
    """Тест классификации физической катастрофы / аварии ЦОД / атаки БПЛА."""
    text = "«Яндекс» сообщил о пожаре в дата-центре в городе Сасово в результате атаки БПЛА, работа ЦОД остановлена."
    cat, markers, severity, advice = classify_fiasco_text(FiascoPlatform.DISASTERS, text)

    assert cat == FiascoCategory.DISASTER_INCIDENT
    assert "пожар" in markers or "атака" in markers or "бпла" in markers
    assert severity == "critical"
    assert "инфраструктурный инцидент" in advice


def test_classify_fiasco_cyber_data_breach():
    """Тест классификации утечки баз данных и слива исходных кодов."""
    text = "Хакеры выложили в сеть архив базы данных клиентов и утечку исходного кода сервиса."
    cat, markers, severity, advice = classify_fiasco_text(FiascoPlatform.CYBER_LEAKS, text)

    assert cat == FiascoCategory.CYBER_DATA_BREACH
    assert "утечка" in markers[0] or "слив" in markers[0] or "исходного кода" in markers
    assert severity == "high"


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
            "title": "BPMSoft: Сорван проект интеграции CRM",
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
