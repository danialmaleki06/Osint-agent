"""Тесты для модуля сбора новостей, публичной активности и заявлений руководства."""

from unittest.mock import patch
import pytest

from osint_mcp.context.news_media import (
    MediaItem,
    build_media_queries,
    classify_news_hit,
    extract_news_date,
    fetch_company_media_presence,
    format_media_profile,
    resolve_news_source,
)


def test_build_media_queries_with_director():
    """Проверка генерации запросов по заявлениям конкретного руководителя и презентациям."""
    queries = build_media_queries(
        company_name='ООО "БПМСОФТ"',
        brand="BPMSoft",
        director_fio="Баранов Денис Валентинович",
    )
    assert len(queries) >= 5
    query_texts = [q[1] for q in queries]

    # Проверяем наличие запросов по имени директора
    assert any("Денис Баранов" in q for q in query_texts)
    assert any("Баранов" in q and "генеральный директор" in q for q in query_texts)

    # Проверяем наличие запросов по презентациям и запускам
    assert any("представил" in q or "презентовал" in q for q in query_texts)
    assert any("конференция" in q or "форум" in q for q in query_texts)

    # Проверяем целевой поиск по официальным технологическим изданиям (CNews и TAdviser)
    assert any("cnews.ru" in q and "tadviser.ru" in q for q in query_texts)


def test_build_media_queries_without_director():
    """Проверка генерации запросов без ФИО руководителя — обязательно включают CNews и TAdviser."""
    queries = build_media_queries(
        company_name='ООО "Яндекс"',
        brand="Yandex",
        director_fio=None,
    )
    query_texts = [q[1] for q in queries]
    assert any("cnews.ru" in q and "tadviser.ru" in q for q in query_texts)


def test_classify_news_hit_leadership_statement():
    """Тест классификации заявлений и интервью первого лица компании."""
    item = classify_news_hit(
        title="Глава BPMSoft Денис Баранов рассказал о планах развития платформы на 2026 год",
        snippet="В интервью CNews генеральный директор Денис Баранов отметил: «Мы наращиваем инвестиции в AI-ассистентов для автоматизации процессов».",
        url="https://www.cnews.ru/interviews/2026-04-12_denis_baranov_bpmsoft",
        director_fio="Баранов Денис Валентинович",
    )

    assert item.category == "заявление_руководства"
    assert "Баранов" in (item.speaker or "")
    assert item.source == "CNews"
    assert "инвестиции в AI-ассистентов" in (item.highlight or "")
    assert item.date == "12.04.2026" or "2026" in (item.date or "")


def test_classify_news_hit_product_presentation():
    """Тест классификации презентации продукта на отраслевом форуме/конференции."""
    item = classify_news_hit(
        title="Компания представила обновленную линейку корпоративного ПО на ЦИПР-2026",
        snippet="18 мая 2026 года на конференции ЦИПР разработчики анонсировали новую версию системы управления бизнес-процессами.",
        url="https://tadviser.ru/index.php/Статья:BPMSoft_CIPR_2026",
        director_fio=None,
    )

    assert item.category == "презентация_или_событие"
    assert item.source == "TAdviser"
    assert "18.05.2026" == item.date
    assert "ЦИПР" in (item.highlight or item.title)


def test_classify_news_hit_corporate_partnership():
    """Тест классификации стратегического партнерства или соглашения."""
    item = classify_news_hit(
        title="BPMSoft и системный интегратор подписали соглашение о стратегическом партнерстве",
        snippet="Компании договорились о совместном внедрении решений для крупнейших промышленных холдингов в марте 2026 года.",
        url="https://www.kommersant.ru/doc/12345678",
        director_fio=None,
    )

    assert item.category == "корпоративная_новость"
    assert item.source == "Коммерсантъ"
    assert "03.2026" == item.date or "2026" in (item.date or "")


def test_resolve_news_source():
    """Тест определения наименований деловых изданий по домену."""
    assert resolve_news_source("https://www.rbc.ru/business/123") == "РБК"
    assert resolve_news_source("https://spb.rbc.ru/spb/456") == "РБК Санкт-Петербург"
    assert resolve_news_source("https://www.vedomosti.ru/technology/articles/789") == "Ведомости"
    assert resolve_news_source("https://tass.ru/ekonomika/999") == "ТАСС"
    assert resolve_news_source("https://vc.ru/tribuna/111") == "VC.ru"
    assert resolve_news_source("https://habr.com/ru/articles/222") == "Хабр"
    assert resolve_news_source("https://tech-portal.org/article") == "tech-portal.org"


def test_extract_news_date_various_formats():
    """Тест извлечения дат в различных форматах (URL, текст, месяцы)."""
    # 1. URL с датой /YYYY/MM/DD/
    assert extract_news_date("https://rbc.ru/news/2026/04/15/id", "Заголовок", "Текст") == "15.04.2026"
    # 2. Текст с русским месяцем: "10 октября 2026"
    assert extract_news_date("https://example.com/item", "Анонс", "10 октября 2026 года состоялся релиз") == "10.10.2026"
    # 3. Числовой формат: DD.MM.YYYY
    assert extract_news_date("https://example.com/item", "Новость 25.02.2026", "Описание") == "25.02.2026"


def test_format_media_profile_detail_levels():
    """Проверка адаптации структуры выдачи под 3 уровня подробности (brief / standard / full)."""
    item_lead = MediaItem(
        category="заявление_руководства",
        title="Гендиректор заявил о росте выручки",
        url="https://rbc.ru/1",
        snippet="«Мы выросли на 40%», заявил директор.",
        source="РБК",
        date="10.04.2026",
        speaker="Иванов Иван",
        highlight="«Мы выросли на 40%»",
    )
    item_event = MediaItem(
        category="презентация_или_событие",
        title="Презентация нового сервиса на выставке",
        url="https://cnews.ru/2",
        snippet="Компания продемонстрировала продукт на форуме.",
        source="CNews",
        date="05.04.2026",
        highlight="продемонстрировала продукт на форуме",
    )
    item_corp = MediaItem(
        category="корпоративная_новость",
        title="Соглашение с партнером",
        url="https://vedomosti.ru/3",
        snippet="Стороны подписали меморандум.",
        source="Ведомости",
        date="01.04.2026",
    )
    items = [item_lead, item_event, item_corp]

    # 1. Brief («кратко») — 1-2 главных события без перегруза
    brief = format_media_profile(items, detail="brief")
    assert "главные_события" in brief
    assert len(brief["главные_события"]) == 2
    assert "заявления_руководства" not in brief  # В brief только компактный список главных событий
    assert brief["всего_найдено"] == 3

    # 2. Standard («средне») — структурированные списки по категориям
    standard = format_media_profile(items, detail="standard")
    assert "заявления_руководства" in standard
    assert "презентации_и_события" in standard
    assert "корпоративные_новости" in standard
    assert len(standard["заявления_руководства"]) == 1
    assert standard["заявления_руководства"][0]["спикер"] == "Иванов Иван"

    # 3. Full («полно») — полная хроника, сниппеты, детали
    full = format_media_profile(items, detail="full")
    assert "хроника_публичной_активности" in full
    assert len(full["хроника_публичной_активности"]) == 3
    assert full["хроника_публичной_активности"][0]["спикер"] == "Иванов Иван"


@pytest.mark.asyncio
async def test_fetch_company_media_presence_mocked():
    """Тест асинхронного сбора с мокированным поиском."""
    fake_hits = [
        {
            "url": "https://www.cnews.ru/news/2026-04-10_baranov_intervyu",
            "title": "Денис Баранов: «Российский софт выходит на новые рубежи»",
            "snippet": "Генеральный директор BPMSoft Денис Баранов в интервью CNews рассказал о масштабном внедрении ИИ.",
        },
        {
            "url": "https://tadviser.ru/index.php/Статья:BPMSoft_CRM_v5",
            "title": "BPMSoft представила версию CRM 5.0 на форуме",
            "snippet": "15 апреля 2026 года на конференции разработчик продемонстрировал новую систему.",
        },
    ]

    with patch("osint_mcp.context.news_media.search_web", return_value=fake_hits):
        res = await fetch_company_media_presence(
            inn="7724744134",
            company_name='ООО "БПМСОФТ"',
            brand="BPMSoft",
            director_fio="Баранов Денис Валентинович",
            detail="standard",
        )

        assert res["всего_найдено"] == 2
        assert len(res["заявления_руководства"]) >= 1
        assert "Баранов" in res["заявления_руководства"][0]["спикер"]
        assert len(res["презентации_и_события"]) >= 1
        assert "CNews" in res["заявления_руководства"][0]["источник"]
        assert "TAdviser" in res["презентации_и_события"][0]["источник"]


@pytest.mark.asyncio
async def test_generate_full_dossier_includes_media_activity():
    """Интеграционный тест: generate_full_dossier возвращает блок медиа-активности с заявлениями руководства и презентациями."""
    from unittest.mock import AsyncMock
    from osint_mcp.server import generate_full_dossier
    from osint_mcp.models import CompanyContext, ContextResult, RiskCollection

    ctx = CompanyContext(
        inn="7724744134",
        name_legal='ООО "БПМСОФТ"',
        name_short='ООО "БПМСОФТ"',
        brand="BPMSoft",
        director_fio="Баранов Денис Валентинович",
    )
    ctx_res = ContextResult(status="ok", context=ctx)
    risk_col = RiskCollection(inn="7724744134", results=[], facts=[])

    fake_hits = [
        {
            "url": "https://www.cnews.ru/news/2026-04-10_baranov_intervyu",
            "title": "Денис Баранов: «BPMSoft ускоряет разработку бизнес-приложений»",
            "snippet": "В интервью CNews генеральный директор Денис Баранов заявил: «Мы развиваем гибкие инструменты для клиентов».",
        },
        {
            "url": "https://tadviser.ru/index.php/Статья:BPMSoft_CIPR_2026",
            "title": "BPMSoft презентовала AI-модуль на форуме ЦИПР",
            "snippet": "На выставке ЦИПР-2026 компания представила новую версию платформы.",
        },
    ]

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)), \
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[])), \
         patch("osint_mcp.context.news_media.search_web", return_value=fake_hits):

        # 1. Запрос standard
        res_std = await generate_full_dossier(inn="7724744134", detail="standard")
        assert "медиа_и_публичная_активность" in res_std
        media_std = res_std["медиа_и_публичная_активность"]
        assert "заявления_руководства" in media_std
        assert len(media_std["заявления_руководства"]) >= 1
        assert "Баранов" in media_std["заявления_руководства"][0]["спикер"]
        assert "презентации_и_события" in media_std
        assert len(media_std["презентации_и_события"]) >= 1
        assert "ЦИПР" in media_std["презентации_и_события"][0]["событие_или_продукт"]

        # 2. Запрос brief
        res_brief = await generate_full_dossier(inn="7724744134", detail="brief")
        assert "медиа_и_публичная_активность" in res_brief
        media_brief = res_brief["медиа_и_публичная_активность"]
        assert "главные_события" in media_brief
        assert len(media_brief["главные_события"]) <= 2

        # 3. Запрос full
        res_full = await generate_full_dossier(inn="7724744134", detail="full")
        assert "медиа_и_публичная_активность" in res_full
        media_full = res_full["медиа_и_публичная_активность"]
        assert "хроника_публичной_активности" in media_full
