"""Тесты для модуля анализа конкурентов и мониторинга их рыночных новостей."""

from unittest.mock import AsyncMock, patch
import pytest

from osint_mcp.context.competitors import (
    CompetitorNewsItem,
    CompetitorProfile,
    _extract_competitor_names_from_text,
    _match_cluster_peers,
    fetch_company_competitors,
    format_competitors_profile,
)
from osint_mcp.models import CompanyContext, ContextResult, RiskCollection
from osint_mcp.server import generate_full_dossier


def test_match_cluster_peers_it_bpm():
    """Тест автоматического сопоставления с отраслевыми конкурентами в сфере корпоративного ПО/CRM."""
    cat, peers = _match_cluster_peers(
        brand="BPMSoft",
        company_name='ООО "БПМСОФТ"',
        okved_text="Разработка компьютерного программного обеспечения",
        products=["BPMSoft CRM", "BPMSoft Low-Code"],
    )
    assert cat is not None
    assert "BPM" in cat or "CRM" in cat
    assert len(peers) >= 3
    peer_brands = [p["brand"] for p in peers]
    assert "ELMA" in peer_brands
    assert "SimpleOne" in peer_brands
    # Сам субъект не должен входить в список своих же конкурентов
    assert "BPMSoft" not in peer_brands


def test_match_cluster_peers_cloud_providers():
    """Тест выявления конкурентов облачного провайдера (Selectel)."""
    cat, peers = _match_cluster_peers(
        brand="Selectel",
        company_name='ООО "Селектел"',
        okved_text="Деятельность по обработке данных, предоставление услуг по размещению информации",
    )
    assert cat is not None
    peer_brands = [p["brand"] for p in peers]
    assert "Yandex Cloud" in peer_brands
    assert "Selectel" not in peer_brands


def test_extract_competitor_names_from_text():
    """Тест извлечения названий конкурентов из сниппетов обзоров рынка."""
    text = (
        "Среди ключевых аналогов и конкурентов компании на рынке: ELMA, SimpleOne, 1C:CRM и Directum. "
        "Они предлагают сопоставимый функционал."
    )
    names = _extract_competitor_names_from_text(text, subject_brand="BPMSoft")
    assert "ELMA" in names
    assert "SimpleOne" in names
    assert "BPMSoft" not in names


def test_format_competitors_profile_detail_levels():
    """Проверка адаптации структуры конкурентного среза под 3 уровня подробности (brief / standard / full)."""
    news1 = CompetitorNewsItem(
        title="ELMA представила новую версию ELMA365 On-Premises",
        date="15.04.2026",
        source="CNews",
        url="https://cnews.ru/elma-release",
        highlight="Анонсированы новые инструменты для корпоративных клиентов.",
    )
    comp1 = CompetitorProfile(
        brand="ELMA",
        profile="Разработчик Low-code платформы ELMA365 и CRM",
        site="elma365.com",
        news=[news1],
    )
    comp2 = CompetitorProfile(
        brand="SimpleOne",
        profile="Российская ESM/ITSM платформа",
        site="simpleone.ru",
        news=[],
    )
    competitors = [comp1, comp2]

    # 1. Brief («кратко») — 1-2 конкурента с компактной строкой последней новости
    brief = format_competitors_profile(competitors, "Enterprise Low-code", detail="brief")
    assert "конкуренты" in brief
    assert len(brief["конкуренты"]) == 2
    assert brief["конкуренты"][0]["конкурент"] == "ELMA"
    assert "ELMA365" in brief["конкуренты"][0]["последняя_новость"]
    assert "кратко" in brief

    # 2. Standard («средне») — структурированные профили со свежими событиями
    standard = format_competitors_profile(competitors, "Enterprise Low-code", detail="standard")
    assert "конкуренты" in standard
    assert len(standard["конкуренты"]) == 2
    assert standard["конкуренты"][0]["бренд"] == "ELMA"
    assert len(standard["конкуренты"][0]["свежие_события"]) == 1
    assert "обзор_конкурентной_среды" in standard

    # 3. Full («полно») — глубокий профиль со всеми новостями и продуктовыми релизами
    full = format_competitors_profile(competitors, "Enterprise Low-code", detail="full")
    assert "конкуренты" in full
    assert full["конкуренты"][0]["масштаб_рынка"] is not None
    assert "новости_и_продуктовые_релизы" in full["конкуренты"][0]
    assert len(full["конкуренты"][0]["новости_и_продуктовые_релизы"]) == 1


@pytest.mark.asyncio
async def test_fetch_company_competitors_mocked():
    """Тест асинхронного сбора конкурентов с мокированным поиском новостей."""
    fake_news = [
        {
            "url": "https://cnews.ru/news/2026-04-05_elma_update",
            "title": "ELMA анонсировала релиз обновленной платформы",
            "snippet": "Компания представила новые модули интеграции для импортозамещения.",
        }
    ]

    with patch("osint_mcp.context.competitors.search_web", return_value=fake_news):
        res = await fetch_company_competitors(
            company_name='ООО "БПМСОФТ"',
            brand="BPMSoft",
            okved_text="Разработка компьютерного программного обеспечения",
            detail="standard",
        )

        assert res["всего_выявлено"] >= 2
        assert "конкуренты" in res
        first = res["конкуренты"][0]
        assert "бренд" in first
        assert "свежие_события" in first
        assert len(first["свежие_события"]) >= 1
        assert all(not item["свежие_события"] for item in res["конкуренты"][1:])


@pytest.mark.asyncio
async def test_generate_full_dossier_includes_competitors():
    """Интеграционный тест: generate_full_dossier возвращает блок 'конкуренты_и_рынок' во всех режимах."""
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
            "url": "https://tadviser.ru/article/elma",
            "title": "ELMA представила модуль интеграции",
            "snippet": "12 апреля 2026 года разработчик запустил новый сервис.",
        }
    ]

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)), \
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[])), \
         patch("osint_mcp.context.competitors.search_web", return_value=fake_hits), \
         patch("osint_mcp.context.news_media.search_news", return_value=[]):

        # 1. Standard
        res_std = await generate_full_dossier(inn="7724744134", detail="standard")
        assert "конкуренты_и_рынок" in res_std
        comp_std = res_std["конкуренты_и_рынок"]
        assert "конкуренты" in comp_std
        assert len(comp_std["конкуренты"]) >= 2
        # Проверяем, что в резюме для человека появился срез конкурентов
        q1 = res_std.get("резюме_для_человека", {}).get("ответы_на_главные_вопросы", {}).get("1_кто_это_и_чем_занимаются", "")
        assert "Конкурентное окружение" in q1

        # 2. Brief
        res_brief = await generate_full_dossier(inn="7724744134", detail="brief")
        assert "конкуренты_и_рынок" in res_brief
        assert "кратко" in res_brief["конкуренты_и_рынок"]

        # 3. Full
        res_full = await generate_full_dossier(inn="7724744134", detail="full")
        assert "конкуренты_и_рынок" in res_full
        assert "новости_и_продуктовые_релизы" in res_full["конкуренты_и_рынок"]["конкуренты"][0]
