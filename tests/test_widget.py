"""Тесты для 7-точечного экспресс-виджета контрагента."""

import pytest
from unittest.mock import AsyncMock, patch

from osint_mcp.context.widget import build_summary_widget
from osint_mcp.models import CompanyContext, ContextResult, RiskCollection
from osint_mcp.server import generate_full_dossier


def test_build_summary_widget_structure():
    """Проверка структуры виджета: 7 обязательных пунктов и Markdown-таблица."""
    mock_dossier = {
        "inn": "7724744134",
        "карточка": {
            "наименование": "ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ \"БПМСОФТ\"",
            "краткое_наименование": "ООО \"БПМСОФТ\"",
            "ИНН": "7724744134",
            "статус": "действующая",
            "дата_регистрации": "2010-04-15",
            "город": "Москва",
            "деятельность": "Разработка компьютерного программного обеспечения",
            "оквэд_код": "62.01",
        },
        "светофор": "🟡 Умеренный риск",
        "score": 45.0,
        "суть_оценки": "Базовые требования соблюдены, перед сделками достаточна стандартная проверка.",
        "финансовая_матрица": {
            "рентабельность_продаж_ros": {
                "выручка": "2.8 млрд ₽",
                "чистая_прибыль": "244.8 млн ₽",
            },
            "динамика_выручки_yoy": {
                "оценка": "🟢 Рост оборота (+14.1%)",
            },
            "чистые_активы": {
                "статус": "🟢 Капитал в норме",
            },
        },
        "резюме_для_человека": {
            "ответы_на_главные_вопросы": {
                "2_безопасно_ли_сотрудничать": "• Налоговая дисциплина: 🟢 долгов перед ФНС нет. • Взыскания приставов (ФССП): 🟢 исполнительных производств нет. • Черный список поставщиков (РНП): 🟢 в черном списке не числится.",
            },
        },
        "кадровый_потенциал_документы": {
            "открыто_вакансий_30дней": 11,
            "динамика_найма": "активный_найм",
            "руководящие_позиции": ["Руководитель направления системного анализа"],
        },
        "медиа_и_публичная_активность": {
            "заявления_руководства": [
                {
                    "спикер": "Юрий Востриков",
                    "тезис": "Цель — 40% рынка и AI-driven low-code",
                    "источник": "TAdviser",
                }
            ],
        },
        "коммерческий_срез": {
            "бренд": "BPMSoft",
            "целевой_сегмент": "Enterprise B2B",
        },
    }

    widget = build_summary_widget(mock_dossier)

    assert "таблица_markdown" in widget
    assert "пункты" in widget
    assert widget["число_пунктов"] == 7
    assert len(widget["пункты"]) == 7

    # Проверяем заголовки и строки Markdown таблицы
    md = widget["таблица_markdown"]
    assert "| № | Метрика | Значение | Статус |" in md
    assert "| :-: | :--- | :--- | :-: |" in md

    # Проверяем каждый из 7 пунктов
    metrics = [it["метрика"] for it in widget["пункты"]]
    assert metrics == [
        "Компания и статус",
        "ОКВЭД / Отрасль",
        "Оценка и вердикт",
        "Финансы",
        "Юр. чистота / Риски",
        "Кадры (HeadHunter)",
        "СМИ и руководство",
    ]

    # Проверяем наполнение пунктов данными
    items_by_metric = {it["метрика"]: it for it in widget["пункты"]}
    assert "7724744134" in items_by_metric["Компания и статус"]["значение"]
    assert "62.01" in items_by_metric["ОКВЭД / Отрасль"]["значение"]
    assert "45/100" in items_by_metric["Оценка и вердикт"]["значение"]
    assert "2.8 млрд ₽" in items_by_metric["Финансы"]["значение"]
    assert "0 ₽ взысканий ФССП" in items_by_metric["Юр. чистота / Риски"]["значение"]
    assert "11 вакансий" in items_by_metric["Кадры (HeadHunter)"]["значение"]
    assert "Юрий Востриков" in items_by_metric["СМИ и руководство"]["значение"]


@pytest.mark.asyncio
async def test_generate_full_dossier_with_widget_option():
    """Тест вызова generate_full_dossier с опцией widget=True/False."""
    ctx = CompanyContext(
        inn="7724744134",
        name_legal='ООО "БПМСОФТ"',
        name_short='ООО "БПМСОФТ"',
        brand="BPMSoft",
        director_fio="Востриков Юрий Викторович",
        okved_code="62.01",
        okved_text="Разработка ПО",
    )
    ctx_res = ContextResult(status="ok", context=ctx)
    risk_col = RiskCollection(inn="7724744134", results=[], facts=[])

    with patch("osint_mcp.server._build_context", AsyncMock(return_value=ctx_res)), \
         patch("osint_mcp.server._collect_risk_facts", AsyncMock(return_value=risk_col)), \
         patch("osint_mcp.server._async_build_reputation_fiasco_facts", AsyncMock(return_value=[])):

        # 1. По умолчанию widget=False — ключа "виджет" нет
        res_default = await generate_full_dossier(inn="7724744134", widget=False)
        assert "виджет" not in res_default

        # 2. При widget=True — ключ "виджет" присутствует с 7 пунктами и таблицей
        res_widget = await generate_full_dossier(inn="7724744134", widget=True)
        assert "виджет" in res_widget
        w = res_widget["виджет"]
        assert "таблица_markdown" in w
        assert len(w["пункты"]) == 7
        assert "62.01" in w["таблица_markdown"]
