"""Тесты для таможенного анализа (ВЭД) и картографического OSINT."""

from datetime import datetime, timezone
from unittest.mock import patch
import pytest

from osint_mcp.context.customs import (
    evaluate_customs_findings,
    build_customs_facts,
)
from osint_mcp.context.geo_reviews import (
    evaluate_geo_findings,
    build_geo_reviews_facts,
)
from osint_mcp.scoring import score_company
from osint_mcp.models import ExtFact


@pytest.mark.parametrize("module,builder,kwargs", [
    ("customs", build_customs_facts, {"inn": "7724744134"}),
    ("geo_reviews", build_geo_reviews_facts,
     {"inn": "7724744134", "company_name": "БПМСОФТ", "address": "Москва"}),
])
def test_search_failure_is_not_an_empty_finding(module, builder, kwargs):
    from osint_mcp.tools.web_search_source import SearchUnavailable
    with patch(f"osint_mcp.context.{module}.search_web", side_effect=SearchUnavailable("HTTP 403")):
        with pytest.raises(SearchUnavailable):
            builder(**kwargs)


async def test_customs_tool_reports_unknown_activity_when_search_failed(monkeypatch):
    from unittest.mock import Mock
    from osint_mcp import server
    from osint_mcp.tools.web_search_source import SearchUnavailable

    monkeypatch.setattr(server, "_build_customs_facts", Mock(side_effect=SearchUnavailable("HTTP 403")))
    result = await server.check_customs_ved("7724744134", company_name="БПМСОФТ")
    assert result["status"] == "unavailable"
    assert result["has_ved_activity"] is None and result["facts_found"] is None


def test_evaluate_customs_findings_sanction_risk():
    """Тест выявления импортной зависимости от ЕС/США и санкционных рисков."""
    raw_declarations = [
        {
            "direction": "import",
            "country": "Германия",
            "goods": "электронные модули и контроллеры Siemens",
            "partner": "Siemens AG",
        },
        {
            "direction": "import",
            "country": "Италия",
            "goods": "клапаны гидравлические",
            "partner": "OMFB S.p.A.",
        },
    ]

    profile = evaluate_customs_findings("7701122334", raw_declarations)
    assert profile.has_ved_activity is True
    assert profile.is_importer is True
    assert "Германия" in profile.high_risk_jurisdictions
    assert "Италия" in profile.high_risk_jurisdictions
    assert "зависимость от импорта" in profile.interpretation
    assert "риск логистических сбоев" in profile.interpretation


def test_evaluate_customs_findings_clean_export():
    """Тест позитивного подтверждения реального производственного экспорта."""
    raw_declarations = [
        {
            "direction": "export",
            "country": "Казахстан",
            "goods": "готовая продукция станки токарные",
            "partner": "ТОО ПромСнаб",
        }
    ]

    profile = evaluate_customs_findings("7701122334", raw_declarations)
    assert profile.has_ved_activity is True
    assert profile.is_exporter is True
    assert len(profile.high_risk_jurisdictions) == 0
    assert "реальный физический товарооборот" in profile.interpretation


def test_build_customs_facts_quarantine_generation():
    """Тест создания PendingFact для таможенных операций."""
    raw_declarations = [
        {
            "direction": "import",
            "country": "Китай",
            "goods": "алюминиевый профиль",
            "partner": "Shenzhen Trade",
            "source_url": "https://customs.gov.ru/decl/123",
        }
    ]

    facts = build_customs_facts(
        inn="7701122334",
        company_name="ООО СнабКомплект",
        declarations=raw_declarations,
    )
    assert len(facts) == 1
    f = facts[0]
    assert f.kind == "customs_trade_signal"
    assert "реальный товарооборот" in f.statement
    assert f.source_url == "https://customs.gov.ru/decl/123"


def test_evaluate_geo_findings_suspicious_garage_address():
    """Тест детекции фиктивного/гаражного адреса (бумажная фирма)."""
    profile = evaluate_geo_findings(
        address="г. Москва, ул. Промышленная, ГСК №5, бокс 12",
        company_name="ООО НефтьПромХолдинг",
        rating=None,
        reviews=[],
        location_features=["гаражный кооператив", "автосервисы"],
    )

    assert profile.has_physical_presence is False
    assert len(profile.suspicious_location_flags) > 0
    assert "риск фиктивного адреса" in profile.interpretation.lower()


def test_evaluate_geo_findings_operational_customer_issues():
    """Тест детекции операционных сбоев по свежим отзывам."""
    reviews = [
        "Ужасный сервис! Не берут трубку уже 3 дня, заказ задержали на неделю!",
        "Сорвали срок поставки, курьер нахамил, менеджеры обманывают.",
        "Раньше было лучше, сейчас просто кошмар, не привезли товар.",
    ]

    profile = evaluate_geo_findings(
        address="г. Санкт-Петербург, Невский пр., д. 10",
        company_name="ООО Экспресс-Доставка",
        rating=2.1,
        reviews=reviews,
    )

    assert len(profile.recent_issues) == 3
    assert "операционные проблемы" in profile.interpretation
    assert "сбои сервиса" in profile.interpretation


def test_scoring_customs_and_geo_integration():
    """Тест влияния таможенных и гео-сигналов на скоринг."""
    now = datetime.now(timezone.utc)

    # 1. Позитивный таможенный факт
    ved_fact = ExtFact(
        fact_id="CUSTOMS-1",
        kind="customs_trade_signal",
        statement="Таможенная активность ВЭД: подтвержден товарооборот станков",
        source_url="https://customs.gov.ru",
        source_type="customs",
        trust="reference",
        retrieved_at=now,
        payload={"flow": "export"},
    )
    res_ved = score_company(facts=[ved_fact])
    assert any(m.criterion == "customs_trade_activity" for m in res_ved.matched)

    # 2. Негативный гео-факт (гараж)
    garage_fact = ExtFact(
        fact_id="GEO-1",
        kind="suspicious_address_signal",
        statement="Картографический OSINT: адрес в гаражном кооперативе",
        source_url="https://yandex.ru/maps",
        source_type="geo_maps",
        trust="reference",
        retrieved_at=now,
        payload={"location": "гараж"},
    )
    res_garage = score_company(facts=[garage_fact])
    assert any(m.criterion == "suspicious_physical_address" for m in res_garage.matched)
    assert res_garage.verdict.floored is True
    assert res_garage.verdict.label == "рискованно"
