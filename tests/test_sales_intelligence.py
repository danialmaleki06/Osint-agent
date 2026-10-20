import pytest
from datetime import datetime, timezone

from osint_mcp.models import (
    CompanyContext,
    HiringInfo,
    SiteTechInfo,
    SoftwareProduct,
    RiskCollection,
    Fact,
)
from osint_mcp.tools.sales_intelligence import build_sales_intelligence


def test_build_sales_intelligence_none_context():
    res = build_sales_intelligence(None)
    assert res == {}


def test_build_sales_intelligence_it_company():
    ctx = CompanyContext(
        inn="7724744134",
        name_legal='ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "БПМСОФТ"',
        name_short='ООО "БПМСОФТ"',
        brand="BPMSOFT",
        okved_code="62.01",
        okved_text="Разработка компьютерного программного обеспечения",
        site_self_description="Внедрение CRM BPMSoft под ключ — для банков, FMCG, производства",
        revenue_latest=2_769_645_000.0,
        size_category="large",
        software_products=[
            SoftwareProduct(
                name="BPMSoft",
                reg_number="17372",
                software_class="09.01 — Средства управления бизнес-процессами (BPM)",
                url="https://reestr.digital.gov.ru/reestr/1435439/",
            )
        ],
        hiring=HiringInfo(
            open_vacancies=45,
            roles=["Python-разработчик", "Системный аналитик"],
            leadership_roles=["Руководитель проектного офиса"],
            tech_stack=["Битрикс24", "PostgreSQL"],
            it_investing=True,
        ),
        site_tech=SiteTechInfo(
            cms=["Tilda"],
            crm_widgets=["Jivo", "amoCRM"],
            analytics=["Яндекс.Метрика"],
        ),
    )

    risk = RiskCollection(
        inn="7724744134",
        results=[],
        facts=[
            Fact(
                fact_id="arb-1",
                kind="arbitration",
                statement="Ответчик по 1 арбитражным делам на 8.7 млн ₽",
                source_url="https://kad.arbitr.ru",
                source_type="checko",
                retrieved_at=datetime.now(timezone.utc),
                payload={"cases_count": 1, "sum_rub": 8_700_000.0, "defendant": True},
            )
        ],
    )

    res = build_sales_intelligence(ctx, risk=risk)

    assert "формула_бизнеса" in res
    assert "IT-вендор" in res["формула_бизнеса"] or "системный интегратор" in res["формула_бизнеса"]
    assert res["целевой_сегмент"] == "Крупный бизнес (Enterprise B2B)"

    # Продукты
    products = res["продуктовая_линейка"]
    assert len(products) >= 1
    assert any(p["название"] == "BPMSoft" for p in products)

    # Боли и триггеры
    pains = res["боли_и_триггеры"]
    categories = [p["категория"] for p in pains]
    assert "масштабирование и дефицит рук" in categories
    assert "смена ЛПР (окно возможностей)" in categories
    assert "инфраструктурный контраст" in categories
    assert "договорные споры и качество сдачи" in categories

    # Офферы
    offers = res["что_предложить"]
    assert len(offers) >= 2
    offer_names = [o["направление"] for o in offers]
    assert any("аутстаффинг" in o.lower() for o in offer_names)
    assert any("облачные" in o.lower() or "инфраструктурные" in o.lower() for o in offer_names)

    # Крючок для контакта
    hook = res["крючок_для_контакта"]
    assert "Руководитель проектного офиса" in hook
    assert "BPMSOFT" in hook


def test_build_sales_intelligence_construction_company():
    ctx = CompanyContext(
        inn="1653022274",
        name_legal='ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "ПСО "КАЗАНЬ"',
        name_short='ООО "ПСО "КАЗАНЬ"',
        okved_code="41.20",
        okved_text="Строительство жилых и нежилых зданий",
        revenue_latest=4_500_000_000.0,
        size_category="large",
    )

    risk = RiskCollection(
        inn="1653022274",
        results=[],
        facts=[
            Fact(
                fact_id="arb-2",
                kind="arbitration",
                statement="Ответчик по 15 делам на 500 млн ₽",
                source_url="https://kad.arbitr.ru",
                source_type="checko",
                retrieved_at=datetime.now(timezone.utc),
                payload={"cases_count": 15, "sum_rub": 500_000_000.0, "defendant": True},
            )
        ],
    )

    res = build_sales_intelligence(ctx, risk=risk)
    assert "Генеральный подрядчик" in res["формула_бизнеса"]
    assert res["целевой_сегмент"] == "Крупный бизнес (Enterprise B2B)"
    assert any(p["категория"] == "договорные споры и качество сдачи" for p in res["боли_и_триггеры"])
