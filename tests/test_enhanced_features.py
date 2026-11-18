"""Тесты расширенных возможностей:
- Устранение 451 в Федресурсе (лимит 15)
- Сводная матрица финансового здоровья (ROS, YoY, чистые активы)
- Расшифровка категорий лицензий (ФСТЭК, ФСБ, связь, МЧС)
- Блок цифрового контура без HTML-мусора
- Поддержка ИП и самозанятых (12-значный ИНН)
- Риск-факторы и скоринг отрицательных чистых активов и налоговой недоимки
"""

from datetime import date, datetime, timezone
import httpx
import pytest

from osint_mcp.config import settings
from osint_mcp.context.fedresurs import FedresursSource, MAX_PUBLICATIONS
from osint_mcp.models import (
    CardExtras,
    CompanyContext,
    ContactInfo,
    FinancialYear,
    LicenseInfo,
    SiteTechInfo,
    SslInfo,
)
from osint_mcp.scoring.engine import score_company
from osint_mcp.tools.report import (
    _build_digital_footprint,
    _build_financial_health_matrix,
    _build_license_breakdown,
    build_report,
)
from osint_mcp.tools.risk import extract_context_financial_risk_facts


def test_fedresurs_page_size_is_15():
    """Федресурс принимает только стандартный размер страницы 15 (размеры 10 и 30 вызывают HTTP 451)."""
    assert MAX_PUBLICATIONS == 15
    src = FedresursSource()
    headers = src._headers("https://fedresurs.ru")
    assert "Sec-Ch-Ua" in headers
    assert headers["Referer"] == "https://fedresurs.ru"


@pytest.mark.parametrize("second_status", [200, 503])
async def test_fedresurs_paginates_and_preserves_first_page(second_status, monkeypatch):
    inn = "7724744134"
    offsets = []
    monkeypatch.setattr(settings, "max_pages", 3)

    def handle(request):
        if request.url.path.endswith("/companies"):
            return httpx.Response(200, json={"pageData": [{"inn": inn, "guid": "company-id"}]})
        offset = int(request.url.params["offset"])
        offsets.append(offset)
        if offset and second_status != 200:
            return httpx.Response(second_status)
        rows = [{"guid": f"item-{i}", "title": "Договор лизинга", "type": "SfactMessage"}
                for i in range(offset, min(offset + MAX_PUBLICATIONS, 16))]
        return httpx.Response(200, json={"found": 16, "pageData": rows})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        result = await FedresursSource(client).check_commercial_facts(inn)

    assert offsets == [0, 15]
    assert len(result.facts) == (16 if second_status == 200 else 15)
    assert result.status == ("ok" if second_status == 200 else "partial")


def test_financial_health_matrix_calculation():
    """Проверка расчета матрицы финансового здоровья: ROS, YoY, чистые активы."""
    ctx = CompanyContext(
        inn="7724744134",
        name_legal='ООО "ТЕСТ"',
        fin_history=[
            FinancialYear(year=2024, revenue=100_000_000.0, profit=25_000_000.0, equity=40_000_000.0),
            FinancialYear(year=2023, revenue=80_000_000.0, profit=15_000_000.0, equity=20_000_000.0),
        ],
        extras=CardExtras(tax_debt=1_200_000.0),
    )
    matrix = _build_financial_health_matrix(ctx)
    assert matrix is not None

    # Рентабельность ROS = 25% -> Высокая
    assert matrix["рентабельность_продаж_ros"]["значение_процент"] == 25.0
    assert "Высокая рентабельность" in matrix["рентабельность_продаж_ros"]["оценка"]

    # Динамика YoY = (100 - 80) / 80 = +25.0%
    assert matrix["динамика_выручки_yoy"]["темп_прироста_процент"] == 25.0
    assert "Рост оборота" in matrix["динамика_выручки_yoy"]["оценка"]

    # Капитал
    assert matrix["чистые_активы"]["критично"] is False

    # Налоговая недоимка
    assert matrix["налоговая_задолженность"]["доля_к_годовой_прибыли_процент"] == 4.8


def test_financial_health_matrix_negative_equity_and_loss():
    """Проверка выявления убытков и отрицательного капитала."""
    ctx = CompanyContext(
        inn="7724744134",
        name_legal='ООО "ПРОБЛЕМНОЕ"',
        fin_history=[
            FinancialYear(year=2024, revenue=50_000_000.0, profit=-10_000_000.0, equity=-15_000_000.0),
            FinancialYear(year=2023, revenue=70_000_000.0, profit=2_000_000.0, equity=5_000_000.0),
        ],
    )
    matrix = _build_financial_health_matrix(ctx)
    assert matrix is not None
    assert matrix["рентабельность_продаж_ros"]["значение_процент"] == -20.0
    assert "Отрицательная рентабельность" in matrix["рентабельность_продаж_ros"]["оценка"]
    assert matrix["чистые_активы"]["критично"] is True
    assert "Отрицательные чистые активы" in matrix["чистые_активы"]["статус"]


def test_license_categorization_and_breakdown():
    """Проверка группировки лицензий по ключевым регуляторам (ФСТЭК, ФСБ, Роскомнадзор)."""
    licenses = [
        LicenseInfo(
            number="Л051-00105-00/00564828",
            issuer="Федеральная служба по техническому и экспортному контролю",
            activity="Разработка и производство средств защиты конфиденциальной информации",
            issued_at=date(2021, 5, 20),
        ),
        LicenseInfo(
            number="185429",
            issuer="Федеральная служба по надзору в сфере связи (Роскомнадзор)",
            activity="Телематические услуги связи",
            issued_at=date(2020, 11, 10),
        ),
        LicenseInfo(
            number="00342",
            issuer="ФСБ России",
            activity="Разработка криптографических средств защиты информации",
            issued_at=date(2019, 3, 1),
        ),
    ]
    breakdown = _build_license_breakdown(licenses)
    assert breakdown is not None
    assert breakdown["всего"] == 3
    cats = breakdown["по_категориям"]
    assert any("ФСТЭК" in c for c in cats)
    assert any("Роскомнадзор" in c for c in cats)
    assert any("ФСБ" in c for c in cats)


def test_digital_footprint_filters_html_noise():
    """Проверка цифрового контура: полезные CMS, CRM, аналитика с номерами счётчиков без HTML-мусора."""
    ctx = CompanyContext(
        inn="7724744134",
        name_legal='ООО "ИТ-КОМПАНИЯ"',
        brand_domain="https://example.com",
        domain_created_at=date(2012, 4, 15),
        ssl_info=SslInfo(valid=True, issuer="Let's Encrypt Authority X3", days_left=80),
        site_tech=SiteTechInfo(
            cms=["HTML5", "CSS", "1C-Битрикс"],
            crm_widgets=["amoCRM (виджет)", "Jivo (онлайн-консультант)"],
            tracker_ids={
                "yandex_metrika": ["54910283", "92837102"],
                "google_analytics": ["G-ABC12345"],
            },
        ),
        extras=CardExtras(contacts=ContactInfo(emails=["info@example.com", "ceo@example.com"])),
    )
    fp = _build_digital_footprint(ctx)
    assert fp is not None
    assert fp["сайт"] == "https://example.com"
    assert "лет" in fp["возраст_домена"]
    assert "🟢 Действителен" in fp["ssl_сертификат"]

    # Проверяем, что тривиальный шум отфильтрован
    assert fp["платформа_cms"] == ["1C-Битрикс"]
    assert "HTML5" not in fp["платформа_cms"]
    assert "CSS" not in fp["платформа_cms"]

    # CRM и аналитика
    assert "amoCRM (виджет)" in fp["crm_и_виджеты"]
    assert any("54910283" in a for a in fp["аналитика_и_трекеры"])
    assert fp["доменная_почта"] == ["example.com"]


def test_individual_entrepreneur_reporting():
    """Проверка отображения ИП с 12-значным ИНН: ОГРНИП, ФИО и статус ЕГРИП."""
    from osint_mcp.models import ContextResult
    from osint_mcp.scoring.models import ScoreResult, Verdict

    ctx = CompanyContext(
        inn="771559726942",
        ogrn="322774600333632",
        name_legal="ИП Иванов Иван Иванович",
        director_fio="Иванов Иван Иванович",
        status="Действует",
        entity_type="individual_entrepreneur",
    )
    score = ScoreResult(
        inn="771559726942",
        verdict=Verdict(label="хорошо", total_score=60.0),
        groups=[],
        matched=[],
        reasons=[],
        warnings=[],
        unmatched_fact_kinds=[],
        criteria_version="1.0",
        scored_at=datetime.now(timezone.utc),
    )
    rep = build_report("brief", ContextResult(status="ok", context=ctx), None, score)
    card = rep["карточка"]
    assert card["тип_субъекта"] == "Индивидуальный предприниматель (ИП)"
    assert card["ОГРНИП"] == "322774600333632"
    assert card["руководитель"] == "Иванов Иван Иванович"
    assert "зарегистрирован в ЕГРИП" in card["статус"]


def test_financial_risk_facts_and_scoring_criteria():
    """Проверка генерации риск-фактов и срабатывания правил scoring.yaml на отрицательные чистые активы и налоговый долг."""
    ctx = CompanyContext(
        inn="7724744134",
        name_legal='ООО "ПРОБЛЕМНЫЙ БАЛАНС"',
        fin_history=[
            FinancialYear(year=2024, revenue=50_000_000.0, profit=1_000_000.0, equity=-8_000_000.0),
        ],
        extras=CardExtras(tax_debt=4_000_000.0),  # Долг 4 млн при прибыли 1 млн (400% прибыли!)
    )
    facts = extract_context_financial_risk_facts(ctx)
    kinds = [f.kind for f in facts]
    assert "negative_net_assets" in kinds
    assert "tax_debt_scale_risk" in kinds

    # Прогоняем через движок скоринга
    score = score_company(facts=facts, context=ctx)
    assert score.verdict.label in ("рискованно", "не рекомендуется")
    assert score.verdict.total_score < 0
    assert any("Отрицательный собственный капитал" in w for w in score.warnings)
    assert any("Налоговая задолженность" in w for w in score.warnings)
