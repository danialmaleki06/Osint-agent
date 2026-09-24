"""Тесты отчётов: brief / full / пакетный режим.

Офлайн, на фикстурах и заглушках источников. Проверяют не сбор данных,
а компоновку: что в каком режиме доходит до пользователя и что честные
оговорки не теряются при сокращении объёма.
"""

from datetime import date, datetime, timezone

import pytest

from osint_mcp.models import (
    CardExtras,
    CompanyContext,
    ContextResult,
    FinancialYear,
    RiskCollection,
    SourceResult,
    TimelineEvent,
)
from osint_mcp.scoring.models import ScoreResult, Verdict
from osint_mcp.tools.report import (
    build_batch_entry,
    build_report,
)

NOW = datetime.now(timezone.utc)


def make_context(inn="7724744134", **overrides) -> CompanyContext:
    base = dict(
        inn=inn,
        name_legal='ООО "БПМСОФТ"',
        name_short='ООО "БПМСОФТ"',
        status="Действует",
        registered_at=date(2010, 4, 15),
        city="Москва",
        director_fio="Директоров Дмитрий Петрович",
        okved_code="62.01",
        okved_text="Разработка компьютерного программного обеспечения",
        capital=20000.0,
        employees=386,
        source="dadata",
        retrieved_at=NOW,
    )
    base.update(overrides)
    return CompanyContext(**base)


def make_score(inn="7724744134", label="можно работать", total=55.0, **overrides) -> ScoreResult:
    base = dict(
        inn=inn,
        verdict=Verdict(label=label, total_score=total),
        groups=[],
        matched=[],
        reasons=["Итог сформирован базовыми сведениями реестра"],
        warnings=[],
        pending=[],
        unmatched_fact_kinds=[],
        criteria_version="abc123",
        scored_at=NOW,
    )
    base.update(overrides)
    return ScoreResult(**base)


def make_risk() -> RiskCollection:
    return RiskCollection(
        inn="7724744134",
        results=[SourceResult(source="checko.arbitration", status="ok")],
        facts=[],
        sources_ok=1,
        sources_failed=0,
    )


def make_context_result(ctx=None, reason=None) -> ContextResult:
    return ContextResult(status="ok", reason=reason, context=ctx)


# ───────────────────────────  brief  ───────────────────────────

def test_brief_has_verdict_and_card():
    report = build_report(
        "brief",
        make_context_result(make_context()),
        make_risk(),
        make_score(),
    )
    assert report["вердикт"] == "можно работать"
    assert report["score"] == 55.0
    assert report["карточка"]["наименование"] == 'ООО "БПМСОФТ"'
    assert report["карточка"]["численность"] == 386
    # Пустое поле не показывается вовсе: отсутствие ключа честнее нуля
    assert "выручка_последний_год" not in report["карточка"]


def test_brief_drops_full_sections():
    """Краткий отчёт не тащит финансы по годам, лицензии и события."""
    ctx = make_context(
        fin_history=[FinancialYear(year=2024, revenue=1.0, report_url="https://bo.nalog.gov.ru/x")],
        extras=CardExtras(
            tax_debt=500.0,
            licenses=[],
            contacts=None,
        ),
        events=[TimelineEvent(event_date=date(2024, 1, 1), event="тест")],
    )
    report = build_report("brief", make_context_result(ctx), make_risk(), make_score())
    assert "разбор" not in report
    assert "источники" not in report
    assert "pending" not in report


def test_brief_keeps_reason_not_verdict():
    """Причина несбора обязана дойти и в кратком отчёте."""
    report = build_report(
        "brief",
        make_context_result(make_context(), reason="Масштаб НЕ УСТАНОВЛЕН: источник молчал."),
        None,
        make_score(),
    )
    assert "что_не_собралось" in report
    assert "НЕ УСТАНОВЛЕН" in report["что_не_собралось"]


def test_brief_without_context():
    """Карточка не собралась — отчёт жив, но честно пуст в карточке."""
    report = build_report(
        "brief",
        make_context_result(None, reason="DaData недоступна"),
        None,
        make_score(label="нельзя", total=0.0),
    )
    assert report["вердикт"] == "нельзя"
    assert report["карточка"] == {}


# ───────────────────────────  full  ───────────────────────────

def test_full_includes_fin_history_and_report_urls():
    ctx = make_context(fin_history=[
        FinancialYear(year=2024, revenue=2_112_308_000.0, profit=244_840_000.0,
                      report_url="https://bo.nalog.gov.ru/download/bfo/pdf/57110232"),
        FinancialYear(year=2023, revenue=2_026_112_000.0, profit=105_268_000.0),
    ])
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    sections = {s["название"]: s for s in report["разбор"]}
    fin = sections["финансы и налоги"]
    text = "\n".join(fin["пункты"])
    assert "2.1 млрд" in text or "2,1 млрд" in text or "2112308" in text.replace(" ", "")
    assert "bo.nalog.gov.ru" in text, "ссылка на отчётность ФНС потерялась"


def test_full_flags_revenue_drop():
    """Падение выручки вдвое — то, что не видно из одного числа."""
    ctx = make_context(fin_history=[
        FinancialYear(year=2024, revenue=100.0),
        FinancialYear(year=2023, revenue=400.0),
    ])
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    fin = next(s for s in report["разбор"] if s["название"] == "финансы и налоги")
    assert any("упала" in line for line in fin["пункты"])


def test_full_tax_debt_visible():
    ctx = make_context(extras=CardExtras(tax_debt=7_109_047.47, tax_year=2025))
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    fin = next(s for s in report["разбор"] if s["название"] == "финансы и налоги")
    assert any("задолженность по налогам" in line for line in fin["пункты"])


def test_full_mass_address_filtered_by_size():
    """Массовый адрес применим к малому бизнесу и не применим к крупному."""
    mass = ["1025480001073", "1157746862085", "1247700338049"]
    small = make_context(size_category="small",
                         extras=CardExtras(mass_address_orgs=mass))
    large = make_context(size_category="large",
                         extras=CardExtras(mass_address_orgs=mass))
    rep_small = build_report("full", make_context_result(small), make_risk(), make_score())
    rep_large = build_report("full", make_context_result(large), make_risk(), make_score())

    def _has(report):
        extras = next(
            (s for s in report["разбор"] if s["название"] == "лицензии, контакты, адрес"),
            None,
        )
        return extras is not None and any("массового адреса" in l for l in extras["пункты"])

    assert _has(rep_small)
    assert not _has(rep_large)


def test_full_unreliable_address_always_shown():
    """Недостоверный адрес — стоп-сигнал независимо от масштаба."""
    ctx = make_context(size_category="large",
                       extras=CardExtras(address_unreliable=True))
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    extras = next(s for s in report["разбор"] if s["название"] == "лицензии, контакты, адрес")
    assert any("недостоверным" in line for line in extras["пункты"])


def test_full_licenses_and_contacts():
    from osint_mcp.models import ContactInfo, LicenseInfo
    ctx = make_context(extras=CardExtras(
        licenses=[LicenseInfo(number="Л050-00107-77/00642316",
                              issuer="ФСТЭК",
                              activity="Защита конфиденциальной информации")],
        contacts=ContactInfo(phones=["+74952873257"], emails=["info@omnichannel.ru"],
                             website="http://cardsmile.ru"),
    ))
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    extras = next(s for s in report["разбор"] if s["название"] == "лицензии, контакты, адрес")
    text = "\n".join(extras["пункты"])
    assert "Л050-00107" in text
    assert "cardsmile.ru" in text


def test_full_events_recent_first():
    ctx = make_context(events=[
        TimelineEvent(event_date=date(2020, 7, 23), event="Смена директора"),
        TimelineEvent(event_date=date(2024, 5, 30), event="Смена наименования"),
    ])
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    events = next(s for s in report["разбор"] if s["название"] == "существенные события истории")
    dates = [line.split(":")[0] for line in events["пункты"]]
    assert dates == sorted(dates, reverse=True)


def test_full_includes_pending_and_sources():
    from osint_mcp.scoring.models import PendingFact
    pending = PendingFact(
        fact_id="SRCH-1", kind="news_mention", statement="упоминание",
        source_url="https://example.org/news", found_by="web_search",
        found_at=NOW,
    )
    score = make_score(pending=[pending])
    report = build_report("full", make_context_result(make_context()), make_risk(), score)
    assert report["pending"][0]["fact_id"] == "SRCH-1"
    assert report["источники"][0]["status"] == "ok"


def test_full_without_context_still_works():
    report = build_report("full", make_context_result(None), None, make_score())
    assert report["разбор"] == []


# ───────────────────────────  batch  ───────────────────────────

def test_batch_entry_is_compact():
    ctx = make_context()
    entry = build_batch_entry(make_context_result(ctx), make_risk(), make_score())
    assert entry["наименование"] == 'ООО "БПМСОФТ"'
    assert entry["вердикт"] == "можно работать"
    assert "разбор" not in entry
    assert "источники" not in entry


def test_batch_entry_keeps_warnings_and_reason():
    score = make_score(warnings=["Долг ФССП: 12 млн ₽"])
    entry = build_batch_entry(
        make_context_result(make_context(), reason="Рыночное имя не установлено."),
        make_risk(),
        score,
    )
    assert entry["warnings"] == ["Долг ФССП: 12 млн ₽"]
    assert "что_не_собралось" in entry


def test_batch_entry_without_anything():
    entry = build_batch_entry(make_context_result(None), None,
                              make_score(label="нельзя", total=0.0))
    assert entry["вердикт"] == "нельзя"
