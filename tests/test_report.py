"""Тесты отчётов: brief / full / пакетный режим.

Офлайн, на фикстурах и заглушках источников. Проверяют не сбор данных,
а компоновку: что в каком режиме доходит до пользователя и что честные
оговорки не теряются при сокращении объёма.
"""

from datetime import date, datetime, timezone

import pytest

from osint_mcp.models import (
    ArbitrationSummary,
    CardExtras,
    CompanyContext,
    ContextResult,
    FinancialYear,
    RiskCollection,
    RoleCounts,
    SourceLink,
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


def make_score(inn="7724744134", label="хорошо", total=55.0, **overrides) -> ScoreResult:
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


def make_risk(**overrides) -> RiskCollection:
    base = dict(
        inn="7724744134",
        results=[SourceResult(source="checko.arbitration", status="ok")],
        facts=[],
        sources_ok=1,
        sources_failed=0,
    )
    base.update(overrides)
    return RiskCollection(**base)


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
    assert report["вердикт"] == "хорошо"
    assert report["светофор"] == "🟢 Низкий риск"
    assert "🟢" in report["уровень_риска"] or "Низкий риск" in report["уровень_риска"]
    assert "суть_оценки" in report
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


def test_brief_keeps_reason_in_debug_mode():
    """В режиме отладки (debug=True) причина несбора передается в отчёт."""
    report = build_report(
        "brief",
        make_context_result(make_context(), reason="Масштаб НЕ УСТАНОВЛЕН: источник молчал."),
        None,
        make_score(),
        debug=True,
    )
    assert "что_не_собралось" in report
    assert "НЕ УСТАНОВЛЕН" in report["что_не_собралось"]
    assert "_диагностика_разработчика" in report


def test_brief_omits_reason_in_user_mode():
    """В пользовательском режиме (debug=False) технические ошибки несбора не выводятся."""
    report = build_report(
        "brief",
        make_context_result(make_context(), reason="Масштаб НЕ УСТАНОВЛЕН: источник молчал."),
        None,
        make_score(),
        debug=False,
    )
    assert "что_не_собралось" not in report
    assert "_диагностика_разработчика" not in report


def test_brief_without_context():
    """Карточка не собралась — отчёт жив, но честно пуст в карточке."""
    report = build_report(
        "brief",
        make_context_result(None, reason="DaData недоступна"),
        None,
        make_score(label="не рекомендуется", total=0.0),
    )
    assert report["вердикт"] == "не рекомендуется"
    assert report["карточка"] == {}


# ───────────────────────────  full  ───────────────────────────

def test_full_includes_fin_history_without_urls():
    """Финансы по годам в отчёте есть, ссылки на PDF в отчёте не выводятся:
    они отдаются дозапросом get_company_links."""
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
    assert "bo.nalog.gov.ru" not in text, "ссылки в отчёте — им место в get_company_links"


def test_source_links_live_in_context_not_report():
    """Ссылки собираются в контекст всегда, но в отчёты не попадают."""
    ctx = make_context(
        fin_history=[FinancialYear(year=2024, revenue=1.0,
                                   report_url="https://bo.nalog.gov.ru/download/bfo/pdf/1")],
        source_links=[SourceLink(what="карточка ЕГРЮЛ", url="https://checko.ru/company/1",
                                 source="checko")],
    )
    for detail in ("brief", "full"):
        report = build_report(detail, make_context_result(ctx), make_risk(), make_score())
        flat = str(report)
        assert "checko.ru" not in flat, f"ссылка утекла в {detail}"
    # А в контексте они живы
    assert ctx.source_links[0].url == "https://checko.ru/company/1"


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


def test_margin_trend_falls_two_years():
    """Маржа тает два года подряд суммарно от 5 п.п. — строка появляется."""
    ctx = make_context(fin_history=[
        FinancialYear(year=2024, revenue=1_000.0, profit=100.0),   # 10%
        FinancialYear(year=2023, revenue=1_000.0, profit=150.0),   # 15%
        FinancialYear(year=2022, revenue=1_000.0, profit=250.0),   # 25% → -15 п.п. за 2 падения
    ])
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    fin = next(s for s in report["разбор"] if s["название"] == "финансы и налоги")
    assert any("маржа тает" in line for line in fin["пункты"])


def test_margin_noise_is_silent():
    """Болтанка в пределах полпункта и разовое падение — не тревога."""
    ctx = make_context(fin_history=[
        FinancialYear(year=2024, revenue=1_000.0, profit=120.0),   # 12%
        FinancialYear(year=2023, revenue=1_000.0, profit=125.0),   # 12.5% (дроп 0.5 — шум)
        FinancialYear(year=2022, revenue=1_000.0, profit=124.0),   # 12.4%
    ])
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    fin = next(s for s in report["разбор"] if s["название"] == "финансы и налоги")
    assert not any("маржа" in line for line in fin["пункты"])


def test_productivity_line_shown():
    """Выручка на сотрудника: нейтральная мера, без утверждений."""
    ctx = make_context(fin_history=[FinancialYear(year=2024, revenue=2_776_964_500.0)],
                       employees=386)
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    prof = next(s for s in report["разбор"] if s["название"] == "профиль деятельности")
    assert any("выручка на сотрудника" in line for line in prof["пункты"])
    assert not any("зарплат" in line.lower() for line in prof["пункты"]), \
        "зарплатоёмкость из налогов врёт — её не должно быть"


def test_gov_share_warns_on_high_dependence():
    """Госконтракты ≥30% выручки — предупреждение о зависимости от бюджета."""
    from osint_mcp.models import ProcurementSummary
    risk = RiskCollection(
        inn="7724744134",
        results=[SourceResult(
            source="checko.procurement", status="ok",
            procurement=ProcurementSummary(
                contracts_44=10,
                as_supplier=RoleCounts(count=10, total_amount=500_000_000.0),
            ))],
    )
    ctx = make_context(fin_history=[FinancialYear(year=2024, revenue=1_000_000_000.0)])
    report = build_report("full", make_context_result(ctx), risk, make_score())
    sales = next(s for s in report["разбор"] if s["название"] == "коммерческие сигналы")
    assert any("зависимость от бюджета" in line for line in sales["пункты"])


def test_gov_share_silent_on_small_sample():
    """Меньше трёх контрактов — не система: строка не создаётся."""
    from osint_mcp.models import ProcurementSummary
    risk = RiskCollection(
        inn="7724744134",
        results=[SourceResult(
            source="checko.procurement", status="ok",
            procurement=ProcurementSummary(
                contracts_44=1,
                as_supplier=RoleCounts(count=1, total_amount=900_000.0),
            ))],
    )
    ctx = make_context(fin_history=[FinancialYear(year=2024, revenue=1_000_000.0)])
    report = build_report("full", make_context_result(ctx), risk, make_score())
    sales = [s for s in report["разбор"] if s["название"] == "коммерческие сигналы"]
    if sales:
        assert not any("госконтракты" in line for line in sales[0]["пункты"])


def test_rename_hint_in_profile():
    """Переименования в профиле: подсказка искать по прежним именам."""
    ctx = make_context(business_model="product",
                       former_names=['ООО "КАРДСМАЙЛ"', 'ООО "ЛАНИТ ОМНИ"'])
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    prof = next(s for s in report["разбор"] if s["название"] == "профиль деятельности")
    assert any("переименований" in line and "КАРДСМАЙЛ" in line for line in prof["пункты"])


def test_full_debt_load_with_revenue_share():
    """Долг мерится прибылью: 150 млн при 100 млн прибыли = 2 года, тревоги нет."""
    ctx = make_context(fin_history=[FinancialYear(
        year=2024, revenue=100_000_000.0, profit=100_000_000.0,
        loans=60_000_000.0, short_debt=90_000_000.0,
    )])
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    fin = next(s for s in report["разбор"] if s["название"] == "финансы и налоги")
    text = "\n".join(fin["пункты"])
    assert "обязательства всего: 150.0 млн ₽" in text
    assert "годам прибыли" not in text


def test_full_debt_three_years_of_profit_is_high():
    """Долг >= 3 лет прибыли — высокая долговая нагрузка."""
    ctx = make_context(fin_history=[FinancialYear(
        year=2024, revenue=100_000_000.0, profit=10_000_000.0,
        loans=60_000_000.0, short_debt=90_000_000.0,
    )])
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    fin = next(s for s in report["разбор"] if s["название"] == "финансы и налоги")
    assert any("15 годам прибыли" in line for line in fin["пункты"])


def test_full_profile_lines_shown_when_heuristics_resolved():
    """Эвристики модели и стадии попадают в отчёт с осторожными формулировками."""
    ctx = make_context(business_model="outsourced", business_stage="growth")
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    section = next(s for s in report["разбор"] if s["название"] == "профиль деятельности")
    text = "\n".join(section["пункты"])
    assert "подряд/аутсорс" in text
    assert "окно входа" in text
    assert "зависит от потока заказов" in text


def test_full_profile_absent_when_unknown():
    """Не хватило данных на эвристику — секции нет: догадку не пишем."""
    ctx = make_context()  # business_model/stage не заданы
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    assert not any(s["название"] == "профиль деятельности" for s in report["разбор"])


def test_full_plaintiff_active_climate_signal():
    """Поток активных исков о взыскании — компания сама ждёт оплаты:
    косвенный сигнал кассового климата, для отсрочек осторожно."""
    risk = RiskCollection(
        inn="7724744134",
        results=[SourceResult(
            source="checko.arbitration", status="ok",
            arbitration=ArbitrationSummary(
                total=10,
                as_plaintiff=RoleCounts(count=7, total_amount=12_000_000.0),
                as_plaintiff_active=RoleCounts(count=4, total_amount=8_000_000.0),
            ),
        )],
        facts=[], sources_ok=1,
    )
    report = build_report("full", make_context_result(make_context()), risk, make_score())
    section = next(
        (s for s in report["разбор"] if s["название"] == "платёжный климат"), None)
    assert section is not None, "сигнал платёжного климата потерялся"
    text = "\n".join(section["пункты"])
    assert "активных исков о взыскании: 4" in text
    assert "осторожно" in text


def test_full_plaintiff_idle_is_silent():
    """Истец без активных исков — сигнал не выводится: старые дела
    ничего не говорят о сегодняшнем платежном климате."""
    risk = RiskCollection(
        inn="7724744134",
        results=[SourceResult(
            source="checko.arbitration", status="ok",
            arbitration=ArbitrationSummary(
                total=5,
                as_plaintiff=RoleCounts(count=5, total_amount=2_000_000.0),
                as_plaintiff_active=RoleCounts(),
            ),
        )],
        facts=[], sources_ok=1,
    )
    report = build_report("full", make_context_result(make_context()), risk, make_score())
    assert not any(s["название"] == "платёжный климат" for s in report["разбор"])


def test_full_liquidity_below_one_is_warning():
    """Деньги + дебиторка не покрывают краткосрочные долги — зависимость
    от непрерывного потока выручки. Рост кредиторки сам по себе не тревога:
    торговый кредит финансирует растущий бизнес."""
    ctx = make_context(fin_history=[FinancialYear(
        year=2024, revenue=10_000_000.0,
        cash=48_700_000.0, receivables=797_765_000.0,
        short_debt=1_556_994_000.0,
    )])
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    fin = next(s for s in report["разбор"] if s["название"] == "финансы и налоги")
    text = "\n".join(fin["пункты"])
    assert "платёжеспособность зависит от непрерывного потока выручки" in text
    # Рост кредиторки над дебиторкой больше НЕ выводится как тревога
    assert "живёт на чужие деньги" not in text


def test_full_zero_debt_is_silent():
    """Займов нет (нули в отчётности) — строки платёжеспособности не выводятся:
    отсутствие долгов не новостное сообщение, а норма."""
    ctx = make_context(fin_history=[FinancialYear(
        year=2024, revenue=10_000_000.0, loans=0.0, short_debt=0.0,
        receivables=1_000_000.0, payables=500_000.0,
    )])
    report = build_report("full", make_context_result(ctx), make_risk(), make_score())
    fin = next(s for s in report["разбор"] if s["название"] == "финансы и налоги")
    assert not any("обязательства всего" in line for line in fin["пункты"])
    assert not any("непрерывного потока" in line for line in fin["пункты"])


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
    report = build_report("full", make_context_result(make_context()), make_risk(), score, debug=True)
    assert report["pending"][0]["fact_id"] == "SRCH-1"
    assert report["источники"][0]["status"] == "ok"
    assert "_диагностика_разработчика" in report


def test_full_omits_sources_in_user_mode():
    score = make_score()
    report = build_report("full", make_context_result(make_context()), make_risk(), score, debug=False)
    assert "источники" not in report
    assert "_диагностика_разработчика" not in report


def test_full_without_context_still_works():
    report = build_report("full", make_context_result(None), None, make_score())
    assert report["разбор"] == []


# ───────────────────────────  batch  ───────────────────────────

def test_batch_entry_is_compact():
    ctx = make_context()
    entry = build_batch_entry(make_context_result(ctx), make_risk(), make_score())
    assert entry["наименование"] == 'ООО "БПМСОФТ"'
    assert entry["вердикт"] == "хорошо"
    assert entry["светофор"] == "🟢 Низкий риск"
    assert "суть_оценки" in entry
    assert "разбор" not in entry
    assert "источники" not in entry


def test_batch_entry_keeps_warnings_and_reason_in_debug():
    score = make_score(warnings=["Долг ФССП: 12 млн ₽"])
    entry = build_batch_entry(
        make_context_result(make_context(), reason="Рыночное имя не установлено."),
        make_risk(),
        score,
        debug=True,
    )
    assert entry["warnings"] == ["Долг ФССП: 12 млн ₽"]
    assert "что_не_собралось" in entry


def test_batch_entry_omits_reason_in_user_mode():
    score = make_score(warnings=["Долг ФССП: 12 млн ₽"])
    entry = build_batch_entry(
        make_context_result(make_context(), reason="Рыночное имя не установлено."),
        make_risk(),
        score,
        debug=False,
    )
    assert entry["warnings"] == ["Долг ФССП: 12 млн ₽"]
    assert "что_не_собралось" not in entry


def test_batch_entry_without_anything():
    entry = build_batch_entry(make_context_result(None), None,
                              make_score(label="не рекомендуется", total=0.0))
    assert entry["вердикт"] == "не рекомендуется"
    assert entry["светофор"] == "⛔ Критический риск"


def test_full_commercial_extended_signals():
    """Проверка вывода ПО Минцифры, зарубежных фабрик и плановых проверок в отчёт."""
    from osint_mcp.models import Fact, InspectionSummary, PlannedInspection, SoftwareProduct
    ctx = make_context(
        software_products=[
            SoftwareProduct(name="BPMSoft", reg_number="17372", status="В реестре"),
        ],
    )
    risk = make_risk(
        results=[
            SourceResult(
                source="checko.inspections",
                status="ok",
                inspections=InspectionSummary(
                    total=1,
                    planned_inspections=[
                        PlannedInspection(
                            authority="МЧС России",
                            date_start=date(2026, 11, 15),
                            inspection_type="Плановый надзор",
                        ),
                    ],
                ),
            ),
        ],
        facts=[
            Fact(
                fact_id="FSA-1",
                kind="fsa_certificate",
                statement="Декларация: светильники; изготовитель ZHEJIANG CO (импорт: Китай)",
                source_url="https://pub.fsa.gov.ru/x",
                source_type="registry_api",
                retrieved_at=NOW,
                payload={"manufacturer": "ZHEJIANG CO, LTD", "is_foreign": True, "origin_country": "Китай"},
            ),
            Fact(
                fact_id="SW-1",
                kind="software_registry",
                statement="BPMSoft в реестре ПО",
                source_url="https://reestr.digital.gov.ru/x",
                source_type="registry_api",
                retrieved_at=NOW,
            ),
        ],
    )
    report = build_report("full", make_context_result(ctx), risk, make_score())
    sales = next(s for s in report["разбор"] if s["название"] == "коммерческие сигналы")
    sales_text = "\n".join(sales["пункты"])
    assert "реестр отечественного ПО" in sales_text
    assert "BPMSoft" in sales_text
    assert "МЧС России" in sales_text
    assert "окно для предложения услуг аудита" in sales_text

    commercial = next(s for s in report["разбор"] if s["название"] == "коммерческая активность")
    comm_text = "\n".join(commercial["пункты"])
    assert "зарубежные заводы и цепочки поставок" in comm_text
    assert "ZHEJIANG CO, LTD (Китай)" in comm_text
    assert "реестр отечественного ПО: 1" in comm_text



def test_report_includes_statutory_hr_and_affiliations_lite():
    from osint_mcp.models import HiringInfo
    ctx = make_context(
        employees=386,
        revenue_latest=2_769_645_000.0,
        hiring=HiringInfo(open_vacancies=15),
        founders=["ООО «ЛАНИТ ВЕНЧУРС»"],
    )
    score = make_score()
    report = build_report("full", make_context_result(ctx), make_risk(), score)

    assert "кадровый_потенциал_документы" in report
    assert report["кадровый_потенциал_документы"]["официальный_штат_фнс"] == 386
    assert report["кадровый_потенциал_документы"]["открыто_вакансий_30дней"] == 15
    assert report["кадровый_потенциал_документы"]["динамика_найма"] == "плановая_ротация"

    assert "корпоративные_связи_lite" in report
    assert report["корпоративные_связи_lite"]["руководитель"]["фио"] == "Директоров Дмитрий Петрович"
    assert report["корпоративные_связи_lite"]["учредители"][0]["наименование"] == "ООО «ЛАНИТ ВЕНЧУРС»"


def test_main_version_data_parity():
    """Проверяет, что все структурированные поля и данные из версии main сохранены и возвращаются в отчёте."""
    from osint_mcp.models import (
        CardExtras,
        ContactInfo,
        EnforcementSummary,
        FinancialYear,
        InspectionSummary,
        LicenseInfo,
        MspInfo,
        ProcurementSummary,
        RoleCounts,
        SoftwareProduct,
        SourceResult,
        TimelineEvent,
    )

    ctx = make_context(
        kpp="772401001",
        address_full="115280, г. Москва, ул. Ленинская Слобода, д. 19",
        region="г. Москва",
        director_post="Генеральный директор",
        director_inn="771234567890",
        capital=50000.0,
        branches=2,
        representative_offices=1,
        former_names=['ООО "СТАРЫЙ БПМСОФТ"'],
        founders=['ООО "ЛАНИТ"'],
        fin_history=[
            FinancialYear(
                year=2024,
                revenue=2_700_000_000.0,
                profit=300_000_000.0,
                assets=1_500_000_000.0,
                balance=1_500_000_000.0,
                capital=50_000.0,
                cash=200_000_000.0,
                receivables=500_000_000.0,
                short_debt=400_000_000.0,
                loans=100_000_000.0,
                equity=800_000_000.0,
            ),
            FinancialYear(year=2023, revenue=2_000_000_000.0, profit=200_000_000.0),
        ],
        events=[
            TimelineEvent(event_date=date(2023, 5, 20), event="Внесение изменений в устав"),
            TimelineEvent(event_date=date(2021, 2, 10), event="Смена наименования"),
        ],
        msp=MspInfo(
            in_registry=True,
            category="medium",
            employees=240,
            included_at=date(2016, 8, 1),
            is_active=True,
        ),
        extras=CardExtras(
            tax_debt=125000.0,
            tax_paid_total=85000000.0,
            tax_year=2024,
            tax_mode=["Общий режим налогообложения (ОСНО)"],
            okved_extra=["62.02 — Консультации в области компьютерных технологий"],
            trademarks=["BPMSoft", "Ланит"],
            address_unreliable=False,
            mass_address_orgs=["1027700000001", "1027700000002"],
            contacts=ContactInfo(
                phones=["+7 (495) 123-45-67"],
                emails=["info@bpmsoft.ru"],
                website="https://bpmsoft.ru",
            ),
            licenses=[
                LicenseInfo(
                    number="Л050-00107-77/00642316",
                    issuer="ФСТЭК России",
                    issued_at=date(2023, 1, 1),
                    activity="Техническая защита конфиденциальной информации",
                )
            ],
        ),
        software_products=[
            SoftwareProduct(
                name="Платформа BPMSoft",
                reg_number="12345",
                reg_date="2022-04-12",
                status="В реестре",
            )
        ],
    )

    risk = RiskCollection(
        inn="7724744134",
        results=[
            SourceResult(
                source="checko.arbitration",
                status="ok",
                arbitration=ArbitrationSummary(
                    total=5,
                    total_claim_amount=15_000_000.0,
                    as_defendant=RoleCounts(count=2, total_amount=4_000_000.0),
                    as_plaintiff=RoleCounts(count=3, total_amount=11_000_000.0),
                ),
            ),
            SourceResult(
                source="checko.enforcement",
                status="ok",
                enforcement=EnforcementSummary(total=1, total_amount=50000.0, outstanding=0.0),
            ),
            SourceResult(
                source="checko.inspections",
                status="ok",
                inspections=InspectionSummary(total=3, with_violations=1),
            ),
            SourceResult(
                source="checko.procurement",
                status="ok",
                procurement=ProcurementSummary(
                    contracts_44=4,
                    as_supplier=RoleCounts(count=4, total_amount=25_000_000.0),
                    total_amount=25_000_000.0,
                ),
            ),
            SourceResult(
                source="checko.registry_flags",
                status="ok",
                flags={"disqualified_persons": False, "mass_founders": False},
            ),
        ],
        facts=[],
    )

    score = make_score()

    # 1. Проверяем карточку в brief
    report_brief = build_report("brief", make_context_result(ctx), risk, score)
    card_brief = report_brief["карточка"]
    assert card_brief["наименование"] == 'ООО "БПМСОФТ"'
    assert card_brief["краткое_наименование"] == 'ООО "БПМСОФТ"'
    assert card_brief["ИНН"] == "7724744134"
    assert card_brief["КПП"] == "772401001"
    assert card_brief["дата_регистрации"] == "2010-04-15"
    assert card_brief["уставный_капитал"] == 50000.0
    assert card_brief["город"] == "Москва"
    assert card_brief["регион"] == "г. Москва"
    assert card_brief["адрес"] == "115280, г. Москва, ул. Ленинская Слобода, д. 19"
    assert card_brief["руководитель"] == "Директоров Дмитрий Петрович"
    assert card_brief["должность_руководителя"] == "Генеральный директор"
    assert card_brief["инн_руководителя"] == "771234567890"
    assert card_brief["оквэд_код"] == "62.01"
    assert card_brief["оквэд_текст"] == "Разработка компьютерного программного обеспечения"
    assert card_brief["филиалы"] == 2
    assert card_brief["представительства"] == 1
    assert card_brief["прежние_наименования"] == ['ООО "СТАРЫЙ БПМСОФТ"']
    assert card_brief["учредители"] == ['ООО "ЛАНИТ"']

    # 2. Проверяем полное досье (full) со всеми структурированными данными
    report_full = build_report("full", make_context_result(ctx), risk, score)

    # Финансовая история
    assert "финансовая_история" in report_full
    assert len(report_full["финансовая_история"]) == 2
    f2024 = report_full["финансовая_история"][0]
    assert f2024["year"] == 2024
    assert f2024["revenue"] == 2_700_000_000.0
    assert f2024["profit"] == 300_000_000.0
    assert f2024["equity"] == 800_000_000.0
    assert f2024["short_debt"] == 400_000_000.0

    # Сводка рисков
    assert "реестры_рисков_сводка" in report_full
    risk_summary = report_full["реестры_рисков_сводка"]
    assert risk_summary["арбитраж"]["total"] == 5
    assert risk_summary["арбитраж"]["as_defendant"]["count"] == 2
    assert risk_summary["арбитраж"]["as_plaintiff"]["count"] == 3
    assert risk_summary["фссп"]["total"] == 1
    assert risk_summary["проверки"]["total"] == 3
    assert risk_summary["проверки"]["with_violations"] == 1
    assert risk_summary["госзакупки"]["contracts_44"] == 4
    assert risk_summary["госзакупки"]["as_supplier"]["total_amount"] == 25_000_000.0
    assert "реестровые_метки" in risk_summary

    # События ЕГРЮЛ
    assert "события_егрюл" in report_full
    assert len(report_full["события_егрюл"]) == 2
    assert report_full["события_егрюл"][0]["событие"] == "Внесение изменений в устав"

    # Реестр МСП
    assert "реестр_мсп" in report_full
    assert report_full["реестр_мсп"]["в_реестре"] is True
    assert report_full["реестр_мсп"]["категория"] == "medium"
    assert report_full["реестр_мсп"]["численность"] == 240

    # Реестровые дополнения
    assert "реестровые_дополнения" in report_full
    rd = report_full["реестровые_дополнения"]
    assert rd["задолженность_по_налогам"] == 125000.0
    assert rd["уплачено_налогов"] == 85000000.0
    assert rd["отчётный_год_налогов"] == 2024
    assert rd["налоговые_режимы"] == ["Общий режим налогообложения (ОСНО)"]
    assert "62.02" in rd["дополнительные_оквэд"][0]
    assert "BPMSoft" in rd["товарные_знаки"]
    assert rd["организаций_по_адресу"] == 2
    assert rd["контакты"]["сайт"] == "https://bpmsoft.ru"

    # Реестр отечественного ПО
    assert "реестр_отечественного_по" in report_full
    assert report_full["реестр_отечественного_по"][0]["name"] == "Платформа BPMSoft"
