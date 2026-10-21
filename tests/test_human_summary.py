"""Тесты для модуля human_summary и человекочитаемого режима отчётов."""

import pytest
from datetime import date, datetime, timezone
from osint_mcp.models import (
    ArbitrationSummary,
    RoleCounts,
    CardExtras,
    CompanyContext,
    ContextResult,
    EnforcementSummary,
    FinancialYear,
    RiskCollection,
    SourceResult,
)
from osint_mcp.scoring.models import ScoreResult, Verdict
from osint_mcp.tools.human_summary import (
    build_human_summary,
    build_human_court_cases,
)
from osint_mcp.tools.report import build_report

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _make_dummy_score(label="хорошо", score=50.0):
    return ScoreResult(
        inn="7701234567",
        verdict=Verdict(total_score=score, label=label),
        groups=[],
        matched=[],
        reasons=["Финансовая устойчивость подтверждена"],
        warnings=[],
        pending=[],
        unmatched_fact_kinds=[],
        criteria_version="abc123",
        scored_at=NOW,
    )


def test_human_summary_llc_healthy():
    ctx = CompanyContext(
        inn="7701234567",
        ogrn="1027700132195",
        name_legal='ООО "ТЕХНОЛОГИИ"',
        brand="TechCorp",
        brand_resolved=True,
        status="Действует",
        city="г. Москва",
        registered_at=date(2015, 6, 1),
        okved_code="62.01",
        okved_text="Разработка компьютерного программного обеспечения",
        employees=120,
        revenue_latest=500_000_000.0,
        fin_history=[
            FinancialYear(year=2024, revenue=500_000_000.0, profit=80_000_000.0, equity=150_000_000.0),
            FinancialYear(year=2023, revenue=400_000_000.0, profit=60_000_000.0, equity=100_000_000.0),
        ],
        size_category="medium",
    )
    score = _make_dummy_score(label="хорошо")
    res = build_human_summary(ctx, None, score)

    tldr = res["суть_в_трех_предложениях"]
    assert "TechCorp" in tldr or "ТЕХНОЛОГИИ" in tldr
    assert "прибыльный" in tldr
    assert "безопасное" in tldr or "надёжное" in tldr

    q = res["ответы_на_главные_вопросы"]
    assert "1_кто_это_и_чем_занимаются" in q
    assert "2_безопасно_ли_сотрудничать" in q
    assert "3_что_происходит_сейчас" in q
    assert "120" in q["1_кто_это_и_чем_занимаются"]

    terms = res["переводчик_терминов"]
    assert "основной_профиль" in terms
    assert "масштаб_бизнеса" in terms


def test_human_summary_ip_entrepreneur():
    ctx = CompanyContext(
        inn="770123456789",
        ogrn="319774600123456",
        name_legal="ИП Смирнов Алексей Петрович",
        status="Действует",
        city="г. Санкт-Петербург",
        registered_at=date(2020, 3, 15),
        okved_text="Деятельность автомобильного грузового транспорта",
        entity_type="individual_entrepreneur",
    )
    score = _make_dummy_score(label="удовлетворительно", score=30.0)
    res = build_human_summary(ctx, None, score)

    tldr = res["суть_в_трех_предложениях"]
    assert "индивидуальный предприниматель" in tldr.lower()
    assert "Смирнов" in tldr


def test_human_court_cases():
    risk = RiskCollection(
        inn="7701234567",
        results=[
            SourceResult(
                source="checko",
                status="ok",
                arbitration=ArbitrationSummary(
                    as_defendant=RoleCounts(count=3, total_amount=15_000_000.0),
                    as_plaintiff_active=RoleCounts(count=2, total_amount=25_000_000.0),
                ),
                enforcement=EnforcementSummary(total=1, outstanding=500_000.0),
            )
        ],
    )
    cases = build_human_court_cases(risk)
    assert len(cases) == 2
    defendant_case = next(c for c in cases if "Ответчик" in c["роль"])
    assert defendant_case["дел"] == 3
    assert "15.0 млн ₽" in defendant_case["сумма"]
    assert "суть_простыми_словами" in defendant_case

    plaintiff_case = next(c for c in cases if "Истец" in c["роль"])
    assert plaintiff_case["дел"] == 2
    assert "25.0 млн ₽" in plaintiff_case["сумма"]


def test_build_report_human_switch():
    ctx = CompanyContext(
        inn="7701234567",
        name_legal='ООО "ТЕХНОЛОГИИ"',
        status="Действует",
    )
    score = _make_dummy_score()

    # human_mode=True -> блок резюме присутствует
    rep_human = build_report("brief", ContextResult(status="ok", context=ctx), None, score, human_mode=True)
    assert "резюме_для_человека" in rep_human
    assert "суть_в_трех_предложениях" in rep_human["резюме_для_человека"]

    # human_mode=False -> чистый официальный реестровый формат
    rep_official = build_report("brief", ContextResult(status="ok", context=ctx), None, score, human_mode=False)
    assert "резюме_для_человека" not in rep_official
