from datetime import date, datetime, timezone
import pytest
from osint_mcp.models import (
    CompanyContext,
    HiringInfo,
    TimelineEvent,
)
from osint_mcp.scoring.models import ScoreResult, Verdict, PendingFact
from osint_mcp.context.reputation_fiascos import (
    build_fiasco_queries,
    FiascoPlatform,
)
from osint_mcp.tools.statutory_hr import build_statutory_hr_profile
from osint_mcp.tools.report import _event_lines
from osint_mcp.tools.human_summary import build_human_summary

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_build_fiasco_queries_brand_guard():
    """Проверяем, что короткие аббревиатуры вроде 'YA' не заменяют реальный бренд 'Яндекс'."""
    queries = build_fiasco_queries(
        company_name="ООО «ЯНДЕКС»",
        brand="YA",
        domain="ya.ru",
        inn="7736207543",
    )
    disasters_q = " ".join(queries[FiascoPlatform.DISASTERS])
    assert "ЯНДЕКС" in disasters_q or "Яндекс" in disasters_q
    assert "YA датацентр" not in disasters_q


def test_event_lines_noise_filtering_and_limit():
    """Проверяем отсечение рутинного шума ЕГРЮЛ и ограничение количества событий."""
    events = [
        TimelineEvent(event_date=date(2026, 9, 21), event="Начало процедуры реорганизации в форме выделения"),
        TimelineEvent(event_date=date(2025, 4, 15), event="Внесение изменений в сведения, содержащиеся в ЕГРЮЛ, не связанных"),
        TimelineEvent(event_date=date(2024, 1, 18), event="Смена генерального директора"),
        TimelineEvent(event_date=date(2023, 5, 10), event="Представление сведений о регистрации юридического лица в качестве страхователя"),
        TimelineEvent(event_date=date(2020, 6, 1), event="Увеличение уставного капитала"),
    ]
    ctx = CompanyContext(inn="7700000000", name_legal="ООО Тест", events=events)
    lines = _event_lines(ctx, max_events=3)
    # Рутинный шум отфильтрован
    assert len(lines) == 3
    assert not any("не связанных" in l for l in lines)
    assert not any("страхователя" in l for l in lines)
    assert "реорганизации" in lines[0]


def test_deep_statutory_hr_profile():
    """Проверяем обогащение кадрового профиля стеком технологий и аналитикой HeadHunter."""
    hiring = HiringInfo(
        open_vacancies=240,
        roles=["Senior C++ Developer", "ML Tech Lead", "DevOps Engineer", "B2B Sales Manager"],
        leadership_roles=["ML Tech Lead"],
        tech_stack=["C / C++", "Python", "AI / Machine Learning (ML/LLM)", "DevOps / SRE (Docker/K8s/CI)"],
        functional_breakdown={"IT и разработка ПО": 180, "Продажи и развитие бизнеса": 40, "Управление и тимлиды": 20},
        hiring_focus="Фокус на IT и разработка ПО (180), продажи и развитие бизнеса (40); стек: C / C++, Python; усиление менеджмента: ML Tech Lead",
        employer_id="1740",
    )
    ctx = CompanyContext(
        inn="7736207543",
        name_legal="ООО «Яндекс»",
        employees=15000,
        revenue_latest=500_000_000_000.0,
        hiring=hiring,
    )
    res = build_statutory_hr_profile(ctx)
    assert res is not None
    assert res["открыто_вакансий_30дней"] == 240
    assert "C / C++" in res["технологический_стек_вакансий"]
    assert "ML Tech Lead" in res["руководящие_позиции"]
    assert "IT и разработка ПО" in res["структура_найма_направления"]
    assert "Фокус на IT" in res["анализ_hh_фокус"]
    assert "https://hh.ru/employer/1740" == res["ссылка_hh_работодатель"]


def test_human_summary_includes_hh_and_fiascos():
    """Проверяем, что резюме для человека включает кадровый срез HH и новости об инцидентах."""
    hiring = HiringInfo(
        open_vacancies=50,
        roles=["Python разработчик", "Тимлид"],
        leadership_roles=["Тимлид"],
        tech_stack=["Python", "SQL / PostgreSQL"],
        hiring_focus="Фокус на IT и разработку ПО, стек: Python, SQL",
    )
    ctx = CompanyContext(
        inn="7724744134",
        name_legal='ООО "БПМСОФТ"',
        employees=386,
        revenue_latest=2_800_000_000.0,
        hiring=hiring,
    )
    pending_fiascos = [
        PendingFact(
            fact_id="F-1",
            kind="fiasco_disaster_incident",
            statement="[РБК] [08.10.2026] Власти подтвердили атаку дронов на дата-центр компании в Сасово: пожар локализован | Вывод: операционный риск",
            source_url="https://rbc.ru",
            found_by="reputation_fiascos_engine",
            found_at=NOW,
        )
    ]
    score = ScoreResult(
        inn="7724744134",
        verdict=Verdict(code="GOOD", label="хорошо", total_score=85),
        groups=[],
        matched=[],
        reasons=[],
        warnings=[],
        pending=pending_fiascos,
        unmatched_fact_kinds=[],
        criteria_version="test-1",
        scored_at=NOW,
    )
    summary = build_human_summary(ctx, None, score)
    q3_text = summary["ответы_на_главные_вопросы"]["3_что_происходит_сейчас"]

    assert "HeadHunter" in q3_text
    assert "50 вакансий" in q3_text
    assert "Происшествия и инциденты в СМИ" in q3_text
    assert "08.10.2026" in q3_text
    assert "атаку дронов" in q3_text
