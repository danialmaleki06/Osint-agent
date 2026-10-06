"""Тесты скоринга коммерческих сигналов Федресурса и Росаккредитации.

Веса заданы в scoring.yaml — здесь проверяется механика: знак, ступень,
затухание и то, что нейтральные виды (гарантии) вердикт не двигают.
"""

from datetime import date, datetime, timedelta, timezone

import pytest

from osint_mcp.models import Fact
from osint_mcp.scoring import load_config, score_company

NOW = datetime.now(timezone.utc)


def fact(fid, kind, payload=None, event=None, url="https://fedresurs.ru/x"):
    return Fact(
        fact_id=fid, kind=kind, statement=f"тест {fid}",
        source_url=url, source_type="registry_api",
        retrieved_at=NOW, event_date=event, payload=payload or {},
    )


@pytest.fixture(autouse=True)
def _fresh_config_cache():
    from osint_mcp.scoring.engine import reload_config
    reload_config()
    yield
    reload_config()


# ── Федресурс: положительные сигналы ────────────────────────────────


def test_leasing_adds_small_positive():
    """Один договор лизинга — небольшой плюс: активы есть, бизнес живой."""
    r = score_company([fact("FR-1", "leasing", {"kind": "leasing"}, event=date.today())])
    crit = next(m for m in r.matched if m.criterion == "leasing_activity")
    assert crit.score > 0
    assert r.verdict.total_score == pytest.approx(60 + crit.score, abs=0.1)


def test_leasing_scale_by_count():
    """Пять публикаций лизинга — верхняя ступень заметно выше первой."""
    one = score_company([fact("FR-1", "leasing", event=date.today())])
    five = score_company([fact(f"FR-{i}", "leasing", event=date.today())
                          for i in range(1, 6)])
    s1 = next(m for m in one.matched if m.criterion == "leasing_activity")
    s5 = next(m for m in five.matched if m.criterion == "leasing_activity")
    assert s5.score > s1.score


def test_pledge_positive():
    r = score_company([fact("FR-1", "pledge", event=date.today())])
    crit = next(m for m in r.matched if m.criterion == "pledge_activity")
    assert crit.score > 0


def test_sro_membership_positive():
    r = score_company([fact("FR-1", "sro_membership", event=date.today())])
    crit = next(m for m in r.matched if m.criterion == "sro_membership")
    assert crit.score > 0


def test_guarantee_is_neutral():
    """Независимая гарантия — тендерное обеспечение, а не качество
    компании: покупки гарантий не должны поднимать вердикт."""
    r = score_company([fact("FR-1", "guarantee", event=date.today())])
    assert r.matched == []
    assert r.verdict.total_score == 60


# ── Федресурс: факторинг — мягкий минус ────────────────────────────


def test_factoring_mild_negative():
    """Поток уступок дебиторки — признак кассовых разрывов: минус,
    но малый: для торговли факторинг — часть нормальной модели."""
    r = score_company([fact("FR-1", "factoring", event=date.today())])
    crit = next(m for m in r.matched if m.criterion == "factoring_usage")
    assert -5 < crit.score < 0


def test_factoring_regular_worse_than_single():
    one = score_company([fact("FR-1", "factoring", event=date.today())])
    many = score_company([fact(f"FR-{i}", "factoring", event=date.today())
                          for i in range(1, 4)])
    s1 = next(m for m in one.matched if m.criterion == "factoring_usage")
    s3 = next(m for m in many.matched if m.criterion == "factoring_usage")
    assert s3.score < s1.score  # регулярный факторинг тянет сильнее вниз


# ── Затухание: трёхлетний договор почти ничего не значит ───────────


def test_leasing_decays_with_age():
    fresh = score_company([fact("FR-1", "leasing", event=date.today())])
    old = score_company([fact("FR-1", "leasing",
                              event=date.today() - timedelta(days=1000))])
    s_fresh = next(m for m in fresh.matched if m.criterion == "leasing_activity")
    s_old = next(m for m in old.matched if m.criterion == "leasing_activity")
    assert s_old.score < s_fresh.score


# ── Росаккредитация ─────────────────────────────────────────────────


def test_fsa_active_certificate_positive():
    """Действующая декларация — компания реально возит товар."""
    r = score_company([fact(
        "FSA-1", "fsa_certificate",
        {"end_date": "2028-01-19"},
        event=date(2028, 1, 19),
        url="https://pub.fsa.gov.ru/rds/declaration/view/18725645/common",
    )])
    crit = next(m for m in r.matched if m.criterion == "fsa_active_certificate")
    assert crit.score > 0


def test_fsa_certificate_without_end_date_not_scored():
    """Запись без даты окончания не поднимает вердикт: unverifiable
    данные не должны работать как положительный сигнал."""
    r = score_company([fact("FSA-1", "fsa_certificate", {})])
    assert not any(m.criterion == "fsa_active_certificate" for m in r.matched)


def test_fsa_no_kind_without_criterion_is_unmatched():
    """Гарантия без критерия попадает в unmatched — сигнал расширять пул,
    но оценку не двигает (двойная проверка нейтральности)."""
    r = score_company([fact("FR-1", "guarantee")])
    assert "guarantee" in r.unmatched_fact_kinds


# ── Совместная картина: коммерческие плюсы не спасают риски ─────────


def test_commercial_positives_do_not_mask_risks():
    """Лизинг и залог дают плюс, но долги ФССП тяжелеют как раньше:
    коммерческие сигналы не должны гасить рисковую картину."""
    facts = [
        fact(f"FR-{i}", "leasing", event=date.today()) for i in range(1, 6)
    ] + [
        fact("ENF-1", "enforcement", {"amount": 16_000_000}, event=date.today()),
    ]
    r = score_company(facts)
    # 60 - 35 (ФССП) + ~4-5 (лизинг с весом группы finance 20%) < 60
    assert r.verdict.total_score < 60
    # Долг ФССП обязан всплыть в warnings независимо от плюсов
    assert any("ФССП" in w for w in r.warnings)


# ── Интеллектуальная собственность: Роспатент (ФИПС) ───────────────


def test_trademark_positive():
    """Товарный знак — подтверждение реального оборота и защиты бренда."""
    r = score_company([fact("TM-1", "trademark", {"name": "БПМСОФТ"})])
    crit = next(m for m in r.matched if m.criterion == "trademarks_registered")
    assert crit.score > 0
    assert "зарегистрирован товарный знак" in crit.reason


def test_trademark_portfolio_higher():
    """Портфель товарных знаков (>2) даёт больший балл, чем единичный знак."""
    one = score_company([fact("TM-1", "trademark", {"name": "ЗНАК 1"})])
    three = score_company([fact(f"TM-{i}", "trademark", {"name": f"ЗНАК {i}"})
                           for i in range(1, 4)])
    s1 = next(m for m in one.matched if m.criterion == "trademarks_registered")
    s3 = next(m for m in three.matched if m.criterion == "trademarks_registered")
    assert s3.score > s1.score
    assert "портфель товарных знаков" in s3.reason


def test_core_kinds_extended():
    """Ядро расширилось новыми видами — контракт с парсерами обновлён."""
    from osint_mcp.models import CORE_FACT_KINDS
    for kind in ("leasing", "pledge", "factoring", "guarantee",
                 "sro_membership", "fedresurs_publication", "fsa_certificate",
                 "trademark", "software_registry", "planned_inspection"):
        assert kind in CORE_FACT_KINDS


def test_software_registry_positive():
    """Продукт в реестре отечественного ПО Минцифры даёт плюс в группу finance."""
    r = score_company([fact("SW-1", "software_registry", {"name": "BPMSoft"})])
    crit = next(m for m in r.matched if m.criterion == "russian_software_registered")
    assert crit.score > 0
    assert "продукт в реестре" in crit.reason


def test_software_registry_multiple_higher():
    """Несколько продуктов в реестре ПО дают больший балл."""
    one = score_company([fact("SW-1", "software_registry")])
    two = score_company([fact("SW-1", "software_registry"), fact("SW-2", "software_registry")])
    s1 = next(m for m in one.matched if m.criterion == "russian_software_registered")
    s2 = next(m for m in two.matched if m.criterion == "russian_software_registered")
    assert s2.score > s1.score


def test_planned_inspections_neutral_trace():
    """Плановая проверка в ЕРКНМ не снижает балл (score=0), но фиксируется в matched."""
    r = score_company([fact("INSP-P-1", "planned_inspection", {"authority": "МЧС"})])
    crit = next(m for m in r.matched if m.criterion == "planned_inspections")
    assert crit.score == 0
    assert "плановая проверка" in crit.reason
    assert "planned_inspection" not in r.unmatched_fact_kinds


