"""Тесты движка скоринга — на fixtures, офлайн, квоту не расходуют."""

from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from osint_mcp.models import CompanyContext, Fact
from osint_mcp.scoring import load_config, score_company
from osint_mcp.scoring.engine import _pick_threshold_score, _render_reason

NOW = datetime.now(timezone.utc)


def fact(fid, kind, payload=None, event=None, url="https://example.org/x"):
    return Fact(
        fact_id=fid, kind=kind, statement=f"тест {fid}",
        source_url=url, source_type="registry_api",
        retrieved_at=NOW, event_date=event, payload=payload or {},
    )


@pytest.fixture
def cfg():
    return load_config()


@pytest.fixture(autouse=True)
def _fresh_config_cache():
    """Тесты правят YAML? Нет — но сбрасываем кэш, чтобы конфиг читался каждый раз."""
    from osint_mcp.scoring.engine import reload_config
    reload_config()
    yield
    reload_config()


# ── Конфиг ──────────────────────────────────────────────────────────

def test_config_loads_and_validates():
    cfg = load_config()
    assert cfg.criteria
    assert cfg.verdicts
    labels = {v.label for v in cfg.verdicts}
    assert labels == {"надёжный", "можно работать", "с осторожностью",
                      "не стоит", "нельзя"}


def test_config_rejects_bad_group(tmp_path):
    """Критерий с неизвестной группой — ошибка запуска, не молчаливый ноль."""
    import yaml
    bad = {
        "groups": {"a": {"weight": 100}},
        "criteria": {"c": {"group": "нет_такой", "match": {"kind": "x"}, "score": -1}},
        "verdicts": [{"min": 0, "label": "ок"}],
    }
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.dump(bad, allow_unicode=True), encoding="utf-8")
    with pytest.raises(ValueError, match="несуществующую группу"):
        load_config(p)


# ── Пороги и причины ────────────────────────────────────────────────

def test_threshold_picks_first_matching():
    ths = [{"above": 100, "score": -30}, {"above": 10, "score": -10},
           {"above": 0, "score": -3}]
    parsed = [_pick_threshold_score.__globals__]  # noqa: F841
    from osint_mcp.scoring.engine import Threshold
    ts = [Threshold(**t) for t in ths]
    assert _pick_threshold_score(ts, 500)[0] == -30
    assert _pick_threshold_score(ts, 50)[0] == -10
    assert _pick_threshold_score(ts, 5)[0] == -3
    assert _pick_threshold_score(ts, 0)[0] == 0.0


def test_reason_render():
    class F:  # заглушка факта
        statement = "Арбитражное дело А40-1"
    out = _render_reason("Ответчик в {count} делах на {sum} ₽: {statement}",
                         value=None, count=3, total=12345.0, fact=F())
    assert out == "Ответчик в 3 делах на 12 345 ₽: Арбитражное дело А40-1"


# ── Скоринг ─────────────────────────────────────────────────────────

def test_clean_company_gets_baseline():
    """Компания без фактов получает baseline и вердикт по порогам."""
    r = score_company([])
    assert r.verdict.total_score == 60
    # 60 >= 50 → «можно работать»
    assert r.verdict.label == "можно работать"
    assert not r.verdict.floored
    assert r.reasons == []  # пустой компании не в чем обвинить


def test_enforcement_sum_thresholds():
    f1 = fact("ENF-1", "enforcement", {"amount": 600000},
              event=date.today() - timedelta(days=1))
    r = score_company([f1])
    crit = next(m for m in r.matched if m.criterion == "enforcement_debt")
    assert crit.raw_value == 600000
    # 600 000 > 100 000, но < 1 000 000 → ступень -8
    assert crit.score == -8


def test_decay_weakens_old_debts():
    fresh = fact("ENF-1", "enforcement", {"amount": 1_000_000},
                 event=date.today())
    old = fact("ENF-2", "enforcement", {"amount": 1_000_000},
               event=date.today() - timedelta(days=365))
    r_fresh = score_company([fresh]).verdict.total_score
    r_old = score_company([old]).verdict.total_score
    assert r_fresh < r_old  # старый долг тянет слабее
    assert r_old > 60 - 20  # полураспад 365д: старый ≈ -10 вместо -20


def test_bankruptcy_floors_verdict():
    """Жёсткий пол: банкротство не даёт подняться выше «нельзя»."""
    good_age = CompanyContext(
        inn="7724744134", name_legal="X", country="RU",
        registered_at=date.today() - timedelta(days=5000),
    )
    bankrupt = fact("FLAG-1", "bankruptcy", {"Тип": "наблюдение"},
                    event=date.today())
    r = score_company([bankrupt], context=good_age)
    assert r.verdict.label == "нельзя"
    assert r.verdict.floored
    assert r.verdict.floor_criterion == "bankruptcy"
    # 15 лет рынка дают плюс, но пол режет вердикт независимо от балла
    assert r.reasons


def test_liquidated_is_fatal():
    f = fact("FLAG-1", "registry_flag", {"status": "Ликвидация"})
    r = score_company([f])
    assert r.verdict.label == "нельзя"
    assert any("не действует" in x for x in r.reasons)


def test_status_word_forms_match():
    """contains_any ловит словоформы: «Ликвидирована», «прекращение деятельности»."""
    for status in ("Ликвидирована", "Прекращение деятельности ЮЛ"):
        f = fact("FLAG-1", "registry_flag", {"status": status})
        r = score_company([f])
        assert r.verdict.label == "нельзя", status


def test_defendant_vs_plaintiff():
    d = fact("ARB-1", "arbitration", {"role": "ответчик", "amount": 1},
             event=date.today())
    r = score_company([d])
    assert any(m.criterion == "defendant_cases" for m in r.matched)
    p = fact("ARB-1", "arbitration", {"role": "истец", "amount": 1},
             event=date.today())
    r2 = score_company([p * 3 if False else p] * 0 or [p])  # один факт
    assert not any(m.criterion == "defendant_cases" for m in r2.matched)


def test_unmatched_kinds_reported():
    """Факт без критерия попадает в unmatched — сигнал расширять пул."""
    f = fact("NEWS-1", "news", {"title": "публикация"})
    r = score_company([f])
    assert "news" in r.unmatched_fact_kinds


def test_company_age_positive():
    """age_days считается от context.registered_at; 11 лет — плюс по верхней ступени."""
    ctx = CompanyContext(
        inn="7724744134", name_legal="X", country="RU",
        registered_at=date.today() - timedelta(days=4000),
    )
    r = score_company([], context=ctx)
    m = next((m for m in r.matched if m.criterion == "company_age"), None)
    assert m is not None
    assert m.raw_value >= 3650
    assert "10+ лет" in m.reason


# ── Реестр видов фактов: ядро + пополняемые источники ───────────────

def test_core_kinds_frozen():
    """Ядро — контракт с парсерами, состав фиксирован."""
    from osint_mcp.models import CORE_FACT_KINDS
    assert CORE_FACT_KINDS == frozenset({
        "registry", "arbitration", "bankruptcy", "enforcement",
        "procurement", "registry_flag", "news",
    })


def test_ext_fact_new_kind_accepted():
    """Новый источник приносит свой kind без правки core-моделей."""
    from osint_mcp.models import ExtFact
    f = ExtFact(
        fact_id="BAN-1", kind="banned_list",
        statement="Организация в реестре запрещённых",
        source_url="https://reestr.example/x", source_type="registry_api",
        retrieved_at=NOW,
    )
    assert f.kind == "banned_list"


def test_ext_fact_bad_kind_rejected():
    """Мусор в kind отклоняется валидатором, а не тишина."""
    from osint_mcp.models import ExtFact
    from pydantic import ValidationError
    for bad in ("Registry", "a-b", "ab", "", "1abc", "кириллица"):
        with pytest.raises(ValidationError):
            ExtFact(
                fact_id="X-1", kind=bad, statement="s",
                source_url="u", source_type="custom", retrieved_at=NOW,
            )


def test_ext_fact_core_kind_accepted():
    """Ядро проходит валидацию всегда — расширения не ломают совместимость."""
    from osint_mcp.models import ExtFact
    f = ExtFact(
        fact_id="X-1", kind="arbitration", statement="s",
        source_url="u", source_type="custom", retrieved_at=NOW,
    )
    assert f.kind == "arbitration"


def test_ext_fact_scores_like_fact():
    """ExtFact попадает в скоринг на общих основаниях.

    Пока критерия на kind нет — факт в unmatched и оценку не меняет.
    Это принципиально: данные с непроверенного источника молча
    вердикт не двигают.
    """
    from osint_mcp.models import ExtFact
    f = ExtFact(
        fact_id="BAN-1", kind="banned_list",
        statement="в реестре запрещённых", source_url="u",
        source_type="registry_api", retrieved_at=NOW,
    )
    r = score_company([f])
    assert r.verdict.total_score == 60   # baseline не тронут
    assert "banned_list" in r.unmatched_fact_kinds
    assert r.matched == []


def test_ext_fact_scores_when_criterion_added(tmp_path):
    """Критерий на новый kind добавляется только YAML'ом — код не трогается."""
    import yaml
    base = yaml.safe_load(
        Path("src/osint_mcp/config_data/scoring.yaml").read_text(encoding="utf-8")
    )
    base["criteria"]["foreign_banned"] = {
        "group": "registry_risk",
        "match": {"kind": "banned_list"},
        "score": -100,
        "verdict_floor": "нельзя",
        "warn_always": True,
        "reason": "Организация в списке запрещённых",
    }
    p = tmp_path / "scoring_ext.yaml"
    p.write_text(yaml.dump(base, allow_unicode=True), encoding="utf-8")

    from osint_mcp.models import ExtFact
    f = ExtFact(
        fact_id="BAN-1", kind="banned_list",
        statement="в списке", source_url="u",
        source_type="registry_api", retrieved_at=NOW,
    )
    r = score_company([f], config_path=p)
    assert r.verdict.label == "нельзя"
    assert r.verdict.floored
    assert r.warnings


# ── Карантин: нереестровые данные не влияют на вердикт ──────────────

def test_pending_does_not_affect_verdict():
    """Находка поиска видна в досье, но оценку не двигает. Ни минусом,
    ни плюсом: мусор из веба не должен ломать вердикт."""
    from osint_mcp.scoring.models import PendingFact
    p = PendingFact(
        fact_id="SRCH-1", kind="dog_connection",
        statement="питомник Верный пёс", source_url="https://example.org/x",
        found_by="web_search", trust="mention", found_at=NOW,
    )
    r = score_company([], pending=[p])
    assert r.verdict.total_score == 60
    assert r.verdict.label == "можно работать"
    assert len(r.pending) == 1
    assert r.pending[0].source_url == "https://example.org/x"


def test_pending_requires_source_url():
    """Данные не из реестра без ссылки не существуют — модель их отвергает."""
    from osint_mcp.scoring.models import PendingFact
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        PendingFact(
            fact_id="SRCH-1", kind="dog_connection", statement="s",
            source_url="",  # ← пустая ссылка = нет факта
            found_by="web_search", found_at=NOW,
        )


# ── Воспроизводимость ───────────────────────────────────────────────

def test_deterministic():
    facts = [
        fact("ENF-1", "enforcement", {"amount": 2_000_000}, event=date.today()),
        fact("ARB-1", "arbitration", {"role": "ответчик"}, event=date.today()),
    ]
    a = score_company(list(facts))
    b = score_company(list(facts))
    assert a.verdict == b.verdict
    assert [m.score for m in a.matched] == [m.score for m in b.matched]


# ── Warnings: тяжёлый минус не прячется хорошей оценкой ─────────────

def test_warning_fires_despite_good_verdict():
    """16 млн долгов ФССП (-35 ступень), но 20 лет рынка (+15) и 25 лет.

    Итог: 60 - 35 + 15 = 40 → «с осторожностью» — а без age-критерия
    и вовсе «можно работать». Но долг ФССП обязан попасть в warnings,
    чтобы пользователь узнал о нём независимо от оценки.
    """
    debt = fact("ENF-1", "enforcement", {"amount": 16_000_000},
                event=date.today())
    r = score_company([debt])
    assert r.verdict.label in ("можно работать", "с осторожностью")
    assert r.warnings, "долг 16 млн обязан быть в warnings"
    assert any("ФССП" in w for w in r.warnings)


def test_warnings_empty_for_clean_company():
    r = score_company([])
    assert r.warnings == []


def test_warnings_sorted_worst_first():
    bank = fact("FLAG-1", "bankruptcy", {}, event=date.today())
    debt = fact("ENF-1", "enforcement", {"amount": 16_000_000},
                event=date.today())
    r = score_company([bank, debt])
    assert r.warnings[0].startswith("Процедура банкротства")  # -90 раньше -35
