"""Тесты карантина: хранение, подтверждение, отклонение, статистика."""

from datetime import datetime, timezone

import pytest

from osint_mcp.scoring import score_company
from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.quarantine import AmbiguousFactId, QuarantineStore

NOW = datetime.now(timezone.utc)


@pytest.fixture
def store(tmp_path):
    s = QuarantineStore(tmp_path / "q.db")
    yield s
    s.close()


def pf(fid: str, url: str = "https://example.org/x") -> PendingFact:
    return PendingFact(
        fact_id=fid, kind="dog_connection", statement=f"находка {fid}",
        source_url=url, found_by="web_search", trust="mention", found_at=NOW,
    )


def test_review_ambiguous_legacy_id_affects_only_selected_article(store):
    store.add("111", [pf("SRCH-1", "https://example.org/one"), pf("SRCH-1", "https://example.org/two")])

    with pytest.raises(AmbiguousFactId):
        store.reject("111", "SRCH-1")
    with pytest.raises(AmbiguousFactId):
        store.confirm("111", "SRCH-1", 0)

    assert store.reject("111", "SRCH-1", source_url="https://example.org/two")
    assert store.confirm("111", "SRCH-1", 0)["source_url"] == "https://example.org/one"
    assert len(store.confirmed_facts("111")) == 1


def test_add_and_list(store):
    n = store.add("111", [pf("SRCH-1"), pf("SRCH-2", "https://e.org/2")])
    assert n == 2
    pending = store.list_pending("111")
    assert len(pending) == 2
    assert {p.fact_id for p in pending} == {"SRCH-1", "SRCH-2"}


def test_duplicates_ignored(store):
    """Одна страница не должна появиться в карантине дважды."""
    store.add("111", [pf("SRCH-1")])
    n = store.add("111", [pf("SRCH-1-dup", "https://example.org/x")])  # тот же URL
    assert n == 0
    assert len(store.list_pending("111")) == 1


def test_same_url_different_subject_kept(store):
    """URL одинаковый, субъект разный — это разные записи."""
    store.add("111", [pf("SRCH-1")])
    n = store.add("222", [pf("SRCH-1")])
    assert n == 1


def test_confirm_returns_review_with_agent_mark(store):
    store.add("111", [pf("SRCH-1")])
    res = store.confirm("111", "SRCH-1", weight=-100.0,
                        confirmed_by="agent",
                        rationale="Прямая связь с питомником")
    assert res is not None
    assert res["weight"] == -100.0
    assert res["confirmed_by"] == "agent"       # это подсказка ИИ
    assert "питомником" in res["rationale"]
    assert res["source_url"] == "https://example.org/x"  # ссылка на месте
    # После подтверждения в pending его нет
    assert store.list_pending("111") == []
    # Но он в confirmed
    assert len(store.confirmed_facts("111")) == 1


def test_confirm_weight_is_agent_hint(store):
    """Вес выставляет агент — это его подсказка, человек видит её с ссылкой."""
    store.add("111", [pf("SRCH-1")])
    res = store.confirm("111", "SRCH-1", weight=-5.0,
                        confirmed_by="agent", rationale="незначительно")
    assert res["weight"] == -5.0
    assert res["confirmed_by"] == "agent"


def test_confirm_missing_returns_none(store):
    assert store.confirm("111", "NOPE", weight=-1) is None


def test_reject(store):
    store.add("111", [pf("SRCH-1")])
    assert store.reject("111", "SRCH-1") is True
    assert store.list_pending("111") == []
    assert store.confirmed_facts("111") == []
    # Повторное отклонение — False (уже обработано)
    assert store.reject("111", "SRCH-1") is False


def test_source_stats_precision(store):
    store.add("111", [pf("SRCH-1"), pf("SRCH-2", "https://e.org/2"),
                      pf("SRCH-3", "https://e.org/3")])
    store.confirm("111", "SRCH-1", weight=-10)
    store.reject("111", "SRCH-2")
    stats = store.source_stats("web_search")
    assert stats["confirmed"] == 1
    assert stats["rejected"] == 1
    assert stats["precision"] == 0.5


def test_source_stats_empty(store):
    stats = store.source_stats("web_search")
    assert stats["precision"] is None


def test_confirmed_fact_flows_into_scoring_unmatched(store):
    """Подтверждённый факт — это ExtFact: скоринг его видит, но без
    критерия в YAML он лежит в unmatched и вердикт не двигает."""
    store.add("111", [pf("SRCH-1")])
    store.confirm("111", "SRCH-1", weight=-100.0)
    r = score_company(store.confirmed_facts("111"))
    assert r.verdict.total_score == 60  # baseline нетронут
    assert "dog_connection" in r.unmatched_fact_kinds


def test_persistence_across_instances(tmp_path, store):
    """Карантин переживает пересоздание объекта (файл SQLite)."""
    store.add("111", [pf("SRCH-1")])
    store.close()

    s2 = QuarantineStore(tmp_path / "q.db")
    assert len(s2.list_pending("111")) == 1
    s2.close()
