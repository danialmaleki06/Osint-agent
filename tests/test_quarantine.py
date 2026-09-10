"""Тесты карантина: хранение, подтверждение, отклонение, статистика."""

from datetime import datetime, timezone

import pytest

from osint_mcp.scoring import score_company
from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.quarantine import QuarantineStore

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


def test_confirm_returns_extfact_with_weight(store):
    store.add("111", [pf("SRCH-1")])
    ext = store.confirm("111", "SRCH-1", weight=-100.0)
    assert ext is not None
    assert ext.kind == "dog_connection"
    assert ext.payload["weight"] == -100.0
    assert ext.payload["confirmed_by"] == "human"
    assert ext.source_url == "https://example.org/x"
    # После подтверждения в pending его нет
    assert store.list_pending("111") == []
    # Но он в confirmed
    assert len(store.confirmed_facts("111")) == 1


def test_confirm_weight_is_human_decision(store):
    """Вес подтверждения задаёт человек, движок его не вычисляет."""
    store.add("111", [pf("SRCH-1")])
    ext = store.confirm("111", "SRCH-1", weight=-5.0)
    assert ext.payload["weight"] == -5.0


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
