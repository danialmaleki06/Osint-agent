"""Карантин фактов: хранение, подтверждение, история доверия источников.

Карантин переживает процесс: факты лежат в SQLite рядом с сессией.
Человек подтверждает/отклоняет находку — подтверждённая становится
ExtFact с заданным весом и попадает в скоринг на общих основаниях.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from osint_mcp.models import ExtFact
from osint_mcp.scoring.models import PendingFact

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_facts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    subject     TEXT NOT NULL,            -- ИНН/ключ проверяемого
    fact_id     TEXT NOT NULL,
    kind        TEXT NOT NULL,
    statement   TEXT NOT NULL,
    source_url  TEXT NOT NULL,
    found_by    TEXT NOT NULL,
    trust       TEXT NOT NULL,
    found_at    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'confirmed', 'rejected')),
    weight      REAL,                     -- вес при подтверждении
    reviewed_at TEXT,
    UNIQUE(subject, source_url)
);
CREATE INDEX IF NOT EXISTS idx_pending_subject ON pending_facts(subject, status);
"""


class QuarantineStore:
    """SQLite-хранилище карантина. Один файл на проект."""

    def __init__(self, path: Path | str = "quarantine.db") -> None:
        # check_same_thread=False: MCP-фреймворк вызывает обработчики
        # из разных потоков, а SQLite-объект по умолчанию привязан к
        # потоку-создателю. За атомарность отвечает сам SQLite.
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def add(self, subject: str, facts: list[PendingFact]) -> int:
        """Добавить находки в карантин. Дубликаты (subject+url) молча
        пропускаются: одна и та же страница не должна появляться дважды."""
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (subject, f.fact_id, f.kind, f.statement, f.source_url,
             f.found_by, f.trust, f.found_at.isoformat(), "pending")
            for f in facts
        ]
        cur = self._conn.executemany(
            "INSERT OR IGNORE INTO pending_facts "
            "(subject, fact_id, kind, statement, source_url, found_by, "
            "trust, found_at, status) VALUES (?,?,?,?,?,?,?,?,?)",
            rows,
        )
        self._conn.commit()
        return cur.rowcount

    def list_pending(self, subject: str) -> list[PendingFact]:
        cur = self._conn.execute(
            "SELECT * FROM pending_facts WHERE subject=? AND status='pending' "
            "ORDER BY found_at",
            (subject,),
        )
        return [
            PendingFact(
                fact_id=r["fact_id"], kind=r["kind"], statement=r["statement"],
                source_url=r["source_url"], found_by=r["found_by"],
                trust=r["trust"], found_at=datetime.fromisoformat(r["found_at"]),
            )
            for r in cur.fetchall()
        ]

    def confirm(
        self, subject: str, fact_id: str, weight: float,
        confirmed_by: str = "agent", rationale: str = "",
    ) -> dict | None:
        """Подтвердить находку с весом.

        weight выставляет агент (подсказка) или человек (переоценка) —
        whoever подтверждает. confirmed_by и rationale фиксируются:
        пользователь всегда видит, чья это оценка и с чем она связана.
        """
        cur = self._conn.execute(
            "SELECT kind, statement, source_url, trust, found_at "
            "FROM pending_facts WHERE subject=? AND fact_id=? "
            "AND status='pending'",
            (subject, fact_id),
        )
        row = cur.fetchone()
        if row is None:
            return None
        self._conn.execute(
            "UPDATE pending_facts SET status='confirmed', weight=?, "
            "reviewed_at=? WHERE subject=? AND fact_id=?",
            (weight, datetime.now(timezone.utc).isoformat(), subject, fact_id),
        )
        self._conn.commit()
        return {
            "fact_id": fact_id, "kind": row["kind"],
            "statement": row["statement"], "source_url": row["source_url"],
            "weight": weight, "confirmed_by": confirmed_by,
            "rationale": rationale,
        }

    def reject(self, subject: str, fact_id: str) -> bool:
        """Отклонить находку как мусор."""
        now = datetime.now(timezone.utc).isoformat()
        cur = self._conn.execute(
            "UPDATE pending_facts SET status='rejected', reviewed_at=? "
            "WHERE subject=? AND fact_id=? AND status='pending'",
            (now, subject, fact_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def confirmed_facts(self, subject: str) -> list[ExtFact]:
        """Все подтверждённые факты субъекта — подсказанные агентом и
        переоценённые человеком. Вес хранится при факте."""
        cur = self._conn.execute(
            "SELECT * FROM pending_facts WHERE subject=? AND status='confirmed'",
            (subject,),
        )
        return [
            ExtFact(
                fact_id=r["fact_id"], kind=r["kind"],
                statement=r["statement"], source_url=r["source_url"],
                source_type="confirmed",
                trust=r["trust"],
                retrieved_at=datetime.fromisoformat(r["reviewed_at"]),
                payload={"weight": r["weight"], "subject": subject},
            )
            for r in cur.fetchall()
        ]

    def source_stats(self, found_by: str) -> dict:
        """Точность источника: сколько находок подтверждено/отклонено.
        Основа для понижения доверия болтливому источнику."""
        cur = self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM pending_facts "
            "WHERE found_by=? AND status != 'pending' GROUP BY status",
            (found_by,),
        )
        stats = {r["status"]: r["n"] for r in cur.fetchall()}
        confirmed = stats.get("confirmed", 0)
        rejected = stats.get("rejected", 0)
        total = confirmed + rejected
        return {
            "found_by": found_by,
            "confirmed": confirmed,
            "rejected": rejected,
            "precision": confirmed / total if total else None,
        }

    def close(self) -> None:
        self._conn.close()
