"""Прогон скоринга через MCP-протокол — то, что увидит агент.

Три сценария на одной организации (ООО «БПМСофт»):
  1. Обычные критерии — вердикт по штатным реестровым фактам.
  2. Дополнительный критерий — в scoring.yaml добавляется критерий на
     карантинный вид факта, находка подтверждается (review_pending),
     вердикт пересчитывается.
  3. Пограничный — тот же факт подтверждается с весом по другую сторону
     порога критерия (-24.9 вместо -30 при рубеже -25): балл меняется,
     вердикт переходит рубеж.

Все ответы инструментов пишутся в _report_scoring.md дословно.
По завершении scoring.yaml и quarantine.db восстанавливаются из копий.

    DADATA_API_KEY=... uv run python scripts/probe_scoring.py
"""

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

INN = "7724744134"
YAML_PATH = Path("src/osint_mcp/config_data/scoring.yaml")
DB_PATH = Path("src/osint_mcp/config_data/quarantine.db")

CRITERION = """
  dog_connection:
    group: registry_risk
    description: "Подтверждённая находка из открытых источников (карантин)"
    match:
      kind: dog_connection
      field: weight
      op: lt
      values: [0]
    aggregate: sum
    field: weight
    thresholds:
      - { below: -25, score: -30 }
      - { below: 0, score: -10 }
    warn_always: true
    reason: "Подтверждённая находка из открытого веба: суммарный вес {sum}"

"""

REPORT: list[str] = [
    "# Живой прогон скоринга через MCP",
    "",
    f"Организация: ООО «БПМСофт», ИНН {INN}. Ответы инструментов приведены "
    "дословно — это то, что видит агент; пересказ построен по правилам из "
    "описаний инструментов.",
    "",
]


def call(session, name: str, **args):
    return session.call_tool(name, args)


async def json_of(result) -> dict:
    return json.loads(result.content[0].text)


def add(title: str) -> None:
    REPORT.append(f"## {title}\n")


def verbatim(result) -> None:
    """Ответ инструмента дословно — как его прочитает модель."""
    REPORT.append("### Ответ инструмента (дословно)\n")
    REPORT.append("```json")
    REPORT.append(result.content[0].text)
    REPORT.append("```\n")


def server():
    # Ключи — только из .env: в окружении сессии висит пустая DADATA_API_KEY
    # и одиночный CHECKO_API_KEY, перекрывающие пул из двух ключей.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("DADATA_", "CHECKO_"))}
    env["PYTHONUTF8"] = "1"
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "osint_mcp.server"], env=env
    )
    return stdio_client(params)


def reset_fact(fact_id: str = "SRCH-1") -> None:
    """Вернуть находку в карантин: confirm работает только для pending.

    Из прошлых сессий SRCH-1 уже подтверждён с весом −30; без сброса
    пограничный сценарий подтвердил бы вес −24.9 отказом.
    """
    import sqlite3

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE pending_facts SET status='pending', weight=NULL, "
        "reviewed_at=NULL WHERE subject=? AND fact_id=?", (INN, fact_id))
    conn.commit()
    conn.close()


def verdict_summary(r: dict) -> str:
    """Как агент обязан пересказать вердикт пользователю."""
    v = r["verdict"]
    lines = [f"**Оценка: {v['label']}** (балл {v['total_score']})"]
    if v.get("floored"):
        lines.append(f"⚠ Вердикт урезан жёстким полом: критерий "
                     f"«{v['floor_criterion']}» не даёт оценке быть выше.")
    for w in r.get("warnings") or []:
        lines.append(f"ВАЖНО: {w}")
    for reason in r.get("reasons") or []:
        lines.append(f"Причина: {reason}")
    for m in r.get("matched") or []:
        urls = ", ".join(m.get("source_urls") or [])
        lines.append(f"- {m['criterion']}: {m['score']} — {m.get('reason') or m['description']}"
                     + (f" ({urls})" if urls else ""))
    if r.get("unmatched_fact_kinds"):
        lines.append("Проверка может быть расширена: данные видов "
                     f"{', '.join(r['unmatched_fact_kinds'])} пока не входят в оценку.")
    if r.get("pending"):
        lines.append("Не проверено, нашлось в открытом виде (карантин):")
        for p in r["pending"]:
            lines.append(f"- {p['statement'][:90]}… — {p['source_url']}")
    return "\n".join(lines)


async def scenario_1() -> dict:
    add("Сценарий 1 — обычные критерии (только реестр)")
    REPORT.append(
        "Агент действует по штатному порядку: resolve → context → verdict. "
        "Никаких внешних находок не подключено.\n")
    async with server() as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            res = await call(s, "resolve_company", query=INN)
            verbatim(res)
            res = await call(s, "get_company_context", inn=INN)
            verbatim(res)
            res = await call(s, "get_verdict", inn=INN)
            verbatim(res)
            REPORT.append("### Пересказ агентом\n")
            REPORT.append(verdict_summary(await json_of(res)))
            REPORT.append("")
            return await json_of(res)


async def scenario_2() -> dict:
    add("Сценарий 2 — добавлен дополнительный критерий")
    REPORT.append(
        "В `scoring.yaml` добавлен критерий `dog_connection` (вид факта из "
        "карантина, порог: суммарный вес ниже −25 → −30 баллов, ниже 0 → −10). "
        "Затем агент подтверждает находку `SRCH-1` с весом −30.\n")
    async with server() as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            res = await call(s, "review_pending", inn=INN, action="confirm",
                             fact_id="SRCH-1", weight=-30.0,
                             rationale="Связь подтверждается страницей сообщества")
            verbatim(res)
            res = await call(s, "get_verdict", inn=INN)
            verbatim(res)
            REPORT.append("### Пересказ агентом\n")
            REPORT.append(verdict_summary(await json_of(res)))
            REPORT.append("")
            return await json_of(res)


async def scenario_3() -> dict:
    add("Сценарий 3 — пограничный случай (вес по другую сторону порога)")
    REPORT.append(
        "Тот же факт подтверждается с весом −24.9 — выше рубежа −25. "
        "Критерий срабатывает по второй ступени (−10 вместо −30): балл "
        "меняется на 20, вердикт переходит границу. Меняется ТОЛЬКО вес "
        "подтверждения — данные те же.\n")
    async with server() as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            res = await call(s, "review_pending", inn=INN, action="confirm",
                             fact_id="SRCH-1", weight=-24.9,
                             rationale="Упоминание косвенное, подтверждения связи нет")
            verbatim(res)
            res = await call(s, "get_verdict", inn=INN)
            verbatim(res)
            REPORT.append("### Пересказ агентом\n")
            REPORT.append(verdict_summary(await json_of(res)))
            REPORT.append("")
            return await json_of(res)


async def main() -> int:
    v1 = await scenario_1()

    yaml_backup, db_backup = YAML_PATH.with_suffix(".yaml.bak"), DB_PATH.with_suffix(".db.bak")
    shutil.copy(YAML_PATH, yaml_backup)
    shutil.copy(DB_PATH, db_backup)
    try:
        reset_fact()
        text = YAML_PATH.read_text(encoding="utf-8")
        YAML_PATH.write_text(
            text.replace("# ── Вердикты", CRITERION + "# ── Вердикты"),
            encoding="utf-8")
        v2 = await scenario_2()
        reset_fact()
        v3 = await scenario_3()
    finally:
        shutil.copy(yaml_backup, YAML_PATH)
        shutil.copy(db_backup, DB_PATH)
        yaml_backup.unlink()
        db_backup.unlink()

    add("Сводка по рубежам")
    REPORT.append("| Сценарий | Балл | Вердикт |")
    REPORT.append("|---|---|---|")
    for name, r in (("1. только реестр", v1),
                    ("2. критерий + вес −30", v2),
                    ("3. вес −24.9 (порог −25)", v3)):
        v = r["verdict"]
        REPORT.append(f"| {name} | {v['total_score']} | {v['label']} |")
    REPORT.append("")

    Path("_report_scoring.md").write_text("\n".join(REPORT), encoding="utf-8")
    print("готово: _report_scoring.md")
    for name, r in (("S1", v1), ("S2", v2), ("S3", v3)):
        print(f"{name}: {r['verdict']['total_score']} → «{r['verdict']['label']}»")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
