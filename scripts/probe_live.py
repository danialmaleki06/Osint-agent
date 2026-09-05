"""Живые прогоны по разным сценариям с проверкой инвариантов.

Замысел: не разглядывать вывод глазами, а формулировать утверждения,
которые обязаны быть верны для ЛЮБОЙ организации, и проверять их на
живых данных. Тесты на записанных образцах проверяют то, что мы уже
знаем; этот стенд ищет то, чего мы не предвидели.

    uv run python scripts/probe_live.py

Расходует квоту справочника: около двадцати обращений на организацию.
"""

import asyncio
import sys
from collections import Counter

import httpx

from osint_mcp.context.checko import CheckoSource
from osint_mcp.models import AffiliationGraph

# Разные по устройству организации: публичное акционерное общество,
# общество с ограниченной ответственностью, холдинговая структура,
# крупный ретейл. У каждой свои особенности разбора.
CASES = [
    ("7724744134", "БПМСофт — опорный случай"),
    ("9717157227", "ЛАНСОФТ — акционерное общество, владельцы не раскрыты"),
    ("7707083893", "Сбербанк — крупнейшая, тысячи дел"),
    ("7736050003", "Газпром — государственное участие"),
    ("7721546864", "Вайлдберриз — крупный ретейл"),
    ("7704217370", "Интернет Решения — маркетплейс"),
    ("7736207543", "Яндекс — вероятна реорганизация"),
]

CALLS = 0
_orig_get = httpx.AsyncClient.get


async def _counted(self, *a, **k):
    global CALLS
    CALLS += 1
    return await _orig_get(self, *a, **k)


httpx.AsyncClient.get = _counted


def check(graph: AffiliationGraph, inn: str) -> list[str]:
    """Утверждения, обязанные быть верными для любой организации."""
    bad: list[str] = []

    def fail(text: str) -> None:
        bad.append(text)

    # ── тождество ────────────────────────────────────────────────
    if any(rc.inn == inn for rc in graph.related_companies):
        fail("организация числится связанной сама с собой")

    inns = [rc.inn for rc in graph.related_companies if rc.inn]
    for dup, count in Counter(inns).items():
        if count > 1:
            fail(f"связанная организация повторяется {count} раза: {dup}")

    people_inns = [p.inn for p in graph.people if p.inn]
    for dup, count in Counter(people_inns).items():
        if count > 1:
            fail(f"человек повторяется {count} раза: {dup}")

    # ── заполненность ────────────────────────────────────────────
    for rc in graph.related_companies:
        if not (rc.inn or rc.ogrn):
            fail(f"связь без идентификатора: {rc.link}")
        if rc.triage_status == "checked" and not rc.name:
            fail(f"проверена, но без наименования: {rc.inn or rc.ogrn}")
        if "ьа" in rc.link or "ьи" in rc.link:
            fail(f"кривой падеж в подписи связи: {rc.link}")
        if rc.deep_summary and not rc.suspicious:
            fail(f"полная проверка ушла на благополучную: {rc.name}")
        if rc.suspicious and not (rc.flags or (rc.status and rc.status != "Действует")):
            fail(f"подозрительна без основания: {rc.name}")

    for p in graph.people:
        if not p.fio and not p.inn:
            fail("человек без имени и без идентификатора")
        if not p.checked and not p.not_checked_reason:
            fail(f"не проверен без объяснения причины: {p.fio}")
        if p.share_percent is not None and not (0 <= p.share_percent <= 100):
            fail(f"доля вне допустимого: {p.fio} = {p.share_percent}")

    # ── согласованность счётчиков ────────────────────────────────
    actual = sum(1 for rc in graph.related_companies if rc.suspicious)
    if actual != graph.suspicious_count:
        fail(f"счётчик подозрительных {graph.suspicious_count} != {actual}")

    # ── честность о неполноте ────────────────────────────────────
    note = graph.coverage_note or ""
    if graph.shareholders_undisclosed and "РАСКРЫВАЕТСЯ" not in note:
        fail("владельцы не раскрыты, но в пометке об этом молчок")
    if any(rc.triage_status == "unavailable" for rc in graph.related_companies) \
            and "НЕ ПРОВЕРЕН" not in note:
        fail("часть организаций не проверена, но в пометке молчок")
    if any(not p.checked for p in graph.people) and not note:
        fail("часть лиц не проверена, но пометки нет вовсе")
    if any(rc.triage_status == "not_checked" for rc in graph.related_companies) \
            and "лимит" not in note:
        fail("до части организаций не дошла очередь, но о лимите молчок")

    # ── пустой результат обязан быть объяснён ────────────────────
    if not graph.people and not graph.related_companies and not note:
        fail("пусто всё и без единого объяснения — читается как «связей нет»")

    return bad


async def one(inn: str, title: str) -> int:
    global CALLS
    CALLS = 0
    src = CheckoSource()
    try:
        graph, res = await src.check_affiliations(inn, deep=True)
    except Exception as e:                       # noqa: BLE001
        print(f"  ✗ ИСКЛЮЧЕНИЕ: {type(e).__name__}: {e}")
        return 1

    if graph is None:
        print(f"  — источник не ответил: {res.reason}")
        return 0

    people = len(graph.people)
    unchecked = sum(1 for p in graph.people if not p.checked)
    rel = len(graph.related_companies)
    susp = graph.suspicious_count
    unavail = sum(1 for rc in graph.related_companies
                  if rc.triage_status == "unavailable")
    print(f"  люди {people} (не проверено {unchecked}) · связей {rel} · "
          f"подозрительных {susp} · недоступно {unavail} · "
          f"АО {graph.shareholders_undisclosed} · фактов {len(res.facts)} · "
          f"обращений {CALLS}")

    if graph.predecessors or graph.successors:
        print(f"    правопреемство: предшественников {len(graph.predecessors)}, "
              f"преемников {len(graph.successors)}")
    for rc in graph.related_companies:
        if rc.suspicious:
            print(f"    !! {rc.name or rc.ogrn} — {rc.status} — {rc.link}")
            if rc.deep_summary:
                print(f"       {rc.deep_summary}")

    problems = check(graph, inn)
    for p in problems:
        print(f"  ✗ {p}")
    return len(problems)


async def main() -> int:
    total = 0
    for inn, title in CASES:
        print(f"\n{'─' * 74}\n{title}  (ИНН {inn})")
        total += await one(inn, title)

    print(f"\n{'─' * 74}")
    print(f"нарушенных инвариантов: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
