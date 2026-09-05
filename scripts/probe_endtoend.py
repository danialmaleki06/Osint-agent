"""Сквозной прогон через протокол — так, как работает настоящий агент.

Отличие от остальных стендов: здесь ничего не вызывается напрямую из
Python. Сервер поднимается отдельным процессом, разговор идёт по
протоколу, ответы разбираются из того же текста, который увидела бы
языковая модель. Проверяется вся цепочка целиком, включая сериализацию
и схемы, а не только логика источников.

    uv run python scripts/probe_endtoend.py

Расходует квоту: около сорока обращений к справочникам.
"""

import asyncio
import json
import os
import sys
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROBLEMS: list[str] = []


def fail(text: str) -> None:
    PROBLEMS.append(text)
    print(f"      ✗ {text}")


def body(result) -> dict:
    """Разобрать ответ инструмента так же, как его читает модель."""
    return json.loads(result.content[0].text)


async def call(session, name: str, **args) -> tuple[dict, float, int]:
    started = time.perf_counter()
    res = await session.call_tool(name, args)
    elapsed = time.perf_counter() - started
    text = res.content[0].text
    if res.is_error:
        fail(f"{name} вернул ошибку: {text[:160]}")
        return {}, elapsed, len(text)
    return json.loads(text), elapsed, len(text)


async def main() -> int:
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "osint_mcp.server"], env=env
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools = (await session.list_tools()).tools
            print(f"сервер {init.server_info.name} {init.server_info.version}, "
                  f"инструментов {len(tools)}")

            # ── 1. Неоднозначное название ────────────────────────────
            print("\n[1] resolve_company («БПМСофт» — название, не номер)")
            r, dt, size = await call(session, "resolve_company", query="БПМСофт")
            print(f"      confidence={r.get('confidence')} "
                  f"найдено={r.get('total_found')} · {dt:.2f}с · {size} знаков")
            for c in (r.get("candidates") or [])[:3]:
                print(f"        {c['inn']}  {c.get('short_name')}  {c.get('city')}")
            if r.get("confidence") != "low":
                fail("два одноимённых кандидата, а выбор не объявлен неоднозначным")
            if not r.get("hint"):
                fail("подсказка пуста")

            # ── 2. Тот же запрос по идентификатору ───────────────────
            print("\n[2] resolve_company (по ИНН)")
            r, dt, size = await call(session, "resolve_company", query="7724744134")
            print(f"      confidence={r.get('confidence')} · {dt:.2f}с · {size} знаков")
            if r.get("confidence") != "high":
                fail("точный идентификатор не дал однозначного ответа")
            if "7724744134" not in (r.get("hint") or ""):
                fail("в подсказке нет ИНН выбранной организации")

            # ── 3. Карточка ──────────────────────────────────────────
            print("\n[3] get_company_context")
            r, dt, size = await call(session, "get_company_context", inn="7724744134")
            ctx = r.get("context") or {}
            print(f"      status={r.get('status')} · {dt:.2f}с · {size} знаков")
            print(f"      {ctx.get('name_short')} · масштаб={ctx.get('size_category')} "
                  f"· сотрудников={ctx.get('employees')} · филиалов={ctx.get('branches')}")
            print(f"      бренд={ctx.get('brand')} · прежние={ctx.get('former_names')}")
            print(f"      reason: {(r.get('reason') or 'пусто')[:90]}")
            if not ctx.get("name_legal"):
                fail("карточка без наименования")
            if ctx.get("brand_resolved") and not ctx.get("brand"):
                fail("бренд объявлен установленным, но пуст")
            if ctx.get("size_category") == "unknown" and not r.get("reason"):
                fail("масштаб неизвестен, а объяснения нет")

            # ── 4. Риски ─────────────────────────────────────────────
            print("\n[4] collect_risk_facts")
            r, dt, size = await call(session, "collect_risk_facts", inn="7724744134")
            print(f"      источников ok={r.get('sources_ok')} "
                  f"отказ={r.get('sources_failed')} · фактов={len(r.get('facts') or [])} "
                  f"· {dt:.2f}с · {size} знаков")
            for res_ in (r.get("results") or []):
                arb = res_.get("arbitration")
                if arb:
                    print(f"        суды: всего {arb['total']}, "
                          f"ответчик {arb['as_defendant']['count']} "
                          f"на {arb['as_defendant']['total_amount']:,.0f} ₽, "
                          f"истец {arb['as_plaintiff']['count']}".replace(",", " "))
                proc = res_.get("procurement")
                if proc:
                    print(f"        закупки: исполнитель {proc['as_supplier']['count']}, "
                          f"заказчик {proc['as_customer']['count']}")
            print(f"      coverage_note: {(r.get('coverage_note') or 'пусто')[:110]}")
            for f in (r.get("facts") or [])[:2]:
                print(f"        [{f['fact_id']}] {f['statement'][:88]}")
            for f in (r.get("facts") or []):
                if not str(f.get("source_url", "")).startswith("http"):
                    fail(f"факт {f.get('fact_id')} без ссылки на первоисточник")
            if size > 8000:
                fail(f"ответ {size} знаков — выходит за разумный объём")

            # ── 5. Связи ─────────────────────────────────────────────
            print("\n[5] check_affiliations")
            r, dt, size = await call(session, "check_affiliations",
                                     inn="7724744134", deep=True)
            print(f"      людей={len(r.get('people') or [])} "
                  f"владельцев={len(r.get('owner_organizations') or [])} "
                  f"связей={len(r.get('related_companies') or [])} "
                  f"подозрительных={r.get('suspicious_count')} · {dt:.2f}с · {size} знаков")
            for o in (r.get("owner_organizations") or []):
                print(f"        владелец: {o.get('name')} — {o.get('via')}")
            for rc in (r.get("related_companies") or []):
                if rc.get("suspicious"):
                    print(f"        !! {rc.get('name')} — {rc.get('status')} "
                          f"— {rc.get('link')}")
                    if rc.get("deep_summary"):
                        print(f"           {rc['deep_summary'][:80]}")
            if r.get("inn") and any(rc.get("inn") == r["inn"]
                                    for rc in (r.get("related_companies") or [])):
                fail("организация числится связанной сама с собой")
            actual = sum(1 for rc in (r.get("related_companies") or [])
                         if rc.get("suspicious"))
            if actual != r.get("suspicious_count"):
                fail(f"счётчик подозрительных {r.get('suspicious_count')} != {actual}")

            # ── 6. Полнота ───────────────────────────────────────────
            print("\n[6] check_coverage")
            r, dt, size = await call(session, "check_coverage", inn="7724744134")
            print(f"      обращений={r.get('total_requests')} · {dt:.2f}с · {size} знаков")
            for u in (r.get("services") or []):
                print(f"        {u['service']:8} {u['requests']:3} запросов · "
                      f"данные {u['ok']} · пусто {u['empty']} · отказ {u['failed']} "
                      f"· за сутки по ключу {u.get('daily_spent')}")
            print(f"      получили: {len(r.get('obtained') or [])} направлений")
            for g in (r.get("gaps") or []):
                print(f"        – [{g['kind']}] {g['what']}")
            if not r.get("checked"):
                fail("проверка была, а отчёт говорит, что её не было")
            if dt > 0.5:
                fail(f"отчёт о полноте занял {dt:.2f}с — он не должен ходить в сеть")

            # ── 7. Акционерное общество ──────────────────────────────
            print("\n[7] check_affiliations по акционерному обществу (ЛАНСОФТ)")
            r, dt, size = await call(session, "check_affiliations",
                                     inn="9717157227", deep=False)
            print(f"      владельцев={len(r.get('owner_organizations') or [])} "
                  f"акционеры_не_раскрыты={r.get('shareholders_undisclosed')} · {dt:.2f}с")
            print(f"      coverage_note: {(r.get('coverage_note') or 'пусто')[:120]}")
            if r.get("shareholders_undisclosed") and \
                    "РАСКРЫВАЕТСЯ" not in (r.get("coverage_note") or ""):
                fail("владельцы не раскрыты, а в пометке об этом молчок")

            # ── 8. Иностранный идентификатор ─────────────────────────
            print("\n[8] resolve_company (казахский БИН)")
            r, dt, size = await call(session, "resolve_company", query="931040001411")
            print(f"      confidence={r.get('confidence')} · {dt:.2f}с")
            print(f"      подсказка: {(r.get('hint') or '')[:110]}")
            if "некорректен" in (r.get("hint") or ""):
                fail("правильный казахский номер объявлен опечаткой")

    print(f"\n{'─'*72}\nнарушенных инвариантов: {len(PROBLEMS)}")
    return 1 if PROBLEMS else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
