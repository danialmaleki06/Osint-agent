"""Живой тест: обзорная проверка ещё 3 компаний разного профиля."""
import asyncio, sys
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

COMPANIES = [
    ("7710140679", "ОАО ЮГК (золото)"),
    ("7814357678", "ООО ЕВРОНЕДРА"),
    ("7707083893", "ПАО Сбербанк"),
]

async def main():
    from osint_mcp.context.checko import CheckoSource
    from osint_mcp.tools.context_builder import build_company_context
    from osint_mcp.tools.risk import collect_risk_facts
    from osint_mcp.scoring import score_company
    ck = CheckoSource()

    for inn, label in COMPANIES:
        try:
            ctx = await build_company_context(inn, None, ck)
            risk = await collect_risk_facts(inn, ck)
            score = score_company(facts=risk.facts, context=ctx.context)
            name = (ctx.context.name_legal[:50] if ctx.context else "—")
            print(f"\n[{inn}] {label}")
            print(f"  name: {name}")
            print(f"  источников: {risk.sources_ok} ok / {risk.sources_failed} failed")
            print(f"  ВЕРДИКТ: {score.verdict.label} (балл {score.verdict.total_score}, floored={score.verdict.floored})")
            for m in score.matched:
                print(f"    {m.criterion:<20} {m.score:>7.1f}  {m.reason[:55]}")
            if score.unmatched_fact_kinds:
                print(f"  без критерия: {score.unmatched_fact_kinds}")
        except Exception as e:
            print(f"\n[{inn}] {label}: ОШИБКА {type(e).__name__}: {str(e)[:80]}")

asyncio.run(main())
