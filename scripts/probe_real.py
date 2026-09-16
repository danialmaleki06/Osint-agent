"""Живые тесты с реальным ключом Checko."""
import asyncio, sys, json
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

async def main():
    from osint_mcp.config import settings
    print(f"CHECKO_API_KEY: {'задан' if settings.checko_api_key else 'НЕТ'} ({settings.checko_api_key[:6]}...)")
    print(f"DADATA_API_KEY: {'задан' if settings.dadata_api_key else 'НЕТ'}")
    print()

    from osint_mcp.context.checko import CheckoSource
    from osint_mcp.tools.context_builder import build_company_context
    from osint_mcp.tools.risk import collect_risk_facts
    from osint_mcp.scoring import score_company
    from osint_mcp.tools.profile import build_profile

    ck = CheckoSource()
    SBER = "7707083893"

    ctx = await build_company_context(SBER, None, ck)
    print("=== 1. resolve/context (fallback Checko) ===")
    print(f"    status: {ctx.status}, reason: {(ctx.reason or '-')[:60]}")
    c = ctx.context
    if c:
        print(f"    name: {c.name_legal}")
        print(f"    статус: {c.status}, регистрация: {c.registered_at}")
        print(f"    руководитель: {c.director_fio} ({c.director_post})")
        print(f"    ОКВЭД: {c.okved_code} {c.okved_text}")
        print(f"    капитал: {c.capital}")
    print()

    risk = await collect_risk_facts(SBER, ck)
    print("=== 2. collect_risk_facts (живой) ===")
    print(f"    источников ok: {risk.sources_ok}, failed: {risk.sources_failed}")
    kinds = {}
    for f in risk.facts:
        kinds[f.kind] = kinds.get(f.kind, 0) + 1
    print(f"    факты: {kinds}")
    print()

    score = score_company(facts=risk.facts, context=ctx.context)
    print("=== 3. Вердикт на живых данных ===")
    print(f"    ОЦЕНКА: {score.verdict.label} | балл: {score.verdict.total_score} | floored: {score.verdict.floored}")
    for m in score.matched:
        print(f"    {m.criterion:<22} {m.score:>7.1f}  {m.reason[:60]}")
    print(f"    warnings: {score.warnings[:2]}")
    print()

    prof = build_profile(ctx.context, risk, score)
    print("=== 4. Профиль (фрагмент) ===")
    print(f"    subject: {prof['subject'].get('наименование')}")
    print(f"    litigation: {prof['litigation']}")
    print(f"    verdict: {prof['verdict'].get('оценка')}, основания: {prof['verdict'].get('основания', [])[:1]}")

asyncio.run(main())
