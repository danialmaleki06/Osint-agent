"""Диагностика: 7710140679 — что за компания по Checko; 7814357678 — почему пусто."""
import asyncio, sys, json
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

async def main():
    from osint_mcp.context.checko import CheckoSource
    from osint_mcp.tools.inn import validate_inn
    ck = CheckoSource()

    for inn, label in [("7710140679", "ЮГК?"), ("7814357678", "Евронедра?")]:
        v = validate_inn(inn)
        print(f"\n=== {inn} ({label}) валидность: {v.valid}, {v.kind} ===")
        r = await ck.check_registry_flags(inn)
        print(f"  registry_flags: status={r.status}, reason={(r.reason or '')[:80]}")
        if r.status == "ok":
            st = (r.flags.get("company_status") if isinstance(r.flags, dict) else None)
            # В facts может быть карточка
            for f in r.facts[:3]:
                print(f"  факт: {f.statement[:80]}")

asyncio.run(main())
