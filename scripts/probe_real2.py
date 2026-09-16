"""Живой тест: bankruptcy-факты Сбера — проверка парсинга ЕФРСБ."""
import asyncio, sys, json
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

async def main():
    from osint_mcp.context.checko import CheckoSource
    ck = CheckoSource()
    r = await ck.check_registry_flags("7707083893")
    print("status:", r.status)
    bank = [f for f in r.facts if f.kind == "bankruptcy"]
    print(f"bankruptcy фактов: {len(bank)}")
    for f in bank[:4]:
        print(f"  [{f.fact_id}] {f.statement[:90]}")
        print(f"      event_date: {f.event_date}, url: {f.source_url}")
    # flags
    print("flags:", {k: v for k, v in r.flags.items() if v})

asyncio.run(main())
