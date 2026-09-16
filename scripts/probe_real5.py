"""7710140679: кто это на самом деле (проверка резолва)."""
import asyncio, sys
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

async def main():
    from osint_mcp.context.checko import CheckoSource
    ck = CheckoSource()
    ctx = await ck.get_context("7710140679")
    c = ctx.context
    if c:
        print("name:", c.name_legal)
        print("ИНН:", c.inn, "| ОГРН:", c.ogrn)
        print("статус:", c.status, "| ОКВЭД:", c.okved_text)
        print("dir:", c.director_fio)
    else:
        print("нет карточки:", ctx.reason)

asyncio.run(main())
