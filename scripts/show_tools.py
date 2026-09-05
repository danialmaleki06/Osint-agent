"""Показать инструменты глазами языковой модели.

Печатает ровно то, что сервер отдаёт агенту в ответ на tools/list:
описание каждого инструмента и схему его параметров. Именно этот текст —
единственный канал, по которому модель понимает, когда и как вызывать
инструмент; на сам код она не смотрит.

    uv run python scripts/show_tools.py           # всё
    uv run python scripts/show_tools.py resolve   # только совпадающие по имени
"""

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

LINE = "─" * 78


async def main() -> int:
    needle = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "osint_mcp.server"], env=env
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools

            shown = 0
            for t in tools:
                if needle and needle not in t.name.lower():
                    continue
                shown += 1
                print(LINE)
                print(f"ИНСТРУМЕНТ: {t.name}")
                print(LINE)
                print()
                print("ОПИСАНИЕ (его читает модель, решая, вызывать ли инструмент):")
                print()
                for line in (t.description or "").strip().splitlines():
                    print("   " + line.strip())
                print()

                props = (t.input_schema or {}).get("properties") or {}
                required = set((t.input_schema or {}).get("required") or [])
                print("ПАРАМЕТРЫ:")
                if not props:
                    print("   нет")
                for name, spec in props.items():
                    mark = "обязательный" if name in required else "необязательный"
                    print(f"   {name} ({spec.get('type', '?')}, {mark})")
                    if spec.get("description"):
                        print(f"      {spec['description']}")
                    if spec.get("examples"):
                        print(f"      примеры: {spec['examples']}")
                print()

                out = t.output_schema or {}
                fields = (out.get("properties") or {})
                if fields:
                    print("ПОЛЯ ОТВЕТА (их пояснения модель тоже видит):")
                    for name, spec in fields.items():
                        desc = spec.get("description")
                        if desc:
                            print(f"   {name}: {desc}")
                        else:
                            print(f"   {name}")
                    print()

            print(LINE)
            print(f"показано инструментов: {shown} из {len(tools)}")
            if needle and not shown:
                print(f"по запросу «{needle}» ничего не найдено")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
