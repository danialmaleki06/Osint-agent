"""Дымовой тест: поднимаем сервер как это делает хост и проходим весь протокол.

Проверяет цепочку initialize -> tools/list -> tools/call целиком,
включая генерацию схем из аннотаций типов.

    uv run python scripts/smoke.py
"""

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> int:
    # Окружение наследуем целиком: подменять его нельзя, иначе процесс
    # останется без PATH и упадёт до того, как заговорит по протоколу.
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "osint_mcp.server"],
        env=env,
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("[ok] initialize")

            tools = (await session.list_tools()).tools
            print(f"[ok] tools/list -> {[t.name for t in tools]}")

            for t in tools:
                schema = t.input_schema.get("properties", {})
                print(f"     {t.name}: параметры {list(schema)}")

            r = await session.call_tool("health_check", {})
            print(f"[ok] health_check -> {r.content[0].text[:90]}...")

            for inn, note in [
                ("7707083893", "действующий ИНН"),
                ("7707083899", "битая контрольная сумма"),
                ("12345", "неверная длина"),
            ]:
                r = await session.call_tool("validate_inn", {"inn": inn})
                data = json.loads(r.content[0].text)
                mark = "valid" if data["valid"] else f"invalid: {data['reason']}"
                print(f"[ok] validate_inn({inn}) [{note}] -> {mark}")

    print("\nВСЁ ПРОШЛО")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
