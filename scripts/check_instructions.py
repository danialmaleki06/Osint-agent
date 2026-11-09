"""Проверка указаний агенту на согласованность с кодом.

Описание инструмента — единственное, по чему модель понимает, как им
пользоваться. Расходиться с настоящей схемой ответа оно не имеет права:
ссылка на несуществующее поле молча уводит агента в сторону, а сбитая
нумерация даёт ему повод остановиться на середине перечня.

Проверяется два свойства:
  * каждое имя поля, упомянутое в описании, существует в схеме ответа;
  * нумерованные перечни идут подряд, и заголовок не обещает больше
    пунктов, чем их на самом деле.

    uv run python scripts/check_instructions.py

Возвращает ненулевой код, если нашлось расхождение, — годится для
запуска перед сдачей вместе с тестами.
"""

import asyncio
import os
import re
import sys

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TOOL_NAMES = {
    "health_check", "validate_inn", "resolve_company",
    "get_company_context", "collect_risk_facts", "check_affiliations",
    "check_coverage", "get_verdict", "search_unverified",
    "review_pending", "get_company_report", "get_company_links",
    "check_companies_batch", "generate_full_dossier",
    "check_provider_limits", "list_catalog_sources",
    "scan_catalog_source", "register_custom_source", "scan_catalog_batch",
}

# Общеупотребительные имена полей, которые пишутся без подчёркивания
# и потому не ловятся по змеиному регистру.
PLAIN_FIELDS = {"facts", "results", "candidates", "people", "flags",
                "status", "reason", "hint", "link", "via", "context"}

NUMBER_WORDS = {"ДВА": 2, "ТРИ": 3, "ЧЕТЫРЕ": 4, "ПЯТЬ": 5,
                "ШЕСТЬ": 6, "СЕМЬ": 7, "ВОСЕМЬ": 8}

# Значения полей, а не имена: встречаются в тексте в кавычках
# и не должны считаться ссылками на несуществующие поля.
KNOWN_VALUES = {
    "not_checked", "legal_entity", "streamable_http",
    "source_failed", "not_requested", "no_data",
    "not_implemented", "not_found", "disambiguation_required",
}


def collect_fields(schema: dict, defs: dict) -> set[str]:
    """Все имена полей, достижимые из схемы ответа, включая вложенные."""
    found: set[str] = set()
    visited: set[str] = set()

    def walk(node: object) -> None:
        if not isinstance(node, dict):
            return
        ref = node.get("$ref")
        if ref:
            name = str(ref).split("/")[-1]
            if name not in visited:
                visited.add(name)
                walk(defs.get(name, {}))
            return
        for key in ("anyOf", "oneOf", "allOf"):
            for sub in node.get(key) or []:
                walk(sub)
        if node.get("type") == "array":
            walk(node.get("items") or {})
        for field, spec in (node.get("properties") or {}).items():
            found.add(field)
            walk(spec)

    walk(schema)
    return found


def check_fields(name: str, description: str, known: set[str]) -> list[str]:
    """Имена полей из описания, которых нет в схеме."""
    mentioned = set(re.findall(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b", description))
    mentioned |= {w for w in re.findall(r"\b[a-z]{4,}\b", description)
                  if w in known or w in PLAIN_FIELDS}
    return sorted(mentioned - known - TOOL_NAMES - KNOWN_VALUES)


def check_numbering(description: str) -> list[str]:
    """Сбитая нумерация и заголовок, обещающий не то количество."""
    problems: list[str] = []
    items = [int(m) for m in re.findall(r"^\s{4}(\d)\. ", description, re.M)]
    items = items or [int(m) for m in re.findall(r"ПРАВИЛО (\d)", description)]
    if not items:
        return problems

    if items != list(range(1, len(items) + 1)):
        problems.append(f"нумерация сбита: {items}")

    claim = re.search(r"\b(" + "|".join(NUMBER_WORDS) + r")\s+(ПОЛ|ПРАВИЛ)",
                      description)
    if claim:
        promised = NUMBER_WORDS[claim.group(1)]
        if promised != len(items):
            problems.append(
                f"заголовок обещает {promised}, а блоков {len(items)}")
    return problems


async def main() -> int:
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "osint_mcp.server"], env=env
    )

    total = 0
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for tool in (await session.list_tools()).tools:
                out = tool.output_schema or {}
                defs = out.get("$defs") or out.get("definitions") or {}
                known = collect_fields(out, defs)
                known |= set((tool.input_schema or {}).get("properties") or {})

                description = tool.description or ""
                problems = [f"упомянуто поле «{g}», которого в ответе нет"
                            for g in check_fields(tool.name, description, known)]
                problems += check_numbering(description)

                mark = "ok" if not problems else "РАСХОЖДЕНИЯ"
                print(f"── {tool.name}: {len(description)} символов, "
                      f"{len(known)} полей в схеме — {mark}")
                for p in problems:
                    print(f"   ✗ {p}")
                total += len(problems)

    print(f"\nрасхождений: {total}")
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
