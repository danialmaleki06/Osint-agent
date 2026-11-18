"""Два живых прогона инструментов MCP: uv run python scripts/mcp_audit.py."""

import argparse
import asyncio
import json
import os
import sys
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

INN = "7724744134"
SOURCE = "international_sanctions"
REGISTERED = "audit_smoke"
ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "health_check": ({}, "status"),
    "generate_full_dossier": ({"inn": INN, "detail": "full", "widget": True}, "виджет"),
    "resolve_company": ({"query": INN}, "status"),
    "check_companies_batch": ({"inns": [INN]}, "результаты"),
    "check_provider_limits": ({}, "providers"),
    "list_catalog_sources": ({}, "catalog_sources"),
    "scan_catalog_source": ({"inn": INN, "source_name": SOURCE}, "hits"),
    "register_custom_source": ({
        "name": REGISTERED, "topic": "smoke", "produces_kind": "smoke",
        "description": "Запись в каталоге временного MCP-сервера", "domains": ["example.com"],
    }, "registered_source"),
    "scan_catalog_batch": ({"source_name": SOURCE, "inns": [INN]}, "details"),
    "search_unverified": ({"inn": INN, "query": "BPMSoft", "kind": "news_mention", "limit": 2}, "hits"),
    "review_pending": ({"inn": INN, "action": "list"}, "pending"),
    "validate_inn": ({"inn": INN}, "valid"),
    "get_company_context": ({"inn": INN}, "status"),
    "collect_risk_facts": ({"inn": INN}, "results"),
    "check_affiliations": ({"inn": INN}, "inn"),
    "check_coverage": ({"inn": INN}, "checked"),
    "get_company_report": ({"inn": INN, "detail": "brief"}, "вердикт"),
    "get_company_links": ({"inn": INN}, "links"),
    "get_verdict": ({"inn": INN}, "verdict"),
    "check_shared_analytics": ({"inn": INN}, "status"),
    "check_customs_ved": ({"inn": INN}, "facts_found"),
    "check_geo_reviews": ({"inn": INN}, "facts_found"),
    "check_reputation_fiascos": ({"inn": INN}, "facts_found"),
}

BOOTSTRAP = """
import sys
from pathlib import Path
from osint_mcp import server
from osint_mcp.context import source_catalog
from osint_mcp.tools.quarantine import QuarantineStore

path = Path(sys.argv[1])
source_catalog._SOURCES_CATALOG_PATH = path / 'sources.yaml'
server._quarantine._store = QuarantineStore(path / 'quarantine.db')
server.main()
"""


def describe_result(name: str, data: dict) -> tuple[str, str]:
    status = data.get("status")
    note = str(data.get("note", ""))
    if name == "search_unverified" and "Веб-поиск недоступен" in note:
        return "unavailable", "поиск недоступен"
    if name == "scan_catalog_source" and "Проверка недоступна" in note:
        return "unavailable", "пустой снимок реестра"
    if status in ("unavailable", "skipped", "not_found", "partial"):
        return status, "статус ответа"
    if data.get("оценка_не_выставлена") or data.get("checked") is False:
        return "unavailable", "проверка не состоялась"
    if name == "check_affiliations" and data.get("coverage_note"):
        return "partial", "см. охват связей"
    if name == "check_companies_batch":
        if not data.get("проверено"):
            return "unavailable", "оценки не выставлены"
        for item in data["результаты"]:
            counts = item.get("источники_рисков", {})
            if item.get("оценка_не_выставлена") or any(counts.get(k) for k in ("частично", "недоступно", "пропущено")):
                return "partial", "неполная проверка рисков"
    coverage = data.get("охват_проверки") or {}
    if "всего_запросов" in coverage:
        ok, empty, failed = (coverage[k] for k in ("с_данными", "без_данных", "с_ошибкой"))
        return ("partial" if failed else "ok"), f"учтено запросов: {ok} с данными, {empty} пустых, {failed} с ошибкой"
    if data.get("sources_failed") or data.get("methods_failed") or data.get("что_не_собралось"):
        return "partial", "есть недоступные источники"
    if any("Базовые реестры рисков" in warning for warning in data.get("warnings", [])):
        return "partial", "ключевые реестры рисков не ответили"
    return "ok", ""


async def run_round(number: int) -> bool:
    with TemporaryDirectory() as temp, open(os.devnull, "w", encoding="utf-8") as log:
        (Path(temp) / "sources.yaml").write_bytes((ROOT / "src/osint_mcp/config_data/sources.yaml").read_bytes())
        env = {**os.environ, "OSINT_EXPOSE_GRANULAR_TOOLS": "true", "OSINT_MCP_TRANSPORT": "stdio"}
        params = StdioServerParameters(command=sys.executable, args=["-c", BOOTSTRAP, temp], cwd=ROOT, env=env)
        async with stdio_client(params, errlog=log) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=120) as session:
                await session.initialize()
                advertised = {tool.name for tool in (await session.list_tools()).tools}
                gate = asyncio.Semaphore(4)

                async def call(name: str, args: dict, expected: str) -> tuple[str, str, str]:
                    if name not in advertised:
                        return name, "error", "отсутствует в tools/list"
                    try:
                        async with gate:
                            reply = await session.call_tool(name, args)
                        if reply.is_error:
                            return name, "error", "MCP isError"
                        data = reply.structured_content or json.loads(reply.content[0].text)
                    except Exception as exc:
                        return name, "error", type(exc).__name__
                    if not isinstance(data, dict) or data.get("error"):
                        return name, "error", "ошибка в полезной нагрузке"
                    if expected not in data and not data.get("оценка_не_выставлена"):
                        return name, "error", f"нет поля {expected}"
                    if name == "generate_full_dossier" and expected in data and next(iter(data)) != expected:
                        return name, "error", "виджет скрыт в конце ответа"
                    return name, *describe_result(name, data)

                ordered = ["register_custom_source", "list_catalog_sources", "generate_full_dossier"]
                # Проверяем запись тестового источника в том же процессе, затем собираем досье.
                results = [await call(name, *CASES[name]) for name in ordered]
                results += await asyncio.gather(*(call(n, *v) for n, v in CASES.items() if n not in ordered))
                results += [(n, "error", "нет сценария прогона") for n in sorted(advertised - CASES.keys())]
                counts = Counter(status for _, status, _ in results)
                print(f"Прогон {number}, инструментов {len(advertised)}", flush=True)
                for name, status, message in results:
                    print(f"{status:12} {name} {message}", flush=True)
                print(dict(counts), flush=True)
                return not counts["error"]


async def main(rounds: int) -> int:
    results = [await run_round(i) for i in range(1, rounds + 1)]
    return 0 if all(results) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, choices=range(1, 6), default=2)
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(asyncio.run(main(parser.parse_args().rounds)))
