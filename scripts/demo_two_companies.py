"""Стенд: два досье через НАСТОЯЩИЕ парсеры проекта (офлайн, ответы из fixtures).

Компания A — «надёжная»: реальные ответы API по ООО «БПМСОФТ» (ИНН 7724744134),
записанные автором проекта с живого Checko.

Компания B — «нельзя доверять»: те же механизмы, но подмешаны факторы
банкротства, санкций, крупного долга ФССП и массового руководителя —
имитация ответов API для проблемной компании.
"""

import asyncio
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import httpx
import respx

from osint_mcp.config import settings
from osint_mcp.context.checko import CheckoSource
from osint_mcp.tools.risk import collect_risk_facts
from osint_mcp.scoring import score_company

# Офлайн-стенд: настоящего ключа нет, сетевые вызовы перехватываются
# respx, ключ подставляем фиктивный — как в тестах проекта.
settings.checko_api_key = "demo-key"

FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures"
NOW = datetime.now(timezone.utc)


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def fresh_flags(base: dict) -> dict:
    """Копия ответа карточки с яркими проблемами (флаги в data верхнего уровня)."""
    data = json.loads(json.dumps(base, ensure_ascii=False))
    d = data["data"]
    d["МассРуковод"] = True       # массовый руководитель
    d["МассУчред"] = True         # массовый учредитель
    d["Санкции"] = True           # санкционные списки
    d["НелегалФин"] = True        # нелегальная финансовая деятельность
    d["НедобПост"] = True         # недобросовестный поставщик
    d["ДисквЛица"] = False
    d["СанкцУчр"] = False
    d["ЕФРСБ"] = [
        {"Тип": "Наблюдение", "Дата": "2026-08-01",
         "Наим": "Введена процедура банкротства"},
    ]
    return data


def fresh_enforcements(base: dict) -> dict:
    data = json.loads(json.dumps(base, ensure_ascii=False))
    d = data["data"]
    d["ОбщКолич"] = 3
    d["ЗапВсего"] = 3
    d["ОбщСум"] = 16_550_000
    d["ОстЗадолж"] = 16_550_000
    d["Записи"] = [
        {"Номер": "ИП-1001", "ПредмИсп": "Задолженность по договору поставки",
         "Сумма": 12_500_000, "Дата": "2026-06-15"},
        {"Номер": "ИП-1002", "ПредмИсп": "Задолженность по налогам",
         "Сумма": 3_200_000, "Дата": "2026-05-20"},
        {"Номер": "ИП-1003", "ПредмИсп": "Задолженность по договору подряда",
         "Сумма": 850_000, "Дата": "2024-02-10"},  # старый — затухание
    ]
    return data


def fresh_legal_cases(base: dict) -> dict:
    data = json.loads(json.dumps(base, ensure_ascii=False))
    d = data["data"]
    # 25 дел ответчиком — верхняя ступень
    d["ЗапВсего"] = 25
    cases = []
    for i in range(1, 26):
        cases.append({
            "Номер": f"А40-{1000+i}", "Дата": "2026-03-01",
            "СуммИск": 500_000, "Истцы": "ООО Кредитор",
            "Ответчики": "ООО Проблемная",
            "Суд": "Арбитражный суд города Москвы",
            "ПрАктив": True, "Роль": "Ответчик",
        })
    d["Записи"] = cases
    return data


def fresh_person(base: dict) -> dict:
    data = json.loads(json.dumps(base, ensure_ascii=False))
    return data


async def dossier(label: str, mocks: dict, inn: str) -> None:
    print(f"\n{'=' * 66}\n{label}\n{'=' * 66}")
    with respx.mock:
        for ep, payload in mocks.items():
            respx.get(f"{settings.checko_base_url}/{ep}").mock(
                return_value=httpx.Response(200, json=payload)
            )
        risk = await collect_risk_facts(inn, CheckoSource())
        result = score_company(facts=risk.facts, context=None)
        v = result.verdict
        print(f"\n  ВЕРДИКТ: {v.label.upper()}")
        print(f"  Балл: {v.total_score}"
              + (f"  (пол: {v.floor_criterion})" if v.floored else ""))
        print("\n  Группы:")
        for g in result.groups:
            if g.score:
                print(f"    {g.group:<14} {g.score:>8.1f}")
        print("\n  Сработавшие критерии:")
        for m in result.matched:
            print(f"    {m.criterion:<24} {m.score:>7.1f}   {m.reason}")
        print("\n  Причины:")
        for r in result.reasons:
            print(f"    • {r}")
        if result.unmatched_fact_kinds:
            print(f"\n  Без критерия (пул можно расширить): "
                  f"{', '.join(result.unmatched_fact_kinds)}")


async def main() -> None:
    company_flags = load("checko_company_bpmsoft.json")
    enforcements = load("checko_enforcements_bpmsoft.json")
    legal_cases = load("checko_legal-cases_bpmsoft.json")
    inspections = load("checko_inspections_bpmsoft.json")
    contracts = load("checko_contracts_bpmsoft.json")

    # A: реальные данные BPMSoft как есть
    await dossier(
        "КОМПАНИЯ A — ООО «БПМСОФТ» (реальные данные API):",
        {"company": company_flags, "enforcements": enforcements,
         "legal-cases": legal_cases, "inspections": inspections,
         "contracts": contracts},
        "7724744134",
    )

    # B: проблемная компания — яркие риски
    await dossier(
        "КОМПАНИЯ B — смоделированный проблемный контрагент:",
        {"company": fresh_flags(company_flags),
         "enforcements": fresh_enforcements(enforcements),
         "legal-cases": fresh_legal_cases(legal_cases),
         "inspections": inspections, "contracts": contracts},
        "7724744127",  # валидный по контрольной сумме, но другой ИНН — для чистоты стенда
    )


if __name__ == "__main__":
    asyncio.run(main())
