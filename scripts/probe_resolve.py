"""Живые прогоны установления личности организации.

Проверяет самый опасный участок системы: если досье собрано не на ту
организацию, оно выглядит совершенно достоверно, и подмену не заметит
ни агент, ни пользователь.

Большинство сценариев используют метод подсказок — его суточный лимит
измеряется тысячами. Обращения по идентификатору расходуют лимит
карточек, которых пятьдесят в сутки, поэтому их здесь единицы.

    uv run python scripts/probe_resolve.py
"""

import asyncio
from collections import Counter

from osint_mcp.context.dadata import DaDataSource
from osint_mcp.models import ResolveResult
from osint_mcp.tools.country import detect_country
from osint_mcp.tools.inn import validate_inn

# Запросы подобраны так, чтобы задеть разные ветки разбора:
# распространённое имя, торговая марка, организация с филиалами,
# несуществующее название, идентификатор вместо имени.
QUERIES = [
    ("Ромашка", "распространённое имя — ожидается выбор пользователя"),
    ("Сбербанк", "сотни филиалов — в выдаче должны быть только головные"),
    ("Яндекс", "торговая марка, юридических лиц несколько"),
    ("Технологии", "слово из тысяч наименований"),
    ("БПМСофт", "опорный случай"),
    ("Зюзюкин и партнёры по неведомому делу", "заведомо несуществующее"),
    ("ООО", "вырожденный запрос из одной формы"),
    ("7724744134", "идентификатор вместо имени"),
]


def check(r: ResolveResult, query: str) -> list[str]:
    """Утверждения, обязанные быть верными для любого запроса."""
    bad: list[str] = []

    def fail(t: str) -> None:
        bad.append(t)

    if not r.hint:
        fail("нет подсказки агенту — он останется без указаний")

    if r.status != "ok" and not r.reason:
        fail(f"состояние «{r.status}» без объяснения причины")

    for c in r.candidates:
        if not c.inn:
            fail(f"кандидат без идентификатора: {c.name}")
        if not c.name:
            fail(f"кандидат без наименования: {c.inn}")

    inns = [c.inn for c in r.candidates if c.inn]
    for dup, count in Counter(inns).items():
        if count > 1:
            fail(f"кандидат повторяется {count} раза: {dup}")

    # Филиалы носят то же имя и тот же идентификатор, что головная
    # организация. Их появление в выдаче создаёт ложный выбор.
    if len(set(inns)) != len(inns):
        fail("в выдаче филиалы вперемешку с головной организацией")

    if r.confidence == "low" and len(r.candidates) < 2:
        fail("выбор объявлен неоднозначным, а выбирать не из чего")

    if r.confidence == "none" and r.candidates:
        fail("состояние «выбирать не из чего», а кандидаты есть")

    if not r.candidates and r.confidence not in ("none",) and r.status == "ok":
        fail(f"кандидатов нет, но уверенность «{r.confidence}» — читается как результат")

    if r.confidence == "high" and r.total_found > 1 and len(r.candidates) > 1:
        actives = [c for c in r.candidates if (c.status or "") == "ACTIVE"]
        if len(actives) > 1:
            fail(f"уверенность высокая, а действующих кандидатов {len(actives)}")

    if r.status == "ok" and r.total_found and not r.candidates:
        fail("найдено больше нуля, а перечень кандидатов пуст")

    return bad


def check_offline() -> list[str]:
    """Разбор идентификаторов — без обращения к сети."""
    bad: list[str] = []
    cases = [
        ("7707083893", True, "RU", "действующий идентификатор организации"),
        ("7707083899", False, None, "битая контрольная сумма"),
        ("500100732259", True, "RU", "двенадцать знаков, предприниматель"),
        ("931040001411", None, "KZ", "казахский идентификатор"),
        ("191309167", None, "BY", "белорусский идентификатор"),
        ("12345", False, None, "неверная длина"),
        ("  7707083893  ", True, "RU", "пробелы по краям"),
        ("7707-083-893", True, "RU", "разделители внутри"),
        ("", False, None, "пустая строка"),
        ("абвгдеёжзийк", False, None, "буквы вместо цифр"),
    ]
    for value, expect_valid, expect_country, title in cases:
        try:
            got = validate_inn(value)
            country = detect_country(value)
        except Exception as e:                              # noqa: BLE001
            bad.append(f"ИСКЛЮЧЕНИЕ на «{title}»: {type(e).__name__}: {e}")
            continue
        if expect_valid is not None and got.valid != expect_valid:
            bad.append(f"«{title}»: ожидалось valid={expect_valid}, получено {got.valid}")
        if not got.valid and not got.reason:
            bad.append(f"«{title}»: отбраковано без объяснения причины")
        if expect_country and country.country != expect_country:
            bad.append(f"«{title}»: страна {country.country}, ожидалась {expect_country}")
        if country.country == "unknown" and not country.note:
            bad.append(f"«{title}»: страна не опознана без объяснения")
    return bad


async def main() -> int:
    total = 0

    print("РАЗБОР ИДЕНТИФИКАТОРОВ (без обращения к сети)")
    offline = check_offline()
    for p in offline:
        print(f"  ✗ {p}")
    print(f"  нарушений: {len(offline)}")
    total += len(offline)

    src = DaDataSource()
    for query, title in QUERIES:
        print(f"\n{'─' * 74}\n«{query}» — {title}")
        try:
            r = await src.resolve(query)
        except Exception as e:                              # noqa: BLE001
            print(f"  ✗ ИСКЛЮЧЕНИЕ: {type(e).__name__}: {e}")
            total += 1
            continue

        print(f"  состояние {r.status} · уверенность {r.confidence} · "
              f"найдено {r.total_found} · кандидатов {len(r.candidates)}")
        for c in r.candidates[:3]:
            print(f"    {c.inn}  {(c.name or '')[:44]:46} {c.status or '—'}")
        print(f"  подсказка: {(r.hint or '')[:150]}")

        problems = check(r, query)
        for p in problems:
            print(f"  ✗ {p}")
        total += len(problems)

    print(f"\n{'─' * 74}\nнарушенных инвариантов: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
