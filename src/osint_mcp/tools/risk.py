"""Сводный сбор реестровых рисков.

Все проверки выполняются параллельно и возвращаются одним ответом.
Причина: каждое обращение агента к инструменту требует отдельного прогона
языковой модели, и пять последовательных вызовов обойдутся в пять прогонов —
это основная часть времени формирования досье, а не сами запросы к API.

Истолкования здесь нет: возвращаются исходные факты со ссылками.
Оценка риска вычисляется отдельно и детерминированно.
"""

import asyncio

import structlog

from osint_mcp.context.checko import CheckoSource
from osint_mcp.models import Fact, RiskCollection, SourceResult
from osint_mcp.tools.country import detect_country
from osint_mcp.tools.inn import validate_inn

log = structlog.get_logger()


async def collect_risk_facts(inn: str, source: CheckoSource | None = None) -> RiskCollection:
    """Опросить все реестровые источники параллельно."""
    # Проверки рисков доступны только по России. Для организаций Беларуси
    # и Казахстана источник данных не существует, и пустой результат
    # означал бы «нарушений нет» — это недопустимо.
    guess = detect_country(inn)
    if guess.country != "RU":
        return RiskCollection(
            inn=inn, results=[], sources_failed=0,
            coverage_note=(
                f"{guess.note} ПРОВЕРКА РИСКОВ НЕ ПРОВОДИЛАСЬ. "
                f"Не сообщай пользователю об отсутствии рисков — "
                f"источники по этой стране недоступны."
                if guess.note else
                "Идентификатор не опознан, проверка не выполнялась."
            ),
        )

    check = validate_inn(inn)
    if not check.valid:
        return RiskCollection(
            inn=inn, results=[],
            sources_failed=0,
            coverage_note=f"ИНН не прошёл проверку: {check.reason}. "
                          f"Проверка не выполнялась.",
        )

    src = source or CheckoSource()
    normalized = check.inn

    # return_exceptions=True принципиально: отказ одного источника
    # не должен обрывать сбор из остальных
    gathered = await asyncio.gather(
        src.check_registry_flags(normalized),
        src.check_arbitration(normalized),
        src.check_enforcement(normalized),
        src.check_inspections(normalized),
        src.check_procurement(normalized),
        return_exceptions=True,
    )

    names = ["checko.registry_flags", "checko.arbitration", "checko.enforcement",
             "checko.inspections", "checko.procurement"]
    results: list[SourceResult] = []
    for name, item in zip(names, gathered):
        if isinstance(item, BaseException):
            results.append(SourceResult(
                source=name, status="unavailable",
                reason=f"Непредвиденная ошибка: {type(item).__name__}",
            ))
        else:
            results.append(item)

    facts: list[Fact] = [f for r in results for f in r.facts]
    ok = sum(1 for r in results if r.status in ("ok", "partial"))
    failed = len(results) - ok

    notes: list[str] = []
    if failed:
        broken = ", ".join(r.source for r in results if r.status not in ("ok", "partial"))
        notes.append(
            f"Недоступны источники: {broken}. Проверка НЕПОЛНАЯ. "
            f"Отсутствие находок по этим направлениям ничего не доказывает — "
            f"обязательно сообщи об этом пользователю."
        )

    # Частичная выгрузка — не отказ, но и не полнота: у крупных организаций
    # записей десятки тысяч, разбивка строится по выборке
    # Причины неполноты у источников разные: где-то выборка вместо всей базы,
    # где-то приблизительный поиск. Обобщать их одной фразой нельзя —
    # получится неверно хотя бы для одного случая, поэтому перечисляем как есть.
    partial = [r for r in results if r.status == "partial" and r.reason]
    for r in partial:
        notes.append(f"[{r.source}] {r.reason}")

    note = " ".join(notes) or None

    log.info("collect_risk_facts", inn=normalized, facts=len(facts),
             ok=ok, failed=failed)

    return RiskCollection(inn=normalized, results=results, facts=facts,
                          sources_ok=ok, sources_failed=failed, coverage_note=note)
