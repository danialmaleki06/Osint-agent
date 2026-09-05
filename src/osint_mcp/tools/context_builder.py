"""Сборка полного контекста компании из нескольких источников.

Контекст собирается из трёх независимых обращений, выполняемых параллельно:
  реестровая карточка  — DaData, бесплатно;
  рыночное наименование — DaData, платный метод;
  масштаб организации   — Checko, финансовая отчётность и численность.

Ни одно из них не является обязательным: отказ любого источника ухудшает
полноту, но не отменяет результат. Недостающее помечается явно.
"""

import asyncio

import structlog

from osint_mcp.context.checko import CheckoSource
from osint_mcp.context.dadata import DaDataSource
from osint_mcp.models import ContextResult
from osint_mcp.tools.country import detect_country
from osint_mcp.tools.names import name_variants

log = structlog.get_logger()


async def build_company_context(
    inn: str,
    dadata: DaDataSource | None = None,
    checko: CheckoSource | None = None,
) -> ContextResult:
    """Собрать опорный контекст компании."""
    dd = dadata or DaDataSource()
    ck = checko or CheckoSource()

    # Страна определяет, какие источники вообще применимы. Без этого шага
    # контрагент из Казахстана дал бы пустой результат, неотличимый
    # от «нарушений не найдено».
    guess = detect_country(inn)

    if guess.country in ("BY", "KZ"):
        return await dd.get_context_foreign(guess)

    if guess.country == "unknown":
        return ContextResult(status="skipped", reason=guess.note)

    base_res, brand, finances, history = await asyncio.gather(
        dd.get_context(inn),
        dd.get_brand(inn),
        ck.get_finances(inn),
        ck.get_name_history(inn),
        return_exceptions=True,
    )

    # Реестровая карточка обязательна: без неё контекста нет
    if isinstance(base_res, BaseException) or base_res.status != "ok" or not base_res.context:
        if isinstance(base_res, BaseException):
            return ContextResult(status="unavailable",
                                 reason=f"Ошибка источника: {type(base_res).__name__}")
        return base_res

    ctx = base_res.context

    # Рыночное наименование — необязательное обогащение
    if not isinstance(brand, BaseException) and brand.resolved:
        ctx.brand_resolved = True
        ctx.brand = brand.brand
        ctx.brand_domain = brand.domain
        ctx.brand_summary = brand.summary
        # Рыночное имя обязано попасть в варианты для поиска — иначе
        # публикации, где компанию называют только так, не найдутся
        ctx.name_variants = name_variants(*ctx.name_variants, brand.brand)

    # Пробелы в сборе. Каждое необязательное обогащение может не состояться,
    # и тогда соответствующее поле останется пустым. Пустое поле неотличимо
    # от «таких сведений не существует» — поэтому причина обязана дойти
    # до агента, а не потеряться здесь.
    gaps: list[str] = []

    # Масштаб — тоже необязательное
    if isinstance(finances, BaseException):
        gaps.append(
            f"Масштаб организации НЕ УСТАНОВЛЕН: ошибка источника "
            f"({type(finances).__name__}). Поля size_category, employees, "
            f"revenue_latest и capital пусты ПОТОМУ ЧТО проверка не состоялась, "
            f"а не потому что сведений нет. Не делай выводов о размере компании."
        )
    else:
        summary, finances_failure = finances
        if not summary:
            gaps.append(
                f"Масштаб организации НЕ УСТАНОВЛЕН: {finances_failure}. "
                f"Поля size_category, employees, revenue_latest и capital пусты "
                f"ПОТОМУ ЧТО проверка не состоялась, а не потому что сведений нет. "
                f"Не делай выводов о размере компании."
            )
        if summary:
            ctx.size_category = summary.size_category
            ctx.employees = summary.employees
            ctx.branches = summary.branches
            ctx.representative_offices = summary.representative_offices
            if summary.years:
                ctx.revenue_latest = summary.years[0].revenue
            # Бесплатный тариф справочника капитал не отдаёт — берём его из
            # карточки второго источника
            if summary.capital is not None and ctx.capital is None:
                ctx.capital = summary.capital

    # Прежние наименования обязаны попасть в варианты для поиска: организация
    # могла сменить название, и публикации о ней выходили под старым
    if isinstance(history, BaseException):
        gaps.append(
            f"Прежние наименования НЕ ПРОВЕРЕНЫ: ошибка источника "
            f"({type(history).__name__}). Пустой former_names здесь НЕ означает, "
            f"что организация не переименовывалась."
        )
    else:
        former, _, history_failure = history
        if history_failure:
            gaps.append(
                f"Прежние наименования НЕ ПРОВЕРЕНЫ: {history_failure}. "
                f"Пустой former_names здесь НЕ означает, что организация "
                f"не переименовывалась. Поиск публикаций пойдёт только по текущему "
                f"имени и может пропустить всё, что писали о ней раньше."
            )
        if former:
            ctx.former_names = former
            ctx.name_variants = name_variants(*ctx.name_variants, *former)

    # Расшифровка кода деятельности: на бесплатном тарифе карточка её
    # не содержит, поэтому берём из официального классификатора
    if ctx.okved_code and not ctx.okved_text:
        ctx.okved_text = await dd.resolve_okved_text(ctx.okved_code)

    log.info("context_built", inn=ctx.inn, brand=ctx.brand,
             size=ctx.size_category, variants=len(ctx.name_variants))

    if not ctx.brand_resolved:
        gaps.append("Рыночное наименование не установлено. Веб-поиск будет вестись "
                    "только по юридическому наименованию, и отсутствие негативных "
                    "находок НИЧЕГО НЕ ДОКАЖЕТ — обязательно оговори это в выводах.")

    # Отдельное состояние на случай, когда обязательный источник ответил,
    # а все обогащающие — нет: карточка есть, но она заведомо неполна,
    # и выдавать её за полную нельзя.
    return ContextResult(status="ok", reason=" ".join(gaps) or None, context=ctx)
