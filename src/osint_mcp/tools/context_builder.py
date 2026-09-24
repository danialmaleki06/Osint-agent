"""Сборка полного контекста компании из нескольких источников.

Контекст собирается из трёх независимых обращений, выполняемых параллельно:
  реестровая карточка  — DaData, бесплатно;
  рыночное наименование — DaData, платный метод;
  масштаб организации   — Checko, финансовая отчётность и численность.

Ни одно из них не является обязательным: отказ любого источника ухудшает
полноту, но не отменяет результат. Недостающее помечается явно.
"""

import asyncio
from datetime import date, datetime

import structlog

from osint_mcp.context.bo_nalog import BoNalogSource
from osint_mcp.context.checko import CheckoSource
from osint_mcp.context.dadata import DaDataSource
from osint_mcp.context.egrul import EgrulSource, brief_from_egrul
from osint_mcp.context.hh import HhSource
from osint_mcp.context.rmsp import RmspSource
from osint_mcp.models import CompanyContext, ContextResult, TimelineEvent
from osint_mcp.tools.country import detect_country
from osint_mcp.tools.names import name_variants

log = structlog.get_logger()


def _context_from_egrul(inn: str, row: dict) -> CompanyContext:
    """Минимальная карточка из краткой выдачи сервиса ЕГРЮЛ.

    Последний эшелон, когда не ответили ни DaData, ни Checko: наименование,
    руководитель и дата регистрации есть, всё остальное остаётся пустым —
    и об этом честно говорит reason сборки.
    """
    brief = brief_from_egrul(row)
    return CompanyContext(
        inn=inn,
        ogrn=brief["ogrn"],
        name_legal=brief["name_legal"] or inn,
        name_short=brief["name_short"],
        registered_at=brief["registered_at"],
        director_fio=brief["director_fio"],
        director_post=brief["director_post"],
        region=brief["region"],
        brand_resolved=False,
        source="egrul",
    )


def _parse_event_date(value) -> "date | None":
    """Дата события из источника: ISO-строка либо None.

    Строка, не разобравшаяся в дату, дату не обнуляет — событие ценнее
    своей неточности.
    """
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return None
    return None


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

    base_res, brand, finances, history, msp_res = await asyncio.gather(
        dd.get_context(inn),
        dd.get_brand(inn),
        ck.get_finances(inn),
        ck.get_name_history(inn),
        # Реестр МСП — бесплатный источник ФНС: квот платных справочников
        # не расходует, опрашивается всегда
        RmspSource().get_msp(inn),
        return_exceptions=True,
    )

    # Реестровая карточка обязательна: без неё контекста нет. Но если DaData
    # недоступна (нет ключа, лимит, сбой), карточку собирает Checko — он
    # отдаёт те же реестровые сведения. Источники независимы: молчание
    # одного не должно ронять проверку целиком.
    base_ctx = None
    base_reason = None
    if not isinstance(base_res, BaseException) and base_res.status == "ok" and base_res.context:
        base_ctx = base_res.context
    else:
        if isinstance(base_res, BaseException):
            base_reason = f"Ошибка источника DaData: {type(base_res).__name__}"
        else:
            base_reason = base_res.reason
        fallback = await ck.get_context(inn)
        if fallback.status == "ok" and fallback.context:
            base_ctx = fallback.context
            base_ctx.brand_resolved = False
            _fallback_note = (
                f"Базовая карточка собрана Checko (DaData недоступна: {base_reason})."
            )
        elif fallback.status == "unavailable":
            # Третий эшелон: сервис ЕГРЮЛ напрямую. Данных меньше, но для
            # краткого отчёта и пакета хватает, а проверка не срывается
            # из-за исчерпанных квот двух платных справочников.
            row, egrul_failure = await EgrulSource().get_card(inn)
            if row:
                base_ctx = _context_from_egrul(inn, row)
                base_ctx.brand_resolved = False
                _fallback_note = (
                    f"Базовая карточка собрана напрямую из сервиса ЕГРЮЛ: "
                    f"DaData недоступна ({base_reason}), Checko недоступен "
                    f"({fallback.reason}). Данных в карточке минимум — "
                    f"масштаб, финансы и связи НЕ ПРОВЕРЕНЫ."
                )
            elif fallback.status == "unavailable":
                base_reason = (
                    f"DaData: {base_reason}; Checko: {fallback.reason}; "
                    f"ЕГРЮЛ: {egrul_failure}"
                )
        elif fallback.status == "ok":
            # Оба ответили «не найдено» — DaData тоже не нашла либо её не было.
            return ContextResult(
                status="ok",
                reason=(f"Организация не найдена в реестре ({base_reason or 'DaData не ответила данными'}; "
                        f"проверка Checko: {fallback.reason})"),
            )
        else:
            if isinstance(base_res, BaseException):
                return ContextResult(status="unavailable",
                                     reason=f"Ошибка источника: {type(base_res).__name__}")
            return base_res

    ctx = base_ctx

    # Рыночное наименование — необязательное обогащение
    if not isinstance(brand, BaseException) and brand.resolved:
        ctx.brand_resolved = True
        ctx.brand = brand.brand
        ctx.brand_domain = brand.domain
        ctx.brand_summary = brand.summary
        # Официальные аккаунты идут придатком к рыночному имени: тем же
        # платным вызовом, выбрасывать их — выбрасывать оплаченное.
        if brand.social_links:
            ctx.social_links = brand.social_links
        # Рыночное имя обязано попасть в варианты для поиска — иначе
        # публикации, где компанию называют только так, не найдутся
        ctx.name_variants = name_variants(*ctx.name_variants, brand.brand)

    # Найм — сигнал направления: что компания ищет и куда растёт. Ищем
    # по рыночному имени (под ним работодатель обычно и зарегистрирован
    # на hh), при его отсутствии — по краткому юридическому. Источник
    # бесплатен, исключений наружу не бросает: отказ приходит в reason.
    search_name = ((ctx.brand or ctx.name_short) if ctx.brand_resolved
                   else ctx.name_short) or ctx.name_legal
    ctx.hiring = await HhSource().get_hiring(search_name)

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
            # Финансовая история целиком: оценивать устойчивость по одному
            # году нельзя — падение выручки и уход в убыток видны только
            # в динамике.
            ctx.fin_history = summary.years
            ctx.extras = summary.extras
            # Бесплатный тариф справочника капитал не отдаёт — берём его из
            # карточки второго источника
            if summary.capital is not None and ctx.capital is None:
                ctx.capital = summary.capital
        elif not isinstance(finances, BaseException):
            # Финансы из платного справочника не получены — переходим на
            # ГИР БО: бесплатный официальный ресурс ФНС, ключей не требует.
            # Динамика выручки и активов спасена даже при исчерпанной квоте.
            try:
                bo_years, bo_failure = await BoNalogSource().get_finances(inn)
            except Exception as e:                              # noqa: BLE001
                # Фолбэк не может быть важнее карточки: неожиданная ошибка
                # бесплатного источника не роняет собранный контекст
                bo_years, bo_failure = None, f"ошибка обращения: {type(e).__name__}"
            if bo_years:
                ctx.fin_history = bo_years
                if bo_years[0].revenue is not None:
                    ctx.revenue_latest = bo_years[0].revenue
                # Масштаб остаётся unknown: без численности категории МСП
                # по выручке одной мы не присваиваем — это делает скоринг
                # по своему правилу, если решит иначе.
                gaps.append(
                    "Финансовая история собрана из ГИР БО (бесплатный ресурс "
                    "ФНС): выручка и активы по годам есть, прибыль и численность "
                    f"НЕ УСТАНОВЛЕНЫ ({finances_failure})."
                )
            else:
                gaps.append(
                    f"Масштаб и финансы НЕ УСТАНОВЛЕНЫ: {finances_failure}. "
                    f"ГИР БО тоже не ответил: {bo_failure}. Поля size_category, "
                    f"employees, revenue_latest и capital пусты ПОТОМУ ЧТО "
                    f"проверка не состоялась, а не потому что сведений нет. "
                    f"Не делай выводов о размере компании."
                )

    # Прежние наименования обязаны попасть в варианты для поиска: организация
    # могла сменить название, и публикации о ней выходили под старым
    if isinstance(history, BaseException):
        gaps.append(
            f"Прежние наименования НЕ ПРОВЕРЕНЫ: ошибка источника "
            f"({type(history).__name__}). Пустой former_names здесь НЕ означает, "
            f"что организация не переименовывалась."
        )
    else:
        former, notable, history_failure = history
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
        # Существенные события истории: смены руководителя, учредителей,
        # адреса, реорганизация. Раньше отбрасывались, а частая перетасовка
        # руководства — классический признак проблемы.
        ctx.events = [
            TimelineEvent(
                event_date=_parse_event_date(rec.get("date")),
                event=rec.get("event") or "",
            )
            for rec in notable or []
            if rec.get("event")
        ]

    # Реестр МСП: бесплатное независимое подтверждение масштаба. None
    # означает «не значится» — для крупного бизнеса это норма, для малого
    # странность, повод перепроверить. Отказ источника — пробел в сборе.
    if isinstance(msp_res, BaseException):
        gaps.append(
            f"Реестр МСП НЕ ПРОВЕРЕН: ошибка источника ({type(msp_res).__name__})."
        )
    else:
        msp, msp_failure = msp_res
        if msp is not None:
            ctx.msp = msp
            if msp.category and ctx.size_category == "unknown":
                # Категорию реестра можно брать только у действующего
                # субъекта. Живой прогон поймал обратное: компания,
                # исключённая из МСП в 2024-м (переросла реестр: 386
                # сотрудников), приходила как «micro» — реестр хранит
                # историческую запись целиком. Численность при этом
                # пригодна и после исключения: это факт, а не статус.
                if msp.is_active:
                    ctx.size_category = msp.category
                    if msp.employees is not None and ctx.employees is None:
                        ctx.employees = msp.employees
                else:
                    if msp.employees is not None and ctx.employees is None:
                        ctx.employees = msp.employees
                    gaps.append(
                        "Организация ИСКЛЮЧЕНА из реестра МСП "
                        f"{(msp.excluded_at.isoformat() if msp.excluded_at else 'дата неизвестна')} — "
                        "её категория в реестре устарела и не использована. "
                        "Масштаб оценивай по выручке и численности из финансовой "
                        "истории, а не по size_category."
                    )
        elif msp_failure:
            gaps.append(f"Реестр МСП НЕ ПРОВЕРЕН: {msp_failure}.")

    # Расшифровка кода деятельности: классификатор тянет через DaData.
    # При её недоступности — локальный okved-справочник уже дал текст в
    # fallback-карточке Checko (поле ОКВЭД.Наим), повторный вызов не нужен.
    if ctx.okved_code and not ctx.okved_text and ctx.source == "dadata":
        ctx.okved_text = await dd.resolve_okved_text(ctx.okved_code)

    log.info("context_built", inn=ctx.inn, brand=ctx.brand,
             size=ctx.size_category, variants=len(ctx.name_variants))

    if not ctx.brand_resolved:
        gaps.append("Рыночное наименование не установлено. Веб-поиск будет вестись "
                    "только по юридическому наименованию, и отсутствие негативных "
                    "находок НИЧЕГО НЕ ДОКАЖЕТ — обязательно оговори это в выводах.")

    try:
        gaps.insert(0, _fallback_note)   # noqa: F821 — определена только при fallback
    except NameError:
        pass

    # Отдельное состояние на случай, когда обязательный источник ответил,
    # а все обогащающие — нет: карточка есть, но она заведомо неполна,
    # и выдавать её за полную нельзя.
    return ContextResult(status="ok", reason=" ".join(gaps) or None, context=ctx)
