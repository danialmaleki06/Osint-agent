"""Профиль контрагента: деловое резюме для менеджера.

Не «детская карточка» и не пересчёт данных — структурированный свод
уже собранных сведений в порядке, в котором их читает менеджер перед
решением: кто перед ним, чем занимается, каково состояние, что решать.
Тон официально-деловой, без упрощений и без «продающих» формулировок.
"""

from datetime import date, datetime, timezone

from osint_mcp.models import CompanyContext, RiskCollection
from osint_mcp.scoring import ScoreResult

_SIZE_LABEL = {
    "micro": "микропредприятие",
    "small": "малое предприятие",
    "medium": "среднее предприятие",
    "large": "крупное предприятие",
}

_STATUS_NOTE = {
    "Действует": None,
}


def _fmt_amount(value: float | None) -> str:
    if value is None:
        return "нет данных"
    v = float(value)
    if v >= 1_000_000_000:
        return f"{v / 1_000_000_000:.1f} млрд ₽"
    if v >= 1_000_000:
        return f"{v / 1_000_000:.1f} млн ₽"
    if v >= 1_000:
        return f"{v / 1_000:.0f} тыс ₽"
    return f"{v:.0f} ₽"


def _fmt_num(value: float) -> str:
    if float(value).is_integer():
        return f"{int(value):,}".replace(",", " ")
    return f"{value:,.1f}".replace(",", " ")


def _activity_line(ctx: CompanyContext) -> str:
    """Чем занимается: ОКВЭД-формулировка + размер. Одна строка.

    ОКВЭД-текст из DaData — первичен (человеческая формулировка);
    если пуст, берём из Checko. Размер — из size_category.
    """
    parts = []
    okved = ctx.okved_text or (ctx.okved_code and f"ОКВЭД {ctx.okved_code}")
    if okved:
        parts.append(okved)
    if ctx.size_category in _SIZE_LABEL:
        parts.append(_SIZE_LABEL[ctx.size_category])
    elif ctx.size_category == "unknown":
        parts.append("масштаб не определён (нет сопоставимой отчётности)")
    return ", ".join(parts) or "вид деятельности не раскрыт"


def _scale_line(ctx: CompanyContext) -> str:
    """Численность/филиалы — только то, что реально известно."""
    parts = []
    if ctx.employees is not None:
        parts.append(f"среднесписочная численность {_fmt_num(ctx.employees)} чел.")
    if ctx.revenue_latest is not None:
        parts.append(f"выручка за последний отчётный год {_fmt_amount(ctx.revenue_latest)}")
    if ctx.capital is not None:
        parts.append(f"уставный капитал {_fmt_amount(ctx.capital)}")
    if ctx.branches:
        pl = "" if ctx.branches == 1 else "а"
        parts.append(f"{_fmt_num(ctx.branches)} филиал{pl}")
    if ctx.representative_offices:
        pl = "" if ctx.representative_offices == 1 else "а"
        parts.append(f"{_fmt_num(ctx.representative_offices)} представительств{pl}")
    return "; ".join(parts)


def _management_line(ctx: CompanyContext) -> str:
    """Руководство и учредители."""
    parts = []
    if ctx.director_fio:
        post = f" ({ctx.director_post})" if ctx.director_post else ""
        parts.append(f"руководитель — {ctx.director_fio}{post}")
    if ctx.founders:
        n = len(ctx.founders)
        pl = "" if n == 1 else "а" if n < 5 else "ей" if False else "а" if n % 10 == 1 and n % 100 != 11 else "ов"
        parts.append(f"учредител{pl}: {n}")
    return "; ".join(parts)


def _registration_line(ctx: CompanyContext) -> str:
    parts = [f"зарегистрирована {ctx.registered_at.strftime('%d.%m.%Y')}"
             if ctx.registered_at else "дата регистрации не установлена"]
    if ctx.region or ctx.city:
        where = ", ".join(x for x in (ctx.region, ctx.city) if x)
        parts.append(f"регион — {where}")
    if ctx.former_names:
        n = len(ctx.former_names)
        parts.append(f"прежних наименований: {n} (компания меняла название)")
    return "; ".join(parts)


def build_profile(
    context: CompanyContext | None,
    risk: RiskCollection | None,
    score: ScoreResult,
) -> dict:
    """Свод для менеджера: секции в порядке принятия решения.

    Никаких новых данных — только перекомпоновка уже полученных.
    Каждый тезис сохраняет связь с fact_id/источниками через исходные
    структуры, которые агент прикладывает к ответу.
    """
    now = datetime.now(timezone.utc)

    # ── 1. Субъект ──
    if context is not None:
        subject = {
            "наименование": context.name_legal,
            "ИНН": context.inn,
            "ОГРН": context.ogrn,
            "статус": context.status or "не установлен",
            "деятельность": _activity_line(context),
            "масштаб и показатели": _scale_line(context) or "нет данных",
            "руководство": _management_line(context) or "нет данных",
            "регистрация": _registration_line(context),
            "адрес": context.address_full,
        }
    else:
        subject = {
            "наименование": None,
            "ИНН": score.inn,
            "примечание": "карточка не собрана — реестр не отвечал; "
                          "сведения ниже неполны",
        }

    # ── 2. Проверки: источник, охват, честно о пробелах ──
    checks = {}
    if risk is not None:
        checks["источников ответило"] = f"{risk.sources_ok} из {risk.sources_ok + risk.sources_failed}"
        if risk.coverage_note:
            checks["охват"] = risk.coverage_note
        flags = [f["statement"] for res in risk.results for f in res.facts
                 if f.kind == "registry_flag" and f.payload.get("flag")]
        if flags:
            checks["реестровые отметки"] = flags

    # ── 3. Судебная нагрузка и долги ──
    litigation = {}
    for res in (risk.results if risk else []):
        if res.arbitration:
            a = res.arbitration
            litigation["арбитраж"] = (
                f"дел: {a.total}"
                + (f", в роли ответчика: {a.as_defendant.count} на сумму "
                   f"{_fmt_amount(a.as_defendant.total_amount)}" if a.as_defendant.count else "")
                + (f", в роли истца: {a.as_plaintiff.count}" if a.as_plaintiff.count else "")
                + (f", активных: {a.active_cases}" if a.active_cases else "")
            )
        if res.enforcement:
            e = res.enforcement
            litigation["исполнительные производства"] = (
                f"{e.total} на сумму {_fmt_amount(e.total_amount)}"
                + (f", непогашено {_fmt_amount(e.outstanding)}" if e.outstanding else "")
            )
        if res.inspections:
            insp = res.inspections
            litigation["надзорные проверки"] = (
                f"{insp.total}, с нарушениями: {insp.with_violations}"
            )

    # ── 4. Вердикт ──
    # Балл и версия правил — служебные сведения (для аудита и логов).
    # Менеджеру они не нужны: его язык — вердикт и факты за ним.
    verdict_block = {
        "оценка": score.verdict.label,
    }
    if score.verdict.floored:
        verdict_block["ограничение"] = (
            f"оценка ограничена уровнем «{score.verdict.label}»: "
            f"сработал запретительный критерий «{score.verdict.floor_criterion}»"
        )
    if score.reasons:
        verdict_block["основания"] = score.reasons
    if score.warnings:
        verdict_block["требует внимания"] = score.warnings

    return {
        "subject": subject,
        "checks": checks,
        "litigation": litigation,
        "verdict": verdict_block,
        "pending": [p.model_dump(mode="json") for p in score.pending],
        "unmatched_fact_kinds": score.unmatched_fact_kinds,
        "scored_at": now.isoformat(),
    }
