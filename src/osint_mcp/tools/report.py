"""Отчёт по организации: объём данных зависит от запроса.

Три режима:
  brief — карточка + вердикт: то, что менеджер читает перед решением;
  full  — всё, что система вообще собрала, включая детали карточки,
          финансовую историю со ссылками на отчётности ФНС, события истории;
  batch — список ИНН одним ответом, кратко по каждому: беглая разведка
          перед тем, как тратить квоту на полную проверку.

Полный режим НЕ запрашивает новых источников поверх штатного прогона:
collect_risk_facts и карточка опрашивают те же службы, что и раньше.
Разница режимов — в том, сколько собранного доходит до пользователя.
"""

from datetime import date, datetime, timezone

from osint_mcp.models import CompanyContext, RiskCollection
from osint_mcp.scoring.models import ScoreResult

# Порог «крупная компания» для массового адреса: у крупного бизнеса
# регистрация по адресу с другими организациями — норма (бизнес-центры),
# и упоминать её как риск — ошибка.
_MASS_ADDRESS_MAX_SIZE = "small"

_SIZE_ORDER = {"micro": 0, "small": 1, "medium": 2, "large": 3}


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


def _fmt_date(value: date | datetime | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    return value.isoformat()


def _size_rank(category: str | None) -> int:
    return _SIZE_ORDER.get(category or "unknown", 1)


def _relevant_mass_address(ctx: CompanyContext) -> list[str]:
    """Массовый адрес, отфильтрованный по масштабу.

    Для микро/малого бизнеса признак решает, для крупного неприменим.
    None-масштаб считаем малым: неизвестность не должна прятать признак.
    """
    extras = ctx.extras
    if not extras or not extras.mass_address_orgs:
        return []
    if _size_rank(ctx.size_category) > _SIZE_ORDER[_MASS_ADDRESS_MAX_SIZE]:
        return []
    return extras.mass_address_orgs


def _fin_lines(ctx: CompanyContext) -> list[str]:
    """Динамика финансов словами: то, что не видно из одного числа.

    Пустая история — не «финансов нет»: означает, что отчётности
    не сданы или источник не ответил; различать их обязан reason сборки.
    """
    lines: list[str] = []
    years = ctx.fin_history
    if years:
        latest = years[0]
        parts = [f"{latest.year}: выручка {_fmt_amount(latest.revenue)}"]
        if latest.profit is not None:
            sign = "прибыль" if latest.profit >= 0 else "убыток"
            parts.append(f"{sign} {_fmt_amount(abs(latest.profit))}")
        if latest.equity is not None and latest.equity < 0:
            parts.append(f"собственный капитал {_fmt_amount(latest.equity)} (отрицательный)")
        lines.append("; ".join(parts))
        if len(years) >= 2:
            prev = next((y for y in years[1:] if y.revenue is not None), None)
            if prev and prev.revenue and latest.revenue is not None:
                ratio = latest.revenue / prev.revenue
                if ratio <= 0.5:
                    lines.append(
                        f"выручка упала более чем вдвое: {_fmt_amount(prev.revenue)} "
                        f"({prev.year}) → {_fmt_amount(latest.revenue)} ({latest.year})"
                    )
                elif ratio >= 2.0:
                    lines.append(
                        f"выручка выросла более чем вдвое: {_fmt_amount(prev.revenue)} "
                        f"({prev.year}) → {_fmt_amount(latest.revenue)} ({latest.year})"
                    )
        # Отчётности по годам — прямые ссылки для проверки каждого числа
        urls = [f"{y.year}: {y.report_url}" for y in years if y.report_url]
        if urls:
            lines.append("отчётности ФНС: " + "; ".join(urls))
    if ctx.extras:
        e = ctx.extras
        bits = []
        if e.tax_debt:
            bits.append(f"задолженность по налогам {_fmt_amount(e.tax_debt)}")
        if e.tax_paid_total is not None:
            bits.append(f"уплачено налогов за {e.tax_year or '—'}: {_fmt_amount(e.tax_paid_total)}")
        if e.tax_mode:
            bits.append("режим: " + ", ".join(e.tax_mode))
        if bits:
            lines.append("; ".join(bits))
    return lines


def _extras_lines(ctx: CompanyContext) -> list[str]:
    """Детали карточки, важные для решения, одной строкой каждое."""
    lines: list[str] = []
    extras = ctx.extras
    if not extras:
        return lines
    if extras.address_unreliable:
        lines.append("адрес признан ФНС недостоверным")
    mass = _relevant_mass_address(ctx)
    if mass:
        lines.append(
            f"по адресу зарегистрировано ещё организаций: {len(mass)} "
            "(признак массового адреса)"
        )
    if extras.licenses:
        names = "; ".join(
            f"{lic.number}{f' ({lic.activity})' if lic.activity else ''}"
            for lic in extras.licenses[:5]
        )
        more = f" и ещё {len(extras.licenses) - 5}" if len(extras.licenses) > 5 else ""
        lines.append(f"лицензии: {names}{more}")
    contacts = extras.contacts
    if contacts:
        bits = []
        if contacts.website:
            bits.append(f"сайт {contacts.website}")
        if contacts.emails:
            bits.append("почта " + ", ".join(contacts.emails[:3]))
        if contacts.phones:
            bits.append("тел. " + ", ".join(contacts.phones[:3]))
        if bits:
            lines.append("; ".join(bits))
    return lines


def _event_lines(ctx: CompanyContext) -> list[str]:
    """События истории — кратко, свежие первыми."""
    if not ctx.events:
        return []
    lines = []
    for ev in sorted(ctx.events, key=lambda e: e.event_date or date.min, reverse=True)[:10]:
        lines.append(f"{ev.event_date.isoformat() if ev.event_date else '—'}: {ev.event}")
    return lines


def _full_sections(ctx: CompanyContext | None) -> list[dict]:
    """Секции полного отчёта, которых нет в кратком."""
    if ctx is None:
        return []
    sections: list[dict] = []
    fin = _fin_lines(ctx)
    if fin:
        sections.append({"название": "финансы и налоги", "пункты": fin})
    extras = _extras_lines(ctx)
    if extras:
        sections.append({"название": "лицензии, контакты, адрес", "пункты": extras})
    events = _event_lines(ctx)
    if events:
        sections.append({"название": "существенные события истории", "пункты": events})
    return sections


def _context_lines(ctx: CompanyContext) -> list[str]:
    """Общая часть краткого и полного отчёта: карточка по-человечески."""
    lines: list[str] = []
    if ctx.status and ctx.status != "Действует":
        lines.append(f"статус: {ctx.status}")
    okved = ctx.okved_text or (ctx.okved_code and f"ОКВЭД {ctx.okved_code}")
    if okved:
        lines.append(f"деятельность: {okved}")
    bits = []
    if ctx.employees is not None:
        bits.append(f"{ctx.employees} чел.")
    if ctx.revenue_latest is not None:
        bits.append(f"выручка {_fmt_amount(ctx.revenue_latest)}")
    if bits:
        lines.append("масштаб: " + ", ".join(bits))
    if ctx.registered_at:
        lines.append(f"зарегистрирована {_fmt_date(ctx.registered_at)}")
    if ctx.director_fio:
        lines.append(f"руководитель: {ctx.director_fio}")
    if ctx.former_names:
        lines.append("прежние наименования: " + "; ".join(ctx.former_names))
    return lines


def _summary_lines(risk: RiskCollection | None, score: ScoreResult) -> list[str]:
    """Сжатая выжимка рисков для краткого отчёта."""
    lines: list[str] = []
    if risk is None:
        lines.append("реестровые проверки не проводились")
        return lines
    if risk.coverage_note:
        lines.append(f"охват: {risk.coverage_note}")
    flags = [
        f["statement"] for res in risk.results for f in res.facts
        if f.kind == "registry_flag" and f.payload.get("flag")
    ]
    if flags:
        lines.extend(flags)
    for res in risk.results:
        if res.arbitration and res.arbitration.as_defendant.count:
            lines.append(
                f"ответчик по {res.arbitration.as_defendant.count} арбитражным делам "
                f"на {_fmt_amount(res.arbitration.as_defendant.total_amount)}"
            )
        if res.enforcement and res.enforcement.total:
            lines.append(
                f"исполнительных производств: {res.enforcement.total} "
                f"на {_fmt_amount(res.enforcement.outstanding or res.enforcement.total_amount)}"
            )
        if res.inspections and res.inspections.with_violations:
            lines.append(f"проверок с нарушениями: {res.inspections.with_violations}")
    return lines


def build_report(
    detail: str,
    context_result,   # ContextResult: обёртка со статусом и причиной
    risk: RiskCollection | None,
    score: ScoreResult,
) -> dict:
    """Собрать отчёт нужного объёма из уже собранных сведений.

    Никаких обращений к источникам — компоновка. Поля reason и coverage_note
    идут в отчёт всегда: сокращать можно объём данных, но не честность
    о том, чего проверка не охватила.
    """
    ctx = context_result.context if context_result else None

    if detail == "brief":
        report: dict = {
            "inn": score.inn or (ctx.inn if ctx else ""),
            "карточка": {},
            "вердикт": score.verdict.label,
            "score": score.verdict.total_score,
            "warnings": score.warnings,
        }
        if ctx is not None:
            report["карточка"] = {
                "наименование": ctx.name_legal,
                "ИНН": ctx.inn,
                "ОГРН": ctx.ogrn,
                **{k: v for k, v in {
                    "город": ctx.city,
                    "статус": ctx.status,
                    "деятельность": ctx.okved_text or ctx.okved_code,
                    "выручка_последний_год": ctx.revenue_latest,
                    "численность": ctx.employees,
                    "руководитель": ctx.director_fio,
                }.items() if v is not None},
            }
        if context_result and context_result.reason:
            report["что_не_собралось"] = context_result.reason
        report["риски_кратко"] = _summary_lines(risk, score)
        if score.reasons:
            report["основания"] = score.reasons
        report["scored_at"] = score.scored_at.isoformat()
        return report

    # full: краткое ядро плюс всё остальное
    report = build_report("brief", context_result, risk, score)
    report.pop("scored_at", None)

    report["карточка"]["адрес"] = ctx.address_full if ctx else None
    if ctx is not None:
        report["карточка"]["учредители"] = ctx.founders
        if ctx.brand_resolved:
            report["карточка"]["рыночное_наименование"] = ctx.brand
            report["карточка"]["сайт"] = ctx.brand_domain or (
                ctx.extras.contacts.website if ctx.extras and ctx.extras.contacts else None
            )
            if ctx.social_links:
                report["карточка"]["соцсети"] = ctx.social_links
            if ctx.brand_summary:
                report["карточка"]["описание"] = ctx.brand_summary
        if ctx.size_category != "unknown":
            report["карточка"]["масштаб"] = ctx.size_category

    report["разбор"] = _full_sections(ctx)
    if risk is not None:
        report["источники"] = [
            {"source": r.source, "status": r.status,
             **({"reason": r.reason} if r.reason else {})}
            for r in risk.results
        ]
    report["pending"] = [p.model_dump(mode="json") for p in score.pending]
    if score.unmatched_fact_kinds:
        report["факты_без_критерия"] = score.unmatched_fact_kinds
    report["scored_at"] = score.scored_at.isoformat()
    return report


def build_batch_entry(
    context_result,
    risk: RiskCollection | None,
    score: ScoreResult,
) -> dict:
    """Одна строка пакетного отчёта: вердикт, суть, главные оговорки."""
    ctx = context_result.context if context_result else None
    entry: dict = {
        "inn": score.inn or (ctx.inn if ctx else ""),
        "вердикт": score.verdict.label,
        "score": score.verdict.total_score,
    }
    if ctx is not None:
        entry["наименование"] = ctx.name_legal
        entry["статус"] = ctx.status
        entry["город"] = ctx.city
    if score.warnings:
        entry["warnings"] = score.warnings[:3]
    if context_result and context_result.reason:
        entry["что_не_собралось"] = context_result.reason
    elif risk is not None and risk.coverage_note:
        entry["охват"] = risk.coverage_note
    summary = _summary_lines(risk, score)
    if summary:
        entry["риски_кратко"] = summary[:5]
    if score.reasons:
        entry["основания"] = score.reasons[:3]
    return entry
