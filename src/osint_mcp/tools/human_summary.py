"""Человеческий переводчик отчёта (Human-friendly summary and translation).

Переводит сухие чиновничьи данные, реестровые коды и аббревиатуры
(ОКВЭД, ССЧ, ГИР БО, ФССП, РНП, ФСТЭК, ROS) на простой, понятный
человеку язык.

Формирует:
  1. TL;DR («Суть в трёх предложениях») на самом верху отчёта.
  2. Ответы на 3 ключевых вопроса:
     - Кто это и чем зарабатывают?
     - Безопасно ли сотрудничать?
     - Что происходит в компании сейчас?
  3. Понятные расшифровки показателей и сюжетные карточки судов и инцидентов.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from osint_mcp.models import CompanyContext, RiskCollection
    from osint_mcp.scoring.models import ScoreResult


def _fmt_rub(val: float | None) -> str:
    if val is None:
        return "нет данных"
    v = float(val)
    if abs(v) >= 1_000_000_000:
        return f"{v / 1_000_000_000:.1f} млрд ₽"
    if abs(v) >= 1_000_000:
        return f"{v / 1_000_000:.1f} млн ₽"
    if abs(v) >= 1_000:
        return f"{v / 1_000:.0f} тыс ₽"
    return f"{v:.0f} ₽"


_SIZE_HUMAN = {
    "micro": "микробизнес (до 15 сотрудников)",
    "small": "малый бизнес (до 100 сотрудников)",
    "medium": "средний бизнес (до 250 сотрудников)",
    "large": "крупный бизнес (более 250 сотрудников)",
}


def _clean_profile_text(text: str | None) -> str:
    """Убирает чиновничий канцелярит из наименования деятельности."""
    if not text:
        return "коммерческая деятельность"
    s = text.strip()
    s = re.sub(r"^(?:деятельность\s+(?:по|в\s+области|в\s+сфере)\s+)", "", s, flags=re.IGNORECASE)
    return s[:1].lower() + s[1:] if s else s


def build_human_summary(
    ctx: "CompanyContext | None",
    risk: "RiskCollection | None",
    score: "ScoreResult",
) -> dict[str, Any]:
    """Сформировать человекочитаемое резюме и ответы на 3 ключевых вопроса."""
    is_ip = False
    name = "Организация"
    city = "России"
    profile = "коммерческая деятельность"
    age_str = ""
    status_str = "Действует"
    size_desc = "бизнес"
    employees = None
    rev_fmt = None
    brand = None

    if ctx is not None:
        is_ip = len(str(ctx.inn or "")) == 12 or getattr(ctx, "entity_type", "") == "individual_entrepreneur"
        name = ctx.name_legal or ("Индивидуальный предприниматель" if is_ip else "Организация")
        brand = ctx.brand if ctx.brand_resolved else None
        city = ctx.city or "России"
        if ctx.okved_text:
            profile = _clean_profile_text(ctx.okved_text)
        elif ctx.okved_code:
            profile = f"профиль ОКВЭД {ctx.okved_code}"
        status_str = ctx.status or "Действует"
        size_desc = _SIZE_HUMAN.get(ctx.size_category, "бизнес")
        employees = ctx.employees
        if ctx.revenue_latest is not None:
            rev_fmt = _fmt_rub(ctx.revenue_latest)

        if ctx.registered_at:
            years_on_market = max(0, (date.today() - ctx.registered_at).days // 365)
            if years_on_market >= 1:
                age_str = f"на рынке {years_on_market} лет (с {ctx.registered_at.year} года)"
            else:
                age_str = f"зарегистрирована в {ctx.registered_at.year} году (молодой бизнес)"

    # Финансовые показатели
    fin_years = ctx.fin_history if ctx else None
    latest_fin = fin_years[0] if fin_years else None
    profit = latest_fin.profit if latest_fin else None
    equity = latest_fin.equity if latest_fin else None
    tax_debt = (ctx.extras.tax_debt if (ctx and ctx.extras) else 0.0) or 0.0

    # Судебные споры
    def_count = 0
    def_amount = 0.0
    plaintiff_count = 0
    plaintiff_amount = 0.0
    enforce_count = 0
    enforce_amount = 0.0

    if risk is not None:
        for res in risk.results:
            if res.arbitration:
                if res.arbitration.as_defendant:
                    def_count += res.arbitration.as_defendant.count or 0
                    def_amount += res.arbitration.as_defendant.total_amount or 0.0
                if res.arbitration.as_plaintiff_active:
                    plaintiff_count += res.arbitration.as_plaintiff_active.count or 0
                    plaintiff_amount += res.arbitration.as_plaintiff_active.total_amount or 0.0
            if res.enforcement:
                enforce_count += res.enforcement.total or 0
                enforce_amount += (res.enforcement.outstanding or res.enforcement.total_amount or 0.0)

    # 1. TL;DR ("Суть в трёх предложениях")
    brand_hint = f' (бренд «{brand}»)' if brand else ''
    if is_ip:
        p1 = f"{name} — действующий индивидуальный предприниматель из {city}, основное направление: {profile}"
        if age_str:
            p1 += f" ({age_str})"
        p1 += "."
    elif status_str != "Действует":
        p1 = f"{name}{brand_hint} — организация из {city} находится в статусе «{status_str}» (деятельность не ведётся либо находится в процессе ликвидации)."
    else:
        bits = [f"{name}{brand_hint} — действующий {size_desc} из {city}"]
        if profile:
            bits.append(f"направление: {profile}")
        tail = []
        if rev_fmt:
            tail.append(f"годовой оборот {rev_fmt}")
        if employees:
            tail.append(f"штат {employees} сотрудников")
        if tail:
            bits.append("со статистикой: " + ", ".join(tail))
        p1 = ", ".join(bits) + "."

    p2_parts = []
    if profit is not None:
        if profit >= 0:
            p2_parts.append(f"бизнес прибыльный (чистая прибыль {_fmt_rub(profit)})")
        else:
            p2_parts.append(f"зафиксирован чистый убыток {_fmt_rub(abs(profit))}")
    if equity is not None and equity < 0:
        p2_parts.append(f"собственный капитал отрицательный ({_fmt_rub(equity)}, долги превышают активы)")

    if tax_debt > 10_000:
        p2_parts.append(f"имеется налоговая задолженность {_fmt_rub(tax_debt)}")
    else:
        p2_parts.append("долгов перед налоговой нет")

    if enforce_count > 0:
        p2_parts.append(f"у приставов открыто {enforce_count} производств на {_fmt_rub(enforce_amount)}")
    else:
        p2_parts.append("счета свободны от арестов приставов")

    if def_count > 0:
        p2_parts.append(f"в судах выступает ответчиком по искам на {_fmt_rub(def_amount)}")

    p2 = "; ".join(p2_parts).capitalize() + "." if p2_parts else "Финансовые и реестровые данные в норме."

    label = score.verdict.label
    if label == "хорошо":
        p3 = "Критических стоп-факторов не обнаружено, сотрудничество оценивается как надёжное и безопасное."
    elif label == "удовлетворительно":
        p3 = "Риск умеренный: базовые требования соблюдены, перед крупными сделками достаточно запросить стандартный комплект закрывающих документов."
    elif label == "рискованно":
        p3 = "Повышенный риск: выявлены чувствительные факторы (суды, долги или падение показателей), безопаснее работать по предоплате."
    else:
        p3 = "Критический риск: присутствуют блокирующие реестровые факторы или риск несостоятельности, заключать сделки не рекомендуется."

    tldr = f"{p1} {p2} {p3}"

    # 2. Ответы на 3 ключевых вопроса
    q1_lines = [
        f"• Форма и статус: {name}{brand_hint}, {'индивидуальный предприниматель' if is_ip else 'юридическое лицо'} ({status_str}).",
    ]
    if age_str:
        q1_lines.append(f"• Опыт на рынке: {age_str}.")
    q1_lines.append(f"• Чем занимаются: {profile}.")
    scale_facts = []
    if employees:
        scale_facts.append(f"штат {employees} человек")
    if rev_fmt:
        scale_facts.append(f"выручка {rev_fmt}")
    if scale_facts:
        q1_lines.append(f"• Масштаб деятельности: {', '.join(scale_facts)} ({size_desc}).")
    if ctx and ctx.city:
        q1_lines.append(f"• География: {ctx.city}.")

    q2_lines = [
        f"• Доходность и запас прочности: {p2_parts[0] if p2_parts else 'данные о прибыли не раскрыты'}.",
    ]
    if tax_debt > 10_000:
        q2_lines.append(f"• Налоговая дисциплина: ⚠️ задолженность {_fmt_rub(tax_debt)} перед ФНС.")
    else:
        q2_lines.append("• Налоговая дисциплина: 🟢 долгов перед ФНС нет, налоги уплачиваются вовремя.")

    if enforce_count > 0:
        q2_lines.append(f"• Взыскания приставов (ФССП): ⚠️ {enforce_count} производств на {_fmt_rub(enforce_amount)}.")
    else:
        q2_lines.append("• Взыскания приставов (ФССП): 🟢 исполнительных производств нет, аресты на счета не накладывались.")

    if def_count > 0:
        q2_lines.append(f"• Судебная нагрузка: выступает ответчиком в арбитраже по искам на {_fmt_rub(def_amount)}.")
    else:
        q2_lines.append("• Судебная нагрузка: 🟢 крупных судебных споров с контрагентами не зафиксировано.")

    rnp_flag = any(
        f.payload.get("flag") == "rnp"
        for res in (risk.results if risk else [])
        for f in res.facts
        if f.kind == "registry_flag"
    )
    if rnp_flag:
        q2_lines.append("• Черный список поставщиков (РНП): ⛔ числится в реестре недобросовестных поставщиков.")
    else:
        q2_lines.append("• Черный список поставщиков (РНП): 🟢 в черном списке не числится, допущен к любым закупкам.")

    q2_lines.append(f"• Резюме надежности: {p3}")

    q3_lines = []
    if fin_years and len(fin_years) >= 2:
        y1, y2 = fin_years[0], fin_years[1]
        if y1.revenue and y2.revenue and y2.revenue > 0:
            growth = ((y1.revenue - y2.revenue) / y2.revenue) * 100
            if growth > 5:
                q3_lines.append(f"• Динамика выручки: 📈 рост на {growth:.0f}% по сравнению с прошлым годом.")
            elif growth < -5:
                q3_lines.append(f"• Динамика выручки: 📉 спад на {abs(growth):.0f}% по сравнению с прошлым годом.")
            else:
                q3_lines.append(f"• Динамика выручки: ⚖️ стабильные обороты (динамика {growth:.0f}%).")

    if plaintiff_count > 0:
        q3_lines.append(f"• Претензии к клиентам: компания сама судится и требует {_fmt_rub(plaintiff_amount)} за выполненные работы (возможен кассовый разрыв).")

    if ctx and ctx.former_names:
        q3_lines.append(f"• Смена названий: ранее была известна как «{'; '.join(ctx.former_names)}».")

    if not q3_lines:
        q3_lines.append("• Текущая активность: стабильный рабочий ритм без резких судебных или кадровых скачков.")

    # 3. Переводчик терминов
    glossary = {
        "основной_профиль": f"{profile} (код ОКВЭД {ctx.okved_code if ctx else ''})".strip(),
        "масштаб_бизнеса": size_desc,
        "официальный_штат": f"{employees} сотрудников (данные ФНС)" if employees else "не указан в открытых источниках",
        "налоговый_статус": f"Задолженность {_fmt_rub(tax_debt)}" if tax_debt > 10_000 else "Задолженностей перед бюджетом нет (чисто)",
        "судебные_приставы_фссп": f"Открыто производств на {_fmt_rub(enforce_amount)}" if enforce_count > 0 else "0 ₽ — принудительных взысканий нет, счета свободны",
        "черный_список_рнп": "Числится (высокий риск)" if rnp_flag else "Не числится (полная благонадежность в закупках)",
    }

    return {
        "суть_в_трех_предложениях": tldr,
        "ответы_на_главные_вопросы": {
            "1_кто_это_и_чем_занимаются": "\n".join(q1_lines),
            "2_безопасно_ли_сотрудничать": "\n".join(q2_lines),
            "3_что_происходит_сейчас": "\n".join(q3_lines),
        },
        "переводчик_терминов": glossary,
    }


def build_human_court_cases(risk: "RiskCollection | None") -> list[dict[str, Any]]:
    """Преобразует арбитражные дела в понятные сюжетные карточки."""
    if risk is None:
        return []
    cases = []
    for res in risk.results:
        arb = res.arbitration
        if not arb:
            continue
        if arb.as_defendant and arb.as_defendant.count:
            cnt = arb.as_defendant.count
            amt = arb.as_defendant.total_amount or 0.0
            cases.append({
                "роль": "Ответчик (с компании требуют деньги)",
                "дел": cnt,
                "сумма": _fmt_rub(amt),
                "суть_простыми_словами": (
                    f"Контрагенты обратились в суд и взыскивают {_fmt_rub(amt)}. "
                    "Это может свидетельствовать о задержках оплат или претензиях к качеству. "
                    "Рекомендуется работать по предоплате."
                ),
            })
        if arb.as_plaintiff_active and arb.as_plaintiff_active.count:
            cnt = arb.as_plaintiff_active.count
            amt = arb.as_plaintiff_active.total_amount or 0.0
            cases.append({
                "роль": "Истец (компания сама взыскивает долги с клиентов)",
                "дел": cnt,
                "сумма": _fmt_rub(amt),
                "суть_простыми_словами": (
                    f"Компания судится с заказчиками и требует выплатить {_fmt_rub(amt)} за работы или товары. "
                    "Деньги поступают с задержками, возможен временный дефицит ликвидности."
                ),
            })
    return cases
