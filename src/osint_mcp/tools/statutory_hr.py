"""Кадровый профиль организации на основе официальных первичных документов и реестров.

Объединяет официальную среднесписочную численность работников (ССЧ ФНС),
выручку из бухгалтерской отчетности (ГИР БО) и текущую активность найма.
"""

from typing import Any
from osint_mcp.models import CompanyContext


def build_statutory_hr_profile(ctx: CompanyContext | None) -> dict[str, Any] | None:
    """Формирует кадровый срез на основе официальных документов и отчетности."""
    if not ctx:
        return None
    
    staff = ctx.employees
    revenue = ctx.revenue_latest
    hiring = ctx.hiring
    vacancies = hiring.open_vacancies if (hiring and hiring.open_vacancies is not None) else 0

    # Если нет ни данных о штате, ни вакансий — блок опускается
    if staff is None and vacancies == 0:
        return None

    productivity = round(revenue / staff) if (revenue and staff and staff > 0) else None

    hiring_ratio = None
    category = "не_определено"
    assessment = ""

    if staff and staff > 0:
        hiring_ratio = round((vacancies / staff) * 100, 2)
        if hiring_ratio == 0:
            category = "стабильный_штат"
            assessment = (
                f"Официальный штат {staff} чел. по данным ФНС. "
                "Открытых вакансий в текущем периоде нет: укомплектованность штата стабильна."
            )
        elif hiring_ratio <= 5.0:
            category = "плановая_ротация"
            assessment = (
                f"Официальный штат {staff} чел. (ФНС), {vacancies} открытых вакансий ({hiring_ratio}% от штата). "
                "Плановый режим естественной ротации кадров, признаков перегрева нет."
            )
        elif hiring_ratio <= 15.0:
            category = "активный_рост"
            assessment = (
                f"Официальный штат {staff} чел. (ФНС), {vacancies} открытых вакансий ({hiring_ratio}% от штата). "
                "Органическое расширение команд под рост объемов бизнеса и новые контракты."
            )
        elif hiring_ratio <= 30.0:
            category = "экспансия_или_текучесть"
            assessment = (
                f"Официальный штат {staff} чел. (ФНС), {vacancies} открытых позиций ({hiring_ratio}% от штата). "
                "Повышенная интенсивность найма: запуск новых направлений либо повышенная текучесть кадров."
            )
        else:
            category = "аномальный_найм"
            assessment = (
                f"Официальный штат {staff} чел. (ФНС), при этом открыто {vacancies} вакансий ({hiring_ratio}% от штата). "
                "Аномально высокая доля открытых позиций (>30% штата): масштабная экспансия или кадровый дефицит."
            )
    elif vacancies > 0:
        category = "активный_найм"
        assessment = (
            f"Открыто {vacancies} активных вакансий за последние 30 дней. "
            "Сведения о среднесписочной численности в налоговой отчетности не раскрыты (микробизнес / спецрежим)."
        )

    res: dict[str, Any] = {
        "официальный_штат_фнс": staff,
        "открыто_вакансий_30дней": vacancies,
        "динамика_найма": category,
        "оценка_кадрового_состояния": assessment,
        "первоисточник_документ": "ФНС России (Сведения о среднесписочной численности работников / РСВ) и ГИР БО",
    }
    if productivity is not None:
        res["выручка_на_сотрудника_руб"] = productivity
    if hiring_ratio is not None:
        res["доля_найма_к_штату_процент"] = hiring_ratio

    return res
