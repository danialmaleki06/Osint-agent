"""Легковесный срез корпоративных связей 1-го уровня (Affiliations Lite).

Формирует структуру владения и контроля без тяжелых рекурсивных графовых обходов:
- Руководство и управляющие организации
- Учредители, доли владения и материнская компания
- Тип бенефициарного контроля (частный, холдинг, госучастие, офшор)
- Прямые дочерние организации
"""

from typing import Any
from osint_mcp.models import CompanyContext

# Список распространенных офшорных и зарубежных юрисдикций
_OFFSHORE_KEYWORDS = (
    "кипр", "cyprus", "limassol", "nicosia", "bvi", "british virgin",
    "виргинск", "сейшел", "seychelles", "белиз", "belize", "панама", "panama",
    "гибралтар", "gibraltar", "джерси", "jersey", "гернси", "guernsey",
    "оаэ", "uae", "dubai", "дубай", "гонконг", "hong kong",
)


def build_affiliations_lite(
    ctx: CompanyContext | None,
    card: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Формирует срез связей 1-го уровня из карточки компании."""
    if not ctx:
        return None

    card = card or {}
    
    # 1. Руководство
    director_name = ctx.director_fio or card.get("Руковод", {}).get("ФИО") if isinstance(card.get("Руковод"), dict) else ctx.director_fio
    director_post = ctx.director_post or (card.get("Руковод", {}).get("Должн") if isinstance(card.get("Руковод"), dict) else "Руководитель")
    
    manager_block: dict[str, Any] = {}
    if director_name:
        manager_block["фио"] = director_name
        manager_block["должность"] = director_post or "Руководитель"

    # Управляющая организация (если вместо директора юрлицо)
    mgmt_org = card.get("УпрОрг")
    if mgmt_org and isinstance(mgmt_org, dict):
        manager_block["управляющая_организация"] = {
            "наименование": mgmt_org.get("Наим") or mgmt_org.get("НаимСокр"),
            "инн": mgmt_org.get("ИНН"),
            "огрн": mgmt_org.get("ОГРН"),
        }

    # 2. Учредители и структура капитала
    founders_list: list[dict[str, Any]] = []
    parent_company = None
    has_foreign = False
    has_state = False

    # Сначала пробуем структурированные данные из карточки Checko / ЕГРЮЛ
    raw_founders = card.get("Учредители") or []
    if isinstance(raw_founders, list):
        for f in raw_founders:
            if not isinstance(f, dict):
                continue
            name = f.get("ФИО") or f.get("Наим") or f.get("НаимСокр") or ""
            f_inn = f.get("ИНН")
            share_pct = None
            if "Процент" in f:
                try:
                    share_pct = float(f["Процент"])
                except (ValueError, TypeError):
                    share_pct = None
            elif "Доля" in f and isinstance(f["Доля"], dict) and "Процент" in f["Доля"]:
                try:
                    share_pct = float(f["Доля"]["Процент"])
                except (ValueError, TypeError):
                    share_pct = None

            is_org = bool(f.get("ОГРН") or f.get("Наим") or (f_inn and len(str(f_inn)) == 10))
            country = f.get("Страна") or ("RU" if not is_org else None)

            # Проверка на иностранный элемент
            f_text = f"{name} {country or ''}".lower()
            f_foreign = any(w in f_text for w in _OFFSHORE_KEYWORDS) or (country and country not in ("RU", "Россия"))
            if f_foreign:
                has_foreign = True

            # Проверка на госучастие
            if any(w in f_text for w in ("муниципальн", "министерство", "департамент", "субъект рф", "российская федерация", "росимущество")):
                has_state = True

            # Материнская компания (доля >= 50%)
            if is_org and share_pct and share_pct >= 50.0 and not parent_company:
                parent_company = {
                    "наименование": name,
                    "инн": f_inn,
                    "доля_владения_процент": share_pct,
                }

            founders_list.append({
                "наименование": name,
                "инн": f_inn,
                "доля_процент": share_pct,
                "тип": "юридическое_лицо" if is_org else "физическое_лицо",
                "иностранный_капитал": f_foreign,
            })

    # Фолбэк на ctx.founders (список строк из DaData)
    if not founders_list and ctx.founders:
        for f_str in ctx.founders[:10]:
            f_text = str(f_str).lower()
            f_foreign = any(w in f_text for w in _OFFSHORE_KEYWORDS)
            if f_foreign:
                has_foreign = True
            if any(w in f_text for w in ("муниципальн", "министерство", "росимущество", "департамент")):
                has_state = True
            founders_list.append({
                "наименование": str(f_str),
                "тип": "юридическое_лицо" if any(w in f_text for w in ("ооо", "пао", "ао", "зао", "ltd", "gmbh")) else "физическое_лицо",
                "иностранный_капитал": f_foreign,
            })

    # 3. Определение типа бенефициарного контроля
    is_ao = bool(card.get("ДержРеестрАО")) or "АКЦИОНЕРНОЕ" in (ctx.name_legal or "").upper()
    if is_ao and not founders_list:
        control_type = "Акционерное общество (реестр акционеров закрыт / у реестродержателя)"
    elif has_foreign:
        control_type = "Иностранный капитал / участие зарубежных структур"
    elif has_state:
        control_type = "Государственное / муниципальное участие"
    elif parent_company:
        control_type = f"Холдинговая структура (материнская компания «{parent_company['наименование']}»)"
    elif founders_list:
        control_type = "Частная российская организация"
    else:
        control_type = "Сведения об учредителях не раскрыты в реестре"

    # 4. Прямые дочерние организации (1-й уровень)
    subsidiaries = []
    for item in (card.get("ДочернОрг") or card.get("СвязУчред") or [])[:5]:
        if isinstance(item, dict):
            s_name = item.get("Наим") or item.get("НаимСокр") or item.get("Наименование")
            s_inn = item.get("ИНН")
            if s_name:
                subsidiaries.append({"наименование": s_name, "инн": s_inn})

    res: dict[str, Any] = {
        "тип_контроля": control_type,
    }
    if manager_block:
        res["руководитель"] = manager_block
    if parent_company:
        res["материнская_компания"] = parent_company
    if founders_list:
        res["учредители"] = founders_list
    if subsidiaries:
        res["дочерние_организации"] = subsidiaries

    return res
