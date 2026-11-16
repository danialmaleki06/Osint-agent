"""Компактный экспресс-виджет контрагента (7 ключевых метрик в формате Markdown-таблицы).

Виджет собирает концентрированную выжимку о контрагенте:
1. Компания и статус: название, бренд, ИНН, возраст бизнеса, статус юрлица.
2. ОКВЭД и профиль: код, расшифровка деятельности, целевой сегмент.
3. Оценка и вердикт: светофор (🟢/🟡/🟠/⛔), скоринг-балл (0-100), краткая суть оценки.
4. Финансы: выручка, чистая прибыль, темп прироста (YoY), состояние капитала.
5. Юридическая чистота: суды/арбитраж, исполнительные производства ФССП, налоги ФНС, РНП.
6. Кадровый пульс (HeadHunter): вакансии за 30 дней, активность найма, ключевые роли руководства.
7. СМИ и руководство: официальные заявления первого лица, CNews, TAdviser, запуски продуктов.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def _extract_company_status(dossier: dict[str, Any]) -> tuple[str, str]:
    """Возвращает строку описания компании и эмодзи статуса."""
    card = dossier.get("карточка") or {}
    name = (
        card.get("краткое_наименование")
        or card.get("наименование")
        or dossier.get("inn", "")
    )
    inn = card.get("ИНН") or dossier.get("inn", "")
    status = card.get("статус") or "действующая"
    reg_date = card.get("дата_регистрации") or ""

    years_str = ""
    if reg_date and re.match(r"^\d{4}", str(reg_date)):
        try:
            reg_year = int(str(reg_date)[:4])
            cur_year = datetime.now(timezone.utc).year
            age = cur_year - reg_year
            if age > 0:
                years_str = f"{age} лет на рынке"
            else:
                years_str = "менее 1 года на рынке"
        except Exception:
            years_str = ""

    brand = dossier.get("коммерческий_срез", {}).get("бренд") or card.get("brand")
    brand_part = f" ({brand})" if brand and brand.lower() not in name.lower() else ""

    parts = [f"{name}{brand_part}", f"ИНН {inn}"]
    if years_str:
        parts.append(years_str)
    parts.append(status.capitalize())

    text = " • ".join(parts)
    icon = "🟢" if "действующ" in status.lower() else "⛔"
    return text, icon


def _extract_okved_profile(dossier: dict[str, Any]) -> tuple[str, str]:
    """Возвращает ОКВЭД и отраслевой профиль компании."""
    card = dossier.get("карточка") or {}
    code = card.get("оквэд_код") or ""
    activity = card.get("деятельность") or card.get("оквэд_текст") or ""
    comm = dossier.get("коммерческий_срез") or {}
    formula = comm.get("формула_бизнеса") or ""
    segment = comm.get("целевой_сегмент") or ""

    desc = activity or formula or "Коммерческая деятельность"
    if segment and segment.lower() not in desc.lower():
        desc = f"{desc} ({segment})"

    text = f"{code} {desc}".strip()
    return text, "💼"


def _extract_scoring_verdict(dossier: dict[str, Any]) -> tuple[str, str]:
    """Возвращает оценку, скоринг и вердикт."""
    traffic_light = dossier.get("светофор") or "🟢 Низкий риск"
    score = dossier.get("score")
    score_str = f"{score:.0f}/100" if score is not None else ""
    verdict = (
        dossier.get("суть_оценки")
        or dossier.get("вердикт")
        or "Требуется стандартная осмотрительность"
    )

    icon = "🟢"
    for emoji in ("⛔", "🟠", "🟡", "🟢"):
        if emoji in traffic_light:
            icon = emoji
            break

    text = f"{traffic_light} ({score_str}) • {verdict}" if score_str else f"{traffic_light} • {verdict}"
    return text, icon


def _extract_finance_summary(dossier: dict[str, Any]) -> tuple[str, str]:
    """Возвращает сжатый финансовый результат."""
    fin_mat = dossier.get("финансовая_матрица") or {}
    ros = fin_mat.get("рентабельность_продаж_ros") or {}
    rev = ros.get("выручка")
    prof = ros.get("чистая_прибыль")
    dyn = fin_mat.get("динамика_выручки_yoy") or {}
    growth_label = dyn.get("оценка") or ""
    assets = fin_mat.get("чистые_активы") or {}
    cap_status = assets.get("статус") or ""

    if not rev and dossier.get("финансовая_история"):
        last = dossier["финансовая_история"][0]
        r_val = last.get("revenue")
        p_val = last.get("profit")
        if r_val:
            rev = f"{r_val / 1e9:.1f} млрд ₽" if r_val >= 1e9 else f"{r_val / 1e6:.1f} млн ₽"
        if p_val is not None:
            prof = f"{p_val / 1e9:.1f} млрд ₽" if abs(p_val) >= 1e9 else f"{p_val / 1e6:.1f} млн ₽"

    parts = []
    if rev:
        parts.append(f"Выручка {rev}")
    if prof:
        parts.append(f"прибыль {prof}")
    if growth_label:
        parts.append(growth_label)
    elif cap_status:
        parts.append(cap_status)

    text = " • ".join(parts) if parts else "Финансовые показатели не раскрыты в открытой отчетности ФНС"
    icon = "🟢" if ("Рост" in text or ("прибыль" in text and "Убыток" not in text)) else "🟡"
    return text, icon


def _extract_legal_risks(dossier: dict[str, Any]) -> tuple[str, str]:
    """Возвращает информацию по судам, приставам (ФССП), налогам и РНП."""
    human_rep = dossier.get("резюме_для_человека", {}).get("ответы_на_главные_вопросы", {})
    safety_text = human_rep.get("2_безопасно_ли_сотрудничать") or ""

    fssp_ok = "исполнительных производств нет" in safety_text or "0 ₽" in safety_text
    tax_ok = "долгов перед фнс нет" in safety_text.lower() or "налоги уплачиваются вовремя" in safety_text.lower()
    rnp_ok = "в черном списке не числится" in safety_text.lower() or "допущен к любым закупкам" in safety_text.lower()

    parts = []
    if fssp_ok:
        parts.append("0 ₽ взысканий ФССП")
    else:
        parts.append("Имеются взыскания ФССП")

    if tax_ok:
        parts.append("чистый налоговый профиль")
    else:
        parts.append("есть вопросы по налогам")

    if rnp_ok:
        parts.append("вне РНП (допущен к закупкам)")
    else:
        parts.append("проверить статус в РНП")

    text = ", ".join(parts)
    icon = "🟢" if (fssp_ok and tax_ok and rnp_ok) else "⚠️"
    return text, icon


def _extract_hh_pulse(dossier: dict[str, Any]) -> tuple[str, str]:
    """Возвращает срез по HeadHunter и кадрам."""
    hh = dossier.get("кадровый_потенциал_документы") or {}
    vac_cnt = hh.get("открыто_вакансий_30дней")
    dyn = hh.get("динамика_найма") or ""
    roles = hh.get("руководящие_позиции") or []

    if vac_cnt is not None and vac_cnt > 0:
        dyn_label = "активный найм" if "активн" in dyn.lower() else "умеренный найм"
        lead_str = f", найм ЛПР: {roles[0]}" if roles else ""
        text = f"{vac_cnt} вакансий за 30 дней ({dyn_label}){lead_str}"
        icon = "📈"
    else:
        text = "Активных вакансий на HeadHunter не зафиксировано"
        icon = "👥"
    return text, icon


def _extract_media_statements(dossier: dict[str, Any]) -> tuple[str, str, list[str]]:
    """Возвращает информацию по CNews, TAdviser и заявлениям руководства (до 3 ключевых тезисов/абзацев)."""
    media = dossier.get("медиа_и_публичная_активность") or {}
    leaders = media.get("заявления_руководства") or []
    events = media.get("презентации_и_события") or []
    corp = media.get("корпоративные_новости") or []
    key_events = media.get("главные_события") or []

    paragraphs: list[str] = []
    seen_texts: set[str] = set()

    def _add(text: str):
        cleaned = re.sub(r"\s+", " ", text).strip().rstrip(".")
        norm_key = re.sub(r"[^\w\s]", "", cleaned.lower())[:40]
        if norm_key and norm_key not in seen_texts:
            seen_texts.add(norm_key)
            paragraphs.append(cleaned)

    # 1. Заявления руководства (интервью, цитаты, позиция)
    for it in leaders:
        spk = it.get("спикер") or "Руководство"
        quote = it.get("тезис") or it.get("цитата_или_тезис") or it.get("заголовок") or ""
        src = it.get("источник") or "СМИ"
        if quote:
            _add(f"{src}: {spk} — {quote}")
        if len(paragraphs) >= 2:
            break

    # 2. Презентации и технологические события (ИИ, low-code, техноцентры, форумы)
    for it in events:
        name = (
            it.get("детали_презентации")
            or it.get("событие_или_продукт")
            or it.get("продукт_или_мероприятие")
            or it.get("описание")
            or it.get("заголовок")
            or ""
        )
        src = it.get("источник") or "СМИ"
        if name:
            _add(f"{src}: {name}")
        if len(paragraphs) >= 3:
            break

    # 3. Главные события (если уровень brief)
    if not paragraphs:
        for it in key_events:
            spk = it.get("спикер")
            thesis = it.get("тезис") or it.get("суть") or ""
            src = it.get("источник") or "СМИ"
            if spk and thesis:
                _add(f"{src}: {spk} — {thesis}")
            elif thesis:
                _add(f"{src}: {thesis}")
            if len(paragraphs) >= 3:
                break

    # 4. Корпоративные соглашения, партнерства
    if len(paragraphs) < 3:
        for it in corp:
            name = it.get("новость") or it.get("заголовок") or it.get("суть") or ""
            src = it.get("источник") or "СМИ"
            if name:
                _add(f"{src}: {name}")
            if len(paragraphs) >= 3:
                break

    if not paragraphs:
        return (
            "Громких заявлений руководства и инцидентов в ведущих деловых СМИ не зафиксировано",
            "ℹ️",
            [],
        )

    # Формируем многострочный текст для таблицы через <br>
    if len(paragraphs) == 1:
        table_text = paragraphs[0]
    else:
        table_text = "<br>".join([f"• {p}" for p in paragraphs])

    icon = "🎙️" if leaders else "📰"
    return table_text, icon, paragraphs


def build_summary_widget(dossier: dict[str, Any]) -> dict[str, Any]:
    """Формирует экспресс-виджет (7 пунктов) в структурированном виде и в формате Markdown-таблицы."""
    c_text, c_icon = _extract_company_status(dossier)
    o_text, o_icon = _extract_okved_profile(dossier)
    s_text, s_icon = _extract_scoring_verdict(dossier)
    f_text, f_icon = _extract_finance_summary(dossier)
    l_text, l_icon = _extract_legal_risks(dossier)
    h_text, h_icon = _extract_hh_pulse(dossier)
    m_text, m_icon, m_paragraphs = _extract_media_statements(dossier)

    items = [
        {"номер": 1, "метрика": "Компания и статус", "значение": c_text, "статус": c_icon},
        {"номер": 2, "метрика": "ОКВЭД / Отрасль", "значение": o_text, "статус": o_icon},
        {"номер": 3, "метрика": "Оценка и вердикт", "значение": s_text, "статус": s_icon},
        {"номер": 4, "метрика": "Финансы", "значение": f_text, "статус": f_icon},
        {"номер": 5, "метрика": "Юр. чистота / Риски", "значение": l_text, "статус": l_icon},
        {"номер": 6, "метрика": "Кадры (HeadHunter)", "значение": h_text, "статус": h_icon},
        {"номер": 7, "метрика": "СМИ и руководство", "значение": m_text, "статус": m_icon, "тезисы": m_paragraphs},
    ]

    lines = [
        "| № | Метрика | Значение | Статус |",
        "| :-: | :--- | :--- | :-: |",
    ]
    for it in items:
        clean_val = str(it["значение"]).replace("|", "/").strip()
        lines.append(f"| {it['номер']} | **{it['метрика']}** | {clean_val} | {it['статус']} |")

    markdown_table = "\n".join(lines)

    return {
        "таблица_markdown": markdown_table,
        "пункты": items,
        "число_пунктов": len(items),
    }
