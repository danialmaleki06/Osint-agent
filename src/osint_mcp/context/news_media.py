"""Мониторинг новостей, публичной активности и заявлений руководства компании.

Модуль OSINT-анализа открытого медиа-пространства:
1. Заявления руководства: что говорил генеральный директор, президент, основатели
   (интервью, цитаты, комментарии рынку, планы развития).
2. Презентации и запуски: где компания и спикеры выступали, что презентовали
   (конференции, форумы ЦИПР/ПМЭФ, выставки, анонсы и релизы продуктов).
3. Корпоративные новости: стратегические соглашения, партнерства, отраслевые награды.

Фильтрация и объем выдачи адаптируются под уровень подробности:
- "brief" («кратко»): 1-2 главных события/заявления руководства в компактном виде.
- "standard" («средне»): ключевые заявления руководства, презентации и новости (по 2-3 на категорию).
- "full" («полно»): развернутый медиа-портрет со всеми цитатами, спикерами, хронологией и ссылками.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import structlog

from osint_mcp.tools.web_search_source import search_web

log = structlog.get_logger()

RU_MONTHS = {
    "январь": "01", "января": "01", "январе": "01", "янв": "01",
    "февраль": "02", "февраля": "02", "феврале": "02", "фев": "02",
    "март": "03", "марта": "03", "марте": "03", "мар": "03",
    "апрель": "04", "апреля": "04", "апреле": "04", "апр": "04",
    "май": "05", "мая": "05", "мае": "05",
    "июнь": "06", "июня": "06", "июне": "06", "июн": "06",
    "июль": "07", "июля": "07", "июле": "07", "июл": "07",
    "август": "08", "августа": "08", "августе": "08", "авг": "08",
    "сентябрь": "09", "сентября": "09", "сентябре": "09", "сен": "09",
    "октябрь": "10", "октября": "10", "октябре": "10", "окт": "10",
    "ноябрь": "11", "ноября": "11", "ноябре": "11", "ноя": "11",
    "декабрь": "12", "декабря": "12", "декабре": "12", "дек": "12",
}

KNOWN_MEDIA_DOMAINS: dict[str, str] = {
    "cnews.ru": "CNews",
    "tadviser.ru": "TAdviser",
    "rbc.ru": "РБК",
    "rt.rbc.ru": "РБК Татарстан",
    "spb.rbc.ru": "РБК Санкт-Петербург",
    "ekb.rbc.ru": "РБК Екатеринбург",
    "ufa.rbc.ru": "РБК Уфа",
    "kommersant.ru": "Коммерсантъ",
    "vedomosti.ru": "Ведомости",
    "tass.ru": "ТАСС",
    "forbes.ru": "Forbes",
    "interfax.ru": "Интерфакс",
    "ria.ru": "РИА Новости",
    "vc.ru": "VC.ru",
    "habr.com": "Хабр",
    "lenta.ru": "Лента.ру",
    "gazeta.ru": "Газета.Ru",
    "rg.ru": "Российская газета",
    "bfm.ru": "BFM.ru",
    "ict.moscow": "ICT.Moscow",
    "rusbase.com": "RB.RU",
    "rb.ru": "RB.RU",
    "retail.ru": "Retail.ru",
    "banki.ru": "Банки.ру",
    "expert.ru": "Эксперт",
}


@dataclass
class MediaItem:
    category: str          # "заявление_руководства" | "презентация_или_событие" | "корпоративная_новость"
    title: str
    url: str
    snippet: str
    source: str
    date: str | None = None
    speaker: str | None = None
    highlight: str | None = None


def resolve_news_source(url: str) -> str:
    """Определяет человекочитаемое наименование делового СМИ или портала."""
    if not url:
        return "Интернет-СМИ"
    try:
        host = urlparse(url).netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        # Сортируем по убыванию длины домена, чтобы поддомены (spb.rbc.ru) проверялись раньше общего домена (rbc.ru)
        for dom, name in sorted(KNOWN_MEDIA_DOMAINS.items(), key=lambda kv: len(kv[0]), reverse=True):
            if host == dom or host.endswith("." + dom):
                return name
        return host or "Интернет-СМИ"
    except Exception:
        return "Интернет-СМИ"


def extract_news_date(url: str, title: str, snippet: str) -> str | None:
    """Извлекает дату публикации из URL, заголовка и сниппета."""
    # 1. Поиск в URL (/YYYY/MM/DD/ или /DD/MM/YYYY/)
    m_url_ymd = re.search(r'/(20\d{2})/(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])(?:/|$|_)', url)
    if m_url_ymd:
        return f"{m_url_ymd.group(3)}.{m_url_ymd.group(2)}.{m_url_ymd.group(1)}"
    m_url_dmy = re.search(r'/(0[1-9]|[12]\d|3[01])/(0[1-9]|1[0-2])/(20\d{2})(?:/|$|_)', url)
    if m_url_dmy:
        return f"{m_url_dmy.group(1)}.{m_url_dmy.group(2)}.{m_url_dmy.group(3)}"

    combined = f"{title} {snippet}"

    # 2. Поиск в тексте: число + месяц словом + год ("15 апреля 2026", "3 марта 2025")
    m_ru = re.search(r'\b([0-3]?\d)\s+([а-яё]+)(?:\s+(20\d{2}))?\b', combined, re.I)
    if m_ru:
        day = int(m_ru.group(1))
        month_word = m_ru.group(2).lower()
        if month_word in RU_MONTHS and 1 <= day <= 31:
            month_num = RU_MONTHS[month_word]
            year = m_ru.group(3)
            if not year:
                m_year = re.search(r'\b(201\d|202\d)\b', combined)
                if m_year:
                    year = m_year.group(1)
            if year:
                return f"{day:02d}.{month_num}.{year}"

    # 3. Числовой формат в тексте: DD.MM.YYYY
    m_num = re.search(r'\b([0-3]?\d)\.(0[1-9]|1[0-2])\.(20\d{2})\b', combined)
    if m_num:
        return f"{int(m_num.group(1)):02d}.{m_num.group(2)}.{m_num.group(3)}"

    # 4. Месяц и год без числа: "март 2025"
    m_my = re.search(r'\b([а-яё]+)\s+(20\d{2})\b', combined, re.I)
    if m_my:
        m_w = m_my.group(1).lower()
        if m_w in RU_MONTHS:
            return f"{RU_MONTHS[m_w]}.{m_my.group(2)}"

    # 5. Только год
    m_yr = re.search(r'\b(202\d)\b', combined)
    if m_yr:
        return m_yr.group(1)

    return None


def _extract_quote_or_highlight(text: str) -> str | None:
    """Извлекает ключевую цитату спикера или тезис новости."""
    # Поиск текста в кавычках («...» или "...")
    m_quotes = re.findall(r'[«"]([^»"]{20,250})[»"]', text)
    if m_quotes:
        # Предпочитаем цитату с смысловыми предикатами
        for q in m_quotes:
            if any(w in q.lower() for w in ("мы ", "наш", "планир", "рынок", "продукт", "разви", "счита", "нов")):
                return f"«{q.strip()}»"
        return f"«{m_quotes[0].strip()}»"

    # Поиск предложения с речевым предикатом
    sentences = re.split(r'[.!?]\s+', text)
    for s in sentences:
        s_low = s.lower()
        if any(w in s_low for w in ("заявил", "рассказал", "отметил", "подчеркнул", "представил", "запустил", "презентовал")):
            clean_s = s.strip()
            if 20 <= len(clean_s) <= 200:
                return clean_s
    return None


def classify_news_hit(
    title: str,
    snippet: str,
    url: str,
    director_fio: str | None = None,
) -> MediaItem:
    """Классифицирует публикацию: заявление руководства, презентация продукта или корпоративная новость."""
    combined = f"{title} {snippet}"
    comb_low = combined.lower()
    source_name = resolve_news_source(url)
    date_str = extract_news_date(url, title, snippet)

    # 1. Заявления руководства ("что говорил глава компании")
    # Проверка на упоминание конкретного ФИО руководителя
    is_leadership = False
    speaker_name = None

    if director_fio and len(director_fio.strip()) >= 5:
        dir_clean = director_fio.strip()
        parts = [p for p in re.split(r'\s+', dir_clean) if len(p) >= 3]
        if parts:
            last_name = parts[0]
            if last_name.lower() in comb_low:
                is_leadership = True
                speaker_name = dir_clean

    speech_markers = [
        "заявил", "заявила", "рассказал", "рассказала", "отметил", "отметила",
        "подчеркнул", "подчеркнула", "интервью", "колонка", "по словам главы",
        "по словам генерального", "по мнению", "высказался", "прокомментировал",
        "сообщил глава", "глава компании", "генеральный директор", "гендиректор",
        "президент компании", "основатель", "сооснователь", "руководитель компании",
    ]

    if not is_leadership:
        matched_speech = [w for w in speech_markers if w in comb_low]
        if len(matched_speech) >= 1:
            is_leadership = True
            # Пытаемся извлечь имя спикера из контекста рядом со словом "генеральный директор" или "глава"
            m_speaker = re.search(
                r'(?:генеральный директор|гендиректор|глава компании|руководитель|основатель|президент)\s+(?:компании\s+)?([А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+)?)',
                combined,
            )
            if m_speaker:
                speaker_name = m_speaker.group(1).strip()
            elif director_fio:
                speaker_name = director_fio

    if is_leadership:
        quote = _extract_quote_or_highlight(combined)
        return MediaItem(
            category="заявление_руководства",
            title=title.strip(),
            url=url,
            snippet=snippet.strip(),
            source=source_name,
            date=date_str,
            speaker=speaker_name or (director_fio if director_fio else "Руководство компании"),
            highlight=quote or (snippet[:180] + "..." if len(snippet) > 180 else snippet),
        )

    # 2. Презентации и запуски ("где-то что-то представлял")
    presentation_markers = [
        "представил", "представила", "представили", "презентовал", "презентовала",
        "анонсировал", "анонсировала", "запустил", "запустила", "выкатил",
        "показал", "показала", "продемонстрировал", "форум", "выставка",
        "конференция", "выступил", "выступила", "доклад", "стенд", "сессия",
        "ципр", "пмэф", "tadviser summit", "cnews forum", "демо", "новинка",
        "новый продукт", "новая версия", "релиз", "обновление сервиса",
        "техноцентр", "технологический центр", "центр разработки",
        "искусственный интеллект", "нейросеть", "нейросети", "ai-driven", "low-code", "low code",
    ]
    is_presentation = any(m in comb_low for m in presentation_markers) or bool(re.search(r'\b(ии|ai)\b', comb_low))
    if is_presentation:
        highlight = _extract_quote_or_highlight(combined)
        return MediaItem(
            category="презентация_или_событие",
            title=title.strip(),
            url=url,
            snippet=snippet.strip(),
            source=source_name,
            date=date_str,
            highlight=highlight or (snippet[:180] + "..." if len(snippet) > 180 else snippet),
        )

    # 3. Корпоративные новости (партнерства, соглашения, награды)
    return MediaItem(
        category="корпоративная_новость",
        title=title.strip(),
        url=url,
        snippet=snippet.strip(),
        source=source_name,
        date=date_str,
        highlight=snippet[:180] + "..." if len(snippet) > 180 else snippet,
    )


def build_media_queries(
    company_name: str,
    brand: str | None = None,
    director_fio: str | None = None,
) -> list[tuple[str, str]]:
    """Формирует набор естественных поисковых запросов для сбора новостей и публичной активности."""
    from osint_mcp.tools.names import core_name

    c_core = core_name(company_name)
    clean_name = c_core or re.sub(
        r'^(общество с ограниченной ответственностью|акционерное общество|публичное акционерное общество|непубличное акционерное общество|ооо|зао|ао|пао|ип)\s+',
        '', company_name, flags=re.I
    ).strip('"«» ')
    clean_name = re.sub(r'["«»„“\'\`]', '', clean_name).strip()

    b_clean = (brand or "").strip()
    b_clean = re.sub(r'["«»„“\'\`]', '', b_clean).strip()

    if b_clean and len(b_clean) >= 3:
        brand_term = b_clean
    elif clean_name and len(clean_name) >= 3:
        brand_term = clean_name
    else:
        brand_term = (clean_name or b_clean or company_name).strip()

    queries: list[tuple[str, str]] = []

    # 1. Запросы по первому лицу / главе компании (если известно ФИО)
    if director_fio and len(director_fio.strip()) >= 5:
        parts = [p for p in re.split(r'\s+', director_fio.strip()) if len(p) >= 3]
        if len(parts) >= 2:
            last, first = parts[0], parts[1]
            queries.append(("leadership", f'"{first} {last}" {brand_term} интервью OR заявил OR рассказал'))
            queries.append(("leadership", f'"{last}" {brand_term} генеральный директор OR глава'))
            queries.append(("leadership", f'"{brand_term}" (site:cnews.ru OR site:tadviser.ru) "{last}" OR "генеральный директор" OR "глава"'))
        elif len(parts) == 1:
            queries.append(("leadership", f'"{parts[0]}" {brand_term} генеральный директор OR интервью'))
            queries.append(("leadership", f'"{brand_term}" (site:cnews.ru OR site:tadviser.ru) "{parts[0]}" OR "генеральный директор"'))
    else:
        # Целевой поиск официальных заявлений руководства в CNews и TAdviser
        queries.append(("leadership", f'"{brand_term}" (site:cnews.ru OR site:tadviser.ru) "генеральный директор" OR "глава" OR интервью'))

    # 2. Общие запросы на заявления руководства в ведущих деловых изданиях
    queries.append(("leadership", f'"{brand_term}" генеральный директор OR глава заявил OR сообщил'))
    queries.append(("leadership", f'"{brand_term}" интервью руководитель OR основатель'))

    # 3. Презентации, новинки, запуски сервисов и релизы продуктов (включая CNews и TAdviser)
    queries.append(("presentation", f'"{brand_term}" (site:cnews.ru OR site:tadviser.ru) представил OR презентовал OR анонсировал'))
    queries.append(("presentation", f'"{brand_term}" представил OR презентовал OR запустил новый'))
    queries.append(("event", f'"{brand_term}" форум OR конференция OR выставка выступление'))

    # 4. Корпоративные соглашения, партнерства
    queries.append(("corporate", f'"{brand_term}" соглашение OR партнерство'))

    return queries


def format_media_profile(
    items: list[MediaItem],
    detail: str = "standard",
) -> dict[str, Any]:
    """Форматирует профиль публичной активности в зависимости от уровня подробности."""
    d_raw = str(detail or "").strip().lower()
    if d_raw in ("brief", "кратко", "коротко", "short", "1"):
        detail_norm = "brief"
    elif d_raw in ("full", "полно", "deep", "максимально", "3"):
        detail_norm = "full"
    else:
        detail_norm = "standard"

    if not items:
        if detail_norm == "brief":
            return {
                "сводка": "Заметной публичной медиа-активности или заявлений руководства в открытых деловых СМИ не зафиксировано.",
                "всего_найдено": 0,
            }
        return {
            "сводка": "Публичная медиа-активность низкая: заявлений руководства, презентаций продуктов или докладов на форумах в открытых источниках не обнаружено.",
            "заявления_руководства": [],
            "презентации_и_события": [],
            "корпоративные_новости": [],
            "всего_найдено": 0,
        }

    # Группировка
    leadership = [it for it in items if it.category == "заявление_руководства"]
    events = [it for it in items if it.category == "презентация_или_событие"]
    corporate = [it for it in items if it.category == "корпоративная_новость"]

    # ── Уровень 1: "brief" («кратко») ──
    if detail_norm == "brief":
        key_events = []
        # Берем 1 главное заявление руководства и 1 ключевое событие/презентацию
        if leadership:
            it = leadership[0]
            key_events.append({
                "тип": "Заявление руководства",
                "спикер": it.speaker or "Глава компании",
                "тезис": it.highlight or it.title,
                "дата": it.date,
                "источник": it.source,
                "url": it.url,
            })
        if events:
            it = events[0]
            key_events.append({
                "тип": "Презентация / событие",
                "суть": it.highlight or it.title,
                "дата": it.date,
                "источник": it.source,
                "url": it.url,
            })
        elif corporate and not key_events:
            it = corporate[0]
            key_events.append({
                "тип": "Новость",
                "суть": it.title,
                "дата": it.date,
                "источник": it.source,
                "url": it.url,
            })

        summary_text = (
            f"Зафиксирована публичная медиа-активность ({len(items)} упоминаний): "
            + "; ".join(e["суть"] if "суть" in e else f'{e["спикер"]}: {e["тезис"]}' for e in key_events[:2])
            + "."
        )

        return {
            "сводка": summary_text,
            "главные_события": key_events,
            "всего_найдено": len(items),
        }

    # ── Уровень 2: "standard" («средне») ──
    if detail_norm == "standard":
        lead_list = [
            {
                "спикер": it.speaker or "Глава компании",
                "тезис": it.highlight or it.title,
                "заголовок": it.title,
                "дата": it.date,
                "источник": it.source,
                "url": it.url,
            }
            for it in leadership[:3]
        ]
        event_list = [
            {
                "событие_или_продукт": it.title,
                "описание": it.highlight or it.snippet,
                "дата": it.date,
                "источник": it.source,
                "url": it.url,
            }
            for it in events[:3]
        ]
        corp_list = [
            {
                "новость": it.title,
                "суть": it.highlight or it.snippet,
                "дата": it.date,
                "источник": it.source,
                "url": it.url,
            }
            for it in corporate[:3]
        ]

        summary_parts = []
        if lead_list:
            summary_parts.append(f"заявления первого лица ({len(lead_list)})")
        if event_list:
            summary_parts.append(f"презентации и анонсы ({len(event_list)})")
        if corp_list:
            summary_parts.append(f"корпоративные новости ({len(corp_list)})")

        summary_txt = (
            f"Компания ведет активную медийную деятельность ({len(items)} публикаций). В открытых источниках представлены: "
            + ", ".join(summary_parts) + "."
            if summary_parts
            else f"Найдено {len(items)} публикаций в СМИ."
        )

        return {
            "сводка": summary_txt,
            "заявления_руководства": lead_list,
            "презентации_и_события": event_list,
            "корпоративные_новости": corp_list,
            "всего_найдено": len(items),
        }

    # ── Уровень 3: "full" («полно») ──
    lead_all = [
        {
            "спикер": it.speaker or "Глава компании",
            "цитата_или_тезис": it.highlight or it.title,
            "заголовок": it.title,
            "дата": it.date,
            "источник": it.source,
            "url": it.url,
            "сниппет": it.snippet,
        }
        for it in leadership
    ]
    event_all = [
        {
            "продукт_или_мероприятие": it.title,
            "детали_презентации": it.highlight or it.snippet,
            "дата": it.date,
            "источник": it.source,
            "url": it.url,
        }
        for it in events
    ]
    corp_all = [
        {
            "заголовок": it.title,
            "содержание": it.highlight or it.snippet,
            "дата": it.date,
            "источник": it.source,
            "url": it.url,
        }
        for it in corporate
    ]
    chronicle = [
        {
            "категория": it.category,
            "заголовок": it.title,
            "дата": it.date,
            "источник": it.source,
            "спикер": it.speaker,
            "суть": it.highlight or it.snippet,
            "url": it.url,
        }
        for it in items
    ]

    return {
        "сводка": f"Полный срез медиа-активности и PR-контура: собрано {len(items)} публикаций и событий.",
        "заявления_руководства": lead_all,
        "презентации_и_события": event_all,
        "корпоративные_новости": corp_all,
        "хроника_публичной_активности": chronicle,
        "всего_найдено": len(items),
    }


async def fetch_company_media_presence(
    inn: str,
    company_name: str,
    brand: str | None = None,
    director_fio: str | None = None,
    detail: str = "standard",
) -> dict[str, Any]:
    """Асинхронный параллельный сбор новостей, заявлений руководства и презентаций компании."""
    queries = build_media_queries(company_name, brand=brand, director_fio=director_fio)
    if not queries:
        return format_media_profile([], detail=detail)

    async def _search_one(hint: str, q: str) -> list[dict[str, Any]]:
        try:
            hits = await asyncio.to_thread(search_web, q, limit=3, retries=1, retry_delay=0.5)
            for h in hits:
                h["query_hint"] = hint
            return hits
        except Exception as exc:  # noqa: BLE001
            log.debug("news_search_query_error", query=q, error=str(exc))
            return []

    tasks = [_search_one(hint, q) for hint, q in queries[:6]]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    seen_urls: set[str] = set()
    raw_hits: list[dict[str, Any]] = []

    for res in gathered:
        if isinstance(res, list):
            for h in res:
                u = (h.get("url") or "").strip()
                if u and u not in seen_urls:
                    seen_urls.add(u)
                    raw_hits.append(h)

    # Классифицируем и собираем объекты
    media_items: list[MediaItem] = []
    for h in raw_hits:
        title = h.get("title") or ""
        snippet = h.get("snippet") or ""
        url = h.get("url") or ""
        if not title and not snippet:
            continue
        item = classify_news_hit(title, snippet, url, director_fio=director_fio)
        media_items.append(item)

    # Сортировка: сначала элементы с определенной датой, затем остальные
    def _sort_key(it: MediaItem):
        if it.date and len(it.date) >= 4:
            # Извлекаем год для приблизительной сортировки
            m_yr = re.search(r'\b(20\d{2})\b', it.date)
            return int(m_yr.group(1)) if m_yr else 2000
        return 0

    media_items.sort(key=_sort_key, reverse=True)

    return format_media_profile(media_items, detail=detail)
