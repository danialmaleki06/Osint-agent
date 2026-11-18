"""Модуль выявления конкурентов контрагента и мониторинга их рыночных новостей.

1. Определение 2-4 ключевых конкурентов на основе:
   - бренда компании,
   - отрасли и кодов ОКВЭД,
   - продуктового профиля (программные продукты, лицензии, товарные знаки),
   - поисковых паттернов («конкуренты», «аналоги», «альтернативы») и отраслевых кластеров.
2. Сбор компактного профиля каждого конкурента:
   - Бренд / Наименование.
   - Профиль и специализация на рынке.
   - Сайт / Домен (если определен).
   - Ключевые свежие новости и события (запуски продуктов, соглашения, партнерства).
   *Примечание:* Сведения о руководителях конкурентов не собираются согласно бизнес-требованиям.
3. Адаптация выдачи под уровень подробности (brief / standard / full):
   - "brief" («кратко»): 1-2 главных конкурента с 1 последней новостью/релизом.
   - "standard" («средне»): 2-3 ключевых конкурента со специализацией и 1-2 свежими новостями.
   - "full" («полно»): 3-5 конкурентов со структурированным сравнением и подборкой событий.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any

import structlog

from osint_mcp.context.news_media import company_mention_pattern, extract_news_date, resolve_news_source
from osint_mcp.tools.web_search_source import search_web

log = structlog.get_logger()

# Отраслевые кластеры ключевых игроков российского B2B-рынка
KNOWN_MARKET_CLUSTERS: list[dict[str, Any]] = [
    {
        "category": "Enterprise BPM / CRM / Low-code",
        "keywords": ["bpmsoft", "terrasoft", "elma", "simpleone", "directum", "naumen", "comindware", "crm", "bpm", "low-code"],
        "peers": [
            {"brand": "ELMA", "profile": "Российский разработчик Low-code платформы ELMA365 и CRM", "site": "elma365.com"},
            {"brand": "SimpleOne", "profile": "Российская платформа для автоматизации сервисных бизнес-процессов (ITSM/ESM)", "site": "simpleone.ru"},
            {"brand": "1С:CRM", "profile": "Отраслевые CRM-решения на платформе 1С:Предприятие", "site": "1c.ru"},
            {"brand": "Directum", "profile": "Интеллектуальная система управления цифровыми процессами и документами", "site": "directum.ru"},
            {"brand": "Naumen", "profile": "Корпоративные решения для контакт-центров, ITSM и клиентского сервиса", "site": "naumen.ru"},
        ],
    },
    {
        "category": "Облачные платформы и дата-центры (Cloud & IaaS/PaaS)",
        "keywords": ["selectel", "yandex cloud", "cloud.ru", "sbercloud", "vk cloud", "rtk-solar", "селектел", "я облако", "облако"],
        "peers": [
            {"brand": "Yandex Cloud", "profile": "Публичная облачная платформа группы Яндекс", "site": "cloud.yandex.ru"},
            {"brand": "Selectel", "profile": "Провайдер IT-инфраструктуры, выделенных серверов и частных облаков", "site": "selectel.ru"},
            {"brand": "Cloud.ru", "profile": "Облачный провайдер корпоративного уровня (экс-SberCloud)", "site": "cloud.ru"},
            {"brand": "VK Cloud", "profile": "Платформа облачных сервисов для бизнеса от VK Tech", "site": "cloud.vk.com"},
        ],
    },
    {
        "category": "Информационная безопасность (Cybersecurity & InfoSec)",
        "keywords": ["positive technologies", "касперский", "kaspersky", "infowatch", "usergate", "код безопасности", "информзащита", "инфобез", "кибербез"],
        "peers": [
            {"brand": "Positive Technologies", "profile": "Лидер в сфере результативной кибербезопасности и SIEM-систем", "site": "ptsecurity.com"},
            {"brand": "Лаборатория Касперского", "profile": "Международный разработчик решений для защиты конечных точек и инфраструктуры", "site": "kaspersky.ru"},
            {"brand": "UserGate", "profile": "Российский разработчик межсетевых экранов нового поколения (NGFW)", "site": "usergate.com"},
            {"brand": "InfoWatch", "profile": "Разработчик DLP-систем и решений для защиты от утечек данных", "site": "infowatch.ru"},
        ],
    },
    {
        "category": "Транспортная логистика и грузоперевозки (Logistics & Freight)",
        "keywords": ["деловые линии", "пэк", "сдэк", "байкал сервис", "возовоз", "dpd", "желдорэкспедиция", "грузоперевозк", "логистик"],
        "peers": [
            {"brand": "Деловые Линии", "profile": "Крупнейший оператор сборных грузов (LTL) и логистических услуг в РФ", "site": "dellin.ru"},
            {"brand": "ПЭК", "profile": "Мультисервисный логистический оператор федерального масштаба", "site": "pecom.ru"},
            {"brand": "СДЭК", "profile": "Курьерская доставка для интернет-магазинов и сборных отправлений", "site": "cdek.ru"},
            {"brand": "Байкал Сервис", "profile": "Транспортная компания по регулярной доставке сборных грузов", "site": "baikalsr.ru"},
        ],
    },
    {
        "category": "E-Commerce и розничные маркетплейсы",
        "keywords": ["wildberries", "вайлдберриз", "ozon", "озон", "яндекс маркет", "мегамаркет", "маркетплейс"],
        "peers": [
            {"brand": "Ozon", "profile": "Мультикатегорийный маркетплейс и финтех-экосистема", "site": "ozon.ru"},
            {"brand": "Wildberries", "profile": "Крупнейший российский онлайн-ритейлер и логистическая сеть ПВЗ", "site": "wildberries.ru"},
            {"brand": "Яндекс Маркет", "profile": "Маркетплейс потребительских товаров экосистемы Яндекса", "site": "market.yandex.ru"},
            {"brand": "Мегамаркет", "profile": "Маркетплейс с программой лояльности СберСпасибо", "site": "megamarket.ru"},
        ],
    },
    {
        "category": "IT-дистрибуция и системная интеграция",
        "keywords": ["крок", "croc", "ланит", "lanit", "софтлайн", "softline", "ай-теко", "i-teco", "интегратор", "дистрибуц"],
        "peers": [
            {"brand": "КРОК", "profile": "Международная IT-компания, системный интегратор комплексных инфраструктурных решений", "site": "croc.ru"},
            {"brand": "ЛАНИТ", "profile": "Многопрофильная группа IT-компаний, интеграция и заказная разработка", "site": "lanit.ru"},
            {"brand": "Софтлайн (Softline)", "profile": "Поставщик решений в области цифровой трансформации и кибербезопасности", "site": "softline.ru"},
            {"brand": "Ай-Теко", "profile": "Ведущий российский системный интегратор в государственном и банковском секторе", "site": "i-teco.ru"},
        ],
    },
    {
        "category": "Учетные системы, ERP и бухгалтерия",
        "keywords": ["1с", "1c", "мойсклад", "моё дело", "контур", "галактика", "парус", "бухгалтер", "erp"],
        "peers": [
            {"brand": "1С", "profile": "Национальный стандарт ERP-систем и учетного ПО для бизнеса", "site": "1c.ru"},
            {"brand": "МойСклад", "profile": "Облачный сервис управления торговлей, складом и CRM для малого бизнеса", "site": "moysklad.ru"},
            {"brand": "СКБ Контур", "profile": "Экосистема продуктов для электронного документооборота, отчетности и бухгалтерии", "site": "kontur.ru"},
            {"brand": "Корпорация «Галактика»", "profile": "Российский разработчик ERP-систем для крупных промышленных холдингов", "site": "galaktika.ru"},
        ],
    },
]


@dataclass
class CompetitorNewsItem:
    title: str
    date: str | None
    source: str
    url: str
    highlight: str | None


@dataclass
class CompetitorProfile:
    brand: str
    profile: str
    site: str | None = None
    market_scale: str | None = None
    news: list[CompetitorNewsItem] = field(default_factory=list)


def _match_cluster_peers(
    brand: str | None,
    company_name: str,
    okved_text: str | None = None,
    products: list[str] | None = None,
) -> tuple[str | None, list[dict[str, str]]]:
    """Находит отраслевой кластер и возвращает список прямых конкурентов."""
    b_low = (brand or "").lower().strip()
    c_low = company_name.lower().strip()
    ok_low = (okved_text or "").lower()
    prod_text = " ".join(products or []).lower()

    haystack = f"{b_low} {c_low} {ok_low} {prod_text}"

    for cluster in KNOWN_MARKET_CLUSTERS:
        for kw in cluster["keywords"]:
            if kw in haystack:
                # Фильтруем самого контрагента из списка конкурентов
                peers = [
                    p for p in cluster["peers"]
                    if p["brand"].lower() not in b_low and b_low not in p["brand"].lower()
                ]
                return cluster["category"], peers

    return None, []


def _extract_competitor_names_from_text(
    snippets_text: str,
    subject_brand: str,
) -> list[str]:
    """Извлекает бренды конкурентов из текстов статей и обзоров рынка."""
    b_low = subject_brand.lower().strip()
    # Ищем конструкции: "конкуренты X: A, B, C" или "аналоги X — A, B"
    found_names: list[str] = []

    # Паттерны перечислений после двоеточия или тире
    pattern = re.compile(
        r'(?:конкурент[а-я]*|аналог[а-я]*|альтернатив[а-я]*|соперник[а-я]*|среди игроков|лидер[а-я]* рынка)[^:—–\n]{0,80}[:—–]\s*([^.\n]+)',
        re.I,
    )
    for m in pattern.finditer(snippets_text):
        chunk = m.group(1)
        raw_items = re.split(r'[,;]\s*|\s+(?:и|или)\s+', chunk)
        for item in raw_items:
            clean = re.sub(r'["«»„“\'\`]', '', item).strip()
            # Пропускаем стоп-слова, предлоги и самого субъекта
            if len(clean) >= 2 and len(clean) <= 25 and clean.lower() not in b_low and b_low not in clean.lower():
                if not re.search(r'\b(компани|рынк|российск|систем|программ|решени)\b', clean, re.I):
                    if clean not in found_names:
                        found_names.append(clean)

    return found_names[:5]


def _build_competitor_queries(
    brand: str,
    company_name: str,
    okved_text: str | None = None,
) -> list[str]:
    """Генерирует поисковые запросы для обнаружения конкурентов."""
    b = brand.strip()
    queries = [
        f'"{b}" главные конкуренты аналоги',
        f'"{b}" рынок альтернативы обзор',
    ]
    if okved_text:
        short_ok = okved_text.split()[0]
        queries.append(f'"{b}" конкуренты {short_ok}')
    return queries


async def _fetch_competitor_recent_news(competitor_brand: str) -> list[CompetitorNewsItem]:
    """Ищет 1-2 свежие продуктовые или корпоративные новости по конкретному конкуренту.
    
    Важно: новости о руководстве/директорах исключены согласно бизнес-требованию.
    """
    # Запрос строго на продукты, анонсы и партнерства компании (без руководства)
    query = f'"{competitor_brand}" представил OR запустил OR анонсировал OR соглашение'
    mention = company_mention_pattern(competitor_brand)
    if mention is None:
        return []
    try:
        hits = await asyncio.to_thread(search_web, query, limit=5, retries=1, retry_delay=0.5)
    except Exception as exc:  # noqa: BLE001
        log.debug("competitor_news_search_error", brand=competitor_brand, error=str(exc))
        return []

    news_items: list[CompetitorNewsItem] = []
    for h in hits:
        title = (h.get("title") or "").strip()
        snippet = (h.get("snippet") or "").strip()
        url = (h.get("url") or "").strip()
        if not title:
            continue

        # Отсекаем новости про кадровые перестановки и высказывания директоров
        comb_low = " ".join(f"{title} {snippet}".casefold().replace("ё", "е").split())
        if not mention.search(comb_low):
            continue
        if any(w in comb_low for w in ("генеральный директор заявил", "глава рассказал", "директор отметил", "назначен гендиректором")):
            continue

        d_str = extract_news_date(url, title, snippet)
        s_lbl = resolve_news_source(url)

        # Выделяем суть
        highlight = snippet[:140] + "..." if len(snippet) > 140 else snippet
        news_items.append(
            CompetitorNewsItem(
                title=title,
                date=d_str,
                source=s_lbl,
                url=url,
                highlight=highlight,
            )
        )
        if len(news_items) >= 2:
            break

    return news_items


def format_competitors_profile(
    competitors: list[CompetitorProfile],
    industry_category: str | None = None,
    detail: str = "standard",
) -> dict[str, Any]:
    """Форматирует срез конкурентного окружения по уровням подробности."""
    d_raw = str(detail or "").strip().lower()
    if d_raw in ("brief", "кратко", "коротко", "short", "1"):
        detail_norm = "brief"
    elif d_raw in ("full", "полно", "deep", "максимально", "3"):
        detail_norm = "full"
    else:
        detail_norm = "standard"

    if not competitors:
        return {
            "сводка": "Прямых публичных конкурентов в открытых источниках не зафиксировано (узконишевая или непубличная деятельность).",
            "конкуренты": [],
            "всего_выявлено": 0,
        }

    # ── Уровень 1: "brief" («кратко») ──
    if detail_norm == "brief":
        brief_list = []
        for c in competitors[:2]:
            last_news = c.news[0] if c.news else None
            news_str = (
                f"{last_news.title} ({last_news.date or 'недавно'}, {last_news.source})"
                if last_news
                else "Свежих публичных анонсов нет"
            )
            brief_list.append({
                "конкурент": c.brand,
                "специализация": c.profile,
                "последняя_новость": news_str,
            })
        return {
            "кратко": f"Ключевые конкуренты на рынке: {', '.join(c.brand for c in competitors[:2])}.",
            "конкуренты": brief_list,
            "всего_выявлено": len(competitors),
        }

    # ── Уровень 2: "standard" («средне») ──
    if detail_norm == "standard":
        std_list = []
        for c in competitors[:3]:
            news_data = [
                {
                    "событие": n.title,
                    "дата": n.date,
                    "источник": n.source,
                    "url": n.url,
                }
                for n in c.news[:2]
            ]
            std_list.append({
                "бренд": c.brand,
                "профиль": c.profile,
                "сайт": c.site,
                "свежие_события": news_data,
            })

        cat_desc = f" ({industry_category})" if industry_category else ""
        return {
            "обзор_конкурентной_среды": f"Конкурентное окружение в сегменте{cat_desc}: выявлены ключевые сопоставимые игроки рынка.",
            "конкуренты": std_list,
            "всего_выявлено": len(competitors),
        }

    # ── Уровень 3: "full" («полно») ──
    full_list = []
    for c in competitors[:5]:
        news_full = [
            {
                "заголовок": n.title,
                "суть": n.highlight,
                "дата": n.date,
                "источник": n.source,
                "url": n.url,
            }
            for n in c.news
        ]
        item_full = {
            "бренд": c.brand,
            "специализация": c.profile,
            "сайт": c.site,
            "масштаб_рынка": c.market_scale or "Сопоставимый отраслевой игрок",
            "новости_и_продуктовые_релизы": news_full,
        }
        full_list.append(item_full)

    return {
        "обзор_конкурентной_среды": f"Глубокий срез конкурентного ландшафта{f' в сегменте «{industry_category}»' if industry_category else ''}: мониторинг продуктовой активности соперников.",
        "конкуренты": full_list,
        "всего_выявлено": len(competitors),
    }


async def fetch_company_competitors(
    company_name: str,
    brand: str | None = None,
    okved_text: str | None = None,
    okved_code: str | None = None,
    products: list[str] | None = None,
    detail: str = "standard",
) -> dict[str, Any]:
    """Асинхронно выявляет конкурентов контрагента и собирает их последние новости (без руководства)."""
    from osint_mcp.tools.names import core_name

    c_core = core_name(company_name)
    b_clean = (brand or "").strip()
    brand_to_use = b_clean if len(b_clean) >= 3 else (c_core or company_name)
    brand_to_use = re.sub(r'["«»„“\'\`]', '', brand_to_use).strip()

    # 1. Поиск в эталонных отраслевых кластерах
    category, cluster_peers = _match_cluster_peers(
        brand=brand_to_use,
        company_name=company_name,
        okved_text=okved_text,
        products=products,
    )

    candidate_peers: list[dict[str, str]] = list(cluster_peers)

    # 2. Если в кластерах не нашлось или нужно дополнить — делаем точечный веб-поиск
    if len(candidate_peers) < 3:
        queries = _build_competitor_queries(brand_to_use, company_name, okved_text)
        async def _run_search(q: str):
            try:
                return await asyncio.to_thread(search_web, q, limit=3, retries=1, retry_delay=0.5)
            except Exception:  # noqa: BLE001
                return []

        search_res = await asyncio.gather(*[_run_search(q) for q in queries[:2]], return_exceptions=True)
        snippets = []
        for r in search_res:
            if isinstance(r, list):
                for hit in r:
                    snippets.append(f"{hit.get('title', '')} {hit.get('snippet', '')}")
        all_text = " ".join(snippets)

        extracted = _extract_competitor_names_from_text(all_text, brand_to_use)
        for name in extracted:
            if not any(p["brand"].lower() == name.lower() for p in candidate_peers):
                candidate_peers.append({
                    "brand": name,
                    "profile": f"Прямой конкурент и альтернатива {brand_to_use}",
                    "site": None,
                })

    # Ограничиваем количество конкурентов в зависимости от detail
    limit = 2 if detail in ("brief", "кратко") else (3 if detail in ("standard", "средне") else 5)
    selected_candidates = candidate_peers[:limit]

    if not selected_candidates:
        return format_competitors_profile([], industry_category=category, detail=detail)

    # 3. Параллельно собираем новости для каждого конкурента
    async def _populate_competitor(c_dict: dict[str, str]) -> CompetitorProfile:
        b_name = c_dict["brand"]
        news_items = await _fetch_competitor_recent_news(b_name)
        return CompetitorProfile(
            brand=b_name,
            profile=c_dict.get("profile", "Игрок сопоставимого сегмента рынка"),
            site=c_dict.get("site"),
            market_scale="Ключевой отраслевой игрок" if c_dict.get("site") else "Альтернативный поставщик",
            news=news_items,
        )

    tasks = [_populate_competitor(c) for c in selected_candidates]
    populated_profiles = await asyncio.gather(*tasks, return_exceptions=True)

    final_profiles: list[CompetitorProfile] = [
        p for p in populated_profiles if isinstance(p, CompetitorProfile)
    ]

    return format_competitors_profile(final_profiles, industry_category=category, detail=detail)
