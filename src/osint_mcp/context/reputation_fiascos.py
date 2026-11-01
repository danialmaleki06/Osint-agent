"""Модуль выявления операционных сбоев, факапов и репутационных рисков.

Источники и контуры:
1. Катастрофы, атаки, пожары, повреждение инфраструктуры (РБК, Ведомости, СМИ, ЧП).
2. Киберинциденты и утечки данных (утечки баз, сливы исходных кодов, компрометация).
3. Федеральные и деловые медиа (уголовные дела, обыски, задержания, силовые проверки).
4. VC.ru (раздел 'Приёмная', досудебные претензии, неплатежи подрядчикам, споры).
5. Хабр (Habr: инженерные постмортемы, разборы аварий, критика в комментариях).
6. Пикабу (Pikabu: публичные конфликты, жалобы потребителей и партнеров).
7. Чёрные списки заказчиков и работодателей (Antijob, Правда Сотрудников, DreamJob:
   невыплаты расчётов, затягивание подписания актов, токсичный менеджмент).
8. Разработческие сообщества (GitHub, GitLab: брошенные репозитории, критические
   баги, утечки ключей/токенов, конфликты с мейнтейнерами).

Фокус анализа: выявление реальных физических, регуляторных, кибернетических и
коммерческих инцидентов компании, влияющих на её надежность и непрерывность бизнеса.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re
import time
from typing import Any
import structlog

from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.web_search_source import search_web

log = structlog.get_logger()


class FiascoPlatform(str, Enum):
    DISASTERS = "disasters"                  # Физические ЧП, атаки БПЛА, пожары, аварии ЦОД
    FEDERAL_MEDIA = "federal_media"          # Федеральные деловые СМИ (РБК, Ъ, Ведомости, обыски)
    CYBER_LEAKS = "cyber_leaks"              # Утечки ПДн, взломы, сливы исходных кодов
    VC_RU = "vc_ru"                          # VC.ru Приёмная (досудебные претензии, неплатежи)
    HABR = "habr"                            # Хабр (инженерные сбои, постмортемы)
    PIKABU = "pikabu"                        # Пикабу (потребительские конфликты)
    BLACKLISTS = "blacklists"                # Черные списки заказчиков/работодателей
    DEV_COMMUNITY = "dev_community"          # GitHub / GitLab


class FiascoCategory(str, Enum):
    DISASTER_INCIDENT = "disaster_incident"          # Физические ЧП, атаки, пожары, взрывы, остановка ЦОД
    CRIMINAL_INVESTIGATION = "criminal_investigation"# Уголовные дела, обыски, задержания, силовые проверки
    CYBER_DATA_BREACH = "cyber_data_breach"          # Утечки баз данных, взломы, сливы кода
    PAYMENT_DEFAULT = "payment_default"              # Неплатежи, удержание средств, затягивание актов
    VENDOR_DISPUTE = "vendor_dispute"                # Конфликт с поставщиком/интегратором, срыв приёмки
    TECH_INCIDENT = "tech_incident"                  # Масштабная авария, потеря данных, постмортем
    EMPLOYER_FRAUD = "employer_fraud"                # Черный список работодателей, токсичный менеджмент
    DEV_VULNERABILITY = "dev_vulnerability"          # Брошенные репозитории, уязвимости, утечки токенов


DISASTER_MARKERS = [
    "пожар", "взрыв", "атака", "бпла", "дрон", "беспилотник", "чп",
    "происшествие", "разрушение", "уничтожен", "остановлен дата-центр",
    "остановлен цод", "авария в дата-центре", "пострадала инфраструктура",
    "возгорание", "обрушение", "удар", "теракт", "катастрофа",
]

CRIMINAL_MARKERS = [
    "обыск", "уголовное дело", "задержание", "арест", "следственный комитет",
    "следственные действия", "мвд", "фсб", "обвинение", "мошенничество",
    "хищение", "выемка документов", "приговорен",
]

CYBER_MARKERS = [
    "утечка данных", "утечка базы", "слив базы", "исходного кода", "взлом",
    "хакеры", "скомпрометирован", "персональные данные", "утечка пдн",
]

PAYMENT_MARKERS = [
    "не заплатили", "не платят", "задержка оплаты", "не подписывают акты",
    "не подписывает акты", "кинули на деньги", "немотивированный отказ",
    "задолженность перед подрядчиком", "просрочка платежа", "досудебная претензия",
    "выбиваем оплату", "отказываются платить", "удержание денег", "не возвращают",
    "банкротств", "дело о банкротстве", "иск о банкротстве", "процедура банкротства",
    "исполнительный лист", "взыскание", "взыскать", "долг перед фнс",
    "неуплата налогов", "налоговая задолженность", "арест счетов", "арест имущества",
]

VENDOR_DISPUTE_MARKERS = [
    "приёмная", "претензия", "сорвали срок", "сорван проект", "разрыв контракта",
    "обман подрядчика", "суд с подрядчиком", "скандал", "не выполнили обязательства",
    "срыв поставки", "односторонний отказ", "штрафные санкции", "штраф фас", "предписание",
    "антимонопольное дело", "нарушение антимонопольного",
    "расторжение контракта", "расторгла контракт", "расторгнут контракт",
    "одностороннее расторжение", "неустойка", "взыскание неустойки",
]

TECH_INCIDENT_MARKERS = [
    "постмортем", "post-mortem", "авария", "сбой", "упал прод", "упал сервер",
    "лежал несколько дней", "потеря данных", "инцидент", "баг биллинга", "ддос",
    "сломали продакшн", "разбор аварии", "сбой в работе", "массовый сбой", "неполадки",
]

BLACKLIST_MARKERS = [
    "черный список", "чёрный список", "не выплатили расчет", "серая зп",
    "кидалово", "текучка", "самодур", "штрафы", "обман сотрудников",
    "не советую работать", "заставляют переделывать", "бегите отсюда",
]

DEV_COMMUNITY_MARKERS = [
    "critical bug", "vulnerability", "credential leak", "abandoned",
    "broken build", "security flaw", "token leak", "unresponsive maintainer",
    "утечка токена", "уязвимость", "заброшенный репозиторий",
]


RU_MONTHS = {
    # Январь
    "январь": "01", "января": "01", "январе": "01", "янв": "01",
    # Февраль
    "февраль": "02", "февраля": "02", "феврале": "02", "фев": "02",
    # Март
    "март": "03", "марта": "03", "марте": "03", "мар": "03",
    # Апрель
    "апрель": "04", "апреля": "04", "апреле": "04", "апр": "04",
    # Май
    "май": "05", "мая": "05", "мае": "05",
    # Июнь
    "июнь": "06", "июня": "06", "июне": "06", "июн": "06",
    # Июль
    "июль": "07", "июля": "07", "июле": "07", "июл": "07",
    # Август
    "август": "08", "августа": "08", "августе": "08", "авг": "08",
    # Сентябрь
    "сентябрь": "09", "сентября": "09", "сентябре": "09", "сен": "09",
    # Октябрь
    "октябрь": "10", "октября": "10", "октябре": "10", "окт": "10",
    # Ноябрь
    "ноябрь": "11", "ноября": "11", "ноябре": "11", "ноя": "11",
    # Декабрь
    "декабрь": "12", "декабря": "12", "декабре": "12", "дек": "12",
}


def extract_date_from_html(html: str) -> str | None:
    """Извлекает дату публикации из фрагмента HTML по стандартным мета-тегам и разметке."""
    # 1. article:published_time или datePublished или pubdate
    m = re.search(r"""(?:article:published_time|datePublished|pubdate|publish_date)["'][^>]*?content=["']([0-9T:Z+.-]+)["']""", html, re.I)
    if not m:
        m = re.search(r"""content=["']([0-9T:Z+.-]+)["'][^>]*?(?:article:published_time|datePublished|pubdate|publish_date)["']""", html, re.I)
    if not m:
        m = re.search(r"""content=["']([0-9T:Z+.-]+)["']\s+itemprop=["']datePublished["']""", html, re.I)
    if not m:
        m = re.search(r"""<time[^>]*datetime=["']([0-9T:Z+.-]+)["']""", html, re.I)
    if m:
        raw_dt = m.group(1)
        m_iso = re.search(r'(20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])', raw_dt)
        if m_iso:
            return f"{m_iso.group(3)}.{m_iso.group(2)}.{m_iso.group(1)}"
        m_yr = re.search(r'(20\d{2})', raw_dt)
        if m_yr:
            return m_yr.group(1)
    # Поиск даты внутри элементов с классами даты/времени
    m_cls = re.search(r'(?:date|time|published|created)[^>]*>(?:<[^>]+>|\s)*([0-3]?\d\.[0-1]?\d\.20\d{2})', html, re.I)
    if m_cls:
        return m_cls.group(1)
    # Поиск дат на странице в стиле "23 марта 2022"
    m_page_ru = re.search(r'\b([0-3]?\d)\s+([а-яё]+)\s+(20\d{2})\b', html, re.I)
    if m_page_ru:
        d = int(m_page_ru.group(1))
        mw = m_page_ru.group(2).lower()
        yr = m_page_ru.group(3)
        if mw in RU_MONTHS and 1 <= d <= 31:
            return f"{d:02d}.{RU_MONTHS[mw]}.{yr}"
    return None


def fetch_page_metadata_date(url: str, timeout: float = 2.0) -> str | None:
    """Извлекает дату публикации из meta/time тегов HTML страницы (fallback)."""
    try:
        import httpx
        with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as client:
            resp = client.get(url)
            if resp.status_code != 200:
                return None
            return extract_date_from_html(resp.text[:262144])
    except Exception:
        pass
    return None


async def async_fetch_page_metadata_date(
    url: str,
    client: Any | None = None,
    timeout: float = 1.8,
) -> str | None:
    """Асинхронное извлечение даты публикации из meta/time тегов HTML страницы."""
    try:
        import httpx
        if client is not None:
            resp = await client.get(url, timeout=timeout)
        else:
            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}
            ) as c:
                resp = await c.get(url)
        if resp.status_code != 200:
            return None
        return extract_date_from_html(resp.text[:262144])
    except Exception:
        pass
    return None


def extract_incident_date(url: str, title: str, snippet: str, fetch_fallback: bool = False) -> str | None:
    """Извлекает дату публикации или происшествия из URL, заголовка и сниппета."""
    # 1. Поиск в URL: /YYYY/MM/DD/ или /DD/MM/YYYY/ или YYYY-MM-DD
    m_url_ymd = re.search(r'/(20\d{2})/(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])(?:/|$|_)', url)
    if m_url_ymd:
        return f"{m_url_ymd.group(3)}.{m_url_ymd.group(2)}.{m_url_ymd.group(1)}"
    m_url_dmy = re.search(r'/(0[1-9]|[12]\d|3[01])/(0[1-9]|1[0-2])/(20\d{2})(?:/|$|_)', url)
    if m_url_dmy:
        return f"{m_url_dmy.group(1)}.{m_url_dmy.group(2)}.{m_url_dmy.group(3)}"
    m_url_dash = re.search(r'[-_/](20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])', url)
    if m_url_dash:
        return f"{m_url_dash.group(3)}.{m_url_dash.group(2)}.{m_url_dash.group(1)}"

    combined = f"{title} {snippet}"

    # 2. Поиск в тексте: число + месяц + год ("8 октября 2026", "1 марта 2022")
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

    # 3. Месяц и год без числа: "март 2022", "в январе 2023 года"
    m_my = re.search(r'\b([а-яё]+)\s+(20\d{2})\b', combined, re.I)
    if m_my:
        month_word = m_my.group(1).lower()
        if month_word in RU_MONTHS:
            return f"{RU_MONTHS[month_word]}.{m_my.group(2)}"

    # 4. Числовой формат в тексте: DD.MM.YYYY или DD.MM.YY
    m_num = re.search(r'\b([0-3]?\d)\.(0[1-9]|1[0-2])\.(20\d{2}|\d{2})\b', combined)
    if m_num:
        yr = m_num.group(3)
        if len(yr) == 2:
            yr = f"20{yr}"
        return f"{int(m_num.group(1)):02d}.{m_num.group(2)}.{yr}"

    # 5. Год в контексте или URL
    m_yr = re.search(r'\b(201\d|202\d)\b', combined) or re.search(r'/(201\d|202\d)/', url)
    if m_yr:
        return m_yr.group(1)

    # 6. Fallback: быстрый запрос мета-тегов со страницы
    if fetch_fallback and url.startswith("http"):
        meta_d = fetch_page_metadata_date(url)
        if meta_d:
            return meta_d

    # 7. Если было число и месяц без года: вернуть "DD.MM"
    if m_ru:
        day = int(m_ru.group(1))
        month_word = m_ru.group(2).lower()
        if month_word in RU_MONTHS and 1 <= day <= 31:
            return f"{day:02d}.{RU_MONTHS[month_word]}"

    return None


@dataclass
class FiascoIncident:
    platform: FiascoPlatform
    category: FiascoCategory
    title: str
    url: str
    snippet: str
    detected_markers: list[str]
    severity: str  # "critical", "high", "moderate"
    vendor_risk_advice: str
    incident_date: str | None = None
    source_label: str = ""


@dataclass
class ReputationFiascosProfile:
    company_name: str
    inn: str
    total_signals: int
    platforms_covered: list[str]
    incidents: list[FiascoIncident] = field(default_factory=list)
    primary_commercial_risk: str = "Низкий риск: системных публичных конфликтов не выявлено"
    recommended_countermeasures: list[str] = field(default_factory=list)


# Региональные редакции РБК: маппинг первых двух цифр ИНН (код региона РФ)
# на название региональной редакции и целевой поддомен/поисковый термин.
REGIONAL_RBC_MAP: dict[str, tuple[str, str]] = {
    "16": ("РБК Татарстан", "rt.rbc.ru"),
    "78": ("РБК Санкт-Петербург", "spb.rbc.ru"),
    "47": ("РБК Санкт-Петербург", "spb.rbc.ru"),
    "66": ("РБК Екатеринбург", "ekb.rbc.ru"),
    "02": ("РБК Уфа", "ufa.rbc.ru"),
    "54": ("РБК Новосибирск", "nsk.rbc.ru"),
    "61": ("РБК Ростов", "rostov.rbc.ru"),
    "23": ("РБК Краснодар", "kuban.rbc.ru"),
    "59": ("РБК Пермь", "perm.rbc.ru"),
    "52": ("РБК Нижний Новгород", "nn.rbc.ru"),
    "39": ("РБК Калининград", "kaliningrad.rbc.ru"),
    "25": ("РБК Приморье", "vostok.rbc.ru"),
    "72": ("РБК Тюмень", "tumen.rbc.ru"),
    "24": ("РБК Красноярск", "krasnoyarsk.rbc.ru"),
    "36": ("РБК Черноземье", "chr.rbc.ru"),
    "34": ("РБК Юг", "ug.rbc.ru"),
}

RBC_SUBDOMAIN_NAMES: dict[str, str] = {
    "rt.rbc.ru": "РБК Татарстан",
    "spb.rbc.ru": "РБК Санкт-Петербург",
    "ekb.rbc.ru": "РБК Екатеринбург",
    "ufa.rbc.ru": "РБК Уфа",
    "nsk.rbc.ru": "РБК Новосибирск",
    "rostov.rbc.ru": "РБК Ростов",
    "kuban.rbc.ru": "РБК Краснодар",
    "perm.rbc.ru": "РБК Пермь",
    "nn.rbc.ru": "РБК Нижний Новгород",
    "kaliningrad.rbc.ru": "РБК Калининград",
    "vostok.rbc.ru": "РБК Приморье",
    "tumen.rbc.ru": "РБК Тюмень",
    "krasnoyarsk.rbc.ru": "РБК Красноярск",
    "chr.rbc.ru": "РБК Черноземье",
    "ug.rbc.ru": "РБК Юг",
    "companies.rbc.ru": "РБК Компании",
}

RBC_PATH_NAMES: dict[str, str] = {
    "/spb_sz/": "РБК Санкт-Петербург",
    "/tatarstan/": "РБК Татарстан",
    "/ekb/": "РБК Екатеринбург",
    "/ufa/": "РБК Уфа",
    "/nsk/": "РБК Новосибирск",
    "/rostov/": "РБК Ростов",
    "/krasnodar/": "РБК Краснодар",
    "/perm/": "РБК Пермь",
    "/nn/": "РБК Нижний Новгород",
    "/kaliningrad/": "РБК Калининград",
    "/vostok/": "РБК Приморье",
    "/tumen/": "РБК Тюмень",
    "/krasnoyarsk/": "РБК Красноярск",
    "/chr/": "РБК Черноземье",
    "/ug/": "РБК Юг",
}


def resolve_media_source_label(url: str, default_plat: FiascoPlatform) -> str:
    """Определяет человекочитаемое наименование источника / регионального СМИ."""
    u_low = (url or "").lower()
    for sub, name in RBC_SUBDOMAIN_NAMES.items():
        if sub in u_low:
            return name
    for path, name in RBC_PATH_NAMES.items():
        if path in u_low:
            return name
    if "rbc.ru" in u_low:
        return "РБК"
    if "business-gazeta.ru" in u_low:
        return "Бизнес Online"
    if "rusbankrot.ru" in u_low:
        return "Русбанкрот"
    if "116.ru" in u_low:
        return "116.ru"
    if "e1.ru" in u_low:
        return "E1.ru"
    if "ngs.ru" in u_low:
        return "NGS.ru"
    if "74.ru" in u_low:
        return "74.ru"
    if "kommersant.ru" in u_low:
        return "Коммерсантъ"
    if "vedomosti.ru" in u_low:
        return "Ведомости"
    if "forbes.ru" in u_low:
        return "Forbes"
    if "interfax.ru" in u_low:
        return "Интерфакс"
    if "tass.ru" in u_low:
        return "ТАСС"
    if "fontanka.ru" in u_low:
        return "Фонтанка"
    if "vc.ru" in u_low:
        return "VC.ru"
    if "habr.com" in u_low:
        return "Хабр"
    if "pikabu.ru" in u_low:
        return "Пикабу"
    if "antijob" in u_low:
        return "Antijob"
    if "pravda-sotrudnikov" in u_low:
        return "Правда Сотрудников"
    if "dreamjob" in u_low:
        return "DreamJob"
    return default_plat.value.upper()

def build_fiasco_queries(
    company_name: str,
    brand: str | None = None,
    domain: str | None = None,
    inn: str | None = None,
) -> dict[FiascoPlatform, list[str]]:
    """Формирует адресные поисковые запросы по ключевым информационным контурам.
    
    Использует естественные поисковые паттерны, которые безотказно обрабатываются
    поисковиками без сбоев на сложной булевой логике со скобками.
    """
    from osint_mcp.tools.names import core_name
    c_core = core_name(company_name)
    clean_name = c_core or re.sub(
        r'^(общество с ограниченной ответственностью|акционерное общество|публичное акционерное общество|непубличное акционерное общество|закрытое акционерное общество|ооо|зао|ао|пао|нко|ип)\s+',
        '', company_name, flags=re.I
    ).strip('"«» ')
    clean_name = re.sub(r'["«»„“\'\`]', '', clean_name).strip()

    b_clean = (brand or "").strip()
    b_clean = re.sub(r'["«»„“\'\`]', '', b_clean).strip()

    has_cyrillic_brand = bool(b_clean and re.search(r'[а-яА-ЯёЁ]', b_clean))
    has_cyrillic_name = bool(re.search(r'[а-яА-ЯёЁ]', clean_name))

    if b_clean and len(b_clean) > 3 and (has_cyrillic_brand or not has_cyrillic_name):
        brand_term = b_clean
    elif clean_name and len(clean_name) >= 3:
        brand_term = clean_name
    elif b_clean and len(b_clean) >= 2:
        brand_term = b_clean
    else:
        brand_term = (clean_name or b_clean or company_name).strip()

    brand_term = re.sub(r'["«»„“\'\`]', '', brand_term).strip()
    domain_term = domain.strip().lower() if domain else ""

    queries: dict[FiascoPlatform, list[str]] = {}

    # 1. ЧП, физические катастрофы, атаки БПЛА, пожары дата-центров
    queries[FiascoPlatform.DISASTERS] = [
        f'{brand_term} датацентр пожар атака',
        f'{brand_term} взрыв пожар ЧП происшествие',
    ]

    # 2. Киберинциденты, утечки баз данных и сливы исходных кодов
    queries[FiascoPlatform.CYBER_LEAKS] = [
        f'{brand_term} утечка данных слив базы',
        f'{brand_term} взлом исходный код хакеры',
    ]

    # 3. Федеральные и деловые медиа: обыски, уголовные дела, расследования
    fed_queries = [
        f'{brand_term} обыск "уголовное дело" арест',
        f'"{brand_term}" санкции блокировка арест счетов',
    ]

    # Если передан ИНН — добавляем целевой запрос по региональной редакции РБК
    if inn and len(str(inn).strip()) in (10, 12):
        reg_code = str(inn).strip()[:2]
        if reg_code in REGIONAL_RBC_MAP:
            rbc_label, _ = REGIONAL_RBC_MAP[reg_code]
            fed_queries.insert(0, f'{rbc_label} {brand_term} обыск суд')

    queries[FiascoPlatform.FEDERAL_MEDIA] = fed_queries

    # 4. VC.ru (Приёмная и коммерческие претензии)
    queries[FiascoPlatform.VC_RU] = [
        f'"{brand_term}" vc.ru приёмная',
        f'"{brand_term}" vc.ru претензия не заплатили',
    ]

    # 5. Хабр (Инженерные постмортемы, сбои и аварии)
    queries[FiascoPlatform.HABR] = [
        f'"{brand_term}" сбой авария habr',
        f'"{brand_term}" утечка инцидент habr',
    ]

    # 6. Пикабу (Потребительские и партнёрские скандалы)
    queries[FiascoPlatform.PIKABU] = [
        f'"{brand_term}" pikabu обман претензия',
        f'"{brand_term}" pikabu не связывайтесь',
    ]

    # 7. Чёрные списки заказчиков и работодателей (Antijob, Правда Сотрудников, DreamJob)
    queries[FiascoPlatform.BLACKLISTS] = [
        f'"{brand_term}" antijob черный список',
        f'"{brand_term}" правда сотрудников отзывы не платят',
    ]

    # 8. Разработческие сообщества (GitHub, GitLab)
    dev_term = domain_term if domain_term else brand_term
    queries[FiascoPlatform.DEV_COMMUNITY] = [
        f'"{dev_term}" github vulnerability leak',
        f'"{brand_term}" gitlab critical bug issue',
    ]

    return queries


def classify_fiasco_text(
    platform: FiascoPlatform,
    text: str,
) -> tuple[FiascoCategory | None, list[str], str, str]:
    """Анализирует текст на негативные маркеры, категорию и формулирует совет аналитику."""
    text_lower = text.lower()
    matched_markers: list[str] = []

    # 1. Чрезвычайные происшествия, атаки, пожары, разрушения
    dm = [m for m in DISASTER_MARKERS if m in text_lower]
    if dm:
        matched_markers.extend(dm)
        return (
            FiascoCategory.DISASTER_INCIDENT,
            matched_markers,
            "critical",
            "Критический физический/инфраструктурный инцидент: пожар, атака или остановка ключевых мощностей (ЦОД, склады, заводы). Угроза непрерывности бизнеса и выполнения контрактов.",
        )

    # 2. Уголовные дела, обыски, задержания
    cm = [m for m in CRIMINAL_MARKERS if m in text_lower]
    if cm:
        matched_markers.extend(cm)
        return (
            FiascoCategory.CRIMINAL_INVESTIGATION,
            matched_markers,
            "critical",
            "Уголовные или следственные риски: обыски, аресты руководства или проверки силовых ведомств несут угрозу блокировки счетов и операционной деятельности.",
        )

    # 3. Киберинциденты и утечки данных
    cl = [m for m in CYBER_MARKERS if m in text_lower]
    if cl:
        matched_markers.extend(cl)
        return (
            FiascoCategory.CYBER_DATA_BREACH,
            matched_markers,
            "high",
            "Инцидент информационной безопасности: утечка данных или компрометация инфраструктуры. Риск вторичных регуляторных штрафов (КоАП 13.11).",
        )

    # 4. Проверка на платежные конфликты
    pm = [m for m in PAYMENT_MARKERS if m in text_lower]
    if pm:
        matched_markers.extend(pm)
        return (
            FiascoCategory.PAYMENT_DEFAULT,
            matched_markers,
            "critical",
            "Критический риск неплатежа: требовать 100% предоплату или жесткие этапы с блокировкой лицензий при просрочке.",
        )

    # 5. Проверка на споры с подрядчиками
    vm = [m for m in VENDOR_DISPUTE_MARKERS if m in text_lower]
    if vm:
        matched_markers.extend(vm)
        return (
            FiascoCategory.VENDOR_DISPUTE,
            matched_markers,
            "high",
            "Риск придирок к закрывающим документам: детально фиксировать ТЗ и формулировки актов приёмки в договоре.",
        )

    # 6. Проверка на технические аварии
    tm = [m for m in TECH_INCIDENT_MARKERS if m in text_lower]
    if tm:
        matched_markers.extend(tm)
        return (
            FiascoCategory.TECH_INCIDENT,
            matched_markers,
            "high",
            "Архитектурные риски: слабая стабильность контура заказчика может сорвать сроки интеграции софта.",
        )

    # 7. Проверка на чёрные списки работодателей
    bm = [m for m in BLACKLIST_MARKERS if m in text_lower]
    if bm:
        matched_markers.extend(bm)
        return (
            FiascoCategory.EMPLOYER_FRAUD,
            matched_markers,
            "moderate",
            "Риск текучки ЛПР: смена руководства или увольнение ключевой команды может затянуть проект.",
        )

    # 8. Проверка на dev-уязвимости
    dev_m = [m for m in DEV_COMMUNITY_MARKERS if m in text_lower]
    if dev_m:
        matched_markers.extend(dev_m)
        return (
            FiascoCategory.DEV_VULNERABILITY,
            matched_markers,
            "moderate",
            "Технические долги в кодовой базе: учитывать возможные задержки при интеграции по API.",
        )

    return None, [], "minor", ""


def evaluate_fiascos_findings(
    inn: str,
    company_name: str,
    raw_hits: list[dict[str, Any]],
    brand: str | None = None,
    fetch_fallback: bool = False,
) -> ReputationFiascosProfile:
    """Агрегирует сырые поисковые находки в профиль инцидентов с фильтрацией релевантности."""
    incidents: list[FiascoIncident] = []
    platforms_seen: set[str] = set()

    clean_name = re.sub(
        r'^(общество с ограниченной ответственностью|акционерное общество|публичное акционерное общество|непубличное акционерное общество|закрытое акционерное общество|ооо|зао|ао|пао|нко|ип)\s+',
        '', company_name, flags=re.I
    ).strip('"«» ')
    clean_name = re.sub(r'["«»„“\'\`]', '', clean_name).strip()

    from osint_mcp.tools.names import name_variants
    stems = set()
    for t in [brand, clean_name, company_name] + name_variants(company_name, brand):
        if not t:
            continue
        t_clean = t.strip().lower()
        t_norm = re.sub(r'["«»„“\'\`]', '', t_clean).strip()
        t_norm = re.sub(r'\s+', ' ', t_norm)
        for cand in {t_clean, t_norm}:
            if not cand:
                continue
            if len(cand) >= 4:
                stems.add(re.sub(r'[аеёиоуыэюяь]$', '', cand))
                stems.add(cand)
            elif len(cand) >= 2:
                stems.add(cand)

    # Для составных названий добавляем ключевые уникальные слова длиной >= 5
    _STOP_WORDS = {
        "компания", "холдинг", "предприятие", "сервис", "группа", "общество",
        "центр", "россия", "северной", "южной", "восточной", "западной",
        "столицы", "инвест", "капитал", "трейд", "проект", "технологии", "решения"
    }
    for w in re.split(r'[\s"«»„“\'`]+', clean_name.lower()):
        w_clean = re.sub(r'[^а-яa-z0-9]', '', w)
        if len(w_clean) >= 5 and w_clean not in _STOP_WORDS:
            stems.add(re.sub(r'[аеёиоуыэюяь]$', '', w_clean))
            stems.add(w_clean)

    for hit in raw_hits:
        url = hit.get("url", "")
        title = hit.get("title", "")
        snippet = hit.get("snippet", "")
        full_text = f"{title} {snippet}".strip()

        # Фильтр релевантности: компания или бренд обязаны упоминаться в заголовке или сниппете
        full_lower = full_text.lower()
        full_clean = re.sub(r'["«»„“\'\`]', '', full_lower)
        full_clean_spaced = re.sub(r'[\s"«»„“\'\`]+', ' ', full_lower)

        matched_stem = any(
            stem in full_lower or stem in full_clean or stem in full_clean_spaced
            for stem in stems
        )
        if stems and not matched_stem:
            continue

        url_lower = url.lower()
        if "vc.ru" in url_lower:
            plat = FiascoPlatform.VC_RU
        elif "habr.com" in url_lower:
            plat = FiascoPlatform.HABR
        elif "pikabu.ru" in url_lower:
            plat = FiascoPlatform.PIKABU
        elif any(d in url_lower for d in ("antijob", "pravda-sotrudnikov", "dreamjob", "neorabote")):
            plat = FiascoPlatform.BLACKLISTS
        elif any(d in url_lower for d in ("github.com", "gitlab.com")):
            plat = FiascoPlatform.DEV_COMMUNITY
        elif any(d in url_lower for d in ("rbc.ru", "vedomosti.ru", "kommersant.ru", "interfax.ru", "forbes.ru", "tass.ru", "lenta.ru", "fontanka.ru", "dzen.ru", "gazeta.ru", "dw.com", "bbc.com", "themoscowtimes.com", "kp.ru")):
            plat = FiascoPlatform.FEDERAL_MEDIA
        else:
            plat = hit.get("platform_hint") or FiascoPlatform.FEDERAL_MEDIA

        cat, markers, severity, advice = classify_fiasco_text(plat, full_text)
        if cat and markers:
            # Если классифицирован как ЧП/катастрофа, платформа маркируется как DISASTERS
            if cat == FiascoCategory.DISASTER_INCIDENT:
                plat = FiascoPlatform.DISASTERS
            elif cat == FiascoCategory.CYBER_DATA_BREACH:
                plat = FiascoPlatform.CYBER_LEAKS

            source_lbl = resolve_media_source_label(url, plat)
            inc_date = extract_incident_date(url, title, snippet, fetch_fallback=fetch_fallback)
            platforms_seen.add(plat.value)
            incidents.append(
                FiascoIncident(
                    platform=plat,
                    category=cat,
                    title=title,
                    url=url,
                    snippet=snippet,
                    detected_markers=markers,
                    severity=severity,
                    vendor_risk_advice=advice,
                    incident_date=inc_date,
                    source_label=source_lbl,
                )
            )

    countermeasures: list[str] = []
    has_disaster = any(i.category == FiascoCategory.DISASTER_INCIDENT for i in incidents)
    has_criminal = any(i.category == FiascoCategory.CRIMINAL_INVESTIGATION for i in incidents)
    has_cyber = any(i.category == FiascoCategory.CYBER_DATA_BREACH for i in incidents)
    has_payment_risk = any(i.category == FiascoCategory.PAYMENT_DEFAULT for i in incidents)
    has_vendor_risk = any(i.category == FiascoCategory.VENDOR_DISPUTE for i in incidents)
    has_tech_risk = any(i.category == FiascoCategory.TECH_INCIDENT for i in incidents)
    has_churn_risk = any(i.category == FiascoCategory.EMPLOYER_FRAUD for i in incidents)

    if has_disaster:
        primary_risk = "КРИТИЧЕСКИЙ ИНФРАСТРУКТУРНЫЙ ИНЦИДЕНТ: Зафиксированы аварии, пожары или поражение мощностей (ЦОД/склады)."
        countermeasures.append("Проверить наличие резервных дата-центров и планов Disaster Recovery (DRP).")
        countermeasures.append("Запросить подтверждение стабильности каналов связи и SLA по непрерывности.")
    elif has_criminal:
        primary_risk = "КРИТИЧЕСКИЙ РЕГУЛЯТОРНЫЙ/УГОЛОВНЫЙ РИСК: Зафиксированы следственные действия, обыски или аресты руководства."
        countermeasures.append("Исключить долгосрочные авансовые расчеты; предусмотреть право расторжения при блокировке счетов.")
    elif has_cyber:
        primary_risk = "ВЫСОКИЙ РИСК ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ: Публичные утечки персональных данных или компрометация исходных кодов."
        countermeasures.append("Провести аудит безопасности перед интеграцией; исключить передачу чувствительных ключей.")
    elif has_payment_risk:
        primary_risk = "ВЫСОКИЙ КОММЕРЧЕСКИЙ РИСК: Зафиксированы публичные жалобы на задержку оплат и споры с подрядчиками."
        countermeasures.append("Не поставлять товар/услуги с постоплатой более 14 дней.")
        countermeasures.append("Включать право приостановки лицензий/доступов при просрочке платежа.")
    elif has_vendor_risk:
        primary_risk = "УМЕРЕННЫЙ РИСК СДАЧИ-ПРИЁМКИ: Зафиксированы конфликты и претензии при согласовании закрывающих актов."
        countermeasures.append("Фиксировать исчерпывающий перечень критериев приёмки в приложении к договору.")
    elif has_tech_risk:
        primary_risk = "ТЕХНИЧЕСКИЙ РИСК: Публичные следы аварий и сбоев инфраструктуры."
        countermeasures.append("Закладывать дополнительный буфер времени на тестирование интеграций.")
    elif has_churn_risk:
        primary_risk = "ОРГАНИЗАЦИОННЫЙ РИСК: Признаки высокой текучки кадров и смены проектных команд."
        countermeasures.append("Фиксировать куратора проекта со стороны заказчика на уровне топ-менеджмента.")
    else:
        primary_risk = "Низкий риск: критических публичных инцидентов, аварий и неплатежей не обнаружено."

    return ReputationFiascosProfile(
        company_name=company_name,
        inn=inn,
        total_signals=len(incidents),
        platforms_covered=sorted(list(platforms_seen)),
        incidents=incidents,
        primary_commercial_risk=primary_risk,
        recommended_countermeasures=countermeasures,
    )


async def async_evaluate_fiascos_findings(
    inn: str,
    company_name: str,
    raw_hits: list[dict[str, Any]],
    brand: str | None = None,
) -> ReputationFiascosProfile:
    """Асинхронная агрегация находок с параллельным fallback-извлечением недостающих дат."""
    import asyncio
    # 1. Быстрый локальный парсинг дат через regex без блокирующих HTTP-запросов
    profile = evaluate_fiascos_findings(
        inn, company_name, raw_hits, brand=brand, fetch_fallback=False,
    )
    # 2. Асинхронное параллельное обогащение для находок без найденной даты
    missing_dates = [
        inc for inc in profile.incidents
        if not inc.incident_date and inc.url.startswith("http")
    ]
    if missing_dates:
        import httpx
        try:
            async with httpx.AsyncClient(
                timeout=1.8, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}
            ) as client:
                tasks = [
                    async_fetch_page_metadata_date(inc.url, client=client, timeout=1.8)
                    for inc in missing_dates
                ]
                dates = await asyncio.gather(*tasks, return_exceptions=True)
                for inc, d in zip(missing_dates, dates):
                    if isinstance(d, str) and d:
                        inc.incident_date = d
        except Exception:
            pass
    return profile


DEFAULT_MONITORING_PLATFORMS = [
    FiascoPlatform.DISASTERS,
    FiascoPlatform.CYBER_LEAKS,
    FiascoPlatform.FEDERAL_MEDIA,
    FiascoPlatform.VC_RU,
    FiascoPlatform.HABR,
    FiascoPlatform.BLACKLISTS,
]


async def async_build_reputation_fiasco_facts(
    inn: str,
    company_name: str,
    brand: str | None = None,
    domain: str | None = None,
    platforms: list[str] | None = None,
) -> list[PendingFact]:
    """Асинхронный параллельный сбор и генерация фактов инцидентов и новостных событий."""
    import asyncio
    facts: list[PendingFact] = []
    now = datetime.now(timezone.utc)

    queries_map = build_fiasco_queries(company_name, brand, domain, inn=inn)

    if platforms:
        target_platform_vals = set(platforms)
    else:
        target_platform_vals = {p.value for p in DEFAULT_MONITORING_PLATFORMS}

    # Параллельный поиск по целевым контурам (без последовательного time.sleep)
    async def _search_one(plat: FiascoPlatform, q: str) -> list[dict[str, Any]]:
        try:
            hits = await asyncio.to_thread(search_web, q, limit=3, retries=1, retry_delay=0.5)
            for h in hits:
                h["platform_hint"] = plat
            return hits
        except Exception as exc:  # noqa: BLE001
            log.warning("fiasco_search_error", query=q, error=str(exc))
            return []

    search_tasks = []
    for plat, q_list in queries_map.items():
        if plat.value not in target_platform_vals:
            continue
        for q in q_list[:1]:  # По одному высокоточному запросу на контур
            search_tasks.append(_search_one(plat, q))

    gathered_hits = await asyncio.gather(*search_tasks, return_exceptions=True)
    raw_hits: list[dict[str, Any]] = []
    for r in gathered_hits:
        if isinstance(r, list):
            raw_hits.extend(r)

    profile = await async_evaluate_fiascos_findings(inn, company_name, raw_hits, brand=brand)

    for i, inc in enumerate(profile.incidents, 1):
        date_str = f"[{inc.incident_date}] " if inc.incident_date else ""
        label_str = f"[{inc.source_label}] " if inc.source_label else f"[{inc.platform.value.upper()}] "
        facts.append(
            PendingFact(
                fact_id=f"FIASCO-{inc.platform.value.upper()}-{i}-{inn}",
                kind=f"fiasco_{inc.category.value}",
                statement=f"{label_str}{date_str}{inc.title}: {inc.snippet} | Вывод: {inc.vendor_risk_advice}",
                source_url=inc.url,
                found_by="reputation_fiascos_engine",
                found_at=now,
                trust="mention",
            )
        )

    return facts


def build_reputation_fiasco_facts(
    inn: str,
    company_name: str,
    brand: str | None = None,
    domain: str | None = None,
    platforms: list[str] | None = None,
) -> list[PendingFact]:
    """Синхронная обёртка для обратной совместимости с тестами и скриптами."""
    import asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(
                asyncio.run,
                async_build_reputation_fiasco_facts(
                    inn=inn,
                    company_name=company_name,
                    brand=brand,
                    domain=domain,
                    platforms=platforms,
                ),
            ).result()
    else:
        return asyncio.run(
            async_build_reputation_fiasco_facts(
                inn=inn,
                company_name=company_name,
                brand=brand,
                domain=domain,
                platforms=platforms,
            )
        )
