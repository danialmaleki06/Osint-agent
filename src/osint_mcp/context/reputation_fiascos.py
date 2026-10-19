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
]

VENDOR_DISPUTE_MARKERS = [
    "приёмная", "претензия", "сорвали срок", "сорван проект", "разрыв контракта",
    "обман подрядчика", "суд с подрядчиком", "скандал", "не выполнили обязательства",
    "срыв поставки", "односторонний отказ", "штрафные санкции", "штраф фас", "предписание",
    "антимонопольное дело", "нарушение антимонопольного",
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


@dataclass
class ReputationFiascosProfile:
    company_name: str
    inn: str
    total_signals: int
    platforms_covered: list[str]
    incidents: list[FiascoIncident] = field(default_factory=list)
    primary_commercial_risk: str = "Низкий риск: системных публичных конфликтов не выявлено"
    recommended_countermeasures: list[str] = field(default_factory=list)


def build_fiasco_queries(
    company_name: str,
    brand: str | None = None,
    domain: str | None = None,
) -> dict[FiascoPlatform, list[str]]:
    """Формирует адресные поисковые запросы по ключевым информационным контурам.
    
    Использует естественные поисковые паттерны, которые безотказно обрабатываются
    поисковиками без сбоев на сложной булевой логике со скобками.
    """
    clean_name = re.sub(r'^(ооо|зао|ао|пао|нко|ип)\s+', '', company_name, flags=re.I).strip('"«» ')
    if brand and len(brand.strip()) > 2:
        brand_term = brand.strip()
    elif clean_name and len(clean_name.strip()) > 2:
        brand_term = clean_name.strip()
    else:
        brand_term = (brand or clean_name).strip()
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
    queries[FiascoPlatform.FEDERAL_MEDIA] = [
        f'{brand_term} обыск "уголовное дело" арест',
        f'"{brand_term}" санкции блокировка арест счетов',
    ]

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
) -> ReputationFiascosProfile:
    """Агрегирует сырые поисковые находки в профиль инцидентов с фильтрацией релевантности."""
    incidents: list[FiascoIncident] = []
    platforms_seen: set[str] = set()

    clean_name = re.sub(r'^(ооо|зао|ао|пао|нко|ип)\s+', '', company_name, flags=re.I).strip('"«» ')
    stems = set()
    for t in [brand, clean_name]:
        if not t:
            continue
        t_clean = t.strip().lower()
        if len(t_clean) >= 4:
            stems.add(re.sub(r'[аеёиоуыэюяь]$', '', t_clean))
            stems.add(t_clean)
        elif len(t_clean) >= 2:
            stems.add(t_clean)

    for hit in raw_hits:
        url = hit.get("url", "")
        title = hit.get("title", "")
        snippet = hit.get("snippet", "")
        full_text = f"{title} {snippet}".strip()

        # Фильтр релевантности: компания или бренд обязаны упоминаться в заголовке или сниппете
        if stems and not any(stem in full_text.lower() for stem in stems):
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


DEFAULT_MONITORING_PLATFORMS = [
    FiascoPlatform.DISASTERS,
    FiascoPlatform.CYBER_LEAKS,
    FiascoPlatform.FEDERAL_MEDIA,
    FiascoPlatform.VC_RU,
    FiascoPlatform.HABR,
    FiascoPlatform.BLACKLISTS,
]


def build_reputation_fiasco_facts(
    inn: str,
    company_name: str,
    brand: str | None = None,
    domain: str | None = None,
    platforms: list[str] | None = None,
) -> list[PendingFact]:
    """Сбор и генерация фактов инцидентов и новостных событий для шины фактов и карантина."""
    facts: list[PendingFact] = []
    now = datetime.now(timezone.utc)

    queries_map = build_fiasco_queries(company_name, brand, domain)
    
    if platforms:
        target_platform_vals = set(platforms)
    else:
        target_platform_vals = {p.value for p in DEFAULT_MONITORING_PLATFORMS}

    raw_hits: list[dict[str, Any]] = []
    for plat, q_list in queries_map.items():
        if plat.value not in target_platform_vals:
            continue
        for q in q_list[:1]:  # По одному высокоточному запросу на контур
            try:
                hits = search_web(q, limit=3, retries=2, retry_delay=1.0)
                for h in hits:
                    h["platform_hint"] = plat
                raw_hits.extend(hits)
            except Exception as exc:  # noqa: BLE001
                log.warning("fiasco_search_error", query=q, error=str(exc))
            time.sleep(0.35)

    profile = evaluate_fiascos_findings(inn, company_name, raw_hits, brand=brand)

    for i, inc in enumerate(profile.incidents, 1):
        facts.append(
            PendingFact(
                fact_id=f"FIASCO-{inc.platform.value.upper()}-{i}-{inn}",
                kind=f"fiasco_{inc.category.value}",
                statement=f"[{inc.platform.value.upper()}] {inc.title}: {inc.snippet} | Вывод: {inc.vendor_risk_advice}",
                source_url=inc.url,
                found_by="reputation_fiascos_engine",
                found_at=now,
                trust="mention",
            )
        )

    return facts
