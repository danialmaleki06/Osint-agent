"""Модуль выявления операционных сбоев, факапов и репутационных рисков.

Источники и контуры:
1. VC.ru (раздел 'Приёмная', досудебные претензии, неплатежи подрядчикам, споры).
2. Хабр (Habr: инженерные постмортемы, разборы аварий, критика в комментариях).
3. Пикабу (Pikabu: публичные конфликты, жалобы потребителей и партнеров).
4. Чёрные списки заказчиков и работодателей (Antijob, Правда Сотрудников, DreamJob:
   невыплаты расчётов, затягивание подписания актов, токсичный менеджмент).
5. Разработческие сообщества (GitHub, GitLab: брошенные репозитории, критические
   баги, утечки ключей/токенов, конфликты с мейнтейнерами).

Фокус анализа: прикладная оценка рисков для того, кто планирует продать компании
услуги, софт или оборудование (риск неплатежа, срыва приёмки, кражи идей на пилотах).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import re
import structlog

from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.web_search_source import search_web

log = structlog.get_logger()


class FiascoPlatform(str, Enum):
    VC_RU = "vc_ru"
    HABR = "habr"
    PIKABU = "pikabu"
    BLACKLISTS = "blacklists"
    DEV_COMMUNITY = "dev_community"


class FiascoCategory(str, Enum):
    PAYMENT_DEFAULT = "payment_default"      # Неплатежи, удержание средств, затягивание актов
    VENDOR_DISPUTE = "vendor_dispute"        # Конфликт с поставщиком/интегратором, срыв приёмки
    TECH_INCIDENT = "tech_incident"          # Масштабная авария, потеря данных, постмортем
    EMPLOYER_FRAUD = "employer_fraud"        # Черный список работодателей, токсичный менеджмент
    DEV_VULNERABILITY = "dev_vulnerability"  # Брошенные репозитории, уязвимости, утечки токенов


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
    "лежал несколько дней", "потеря данных", "инцидент", "утечка базы",
    "утечка персональных данных", "утечка исходного кода", "утечка", "баг биллинга", "ддос",
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
    """Формирует адресные поисковые запросы по 5 специализированным контурам.
    
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

    # 1. VC.ru (Приёмная и коммерческие претензии)
    queries[FiascoPlatform.VC_RU] = [
        f'site:vc.ru "{brand_term}" приёмная',
        f'"{brand_term}" vc.ru претензия не заплатили',
    ]

    # 2. Хабр (Инженерные постмортемы, сбои и аварии)
    queries[FiascoPlatform.HABR] = [
        f'"{brand_term}" сбой авария habr',
        f'"{brand_term}" утечка инцидент habr',
    ]

    # 3. Пикабу (Потребительские и партнёрские скандалы)
    queries[FiascoPlatform.PIKABU] = [
        f'"{brand_term}" pikabu обман претензия',
        f'"{brand_term}" pikabu не связывайтесь',
    ]

    # 4. Чёрные списки заказчиков и работодателей (Antijob, Правда Сотрудников, DreamJob)
    queries[FiascoPlatform.BLACKLISTS] = [
        f'"{brand_term}" antijob черный список',
        f'"{brand_term}" правда сотрудников отзывы не платят',
    ]

    # 5. Разработческие сообщества (GitHub, GitLab)
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
    """Анализирует текст на негативные маркеры, категорию и формулирует совет продавцу."""
    text_lower = text.lower()
    matched_markers: list[str] = []

    # Проверка на платежные конфликты
    pm = [m for m in PAYMENT_MARKERS if m in text_lower]
    if pm:
        matched_markers.extend(pm)
        return (
            FiascoCategory.PAYMENT_DEFAULT,
            matched_markers,
            "critical",
            "Критический риск неплатежа: требовать 100% предоплату или жесткие этапы с блокировкой лицензий при просрочке.",
        )

    # Проверка на споры с подрядчиками
    vm = [m for m in VENDOR_DISPUTE_MARKERS if m in text_lower]
    if vm:
        matched_markers.extend(vm)
        return (
            FiascoCategory.VENDOR_DISPUTE,
            matched_markers,
            "high",
            "Риск придирок к закрывающим документам: детально фиксировать ТЗ и формулировки актов приёмки в договоре.",
        )

    # Проверка на технические аварии
    tm = [m for m in TECH_INCIDENT_MARKERS if m in text_lower]
    if tm:
        matched_markers.extend(tm)
        return (
            FiascoCategory.TECH_INCIDENT,
            matched_markers,
            "high",
            "Архитектурные риски: слабая стабильность контура заказчика может сорвать сроки интеграции софта.",
        )

    # Проверка на чёрные списки работодателей
    bm = [m for m in BLACKLIST_MARKERS if m in text_lower]
    if bm:
        matched_markers.extend(bm)
        return (
            FiascoCategory.EMPLOYER_FRAUD,
            matched_markers,
            "moderate",
            "Риск текучки ЛПР: смена руководства или увольнение ключевой команды может затянуть проект.",
        )

    # Проверка на dev-уязвимости
    dm = [m for m in DEV_COMMUNITY_MARKERS if m in text_lower]
    if dm:
        matched_markers.extend(dm)
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
) -> ReputationFiascosProfile:
    """Агрегирует сырые поисковые находки по 5 платформам в профиль рисков."""
    incidents: list[FiascoIncident] = []
    platforms_seen: set[str] = set()

    for hit in raw_hits:
        url = hit.get("url", "")
        title = hit.get("title", "")
        snippet = hit.get("snippet", "")
        full_text = f"{title} {snippet}".strip()

        # Определяем платформу по домену
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
        else:
            plat = FiascoPlatform.VC_RU

        cat, markers, severity, advice = classify_fiasco_text(plat, full_text)
        if cat and markers:
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

    # Формируем итоговые контрмеры для коммерческого специалиста
    countermeasures: list[str] = []
    has_payment_risk = any(i.category == FiascoCategory.PAYMENT_DEFAULT for i in incidents)
    has_vendor_risk = any(i.category == FiascoCategory.VENDOR_DISPUTE for i in incidents)
    has_tech_risk = any(i.category == FiascoCategory.TECH_INCIDENT for i in incidents)
    has_churn_risk = any(i.category == FiascoCategory.EMPLOYER_FRAUD for i in incidents)

    if has_payment_risk:
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
        primary_risk = "Низкий риск: критических публичных факапов и неплатежей по целевым платформам не обнаружено."

    return ReputationFiascosProfile(
        company_name=company_name,
        inn=inn,
        total_signals=len(incidents),
        platforms_covered=sorted(list(platforms_seen)),
        incidents=incidents,
        primary_commercial_risk=primary_risk,
        recommended_countermeasures=countermeasures,
    )


def build_reputation_fiasco_facts(
    inn: str,
    company_name: str,
    brand: str | None = None,
    domain: str | None = None,
    platforms: list[str] | None = None,
) -> list[PendingFact]:
    """Сбор и генерация фактов репутационных факапов для шины фактов и карантина."""
    facts: list[PendingFact] = []
    now = datetime.now(timezone.utc)

    queries_map = build_fiasco_queries(company_name, brand, domain)
    target_platforms = set(platforms) if platforms else set(FiascoPlatform)

    raw_hits: list[dict[str, Any]] = []
    for plat, q_list in queries_map.items():
        if plat.value not in [p if isinstance(p, str) else p.value for p in target_platforms]:
            continue
        for q in q_list[:1]:  # По одному высокоточному запросу на платформу для снижения троттлинга
            try:
                hits = search_web(q, limit=3, retries=1)
                raw_hits.extend(hits)
            except Exception as exc:  # noqa: BLE001
                log.warning("fiasco_search_error", query=q, error=str(exc))

    profile = evaluate_fiascos_findings(inn, company_name, raw_hits)

    for i, inc in enumerate(profile.incidents, 1):
        facts.append(
            PendingFact(
                fact_id=f"FIASCO-{inc.platform.value.upper()}-{i}-{inn}",
                kind=f"fiasco_{inc.category.value}",
                statement=f"[{inc.platform.value.upper()}] {inc.title}: {inc.snippet} | Совет: {inc.vendor_risk_advice}",
                source_url=inc.url,
                found_by="reputation_fiascos_engine",
                found_at=now,
                trust="mention",
            )
        )

    return facts
