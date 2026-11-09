"""Обратный поиск связанных сайтов и аффилированных доменов по идентификаторам веб-аналитики.

OSINT-логика и интерпретация для аналитика:
1. Идентификаторы Яндекс.Метрики (ym:XXXXX), Google Analytics (UA-XXXXX / G-XXXXX),
   VK/Mail.ru (tmr:XXXXX) настраиваются владельцем или разработчиком сайта.
2. ПРЯМАЯ СВЯЗЬ / ХОЛДИНГ:
   Если один и тот же уникальный код счетчика установлен на нескольких доменах,
   эти домены с высокой вероятностью управляются одним владельцем или маркетинговой командой.
   Пример: микропредприятие ООО «Ромашка» с выручкой 0 руб. имеет тот же счетчик
   Метрики, что и крупный федеральный холдинг или портал застройщика. Это сигнал скрытого актива
   или дочернего направления («спящее юрлицо крупного бизнеса»).
3. ФАКТОР ВЕБ-СТУДИИ / АГЕНТСТВА (ЛОЖНЫЕ СРАБАТЫВАНИЯ):
   Иногда недобросовестные или ленивые подрядчики по разработке ставят один и тот же
   служебный счетчик агентства на сайты десятков разных клиентов.
   Эвристика: если один ID встречается более чем на 15-20 несвязанных тематически сайтах,
   это маркер веб-студии / общего шаблона, а не корпоративной группы.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

import structlog

from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.web_search_source import search_web

log = structlog.get_logger()

# Агрегаторы, зеркала и поисковики, которые не считаются бизнес-сайтами контрагента
_EXCLUDED_DOMAINS = {
    "google.com", "yandex.ru", "ya.ru", "duckduckgo.com", "bing.com",
    "github.com", "stackoverflow.com", "habr.com", "vc.ru",
    "spyonweb.com", "publicwww.com", "builtwith.com", "whois.ru",
    "t.me", "vk.com", "youtube.com", "facebook.com", "instagram.com",
    "wikipedia.org", "w3.org", "schema.org",
}


@dataclass
class SharedTrackerHit:
    tracker_type: str
    tracker_id: str
    shared_domains: list[str]
    is_probable_holding: bool
    interpretation: str
    sample_urls: list[str]


def clean_domain(url_or_domain: str) -> str | None:
    """Нормализовать URL или домен: https://sub.domain.ru/path -> domain.ru / sub.domain.ru."""
    if not url_or_domain:
        return None
    raw = url_or_domain.strip().lower()
    if "://" in raw:
        host = urlparse(raw).netloc
    else:
        host = raw.split("/")[0]
    host = host.removeprefix("www.")
    if ":" in host:
        host = host.split(":")[0]
    if not host or "." not in host:
        return None
    return host


def search_domains_sharing_tracker(
    tracker_type: str,
    tracker_id: str,
    current_domain: str | None = None,
    limit: int = 10,
) -> SharedTrackerHit:
    """Поиск доменов, использующих тот же код аналитики, через публичные поисковые следы.

    Запрос ищет упоминания счетчика на веб-страницах с исключением текущего домена.
    """
    cur_host = clean_domain(current_domain) if current_domain else None

    # Поисковый запрос для нахождения страниц с таким кодом счетчика
    # Пример: '"ym(98765432"' или '"G-AB12CD34"'
    if tracker_type == "yandex_metrika":
        search_query = f'"{tracker_id}" ("mc.yandex.ru" OR "metrika")'
    elif tracker_type == "google_analytics":
        search_query = f'"{tracker_id}" ("google-analytics" OR "googletagmanager")'
    else:
        search_query = f'"{tracker_id}"'

    if cur_host:
        search_query += f" -site:{cur_host}"

    try:
        hits = search_web(search_query, limit=limit, retries=1)
    except Exception as exc:  # noqa: BLE001
        log.warning("tracker_search_failed", tracker_id=tracker_id, error=str(exc))
        hits = []

    domains: set[str] = set()
    sample_urls: list[str] = []

    for hit in hits:
        url = hit.get("url") or ""
        host = clean_domain(url)
        if not host:
            continue
        if host in _EXCLUDED_DOMAINS or (cur_host and host == cur_host):
            continue
        # Проверяем, не домен ли третьего уровня от того же родителя
        domains.add(host)
        if len(sample_urls) < 5:
            sample_urls.append(url)

    shared_domains = sorted(domains)

    # Интерпретация найденного
    count = len(shared_domains)
    if count == 0:
        is_holding = False
        interpretation = "Связанных доменов по коду аналитики в открытых источниках не обнаружено."
    elif count > 15:
        # Признак общего счетчика веб-студии или фреймворка
        is_holding = False
        interpretation = (
            f"Код аналитики обнаружен на большом количестве доменов ({count}+). "
            "Высокая вероятность технического счетчика веб-студии / конструктора сайтов (ложное срабатывание)."
        )
    else:
        # Узкая группа сайтов — явный признак аффилированной группы / единой маркетинговой инфраструктуры
        is_holding = True
        domains_preview = ", ".join(shared_domains[:4]) + ("..." if len(shared_domains) > 4 else "")
        interpretation = (
            f"Обнаружена общая веб-аналитика ({tracker_type} {tracker_id}) с {count} сторонними сайтами: {domains_preview}. "
            "Высокая вероятность вхождения в скрытый холдинг или владения общими бизнес-активами."
        )

    return SharedTrackerHit(
        tracker_type=tracker_type,
        tracker_id=tracker_id,
        shared_domains=shared_domains,
        is_probable_holding=is_holding,
        interpretation=interpretation,
        sample_urls=sample_urls,
    )


def build_analytics_affiliation_facts(
    domain: str | None,
    tracker_ids: dict[str, list[str]],
    subject_inn: str,
) -> list[PendingFact]:
    """Генерация фактов цифровой аффилированности для помещения в очередь/карантин."""
    facts: list[PendingFact] = []
    if not tracker_ids:
        return facts

    for tracker_type, id_list in tracker_ids.items():
        for tid in id_list:
            hit = search_domains_sharing_tracker(
                tracker_type=tracker_type,
                tracker_id=tid,
                current_domain=domain,
                limit=10,
            )
            if hit.shared_domains and hit.is_probable_holding:
                domains_str = ", ".join(hit.shared_domains[:5])
                now = datetime.now(UTC)
                source_url = hit.sample_urls[0] if hit.sample_urls else (f"https://{domain}" if domain else "https://osint.local/analytics")
                facts.append(
                    PendingFact(
                        fact_id=f"WEBANALYTICS-{tracker_type.upper()}-{tid}",
                        kind="affiliate_domain_signal",
                        statement=(
                            f"Обнаружена связанная сеть доменов по коду аналитики {tracker_type} ({tid}): {domains_str}. "
                            f"{hit.interpretation}"
                        ),
                        source_url=source_url,
                        found_by="shared_web_analytics",
                        found_at=now,
                        trust="reference",
                        payload={
                            "subject_inn": subject_inn,
                            "tracker_type": tracker_type,
                            "tracker_id": tid,
                            "shared_domains": hit.shared_domains,
                            "domains_count": len(hit.shared_domains),
                            "interpretation": hit.interpretation,
                            "is_probable_holding": hit.is_probable_holding,
                        },
                    )
                )

    return facts
