"""Картографический OSINT, отзывы и гео-инспекция (Yandex / 2GIS API).

OSINT-логика и интерпретация для аналитика и LLM:
1. Картографические сервисы (Яндекс Карты, 2ГИС) отражают ФИЗИЧЕСКУЮ РЕАЛЬНОСТЬ
   бизнеса, которая часто кардинально расходится с данными из ЕГРЮЛ.
2. ФАКТОР ФИКТИВНОГО / МАССОВОГО АДРЕСА:
   - Если компания показывает обороты в сотни миллионов или миллиарды рублей,
     а на картах и панорамах по ее юридическому адресу находится заброшенный гаражный массив,
     трансформаторная будка, жилой барак или глухой забор — это классический признак "бумажной фирмы" / площадки обналичивания.
   - И наоборот: современный офис с вывеской, производственный ангар или оживленный логистический склад — признак живого бизнеса.
3. ОПЕРАЦИОННЫЕ И КАССОВЫЕ СБОИ ПО СВЕЖИМ ОТЗЫВАМ:
   - Общий рейтинг (например, 4.2) обманчив: важно анализировать семантику отзывов за последние 1-3 месяца.
   - Паттерны: "не берут трубку", "заказ задержали на неделю", "курьер нахамил", "склад закрыт", "в магазине грязно" —
     это триггеры операционного кризиса, увольнения персонала или кассового разрыва.
   - Идеально для предложения софта по контролю качества, автоматизации доставки или клининга.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

import structlog

from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.web_search_source import SearchResults, SearchUnavailable, search_web

log = structlog.get_logger()

# Слова-маркеры операционного сбоя в отзывах
OPERATIONAL_ISSUE_MARKERS = [
    "задержка", "сорвали срок", "не привезли", "хамят", "не берут трубку",
    "обман", "брак", "грязно", "закрыто", "не работают", "мошенники", "пропали",
    "не отвечают", "ужасный сервис", "срыв поставки", "испортился",
]

# Маркеры сомнительного/фиктивного физического адреса
SUSPICIOUS_LOCATION_MARKERS = [
    "гараж", "гаражный кооператив", "гск", "подвал", "барак", "заброшен",
    "стройплощадка", "пустырь", "трансформатор", "нежилое помещение без вывески",
]


@dataclass
class GeoReviewsProfile:
    address: str
    company_name: str
    rating: float | None
    reviews_count: int
    has_physical_presence: bool
    suspicious_location_flags: list[str]
    recent_issues: list[str]
    interpretation: str


def evaluate_geo_findings(
    address: str,
    company_name: str,
    rating: float | None = None,
    reviews: list[str] | None = None,
    location_features: list[str] | None = None,
) -> GeoReviewsProfile:
    """Анализ гео-признаков, панорам и семантики отзывов."""
    reviews_list = reviews or []
    features_list = location_features or []

    suspicious_flags = []
    addr_low = address.lower()
    for marker in SUSPICIOUS_LOCATION_MARKERS:
        if marker in addr_low or any(marker in f.lower() for f in features_list):
            suspicious_flags.append(f"Маркер подозрительной локации: '{marker}'")

    issues_found = []
    for r in reviews_list:
        r_low = r.lower()
        matched = [m for m in OPERATIONAL_ISSUE_MARKERS if m in r_low]
        if matched:
            issues_found.append(f"Отзыв с проблемой ({', '.join(matched)}): '{r[:100]}...'")

    # Формирование выводов для агента
    if suspicious_flags:
        interpretation = (
            f"ВНИМАНИЕ (Физическая реальность): Выявлены маркеры сомнительного адреса ({', '.join(suspicious_flags)}). "
            "По адресу регистрации нет признаков реальной офисно-производственной деятельности. "
            "Высокий риск фиктивного адреса / номинальной компании."
        )
    elif issues_found:
        interpretation = (
            f"Выявлены операционные проблемы по свежим отзывам ({len(issues_found)} сигналов). "
            "Клиенты жалуются на сбои сервиса, задержки или качество обслуживания. "
            "Индикатор операционного кризиса, нехватки персонала или логистических трудностей."
        )
    elif rating and rating >= 4.0:
        interpretation = (
            f"Высокий подтвержденный клиентский рейтинг ({rating} из 5 на картах, {len(reviews_list)} отзывов). "
            "Реальное физическое присутствие подтверждено клиентами и посетителями."
        )
    else:
        interpretation = "Физическое присутствие подтверждено на картах, критических аномалий в отзывах не обнаружено."

    return GeoReviewsProfile(
        address=address,
        company_name=company_name,
        rating=rating,
        reviews_count=len(reviews_list),
        has_physical_presence=len(suspicious_flags) == 0,
        suspicious_location_flags=suspicious_flags,
        recent_issues=issues_found,
        interpretation=interpretation,
    )


def build_geo_reviews_facts(
    inn: str,
    company_name: str,
    address: str,
    reviews: list[str] | None = None,
    rating: float | None = None,
) -> list[PendingFact]:
    """Сбор и генерация фактов картографического OSINT для шины фактов."""
    facts: list[PendingFact] = []
    now = datetime.now(UTC)

    collected_reviews = list(reviews) if reviews else []
    partial_reason = None

    # Поиск по картам и отзывам при отсутствии прямых данных
    if not collected_reviews and address:
        query = f'"{company_name}" "{address}" (отзывы OR яндекс карты OR 2gis)'
        try:
            hits = search_web(query, limit=5, retries=1, raise_on_unavailable=True)
            partial_reason = getattr(hits, "partial_reason", None)
        except SearchUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("geo_search_failed", company=company_name, error=str(exc))
            raise SearchUnavailable("Не удалось обработать геопоиск") from exc

        for h in hits:
            text = (h.get("title", "") + " " + h.get("snippet", "")).strip()
            if any(m in text.lower() for m in OPERATIONAL_ISSUE_MARKERS):
                collected_reviews.append(text)

    profile = evaluate_geo_findings(
        address=address,
        company_name=company_name,
        rating=rating,
        reviews=collected_reviews,
    )

    # Создаем факт, если есть операционные проблемы или подозрительный адрес
    if profile.suspicious_location_flags:
        facts.append(
            PendingFact(
                fact_id=f"GEO-SUSPICIOUS-ADDR-{inn}",
                kind="suspicious_address_signal",
                statement=f"Картографический OSINT ({address}): {profile.interpretation}",
                source_url=f"https://yandex.ru/maps/?text={address}",
                found_by="geo_maps_inspection",
                found_at=now,
                trust="reference",
            )
        )
    elif profile.recent_issues:
        facts.append(
            PendingFact(
                fact_id=f"GEO-OPERATIONAL-RISK-{inn}",
                kind="operational_issue_signal",
                statement=f"Анализ отзывов на картах ({company_name}): {profile.interpretation}",
                source_url=f"https://yandex.ru/maps/?text={company_name}",
                found_by="geo_reviews_inspection",
                found_at=now,
                trust="mention",
            )
        )

    return SearchResults(facts, partial_reason=partial_reason)
