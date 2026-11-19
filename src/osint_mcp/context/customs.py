"""Таможенные данные и ВЭД (Импорт / Экспорт).

OSINT-логика и интерпретация для аналитика и LLM:
1. Таможенная база и реестры внешнеэкономической деятельности фиксируют
   реальные трансграничные поставки, физический товарооборот и номенклатуру (ТН ВЭД).
2. САНКЦИОННАЯ УЯЗВИМОСТЬ И РИСК СНАБЖЕНИЯ:
   - Если компания импортирует критические компоненты, сырье или оборудование из
     ЕС, США или недружественных юрисдикций, она находится под высоким риском
     срыва поставок, блокировок платежей в банках-корреспондентах и вторичных санкций.
   - Триггер: возможность предложить альтернативную логистику (Китай, Турция, СНГ) или юридическое сопровождение ВЭД.
3. РЕАЛЬНЫЙ ТОВАРООБОРОТ VS "БУМАЖНАЯ ВЫРУЧКА":
   - Финансовую отчетность в ФНС можно скорректировать на бумаге, но таможенные декларации (ГТД),
     проходящие валютный контроль ФТС, подтверждают реальное физическое перемещение грузов.
   - Отсутствие импорта/экспорта у производственной компании, декларирующей выпуск иностранного оборудования —
     признак возможной "переклейки шильдиков" или фиктивных операций.
4. СМЕНА ПОСТАВЩИКА / КРИЗИС ЦЕПОЧКИ:
   - Резкий перерыв в регулярных поставках от многолетнего контрагента указывает
     на разрыв коммерческих отношений, дефолт партнера или кассовый разрыв.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog

from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.web_search_source import SearchResults
from osint_mcp.context.customs_mentions import find_customs_mentions

log = structlog.get_logger()

# Список юрисдикций с высоким санкционным / расчетным риском для РФ
HIGH_RISK_ORIGINS = {
    "германия", "сша", "италия", "франция", "великобритания", "япония",
    "польша", "нидерланды", "ес", "евросоюз", "европа", "taiwan", "тайвань",
    "germany", "usa", "italy", "france", "uk", "japan", "poland", "netherlands", "eu",
}

# Доверенные агрегаторы и таможенные реестры
CUSTOMS_PLATFORMS = {
    "customs.gov.ru", "stat.customs.gov.ru", "importgenius.com",
    "panjiva.com", "volga-ved.ru", "statimex.ru", "ved-stat.com",
}


@dataclass
class CustomsProfile:
    inn: str
    has_ved_activity: bool
    is_importer: bool
    is_exporter: bool
    high_risk_jurisdictions: list[str]
    supplies_summary: list[str]
    interpretation: str


def evaluate_customs_findings(
    inn: str,
    raw_declarations: list[dict[str, Any]],
) -> CustomsProfile:
    """Анализ собранных деклараций и формирование выводов по ВЭД."""
    if not raw_declarations:
        return CustomsProfile(
            inn=inn,
            has_ved_activity=False,
            is_importer=False,
            is_exporter=False,
            high_risk_jurisdictions=[],
            supplies_summary=[],
            interpretation="Сведений об активных внешнеторговых операциях (импорт/экспорт) в открытых таможенных базах не обнаружено.",
        )

    is_importer = False
    is_exporter = False
    high_risk_countries = set()
    summaries = []

    for item in raw_declarations:
        direction = str(item.get("direction", "import")).lower()
        if "импорт" in direction or "import" in direction:
            is_importer = True
        if "экспорт" in direction or "export" in direction:
            is_exporter = True

        country = str(item.get("country", "")).strip().lower()
        product = str(item.get("goods", item.get("product", "товары"))).strip()
        partner = str(item.get("partner", "контрагент")).strip()

        for hr in HIGH_RISK_ORIGINS:
            if hr in country:
                high_risk_countries.add(country.title())

        line = f"{direction.title()}: {product} ({country.title() or 'страна не указана'}, партнер: {partner})"
        summaries.append(line)

    high_risk_list = sorted(high_risk_countries)

    # Бизнес-интерпретация для агента
    if high_risk_list:
        interpretation = (
            f"Выявлена высокая зависимость от импорта из недружественных юрисдикций ({', '.join(high_risk_list)}). "
            "Критический риск логистических сбоев, блокировок трансграничных платежей и вторичных санкций. "
            "Триггер для предложения параллельного импорта, альтернативных маршрутов (Турция/Китай) и юридической защиты ВЭД."
        )
    elif is_importer or is_exporter:
        flows = []
        if is_importer: flows.append("импортные")
        if is_exporter: flows.append("экспортные")
        interpretation = (
            f"Подтвержден реальный физический товарооборот ({' и '.join(flows)} поставки). "
            "Бизнес ведет активную трансграничную торговлю в стабильных юрисдикциях, подтверждая реальность производственно-складской базы."
        )
    else:
        interpretation = "Зафиксированы единичные таможенные операции без выраженной санкционной зависимости."

    return CustomsProfile(
        inn=inn,
        has_ved_activity=True,
        is_importer=is_importer,
        is_exporter=is_exporter,
        high_risk_jurisdictions=high_risk_list,
        supplies_summary=summaries[:10],
        interpretation=interpretation,
    )


def build_customs_facts(
    inn: str,
    company_name: str | None = None,
    declarations: list[dict[str, Any]] | None = None,
) -> list[PendingFact]:
    """Сбор и генерация таможенных фактов в шину фактов/карантин."""
    facts: list[PendingFact] = []
    now = datetime.now(UTC)

    # Если декларации не переданы напрямую, выполняем целевой поиск по таможенным базам
    collected_declarations = list(declarations) if declarations else []
    partial_reason = None

    if declarations is None:
        hits = find_customs_mentions(inn)
        for index, hit in enumerate(hits, 1):
            facts.append(PendingFact(
                fact_id=f"CUSTOMS-MENTION-{inn}-{index}", kind="customs_trade_signal",
                statement=f"Публичное упоминание ВЭД: {hit.get('title') or ''}. {hit.get('snippet') or ''} Это не подтверждение поставки или таможенной декларации.",
                source_url=hit["url"], found_by="customs_web_mention", found_at=now, trust="mention",
                payload={"evidence_type": hit.get("evidence_type", "web_mention"), "inn": inn},
            ))
        return SearchResults(facts, partial_reason=getattr(hits, "partial_reason", None))

    profile = evaluate_customs_findings(inn, collected_declarations)

    if profile.has_ved_activity:
        source_link = (
            collected_declarations[0].get("source_url")
            if collected_declarations and collected_declarations[0].get("source_url")
            else f"https://customs.gov.ru/check?inn={inn}"
        )

        statement = (
            f"Таможенная активность ВЭД: подтвержден реальный товарооборот "
            f"({len(profile.supplies_summary)} операций). {profile.interpretation}"
        )

        facts.append(
            PendingFact(
                fact_id=f"CUSTOMS-VED-{inn}",
                kind="customs_trade_signal",
                statement=statement,
                source_url=source_link,
                found_by="customs_registry",
                found_at=now,
                trust="reference",
            )
        )

    return SearchResults(facts, partial_reason=partial_reason)
