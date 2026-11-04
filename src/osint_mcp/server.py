"""Точка входа MCP-сервера.

Запуск:
    uv run python -m osint_mcp.server            # stdio (по умолчанию)
    OSINT_MCP_TRANSPORT=http uv run python -m osint_mcp.server

ВАЖНО про stdio: в этом режиме stdout принадлежит протоколу.
Любой print() в stdout ломает обмен сообщениями с хостом.
Поэтому логи уходят строго в stderr — см. настройку structlog ниже.
"""

import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import structlog
from mcp.server.mcpserver import MCPServer
from pydantic import Field

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.context.checko import CheckoSource
from osint_mcp.context.competitors import (
    fetch_company_competitors as _fetch_company_competitors,
)
from osint_mcp.context.customs import (
    build_customs_facts as _build_customs_facts,
)
from osint_mcp.context.customs import (
    evaluate_customs_findings as _evaluate_customs_findings,
)
from osint_mcp.context.dadata import DaDataSource
from osint_mcp.context.geo_reviews import (
    build_geo_reviews_facts as _build_geo_reviews_facts,
)
from osint_mcp.context.news_media import (
    fetch_company_media_presence as _fetch_company_media_presence,
)
from osint_mcp.context.reputation_fiascos import (
    async_build_reputation_fiasco_facts as _async_build_reputation_fiasco_facts,
)
from osint_mcp.context.site import inspect_site_content as _inspect_site_content
from osint_mcp.context.source_catalog import (
    SourceSpec as _SourceSpec,
)
from osint_mcp.context.source_catalog import (
    execute_catalog_batch as _execute_catalog_batch,
)
from osint_mcp.context.source_catalog import (
    execute_catalog_source as _execute_catalog_source,
)
from osint_mcp.context.source_catalog import (
    load_source_catalog as _load_source_catalog,
)
from osint_mcp.context.source_catalog import (
    save_source_to_catalog as _save_source_to_catalog,
)
from osint_mcp.context.web_analytics import (
    build_analytics_affiliation_facts as _build_analytics_affiliation_facts,
)
from osint_mcp.models import (
    AffiliationGraph,
    ContextResult,
    CoverageReport,
    InnCheck,
    ProvidersLimitsReport,
    ResolveResult,
    RiskCollection,
    ServerHealth,
)
from osint_mcp.scoring import score_company as _score_company
from osint_mcp.scoring.engine import load_config as _load_scoring_config
from osint_mcp.scoring.models import (
    ScoreResult,
    SearchUnverifiedResult,
    Verdict,
)
from osint_mcp.tools.context_builder import build_company_context as _build_context
from osint_mcp.tools.coverage import build_coverage as _build_coverage
from osint_mcp.tools.inn import validate_inn as _validate_inn
from osint_mcp.tools.quarantine import QuarantineStore
from osint_mcp.tools.query_guard import (
    build_discrepancy_fact as _build_discrepancy_fact,
)
from osint_mcp.tools.query_guard import (
    check_query_inn_consistency as _check_query_inn_consistency,
)
from osint_mcp.tools.query_guard import (
    extract_inn_and_name as _extract_inn_and_name,
)
from osint_mcp.tools.quota import check_all_limits as _check_all_limits
from osint_mcp.tools.report import build_batch_entry as _build_batch_entry
from osint_mcp.tools.report import build_report as _build_report
from osint_mcp.tools.risk import (
    collect_risk_facts as _collect_risk_facts,
)
from osint_mcp.tools.risk import (
    extract_context_financial_risk_facts as _extract_financial_risk_facts,
)
from osint_mcp.tools.web_search_source import search_pending as _search_pending


class _LazyQuarantineStore:
    """Создаёт SQLite-хранилище при первом обращении, а не при импорте.

    Это позволяет импортировать модуль для introspection и тестов без
    побочных эффектов на файловой системе.
    """

    def __init__(self) -> None:
        from threading import RLock

        self._lock = RLock()
        self._store: QuarantineStore | None = None

    def _get_store(self) -> QuarantineStore:
        if self._store is None:
            with self._lock:
                if self._store is None:
                    path = Path(__file__).parent / "config_data" / "quarantine.db"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    self._store = QuarantineStore(path)
        return self._store

    def __getattr__(self, name: str):
        return getattr(self._get_store(), name)


_quarantine = _LazyQuarantineStore()

SERVER_NAME = "osint-mcp"
VERSION = "0.4.0"

# Логи — только в stderr, иначе stdio-транспорт развалится
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.JSONRenderer(ensure_ascii=False),
    ],
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
)
log = structlog.get_logger()

mcp = MCPServer(SERVER_NAME, version=VERSION)

PRIMARY_TOOLS = [
    "health_check",
    "generate_full_dossier",
    "resolve_company",
    "check_companies_batch",
    "check_provider_limits",
    "list_catalog_sources",
    "scan_catalog_source",
    "register_custom_source",
    "scan_catalog_batch",
    "search_unverified",
    "review_pending",
]

GRANULAR_TOOLS = [
    "validate_inn",
    "get_company_context",
    "collect_risk_facts",
    "check_affiliations",
    "check_coverage",
    "get_company_report",
    "get_company_links",
    "get_verdict",
    "check_shared_analytics",
    "check_customs_ved",
    "check_geo_reviews",
    "check_reputation_fiascos",
]

TOOLS = list(PRIMARY_TOOLS)
if settings.expose_granular_tools:
    TOOLS.extend(GRANULAR_TOOLS)



_source = DaDataSource()
_checko = CheckoSource()


@mcp.tool()
def health_check() -> ServerHealth:
    """Проверить, что MCP-сервер запущен и отвечает.

    Диагностический инструмент. Вызывай его, если другие инструменты этого
    сервера ведут себя странно: успешный ответ означает, что соединение
    и протокол исправны, а причину следует искать в конкретном инструменте.

    Возвращает имя и версию сервера, время ответа и список инструментов.
    """
    log.info("tool_call", tool="health_check")
    return ServerHealth(
        server=SERVER_NAME,
        version=VERSION,
        checked_at=datetime.now(UTC),
        tools=TOOLS,
    )


def validate_inn(
    inn: Annotated[
        str,
        Field(
            description=(
                "ИНН строкой: 10 цифр для организации, 12 для ИП или физлица. "
                'Например "7707083893". Пробелы и дефисы допустимы.'
            ),
            examples=["7707083893", "500100732259"],
        ),
    ],
) -> InnCheck:
    """Проверить ИНН по контрольной сумме, не обращаясь к сети.

    Принимает 10 знаков (организация) или 12 (ИП либо физлицо).
    Пробелы и дефисы отбрасываются.

    Возвращает структуру InnCheck:
      valid: bool — true при корректной контрольной сумме; false при математической ошибке/опечатке.
      kind: str — "legal_entity_10", "sole_proprietor_12" или None.
      reason: str — описание ошибки контрольной суммы (если valid=false).
    """
    result = _validate_inn(inn)
    log.info("tool_call", tool="validate_inn", inn=result.inn,
             valid=result.valid, kind=result.kind)
    return result


@mcp.tool()
async def resolve_company(
    query: Annotated[
        str,
        Field(
            description="Наименование организации для поиска кандидатов и их ИНН. "
                        'Например: "Ромашка" либо "Сбербанк"',
            examples=["ООО Ромашка", "Сбербанк"],
        ),
    ],
) -> ResolveResult:
    """Уточнить кандидатов и ИНН по наименованию организации.

    ВНИМАНИЕ ДЛЯ LLM-АГЕНТА:
    - Вызывай этот инструмент ТОЛЬКО если пользователь дал неточное/неоднозначное НАЗВАНИЕ компании БЕЗ ИНН,
      и нужно найти список кандидатов, чтобы выбрать правильный ИНН.
    - ЕСЛИ ИНН ОРГАНИЗАЦИИ УЖЕ ИЗВЕСТЕН — ЗАПРЕЩЕНО ВЫЗЫВАТЬ resolve_company!
      Сразу вызывай единый инструмент generate_full_dossier(inn=...), он за один вызов вернёт все данные.

    Возвращает структуру ResolveResult:
      status: "ok", "multiple", "not_found", "unavailable"
      confidence:
        "high" — однозначное совпадение по ИНН/ОГРН или точному названию;
        "medium" — найдена одна действующая организация, остальные ликвидированы;
        "low" — найдено несколько действующих организаций (список в поле candidates);
        "none" — организация не найдена.
      inn: ИНН выбранной организации (при однозначном совпадении).
      name: наименование организации.
      candidates: список организаций-кандидатов с реквизитами при неоднозначном поиске.
      hint: пояснение и рекомендации по дальнейшей обработке.
    """
    result = await _source.resolve(query)
    # Источники независимы: если DaData недоступна, а запрос — идентификатор
    # (ИНН/ОГРН/ОКПО), организацию определяет Checko своей карточкой.
    # По названию Checko искать не умеет — это честно сообщается в hint.
    if result.status == "unavailable":
        from osint_mcp.tools.inn import validate_inn as _vinn
        probe = _vinn(query)
        if probe.valid:
            fallback = await _checko.get_context(probe.inn)
            if fallback.status == "ok" and fallback.context:
                ctx = fallback.context
                from osint_mcp.models import Candidate
                from osint_mcp.models import ResolveResult as _RR
                result = _RR(
                    query=query, status="ok", confidence="high",
                    total_found=1,
                    candidates=[Candidate(
                        inn=ctx.inn, ogrn=ctx.ogrn, name=ctx.name_legal,
                        short_name=ctx.name_short, city=ctx.city,
                        status=ctx.status, registered_at=ctx.registered_at,
                        director=ctx.director_fio, okved=ctx.okved_code,
                    )],
                    hint=(f"DaData недоступна, организация определена Checko: "
                          f"{ctx.name_legal}, ИНН {ctx.inn}. Продолжай с этим ИНН. "
                          f"Карточка соберётся из Checko."),
                )
    log.info("tool_call", tool="resolve_company", query=query,
             confidence=result.confidence, found=result.total_found)
    return result


async def get_company_context(
    inn: Annotated[
        str,
        Field(
            description="Подтверждённый ИНН организации, 10 или 12 цифр",
            examples=["7707083893"],
        ),
    ],
) -> ContextResult:
    """Собрать базовую карточку организации из официальных реестров.

    Возвращает ContextResult со следующими полями:
      status: "ok", "not_found", "partial", "unavailable".
      context:
        - Реквизиты: ИНН, ОГРН, КПП, статус в ЕГРЮЛ, дата регистрации, уставный капитал.
        - Адрес и филиалы (поля branches, representative_offices).
        - Руководитель и учредители по ЕГРЮЛ.
        - Основной и дополнительные коды ОКВЭД.
        - Категория масштаба бизнеса по реестру МСП (micro, small, medium, large).
        - Численность сотрудников и ключевые финансовые показатели (ГИР БО).
        - Прежние наименования (former_names).
      reason: диагностическая информация, если часть данных не была получена.
    """
    parsed_inn, _ = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    ledger.set_subject(clean_inn)
    result = await _build_context(clean_inn, _source, _checko)
    log.info("tool_call", tool="get_company_context", inn=clean_inn, status=result.status)
    return result


async def check_affiliations(
    inn: Annotated[
        str,
        Field(description="ИНН организации", examples=["7724744134"]),
    ],
    deep: Annotated[
        bool,
        Field(
            description=(
                "Проверять ли подозрительные связанные организации полностью — "
                "суды, приставы, надзор. Оставь true: без этого связанная "
                "организация останется строкой в списке. Поставь false, только "
                "если пользователь просил быстро"
            ),
        ),
    ] = True,
) -> AffiliationGraph:
    """Построить граф корпоративных связей: бенефициары, руководители, смежные юрлица.

    Возвращает AffiliationGraph:
      shareholders_undisclosed: флаг закрытого реестра акционеров (для АО).
      owner_organizations: список юридических лиц — владельцев долей с их связями (via)
        и результатами глубокой проверки (deep_summary).
      people: руководители и учредители-физлица с личными риск-признаками
        (дисквалификация, банкротство, массовый руководитель/учредитель, реестр недобросовестных поставщиков).
      related_companies: смежные и дочерние организации, включая флаг suspicious
        (недействующие, имеющие негативные отметки ФНС или высокую судебную нагрузку).
      predecessors: правопредшественники организации при реорганизации.
      coverage_note: техническая информация об охвате источников.
    """
    parsed_inn, _ = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    ledger.set_subject(clean_inn)
    graph, result = await _checko.check_affiliations(clean_inn, deep=deep)
    log.info("tool_call", tool="check_affiliations", inn=clean_inn,
             people=len(graph.people) if graph else 0,
             suspicious=graph.suspicious_count if graph else 0,
             status=result.status)
    if graph is None:
        return AffiliationGraph(
            inn=clean_inn,
            coverage_note=(f"Проверка связей НЕ ВЫПОЛНЕНА: {result.reason}. "
                           f"Пустые списки здесь не означают отсутствия связей."),
        )
    return graph


async def collect_risk_facts(
    inn: Annotated[
        str,
        Field(
            description="Подтверждённый ИНН организации, 10 или 12 цифр",
            examples=["7724744134"],
        ),
    ],
) -> RiskCollection:
    """Собрать факты рисков по шести направлениям: ФНС, банкротство, арбитраж, ФССП, проверки ЕРКНМ, закупки.

    Возвращает RiskCollection:
      facts: список подтверждённых фактов риска, каждый со стабильным fact_id и ссылкой source_url.
      arbitration: судебная нагрузка с разделением ролей (as_defendant vs as_plaintiff) и суммами исков.
      contracts: участие в регулируемых закупках (44-ФЗ, 223-ФЗ) с разделением ролей (as_supplier vs as_customer).
      results: детальные статусы проверки по каждому из опрашиваемых реестров.
      coverage_note: примечания по полноте охвата реестров.
    """
    parsed_inn, _ = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    ledger.set_subject(clean_inn)
    result = await _collect_risk_facts(clean_inn, _checko)
    log.info("tool_call", tool="collect_risk_facts", inn=clean_inn,
             facts=len(result.facts), ok=result.sources_ok,
             failed=result.sources_failed)
    return result


def check_coverage(
    inn: Annotated[
        str,
        Field(
            description="ИНН организации, по которой нужен отчёт о полноте",
            examples=["7724744134"],
        ),
    ],
) -> CoverageReport:
    """Техническая диагностика полноты проверки и журнал обращений к источникам.

    Возвращает CoverageReport:
      checked: bool — выполнялись ли обращения к источникам по данному субъекту.
      gaps: список пробелов в данных с классификацией (source_failed, no_data, not_requested, not_implemented).
      obtained: список успешно собранных блоков данных.
      services: расход запросов к API внешних сервисов за текущую сессию и сутки.
    """
    parsed_inn, _ = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    result = _build_coverage(clean_inn)
    log.info("tool_call", tool="check_coverage", inn=clean_inn,
             checked=result.checked, requests=result.total_requests)
    return result


def _normalize_detail_level(val: str | None) -> str:
    s = str(val or "").strip().lower()
    if s in ("brief", "кратко", "коротко", "short", "1"):
        return "brief"
    if s in ("standard", "средне", "medium", "стандарт", "обычно", "2"):
        return "standard"
    if s in ("full", "полно", "детально", "detailed", "максимум", "3"):
        return "full"
    return "standard"


async def get_company_report(
    inn: Annotated[
        str,
        Field(
            description="Подтверждённый ИНН организации, 10 или 12 цифр",
            examples=["7724744134"],
        ),
    ],
    detail: Annotated[
        str,
        Field(
            description=(
                'Уровень подробности отчёта (3 уровня):\n'
                '- "brief" ("кратко") — экспресс-скрининг (светофор, вердикт, баллы, базовая карточка, главные риски, TL;DR);\n'
                '- "standard" ("средне", по умолчанию) — стандартный аудит (полная карточка, разбор судов, ФССП, налогов, лицензий, кадров, СМИ и первоисточники);\n'
                '- "full" ("полно") — глубокий Due Diligence (включает глубокие связи/бенефициаров, таможню/ВЭД, гео-отзывы и сети веб-аналитики).'
            ),
            examples=["brief", "standard", "full", "кратко", "средне", "полно"],
        ),
    ] = "standard",
    include_reputation: Annotated[
        bool,
        Field(
            description="Включать ли глубокий OSINT-поиск инцидентов, аварий, неплатежей и публикаций в СМИ (по умолчанию true)",
        ),
    ] = True,
    expected_name: Annotated[
        str | None,
        Field(
            description="Ожидаемое наименование компании из запроса пользователя (для контроля соответствия ИНН ↔ название)",
        ),
    ] = None,
    debug: Annotated[
        bool,
        Field(
            description=(
                "Режим технической отладки для разработчика (по умолчанию false). "
                "Если false (пользовательский режим) — выдаются только чистые бизнес-факты, "
                "без технического мусора об упавших API и таймаутах. "
                "Ставить true ТОЛЬКО если пользователь прямо просит технические логи, "
                "диагностику API, ошибки провайдеров или сетевые таймауты."
            ),
        ),
    ] = False,
    human_mode: Annotated[
        bool | None,
        Field(
            description=(
                "Человеческий понятный язык отчёта (по умолчанию true, настраивается в конфиге). "
                "Если true — добавляет TL;DR-резюме в 3 предложениях, ответы на 3 ключевых вопроса "
                "и переводит чиновничьи аббревиатуры (ОКВЭД, ССЧ, ГИР БО, ФССП, РНП) на живой русский язык. "
                "Если false — возвращает официальный сухой реестровый формат."
            ),
        ),
    ] = None,
) -> dict:
    """Сформировать агрегированный отчёт по организации в формате структурированного JSON.

    Параметры:
      detail:
        "brief" — базовая карточка, скоринговый вердикт со светофором, warnings и ключевые риски;
        "full" — детальные данные: динамика финансов по годам, налоги, лицензии, кадровый контур,
                 исторические события, карантинные находки и прямые ссылки на первоисточники.
      expected_name: ожидаемое наименование организации для детекции расхождений с ЕГРЮЛ.
      debug: включение технической диагностики источников (_диагностика_разработчика).
      human_mode: включение блока резюме для человека (TL;DR и ответы на ключевые вопросы).

    Возвращает структурированный словарь с разделами:
      карточка, статус, светофор, вердикт, score, warnings, риски,
      коммерческий_срез, кадровый_потенциал_документы, ссылки.
    """
    import asyncio

    from osint_mcp.tools.hr_hub import detect_corporate_hr_hub
    from osint_mcp.tools.query_guard import (
        build_discrepancy_fact,
        check_query_inn_consistency,
        extract_inn_and_name,
    )

    detail_norm = _normalize_detail_level(detail)

    parsed_inn, parsed_name = extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    target_expected_name = expected_name or parsed_name
    ledger.set_subject(clean_inn)

    # Запускаем сбор контекста и риск-фактов параллельно
    context_task = _build_context(clean_inn, _source, _checko)
    risk_task = _collect_risk_facts(clean_inn, _checko)
    context_result, risk = await asyncio.gather(context_task, risk_task)

    # Та же защита, что в get_verdict: молчание всех источников —
    # не «чистая проверка», и вердиктом это выдавать нельзя.
    if context_result.context is None and risk.sources_ok == 0:
        return {
            "inn": clean_inn,
            "вердикт": "не рекомендуется",
            "оценка_не_выставлена": (
                "Реестровые источники недоступны"
                + (f": {context_result.reason}" if context_result.reason else "")
                + ". Оценка НЕ ВЫСТАВЛЕНА: ни один источник не ответил. "
                "Проверьте ключи DaData/Checko в .env и доступность API."
            ),
        }

    # Проверка расхождения запроса «Имя ↔ ИНН»
    query_discrepancy = None
    if target_expected_name and context_result.context:
        query_discrepancy = check_query_inn_consistency(target_expected_name, context_result.context)
        if query_discrepancy:
            disc_fact = build_discrepancy_fact(query_discrepancy)
            risk.facts.append(disc_fact)

    # Параллельный поиск репутационных рисков и детекция HR-хаба холдинга
    fiasco_facts = []
    hr_hub_info = None
    news_media_info = None
    competitors_info = None
    if context_result.context:
        ctx = context_result.context
        from osint_mcp.tools.names import core_name
        clean_core = core_name(ctx.name_short or ctx.name_legal)
        b_raw = (ctx.brand or "").strip()
        if b_raw and len(b_raw) > 3:
            brand_to_use = b_raw
        elif clean_core and len(clean_core) >= 3:
            brand_to_use = clean_core
        else:
            brand_to_use = b_raw or clean_core

        target_name = ctx.name_short or ctx.name_legal or clean_core or clean_inn
        target_domain = ctx.brand_domain or (
            ctx.extras.contacts.website if ctx.extras and ctx.extras.contacts else None
        )

        async def _fetch_fiascos():
            if not include_reputation:
                return []
            try:
                facts = await _async_build_reputation_fiasco_facts(
                    inn=clean_inn,
                    company_name=target_name or clean_inn,
                    brand=brand_to_use,
                    domain=target_domain,
                )
                if facts:
                    _quarantine.add(clean_inn, facts)
                return facts
            except Exception as exc:  # noqa: BLE001
                log.warning("get_company_report_reputation_error", error=str(exc))
                return []

        async def _fetch_hr_hub():
            try:
                return await detect_corporate_hr_hub(ctx)
            except Exception as exc:  # noqa: BLE001
                log.debug("get_company_report_hr_hub_error", error=str(exc))
                return None

        async def _fetch_affiliations():
            if detail_norm != "full":
                return None
            try:
                graph, _ = await _checko.check_affiliations(clean_inn, deep=True)
                if graph:
                    return {
                        "subject_inn": clean_inn,
                        "deep": True,
                        "shareholders_undisclosed": graph.shareholders_undisclosed,
                        "suspicious_count": graph.suspicious_count,
                        "owner_organizations": [o.model_dump() for o in graph.owner_organizations],
                        "people": [p.model_dump() for p in graph.people],
                        "related_companies": [r.model_dump() for r in graph.related_companies],
                        "predecessors": [pr.model_dump() for pr in graph.predecessors],
                    }
                return None
            except Exception as exc:  # noqa: BLE001
                log.warning("get_company_report_affiliations_error", error=str(exc))
                return None

        async def _fetch_customs():
            if not include_reputation or detail_norm != "full":
                return None
            try:
                facts = await asyncio.to_thread(_build_customs_facts, inn=clean_inn, company_name=target_name)
                if facts:
                    _quarantine.add(clean_inn, facts)
                profile = _evaluate_customs_findings(clean_inn, [])
                interpretation = facts[0].statement if facts else profile.interpretation
                return {
                    "has_ved_activity": bool(facts),
                    "facts_count": len(facts),
                    "interpretation": interpretation,
                    "facts": [f.statement for f in facts] if facts else [],
                }
            except Exception as exc:  # noqa: BLE001
                log.warning("get_company_report_customs_error", error=str(exc))
                return None

        async def _fetch_geo():
            target_addr = ctx.address_full if ctx else None
            if not include_reputation or detail_norm != "full" or not target_addr:
                return None
            try:
                facts = await asyncio.to_thread(
                    _build_geo_reviews_facts,
                    inn=clean_inn,
                    company_name=target_name or clean_inn,
                    address=target_addr,
                )
                if facts:
                    _quarantine.add(clean_inn, facts)
                interpretation = (
                    facts[0].statement
                    if facts
                    else "Физическое присутствие подтверждено, критических сигналов не выявлено."
                )
                return {
                    "address": target_addr,
                    "facts_count": len(facts),
                    "interpretation": interpretation,
                    "facts": [f.statement for f in facts] if facts else [],
                }
            except Exception as exc:  # noqa: BLE001
                log.warning("get_company_report_geo_error", error=str(exc))
                return None

        async def _fetch_analytics():
            if not include_reputation or detail_norm != "full" or not target_domain:
                return None
            try:
                _, tech, err = await _inspect_site_content(target_domain)
                tracker_ids = tech.tracker_ids if tech else {}
                if not tracker_ids:
                    return None
                facts = await asyncio.to_thread(
                    _build_analytics_affiliation_facts,
                    domain=target_domain,
                    tracker_ids=tracker_ids,
                    subject_inn=clean_inn,
                )
                if facts:
                    _quarantine.add(clean_inn, facts)
                networks = []
                for f in facts:
                    networks.append({
                        "tracker_type": f.payload.get("tracker_type"),
                        "tracker_id": f.payload.get("tracker_id"),
                        "shared_domains": f.payload.get("shared_domains"),
                        "is_probable_holding": f.payload.get("is_probable_holding"),
                        "interpretation": f.payload.get("interpretation"),
                        "statement": f.statement,
                    })
                return {
                    "site": target_domain,
                    "tracker_ids": tracker_ids,
                    "shared_networks": networks,
                }
            except Exception as exc:  # noqa: BLE001
                log.warning("get_company_report_analytics_error", error=str(exc))
                return None

        async def _fetch_news_media():
            if not include_reputation:
                return None
            try:
                dir_fio = getattr(ctx, "director_fio", None) or getattr(ctx, "director", None)
                return await _fetch_company_media_presence(
                    inn=clean_inn,
                    company_name=target_name or clean_inn,
                    brand=brand_to_use,
                    director_fio=dir_fio,
                    detail=detail_norm,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("get_company_report_news_media_error", error=str(exc))
                return None

        async def _fetch_competitors():
            try:
                products = [p.name for p in (ctx.software_products or [])]
                return await _fetch_company_competitors(
                    company_name=target_name or clean_inn,
                    brand=brand_to_use,
                    okved_text=ctx.okved_text,
                    okved_code=ctx.okved_code,
                    products=products,
                    detail=detail_norm,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("get_company_report_competitors_error", error=str(exc))
                return None

        (
            fiasco_facts,
            hr_hub_info,
            affiliations_info,
            customs_info,
            geo_info,
            analytics_info,
            news_media_info,
            competitors_info,
        ) = await asyncio.gather(
            _fetch_fiascos(),
            _fetch_hr_hub(),
            _fetch_affiliations(),
            _fetch_customs(),
            _fetch_geo(),
            _fetch_analytics(),
            _fetch_news_media(),
            _fetch_competitors(),
        )

    if context_result.context:
        risk.facts.extend(_extract_financial_risk_facts(context_result.context))

    score = _score_company(
        facts=risk.facts + _quarantine.confirmed_facts(clean_inn),
        context=context_result.context,
    )

    # Защита от фальшивого «отлично»: если ключевые реестры судов/рисков отказали (Checko 403 / лимиты)
    core_risk_sources = {"checko.arbitration", "checko.registry_flags", "checko.enforcement"}
    core_ok = sum(1 for r in (risk.results if risk else []) if r.source in core_risk_sources and r.status in ("ok", "partial"))
    core_failed = sum(1 for r in (risk.results if risk else []) if r.source in core_risk_sources and r.status not in ("ok", "partial"))

    if core_failed >= 2 and core_ok == 0:
        quota_warn = "⚠️ Базовые реестры рисков (арбитраж Kad.Arbitr, приставы ФССП, отметки ЕГРЮЛ) недоступны (лимит API Checko 403). Судебные и юридические риски не проверены!"
        if quota_warn not in score.warnings:
            score.warnings.append(quota_warn)
        if score.verdict.total_score >= 50.0:
            from osint_mcp.scoring.models import Verdict
            score.verdict = Verdict(code="FAIR", label="удовлетворительно", total_score=min(score.verdict.total_score, 45.0), floored=True)
            score.reasons.append("Оценка ограничена до «удовлетворительно»: ключевые реестры арбитража и юридических рисков не ответили")

    # Если зафиксированы ЧП инфраструктуры/ЦОД или кибератаки — снижаем вердикт с «отлично»
    has_disaster = any(getattr(f, "kind", "") in ("fiasco_disaster_incident", "fiasco_cyber_data_breach") for f in fiasco_facts)
    if has_disaster and score.verdict.total_score >= 50.0:
        from osint_mcp.scoring.models import Verdict
        score.verdict = Verdict(code="FAIR", label="удовлетворительно", total_score=min(score.verdict.total_score, 40.0), floored=True)
        score.reasons.append("Оценка снижена: в открытых источниках/СМИ зафиксированы аварии ЦОД/инфраструктуры или утечки данных")

    if fiasco_facts:
        for f in fiasco_facts:
            if f not in score.pending:
                score.pending.append(f)
    is_debug = debug or getattr(settings, "osint_debug", False)
    is_human = human_mode if human_mode is not None else getattr(settings, "human_friendly_mode", True)
    result = _build_report(detail_norm, context_result, risk, score, debug=is_debug, human_mode=is_human, media_info=news_media_info, competitors_info=competitors_info)

    if query_discrepancy:
        result["расхождение_запроса"] = query_discrepancy

    if hr_hub_info:
        result["кадровый_хаб_холдинга"] = hr_hub_info
        if "кадровый_потенциал_документы" in result:
            result["кадровый_потенциал_документы"]["кадровый_хаб_холдинга"] = hr_hub_info

    if affiliations_info:
        result["связи_и_аффилированность"] = affiliations_info
    if customs_info:
        result["вэд_и_таможня"] = customs_info
    if geo_info:
        result["гео_и_отзывы"] = geo_info
    if analytics_info:
        result["веб_аналитика_и_сеть"] = analytics_info
    if news_media_info:
        result["медиа_и_публичная_активность"] = news_media_info
    if competitors_info:
        result["конкуренты_и_рынок"] = competitors_info

    if fiasco_facts:
        incidents_list = []
        for f in fiasco_facts:
            m_date = re.search(r"\[([0-3]?\d\.[0-1]?\d(?:\.(?:20)?\d{2})?|\d{4})\]", f.statement)
            event_date = m_date.group(1) if m_date else None
            m_lbl = re.search(r"^\[(.*?)\]", f.statement)
            source_lbl = m_lbl.group(1) if m_lbl else ""
            clean_stmt = re.sub(r"^\[.*?\]\s*", "", f.statement).strip()
            item = {
                "source": source_lbl,
                "date": event_date,
                "statement": f.statement,
                "url": f.source_url,
            }
            if is_human:
                item["сюжет_простыми_словами"] = clean_stmt
            incidents_list.append(item)
        if detail_norm == "brief":
            result["инциденты_и_сми"] = incidents_list[:2]
        else:
            result["инциденты_и_сми"] = incidents_list

        # Выносим ключевые репутационные инциденты и публикации СМИ в warnings,
        # чтобы прямо под оценкой у пользователя не возникало ложного впечатления «золотой репутации»
        if "warnings" not in result or result["warnings"] is None:
            result["warnings"] = []
        for item in incidents_list[:3]:
            d_prefix = f"[{item['date']}] " if item.get("date") else ""
            s_label = f"{item['source']}: " if item.get("source") else ""
            summary_txt = item.get("сюжет_простыми_словами") or item["statement"]
            short_txt = summary_txt.split(" | Вывод:")[0].strip()
            if len(short_txt) > 160:
                short_txt = short_txt[:157] + "..."
            warn_msg = f"Репутационный риск / инцидент в СМИ: {d_prefix}{s_label}{short_txt}"
            if warn_msg not in result["warnings"]:
                result["warnings"].append(warn_msg)

    # Обогащаем коммерческий срез репутационными фактами и инцидентами
    if context_result.context:
        from osint_mcp.tools.sales_intelligence import (
            build_sales_intelligence as _build_sales_intel,
        )
        sales_intel = _build_sales_intel(
            context_result.context,
            risk=risk,
            fiascos=fiasco_facts,
            detail=detail_norm,
        )
        if sales_intel:
            if detail_norm == "brief":
                result["коммерческий_срез"] = {
                    "формула_бизнеса": sales_intel.get("формула_бизнеса"),
                    "целевой_сегмент": sales_intel.get("целевой_сегмент"),
                    "крючок_для_контакта": sales_intel.get("крючок_для_контакта"),
                }
            else:
                result["коммерческий_срез"] = sales_intel

    # Добавляем кликабельные первоисточники для компактного цитирования агентом в markdown
    if context_result.context and context_result.context.source_links:
        result["ссылки"] = [l.model_dump() for l in context_result.context.source_links]

    if detail_norm == "full" and risk and risk.facts:
        result["факты_проверки"] = [
            {
                "fact_id": f.fact_id,
                "kind": f.kind,
                "statement": f.statement,
                "source_url": f.source_url,
                "source_type": f.source_type,
                "event_date": f.event_date.isoformat() if f.event_date else None,
            }
            for f in risk.facts
        ]

    if detail_norm in ("standard", "full") or is_debug:
        coverage_rep = _build_coverage(clean_inn)
        if coverage_rep and coverage_rep.checked:
            result["охват_проверки"] = {
                "всего_запросов": coverage_rep.total_requests,
                "методы_успешно": coverage_rep.methods_ok,
                "методы_не_ответили": coverage_rep.methods_failed,
                "собранные_сведения": coverage_rep.obtained,
                "пробелы_в_данных": [g.model_dump() for g in coverage_rep.gaps] if coverage_rep.gaps else [],
            }

    detail_labels = {"brief": "кратко", "standard": "средне", "full": "полно"}
    result["детализация"] = detail_labels.get(detail_norm, detail_norm)
    log.info("tool_call", tool="get_company_report", inn=clean_inn,
             detail=detail_norm, verdict=score.verdict.label,
             fiascos=len(fiasco_facts))
    return result


@mcp.tool()
async def generate_full_dossier(
    inn: Annotated[
        str,
        Field(
            description=(
                "ИНН организации (10 или 12 цифр) либо наименование компании. "
                "ЕДИНЫЙ ГЛАВНЫЙ ИНСТРУМЕНТ ПРОВЕРКИ КОНТРАГЕНТА. "
                "Если передан ИНН — сразу формирует полное досье за 1 вызов. "
                "Если передано название — автоматически определяет организацию и формирует досье."
            ),
            examples=["7724744134", "7707083893", "ООО Вайлдберриз"],
        ),
    ],
    detail: Annotated[
        str,
        Field(
            description=(
                'Уровень подробности досье (3 уровня):\n'
                '- "brief" ("кратко") — экспресс-скрининг (светофор, вердикт, баллы, базовая карточка, главные риски, TL;DR);\n'
                '- "standard" ("средне", по умолчанию) — стандартный аудит (полная карточка, разбор судов, ФССП, налогов, лицензий, кадров, СМИ и первоисточники);\n'
                '- "full" ("полно") — глубокий Due Diligence (включает глубокие связи/бенефициаров, таможню/ВЭД, гео-отзывы и сети веб-аналитики).'
            ),
            examples=["brief", "standard", "full", "кратко", "средне", "полно"],
        ),
    ] = "standard",
    expected_name: Annotated[
        str | None,
        Field(
            description="Ожидаемое наименование компании из запроса пользователя (для проверки расхождения названия и ИНН)",
        ),
    ] = None,
    debug: Annotated[
        bool,
        Field(
            description=(
                "Режим технической отладки для разработчика (по умолчанию false). "
                "Передавать true ТОЛЬКО если пользователь прямо запросил техническую диагностику, "
                "статусы API провайдеров или сетевые ошибки."
            ),
        ),
    ] = False,
    human_mode: Annotated[
        bool | None,
        Field(
            description=(
                "Человеческий понятный язык отчёта (по умолчанию true, настраивается в конфиге). "
                "Если true — формирует TL;DR, ответы на 3 вопроса и понятные сюжетные описания."
            ),
        ),
    ] = None,
) -> dict:
    """ГЛАВНЫЙ ЕДИНЫЙ ИНСТРУМЕНТ ПРОВЕРКИ КОНТРАГЕНТА. ВСЕГДА ВЫЗЫВАЙ ЕГО, ЕСЛИ ИЗВЕСТЕН ИНН.

    Выполняет исчерпывающий OSINT-аудит организации ЗА ОДИН ВЫЗОВ:
    - Официальные реестры (ЕГРЮЛ, ФНС, ГИР БО, Реестр МСП, Минцифры)
    - Арбитраж, исполнительные производства ФССП, проверки и реестровые метки
    - Корпоративные связи, учредители, бенефициары и аффилированность
    - Таможня и внешнеэкономическая деятельность (ВЭД, импорт/экспорт)
    - Картографический OSINT, фактическое присутствие и семантика отзывов
    - Цифровая инфраструктура и общие сети веб-аналитики (Яндекс.Метрика / Google Analytics)
    - Кадровый контур и наём (HeadHunter, HR-хаб холдинга)
    - Глубокий OSINT-поиск инцидентов, ЧП, аварий, сбоев и публикаций в СМИ
    - Детерминированный скоринговый вердикт со светофором (🟢/🟡/🟠/⛔) и баллами.

    Возвращает исчерпывающий структурированный JSON со всеми фактами, оценками и ссылками на первоисточники.
    Никаких дополнительных вызовов других инструментов после этого НЕ ТРЕБУЕТСЯ.
    """
    parsed_inn, parsed_name = _extract_inn_and_name(inn)
    raw_candidate = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    probe = _validate_inn(raw_candidate)
    if not probe.valid:
        # Запрос не является валидным ИНН — пробуем разрешить организацию по наименованию
        resolve_res = await _source.resolve(inn)
        if resolve_res.status == "ok" and resolve_res.confidence in ("high", "medium") and resolve_res.candidates:
            clean_inn = resolve_res.candidates[0].inn
            target_expected = expected_name or resolve_res.candidates[0].name or parsed_name
        elif resolve_res.confidence == "low" and len(resolve_res.candidates) > 1:
            return {
                "status": "multiple_candidates",
                "query": inn,
                "confidence": resolve_res.confidence,
                "total_found": resolve_res.total_found,
                "candidates": [c.model_dump() for c in resolve_res.candidates],
                "hint": (
                    "По запросу найдено несколько действующих организаций. "
                    "Уточните нужную компанию или вызовите generate_full_dossier с конкретным ИНН."
                ),
            }
        elif resolve_res.status in ("not_found", "unavailable") or resolve_res.confidence == "none" or not resolve_res.candidates:
            return {
                "status": resolve_res.status if resolve_res.status != "ok" else "not_found",
                "query": inn,
                "hint": resolve_res.hint or "Организация по данному наименованию не найдена.",
            }
        else:
            clean_inn = raw_candidate
            target_expected = expected_name or parsed_name
    else:
        clean_inn = probe.inn
        target_expected = expected_name or parsed_name

    return await get_company_report(
        inn=clean_inn,
        detail=detail,
        include_reputation=True,
        expected_name=target_expected,
        debug=debug,
        human_mode=human_mode,
    )


async def get_company_links(
    inn: Annotated[
        str,
        Field(
            description="Подтверждённый ИНН организации, 10 или 12 цифр",
            examples=["7724744134"],
        ),
    ],
) -> dict:
    """Получить прямые ссылки на официальные реестры и первоисточники по организации.

    Возвращает словарь:
      inn: ИНН организации.
      links: список объектов со ссылками на первоисточники (карточка ЕГРЮЛ,
             бухгалтерская отчётность ФНС ГИР БО по годам, реестр МСП, картотека арбитражных дел).
    """
    parsed_inn, _ = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    ledger.set_subject(clean_inn)
    context_result = await _build_context(clean_inn, _source, _checko)
    ctx = context_result.context
    links = list(ctx.source_links) if ctx is not None else []

    result: dict = {"inn": clean_inn, "links": [l.model_dump() for l in links]}
    if not links:
        result["note"] = (
            "Ссылок нет: организация не найдена в реестрах либо все "
            "источники не ответили. Пустой список НЕ означает, что "
            "сведений не существует."
        )
    elif context_result.reason:
        result["что_не_собралось"] = context_result.reason
    log.info("tool_call", tool="get_company_links", inn=clean_inn, links=len(links))
    return result


@mcp.tool()
async def check_companies_batch(
    inns: Annotated[
        list[str],
        Field(
            description=(
                "Список ИНН организаций, 10 цифр каждый. "
                'Например: ["7707083893", "7724744134"]'
            ),
            examples=[["7707083893", "7724744134"]],
        ),
    ],
    debug: Annotated[
        bool,
        Field(
            description=(
                "Режим технической отладки для разработчика (по умолчанию false). "
                "Включает оговорки о недоступных источниках по каждому контрагенту."
            ),
        ),
    ] = False,
) -> dict:
    """Пакетная экспресс-проверка списка компаний по их ИНН (до 20 организаций за один вызов).

    Возвращает словарь:
      companies: список кратких результатов по каждому ИНН (наименование, статус,
                 вердикт, светофор, ключевые риски и предупреждения).
    """
    # Дедупликация с сохранением порядка: один ИНН дважды — одна проверка.
    seen: set[str] = set()
    unique_items: list[tuple[str, str | None]] = []
    for raw in inns:
        parsed_inn, parsed_name = _extract_inn_and_name(raw)
        cleaned = (parsed_inn or raw).strip().replace(" ", "").replace("-", "")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_items.append((cleaned, parsed_name))

    if not unique_items:
        return {"error": "Список ИНН пуст"}
    if len(unique_items) > 20:
        return {
            "error": (
                f"В списке {len(unique_items)} ИНН, максимум за вызов — 20. "
                "Разбейте на несколько вызовов и предупредите пользователя "
                "о расходе квоты"
            )
        }

    entries: list[dict] = []
    for inn, expected_name in unique_items:
        ledger.set_subject(inn)
        try:
            context_result = await _build_context(inn, _source, _checko)
            risk = await _collect_risk_facts(inn, _checko)
        except Exception as e:                                  # noqa: BLE001
            log.warning("batch_item_failed", inn=inn, error=type(e).__name__)
            entries.append({
                "inn": inn,
                "вердикт": "не рекомендуется",
                "оценка_не_выставлена": (
                    f"Проверка не состоялась: внутренняя ошибка {type(e).__name__}. "
                    "Это НЕ оценка компании — повторите по отдельности."
                ),
            })
            continue

        # Источники молчали — честно сказать, а не выдать «нельзя».
        if context_result.context is None and risk.sources_ok == 0:
            entries.append({
                "inn": inn,
                "вердикт": None,
                "оценка_не_выставлена": (
                    "Источники недоступны"
                    + (f": {context_result.reason}" if context_result.reason else "")
                    + ". Оценка не производилась."
                ),
            })
            continue

        query_discrepancy = None
        if expected_name and context_result.context:
            query_discrepancy = _check_query_inn_consistency(expected_name, context_result.context)
            if query_discrepancy:
                disc_fact = _build_discrepancy_fact(query_discrepancy)
                risk.facts.append(disc_fact)

        if context_result.context:
            risk.facts.extend(_extract_financial_risk_facts(context_result.context))
        score = _score_company(
            facts=risk.facts + _quarantine.confirmed_facts(inn),
            context=context_result.context,
        )
        if query_discrepancy:
            score.warnings.insert(
                0,
                f"ВНИМАНИЕ: Запрошена «{query_discrepancy['запрошено_наименование']}», "
                f"в ЕГРЮЛ — «{query_discrepancy['фактическое_в_реестре']}»!",
            )
        is_debug = debug or getattr(settings, "osint_debug", False)
        entries.append(_build_batch_entry(context_result, risk, score, debug=is_debug))
        log.info("batch_item", inn=inn, verdict=score.verdict.label)

    return {
        "запрошено": len(inns),
        "проверено": len(entries),
        "результаты": entries,
        "note": (
            "Ответ краткий по замыслу. Для подробного разбора конкретной "
            "компании вызовите get_company_report с detail=full"
        ),
    }


async def get_verdict(
    inn: Annotated[
        str,
        Field(
            description="Подтверждённый ИНН организации, 10 цифр",
            examples=["7724744134"],
        ),
    ],
    profile: Annotated[
        bool,
        Field(
            description=(
                "true — вернуть также деловой свод (profile): субъект, "
                "проверки, судебная нагрузка, вердикт — структурированно, "
                "для показа менеджеру без вызова остальных инструментов"
            ),
        ),
    ] = False,
    expected_name: Annotated[
        str | None,
        Field(
            description="Ожидаемое наименование компании (для контроля соответствия ИНН ↔ название)",
        ),
    ] = None,
) -> ScoreResult:
    """Рассчитать детерминированный скоринговый вердикт по правилам scoring.yaml.

    Возвращает ScoreResult:
      verdict: вердикт надёжности и маркер светофора (🟢/🟡/🟠/⛔).
      total_score: итоговый числовой балл.
      groups: баллы и риски в разрезе функциональных групп (суды, финансы, надзор, реестры, персоналии).
      matched: сработавшие критерии скоринга с идентификаторами фактов (fact_ids) и ссылками.
      reasons: список основных причин снижения оценки.
      warnings: критические негативные факторы (warn_always: true), требующие внимания независимо от вердикта.
      pending: находки из карантина нереестровых источников.
    """
    parsed_inn, parsed_name = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    target_expected_name = expected_name or parsed_name
    ledger.set_subject(clean_inn)
    # Карточка собирается первой: наименование из неё нужно резервному
    # источнику банкротств, который ищет по строке, а не по ИНН.
    context_result = await _build_context(clean_inn, _source, _checko)
    risk = await _collect_risk_facts(
        clean_inn, _checko,
        name=(context_result.context.name_short or context_result.context.name_legal
              if context_result.context else None),
    )

    # ЗАЩИТА ОТ «ЧИСТО НЕПРОВЕРЕННОГО». Пустые факты неотличимы от чистых:
    # если ни один источник не ответил (в т.ч. молчание из-за не заданных
    # ключей), движок посчитал бы baseline «можно работать» по компании,
    # которую не проверял никто. Такая оценка хуже отсутствия оценки —
    # она выглядит достоверно. Отказываемся считать, пока источники молчат.
    #
    # Живой прогон поймал дыру в этой защите: раньше требовалось ещё и
    # отсутствие карточки. Но карточка из ЕГРЮЛ (последний эшелон) ничего
    # не проверяет: суды, приставы, надзор остались непроверенными, а
    # вердикт считался по единственному уцелевшему критерию — возрасту —
    # и выглядел как «надёжный, 75». Карточка есть, проверки нет —
    # оценивать нельзя точно так же.
    if risk.sources_ok == 0:
        reason = (
            "Реестровые источники недоступны"
            + (f": {context_result.reason}" if context_result.reason else "")
            + ". Оценка НЕ ВЫСТАВЛЕНА: ни один источник рисков не ответил, "
            "выдавать вердикт по непроверенной организации нельзя. "
            "Карточка компании сама по себе проверкой рисков не является. "
            "Проверьте ключи DaData/Checko в .env и доступность API."
        )
        log.warning("verdict_refused", inn=clean_inn,
                    sources_failed=risk.sources_failed,
                    context_status=context_result.status)
        return ScoreResult(
            inn=clean_inn,
            verdict=Verdict(label="не рекомендуется", total_score=0.0),
            groups=[],
            matched=[],
            reasons=["Оценка не производилась — " + reason],
            warnings=["Оценка НЕ ВЫСТАВЛЕНА: источники недоступны, "
                      "организацию никто не проверял. НЕ РАБОТАЙТЕ "
                      "с этим вердиктом как с реальной оценкой."],
            pending=[],
            criteria_version=_load_scoring_config().criteria_version,
            scored_at=datetime.now(UTC),
        )

    # Проверка расхождения запроса «Имя ↔ ИНН»
    query_discrepancy = None
    if target_expected_name and context_result.context:
        query_discrepancy = _check_query_inn_consistency(target_expected_name, context_result.context)
        if query_discrepancy:
            disc_fact = _build_discrepancy_fact(query_discrepancy)
            risk.facts.append(disc_fact)

    if context_result.context:
        risk.facts.extend(_extract_financial_risk_facts(context_result.context))
    result = _score_company(
        facts=risk.facts + _quarantine.confirmed_facts(clean_inn),
        context=context_result.context,
    )
    if query_discrepancy:
        result.warnings.insert(
            0,
            f"ВНИМАНИЕ: Запрошена организация «{query_discrepancy['запрошено_наименование']}», "
            f"однако по указанному ИНН в ЕГРЮЛ зарегистрирована «{query_discrepancy['фактическое_в_реестре']}». "
            "Возможно, передан ошибочный ИНН чужого юридического лица!",
        )

    # Защита от фальшивого «отлично» при отказе ключевых реестров
    core_risk_sources = {"checko.arbitration", "checko.registry_flags", "checko.enforcement"}
    core_ok = sum(1 for r in (risk.results if risk else []) if r.source in core_risk_sources and r.status in ("ok", "partial"))
    core_failed = sum(1 for r in (risk.results if risk else []) if r.source in core_risk_sources and r.status not in ("ok", "partial"))

    if core_failed >= 2 and core_ok == 0:
        quota_warn = "⚠️ Базовые реестры рисков (арбитраж Kad.Arbitr, приставы ФССП, отметки ЕГРЮЛ) недоступны (лимит API Checko 403). Судебные и юридические риски не проверены!"
        if quota_warn not in result.warnings:
            result.warnings.append(quota_warn)
        if result.verdict.total_score >= 50.0:
            result.verdict = Verdict(code="FAIR", label="удовлетворительно", total_score=min(result.verdict.total_score, 45.0), floored=True)
            result.reasons.append("Оценка ограничена до «удовлетворительно»: ключевые реестры арбитража и юридических рисков не ответили")

    # Снижение оценки при наличии инцидентов ЦОД, аварий или кибератак
    pending_facts = _quarantine.list_pending(clean_inn)
    has_disaster = any(
        getattr(f, "kind", "") in ("fiasco_disaster_incident", "fiasco_cyber_data_breach")
        for f in (risk.facts + pending_facts + _quarantine.confirmed_facts(clean_inn))
    )
    if has_disaster and result.verdict.total_score >= 50.0:
        result.verdict = Verdict(code="FAIR", label="удовлетворительно", total_score=min(result.verdict.total_score, 40.0), floored=True)
        result.reasons.append("Оценка снижена: в открытых источниках/СМИ зафиксированы аварии ЦОД/инфраструктуры или утечки данных")

    log.info("tool_call", tool="get_verdict", inn=clean_inn,
             verdict=result.verdict.label, score=result.verdict.total_score,
             floored=result.verdict.floored)
    if profile:
        # Деловой свод поверх результата: те же данные, порядок для
        # менеджера. Не пересчёт — компоновка.
        from osint_mcp.tools.profile import build_profile
        result.profile = build_profile(context_result.context, risk, result)
    return result


@mcp.tool()
async def search_unverified(
    inn: Annotated[
        str,
        Field(description="ИНН организации, по которой ищем", examples=["7724744134"]),
    ],
    query: Annotated[
        str,
        Field(
            description="Поисковый запрос. Пример: «ООО Ромашка собаки питомник»",
            examples=["ООО Ромашка собаки питомник"],
        ),
    ],
    kind: Annotated[
        str,
        Field(
            description="Вид факта для находок, например dog_connection",
            examples=["dog_connection", "news_mention"],
        ),
    ],
    limit: Annotated[int, Field(description="Сколько находок искать (макс 10)")] = 5,
) -> SearchUnverifiedResult:
    """Поиск упоминаний организации в открытых веб-источниках с помещением находок в карантин.

    Возвращает SearchUnverifiedResult:
      inn: ИНН организации.
      query: поисковый запрос.
      found: количество найденных совпадений.
      added_to_quarantine: количество новых фактов, добавленных в карантин.
      hits: перечень находок (PendingFact) со ссылками source_url.
    """
    parsed_inn, _ = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    ledger.set_subject(clean_inn)
    found = _search_pending(query, kind, limit=min(limit, 10))
    added = _quarantine.add(clean_inn, found)
    log.info("tool_call", tool="search_unverified", inn=clean_inn,
             found=len(found), added=added)
    return SearchUnverifiedResult(
        inn=clean_inn,
        query=query,
        found=len(found),
        added_to_quarantine=added,
        hits=list(found),
        note="Находки сохранены в карантин; в основной вердикт не включены.",
    )


@mcp.tool()
def review_pending(
    inn: Annotated[
        str,
        Field(description="ИНН организации", examples=["7724744134"]),
    ],
    action: Annotated[
        str, Field(description="«list» — показать карантин; «confirm» — подтвердить; «reject» — отклонить"),
    ],
    fact_id: Annotated[
        str | None,
        Field(description="ID находки (обязателен для confirm/reject)"),
    ] = None,
    weight: Annotated[
        float,
        Field(
            description=(
                "Оценка агента: насколько находка влияет на решение о "
                "сотрудничестве. Обязателен для confirm"
            ),
        ),
    ] = None,
    rationale: Annotated[
        str,
        Field(
            description=(
                "Краткое объяснение оценки — показывается пользователю "
                "рядом со ссылкой на находку"
            ),
        ),
    ] = "",
) -> dict:
    """Управление карантином нереестровых находок: просмотр, подтверждение с весом или отклонение.

    Действия:
      action="list" — получить список находок в карантине по указанному ИНН;
      action="confirm" — подтвердить факт (fact_id) с присвоением веса (weight) и обоснования (rationale);
      action="reject" — отклонить факт как нерелевантный или ошибочный.
    """
    parsed_inn, _ = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    if action == "list":
        pending = _quarantine.list_pending(clean_inn)
        return {
            "inn": clean_inn,
            "pending": [p.model_dump(mode="json") for p in pending],
            "count": len(pending),
        }

    if action == "confirm":
        if weight is None:
            return {
                "error": "weight обязателен: выставь оценку находки сам — "
                         "насколько она влияет на решение о сотрудничестве"
            }
        result = _quarantine.confirm(clean_inn, fact_id or "", weight,
                                     confirmed_by="agent", rationale=rationale)
        if result is None:
            return {"error": f"Находка {fact_id} не найдена в карантине"}
        log.info("tool_call", tool="review_pending", inn=clean_inn,
                 action="confirm", fact_id=fact_id, weight=weight)
        return {
            "confirmed": True,
            "review": {
                **result,
                "note": "Подтверждённая находка включена в скоринг.",
            },
        }

    if action == "reject":
        ok = _quarantine.reject(clean_inn, fact_id or "")
        log.info("tool_call", tool="review_pending", inn=clean_inn,
                 action="reject", fact_id=fact_id, ok=ok)
        return {"rejected": ok}

    return {"error": f"Неизвестное action: {action} (list/confirm/reject)"}


@mcp.tool()
async def check_provider_limits() -> ProvidersLimitsReport:
    """Проверить остаток суточных квот, лимитов и состояние ключей всех провайдеров.

    Возвращает ProvidersLimitsReport:
    - summary: суммарная суточная ёмкость обращений, число активных ключей, расчётный запас проверок;
    - providers: детализированный статус по каждому из сервисов (Checko, DaData, HH, ГИР БО, ЕГРЮЛ, МСП и др.);
    - alerts: критические предупреждения об исчерпании ключей или лимитов.
    """
    log.info("tool_call", tool="check_provider_limits")
    return await _check_all_limits(_source)


@mcp.tool()
def list_catalog_sources() -> dict:
    """Показать каталог доступных подключаемых источников и критериев (Библиотека сигналов).

    КОГДА ВЫЗЫВАТЬ:
    Когда требуется узнать, какие специализированные проверки доступны в системе
    помимо базовых реестров (например: санкции, офис/животные/культура, стек вакансий, отзывы о ЗП).
    """
    catalog = _load_source_catalog()
    return {
        "catalog_sources": {
            name: {
                "topic": s.topic,
                "type": s.type,
                "trust": s.trust,
                "description": s.description,
                "produces_kind": s.produces_kind,
                "domains": s.domains,
                "keywords": s.keywords,
            }
            for name, s in catalog.sources.items()
        },
        "count": len(catalog.sources),
        "note": "Любой из этих источников можно запустить точечно через scan_catalog_source",
    }


@mcp.tool()
async def scan_catalog_source(
    inn: Annotated[
        str,
        Field(description="ИНН проверяемой организации", examples=["7724744134"]),
    ],
    source_name: Annotated[
        str,
        Field(
            description=(
                "Имя источника из Каталога источников (см. list_catalog_sources). "
                "Например: 'international_sanctions', 'office_environment', 'tech_stack_requirements', 'employee_reviews_salary'"
            ),
            examples=["office_environment", "international_sanctions"],
        ),
    ],
) -> SearchUnverifiedResult:
    """Точечно опросить подключённый источник из Библиотеки источников.

    Вместо слепого поиска по всему интернету выполняет адресный поиск по доверенным
    доменам или официальному сайту компании с фильтрацией по профильным ключевым словам.
    Все находки изолируются в карантин с указанием вида факта (kind) и ссылки (source_url).
    После подтверждения (review_pending) факт попадает в скоринг по правилам scoring.yaml.
    """
    parsed_inn, auto_name = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    ledger.set_subject(clean_inn)
    catalog = _load_source_catalog()
    spec = catalog.sources.get(source_name)
    if spec is None:
        return SearchUnverifiedResult(
            inn=clean_inn,
            query=source_name,
            found=0,
            added_to_quarantine=0,
            hits=[],
            note=f"Источник '{source_name}' не найден в каталоге. См. list_catalog_sources",
        )

    # Достаём название и сайт из контекста (если уже собраны)
    context_res = await _build_context(clean_inn, _source, _checko)
    name = (
        context_res.context.name_short or context_res.context.name_legal
        if context_res.context
        else auto_name
    )
    domain = context_res.context.brand_domain if context_res.context else None

    import asyncio
    found = await asyncio.to_thread(
        _execute_catalog_source,
        source_name=source_name,
        spec=spec,
        inn=clean_inn,
        name=name,
        brand_domain=domain,
    )
    added = _quarantine.add(clean_inn, found)
    log.info("tool_call", tool="scan_catalog_source", inn=clean_inn,
             source=source_name, found=len(found), added=added)

    return SearchUnverifiedResult(
        inn=clean_inn,
        query=f"catalog:{source_name}",
        found=len(found),
        added_to_quarantine=added,
        hits=list(found),
        note=(
            f"Находки по источнику '{source_name}' помещены в карантин (kind='{spec.produces_kind}'). "
            "Для учёта в скоринге подтвердите находку через review_pending(confirm)."
        ),
    )


@mcp.tool()
def register_custom_source(
    name: Annotated[
        str,
        Field(description="Уникальный идентификатор источника, например 'kz_customs_registry'", examples=["kz_customs_registry"]),
    ],
    topic: Annotated[
        str,
        Field(description="Категория темы, например 'sanctions', 'customs', 'licensing', 'company_culture'"),
    ],
    produces_kind: Annotated[
        str,
        Field(description="Вид порождаемого факта (ExtFact.kind), например 'kz_customs_violation'"),
    ],
    description: Annotated[
        str,
        Field(description="Человекочитаемое описание источника"),
    ],
    scope: Annotated[
        str,
        Field(
            description=(
                "'global' — единый реестр/база данных на все компании сразу; "
                "'company_asset' — точечный аудит сайта/активов конкретной компании"
            ),
            examples=["global", "company_asset"],
        ),
    ] = "company_asset",
    domains: Annotated[
        list[str],
        Field(description="Доверенные целевые домены для адресного поиска, например ['kgd.gov.kz']"),
    ] = [],
    keywords: Annotated[
        list[str],
        Field(description="Ключевые слова-сигналы для фильтрации"),
    ] = [],
    search_template: Annotated[
        str,
        Field(description="Шаблон запроса. Доступны {inn}, {name}, {domain}"),
    ] = "",
) -> dict:
    """Зарегистрировать новый подключаемый источник в Каталоге источников на лету.

    КОГДА ВЫЗЫВАТЬ:
    Когда пользователю необходимо подключить новую специализированную проверку
    (реестр лицензий, таможенные базы, специфические правила) без изменения исходного кода.
    После регистрации источник сразу доступен для одиночных вызовов scan_catalog_source
    и пакетных проверок scan_catalog_batch.
    """
    scope_norm = "global" if scope.strip().lower() == "global" else "company_asset"
    spec = _SourceSpec(
        scope=scope_norm,
        topic=topic.strip(),
        type="dataset_table" if scope_norm == "global" and not domains else "curated_domains",
        trust="reference" if scope_norm == "global" else "mention",
        description=description.strip(),
        produces_kind=produces_kind.strip(),
        domains=domains,
        keywords=keywords,
        search_template=search_template,
    )
    _save_source_to_catalog(name.strip(), spec)
    log.info("tool_call", tool="register_custom_source", name=name, scope=scope_norm)
    return {
        "status": "ok",
        "registered_source": name,
        "scope": scope_norm,
        "produces_kind": spec.produces_kind,
        "note": f"Источник '{name}' успешно добавлен в каталог и готов к проверкам.",
    }


@mcp.tool()
async def scan_catalog_batch(
    source_name: Annotated[
        str,
        Field(description="Имя источника из Каталога источников", examples=["international_sanctions"]),
    ],
    inns: Annotated[
        list[str],
        Field(description="Список ИНН организаций для пакетной проверки (до 100 компаний)"),
    ],
) -> dict:
    """Пакетная проверка списка компаний (до 100 ИНН) по единому источнику.

    АРХИТЕКТУРНОЕ ПРЕИМУЩЕСТВО:
    Для глобальных источников (scope='global') НЕ делает 100 отдельных веб-поисков!
    Опрашивает центральную базу/реестр за один шаг.
    Находки автоматически изолируются в карантин для каждого ИНН со ссылками на первоисточник.
    """
    clean_inns = []
    for raw in inns:
        p_inn, _ = _extract_inn_and_name(raw)
        c = (p_inn or raw).strip().replace(" ", "").replace("-", "")
        if c:
            clean_inns.append(c)
    if not clean_inns:
        return {"error": "Список ИНН пуст"}
    if len(clean_inns) > 100:
        return {"error": "Максимальный размер пакета — 100 ИНН за один вызов"}

    catalog = _load_source_catalog()
    spec = catalog.sources.get(source_name)
    if spec is None:
        return {"error": f"Источник '{source_name}' не найден в каталоге"}

    import asyncio
    grouped_hits = await asyncio.to_thread(
        _execute_catalog_batch,
        source_name=source_name,
        inns=clean_inns,
        catalog=catalog,
    )

    total_added = 0
    results_summary = {}
    for inn, facts in grouped_hits.items():
        if facts:
            added = _quarantine.add(inn, facts)
            total_added += added
            results_summary[inn] = {
                "hits_count": len(facts),
                "added_to_quarantine": added,
                "statements": [f.statement for f in facts],
            }
        else:
            results_summary[inn] = {"hits_count": 0, "status": "clean_or_not_found"}

    log.info("tool_call", tool="scan_catalog_batch", source=source_name,
             companies=len(clean_inns), total_added=total_added)

    return {
        "source": source_name,
        "scope": spec.scope,
        "total_requested": len(clean_inns),
        "total_hits_added": total_added,
        "details": results_summary,
        "note": "Пакетная проверка завершена без повторного веб-поиска по каждой компании.",
    }


async def check_shared_analytics(
    inn: Annotated[
        str,
        Field(
            description="ИНН организации для поиска связанных доменов и скрытого холдинга по кодам веб-аналитики",
            examples=["7724744134"],
        ),
    ],
    site_url: Annotated[
        str | None,
        Field(
            default=None,
            description="Опциональный URL сайта компании (если не передан, берётся автоматически из контекста компании)",
            examples=["https://bpmsoft.ru"],
        ),
    ] = None,
) -> dict:
    """Анализ цифровой инфраструктуры и связей через веб-аналитику (Яндекс.Метрика, Google Analytics, VK).

    Извлекает уникальные идентификаторы счетчиков с сайта компании и находит другие домены
    с теми же счетчиками для обнаружения скрытых аффилированных структур или сетей холдинга.
    """
    parsed_inn, _ = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    target_site = site_url

    # Если сайт не передан, получаем его из контекста
    if not target_site:
        ctx_res = await _build_context(clean_inn, _source, _checko)
        if ctx_res.context:
            target_site = ctx_res.context.brand_domain or (
                ctx_res.context.extras.contacts.website
                if ctx_res.context.extras and ctx_res.context.extras.contacts
                else None
            )

    if not target_site:
        return {
            "inn": clean_inn,
            "status": "no_site",
            "message": "У организации не найден официальный сайт для извлечения кодов аналитики.",
            "tracker_ids": {},
            "shared_networks": [],
        }

    _, tech, err = await _inspect_site_content(target_site)
    tracker_ids = tech.tracker_ids if tech else {}

    if not tracker_ids:
        return {
            "inn": clean_inn,
            "site": target_site,
            "status": "no_trackers",
            "message": f"На сайте {target_site} не обнаружено кодов Яндекс.Метрики или Google Analytics (или сайт недоступен: {err}).",
            "tracker_ids": {},
            "shared_networks": [],
        }

    import asyncio
    facts = await asyncio.to_thread(
        _build_analytics_affiliation_facts,
        domain=target_site,
        tracker_ids=tracker_ids,
        subject_inn=clean_inn,
    )

    added_to_quarantine = 0
    if facts:
        added_to_quarantine = _quarantine.add(clean_inn, facts)

    networks_summary = []
    for f in facts:
        networks_summary.append({
            "tracker_type": f.payload.get("tracker_type"),
            "tracker_id": f.payload.get("tracker_id"),
            "shared_domains": f.payload.get("shared_domains"),
            "is_probable_holding": f.payload.get("is_probable_holding"),
            "interpretation": f.payload.get("interpretation"),
            "statement": f.statement,
        })

    log.info("tool_call", tool="check_shared_analytics", inn=clean_inn,
             site=target_site, trackers=list(tracker_ids.keys()),
             networks=len(networks_summary), quarantined=added_to_quarantine)

    return {
        "inn": clean_inn,
        "site": target_site,
        "status": "ok",
        "tracker_ids": tracker_ids,
        "networks_found": len(networks_summary),
        "shared_networks": networks_summary,
        "added_to_quarantine": added_to_quarantine,
    }


async def check_customs_ved(
    inn: Annotated[
        str,
        Field(
            description="ИНН организации для таможенной проверки и анализа ВЭД (импорт/экспорт/санкционные риски)",
            examples=["7724744134"],
        ),
    ],
    company_name: Annotated[
        str | None,
        Field(
            default=None,
            description="Опциональное наименование компании (если не передано, берется из реестрового контекста)",
        ),
    ] = None,
) -> dict:
    """Анализ таможенных данных и внешнеэкономической деятельности (ВЭД, импорт/экспорт).

    Проверяет таможенные декларации (ГТД), базы ФТС и поставки по ИНН для выявления
    санкционных рисков, критической импортной зависимости и подтверждения реального товарооборота.
    """
    parsed_inn, auto_name = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    target_name = company_name or auto_name

    if not target_name:
        ctx_res = await _build_context(clean_inn, _source, _checko)
        if ctx_res.context:
            target_name = ctx_res.context.name_short or ctx_res.context.name_legal

    import asyncio
    facts = await asyncio.to_thread(
        _build_customs_facts,
        inn=clean_inn,
        company_name=target_name,
    )

    added_to_quarantine = 0
    if facts:
        added_to_quarantine = _quarantine.add(clean_inn, facts)

    profile = _evaluate_customs_findings(clean_inn, [])
    # Если нашлись факты в веб-поиске, формируем профиль по первому факту
    interpretation = facts[0].statement if facts else profile.interpretation

    log.info("tool_call", tool="check_customs_ved", inn=clean_inn,
             name=target_name, facts_count=len(facts), quarantined=added_to_quarantine)

    return {
        "inn": clean_inn,
        "company_name": target_name,
        "has_ved_activity": bool(facts),
        "facts_found": len(facts),
        "added_to_quarantine": added_to_quarantine,
        "interpretation": interpretation,
    }


async def check_geo_reviews(
    inn: Annotated[
        str,
        Field(
            description="ИНН организации для картографического OSINT и проверки отзывов",
            examples=["7724744134"],
        ),
    ],
    address: Annotated[
        str | None,
        Field(
            default=None,
            description="Опциональный юридический или фактический адрес (если не передан, берется из ЕГРЮЛ)",
        ),
    ] = None,
) -> dict:
    """Картографический OSINT, панорамы и семантика отзывов клиентов (Яндекс.Карты, 2ГИС).

    Сопоставляет юридический адрес из ЕГРЮЛ с реальными гео-объектами на картах
    и анализирует семантику свежих отзывов для выявления операционных сбоев или признаков фиктивного адреса.
    """
    parsed_inn, auto_name = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    target_addr = address
    target_name = auto_name

    if not target_addr or not target_name:
        ctx_res = await _build_context(clean_inn, _source, _checko)
        if ctx_res.context:
            if not target_addr:
                target_addr = ctx_res.context.address_full
            target_name = ctx_res.context.name_short or ctx_res.context.name_legal

    if not target_addr:
        return {
            "inn": clean_inn,
            "status": "no_address",
            "message": "Юридический адрес организации не найден.",
        }

    import asyncio
    facts = await asyncio.to_thread(
        _build_geo_reviews_facts,
        inn=clean_inn,
        company_name=target_name or clean_inn,
        address=target_addr,
    )

    added_to_quarantine = 0
    if facts:
        added_to_quarantine = _quarantine.add(clean_inn, facts)

    interpretation = facts[0].statement if facts else "Физическое присутствие подтверждено, критических сигналов не выявлено."

    log.info("tool_call", tool="check_geo_reviews", inn=clean_inn,
             address=target_addr, facts_count=len(facts), quarantined=added_to_quarantine)

    return {
        "inn": clean_inn,
        "company_name": target_name,
        "address": target_addr,
        "facts_found": len(facts),
        "added_to_quarantine": added_to_quarantine,
        "interpretation": interpretation,
    }


async def check_reputation_fiascos(
    inn: Annotated[
        str,
        Field(
            description="ИНН организации для поиска операционных сбоев, факапов и коммерческих рисков",
            examples=["7724744134"],
        ),
    ],
    company_name: Annotated[
        str | None,
        Field(
            default=None,
            description="Опциональное наименование компании или бренд (если не передано, берется из ЕГРЮЛ)",
        ),
    ] = None,
    domain: Annotated[
        str | None,
        Field(
            default=None,
            description="Опциональный домен корпоративного сайта для точного таргетинга (например, 'bpmsoft.ru')",
        ),
    ] = None,
    platforms: Annotated[
        list[str] | None,
        Field(
            default=None,
            description="Список целевых платформ: ['vc_ru', 'habr', 'pikabu', 'blacklists', 'dev_community']. Если не указано, проверяются все 5.",
        ),
    ] = None,
) -> dict:
    """Глубокий поиск забытых факапов, неплатежей, споров с подрядчиками и аварий.

    КОНТУРЫ ПОИСКА (5 платформ):
    1. VC.ru (Приёмная): досудебные претензии, невозврат денег, удержание оплат подрядчикам.
    2. Хабр (Habr): инженерные постмортемы, падения продакшна, критика в комментариях инженеров.
    3. Пикабу (Pikabu): публичные разоблачения, потребительские и партнёрские конфликты.
    4. Чёрные списки работодателей/заказчиков (Antijob, Правда Сотрудников, DreamJob): невыплаты расчётов, затягивание актов, токсичный менеджмент.
    5. Разработческие сообщества (GitHub, GitLab): заброшенные репозитории, критические баги, утечки токенов/ключей.

    ПРИКЛАДНАЯ ЦЕННОСТЬ ДЛЯ СЕЙЛА / ПОСТАВЩИКА / ПАРТНЁРА:
    Позволяет узнать поведенческую культуру контрагента ДО подписания договора:
    - Затягивают ли они оплаты и подписание актов сдачи-приёмки?
    - Были ли крупные технологические аварии и простои сервисов?
    - Не увольняется ли команда посреди проекта?
    Все находки помещаются в SQLite-карантин (quarantine.db) со статусом 'pending' и категорией риска.
    """
    parsed_inn, auto_name = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    target_name = company_name or auto_name
    target_domain = domain
    brand_candidate = None

    if not target_name or not target_domain:
        fast_res = await _source.get_context(clean_inn)
        if fast_res.status != "ok" or not fast_res.context:
            fast_res = await _checko.get_context(clean_inn)
        if fast_res.context:
            ctx = fast_res.context
            if not target_name:
                b = (ctx.brand or "").strip()
                if b and len(b) > 2 and re.search(r"[а-яА-ЯёЁ]", b):
                    target_name = b
                else:
                    target_name = ctx.name_short or ctx.name_legal or b
            if not brand_candidate and ctx.brand:
                brand_candidate = ctx.brand
            if not target_domain:
                target_domain = ctx.brand_domain or (
                    ctx.extras.contacts.website if ctx.extras and ctx.extras.contacts else None
                )

    from osint_mcp.tools.names import core_name
    if target_name:
        clean_core = core_name(target_name)
        if clean_core and len(clean_core) > 2:
            brand_candidate = clean_core

    facts = await _async_build_reputation_fiasco_facts(
        inn=clean_inn,
        company_name=target_name or clean_inn,
        brand=brand_candidate or target_name,
        domain=target_domain,
        platforms=platforms,
    )

    added_to_quarantine = 0
    if facts:
        added_to_quarantine = _quarantine.add(clean_inn, facts)

    log.info("tool_call", tool="check_reputation_fiascos", inn=clean_inn,
             company=target_name, facts_count=len(facts), quarantined=added_to_quarantine)

    incidents_summary = []
    for f in facts:
        m_date = re.search(r"\[([0-3]?\d\.[0-1]?\d(?:\.(?:20)?\d{2})?|\d{4})\]", f.statement)
        event_date = m_date.group(1) if m_date else None
        m_lbl = re.search(r"^\[(.*?)\]", f.statement)
        source_lbl = m_lbl.group(1) if m_lbl else ""
        incidents_summary.append({
            "fact_id": f.fact_id,
            "kind": f.kind,
            "source_label": source_lbl,
            "date": event_date,
            "statement": f.statement,
            "source_url": f.source_url,
        })

    return {
        "inn": clean_inn,
        "company_name": target_name,
        "domain": target_domain,
        "platforms_checked": platforms or ["disasters", "cyber_leaks", "federal_media", "vc_ru", "habr", "blacklists"],
        "facts_found": len(facts),
        "added_to_quarantine": added_to_quarantine,
        "incidents": incidents_summary,
    }


if settings.expose_granular_tools:
    for _fn in (
        validate_inn,
        get_company_context,
        check_affiliations,
        collect_risk_facts,
        check_coverage,
        get_company_report,
        get_company_links,
        get_verdict,
        check_shared_analytics,
        check_customs_ved,
        check_geo_reviews,
        check_reputation_fiascos,
    ):
        mcp.tool()(_fn)


def _serve_http() -> None:


    """Сетевой режим: тот же сервер, но доступный по адресу.

    Отличие от локального запуска не только в транспорте. Локально
    процесс порождает само приложение, и снаружи к нему не подступиться.
    В сети ключи к платным справочникам оказываются за общедоступным
    адресом, поэтому проверка доступа обязательна.
    """
    import uvicorn

    from osint_mcp.config import settings
    from osint_mcp.http_auth import TokenAuth

    if not settings.mcp_token:
        raise SystemExit("""
Сетевой режим без токена не запускается.

Ключи к платным справочникам лежат на сервере, и открытый адрес
позволит любому, кто его узнает, расходовать вашу суточную квоту.
Случайный адрес — не секрет: он попадает в журналы и переписку.

Задайте токен и повторите:
    OSINT_MCP_TOKEN=<длинная случайная строка>

Клиент обязан присылать его заголовком:
    Authorization: Bearer <тот же токен>
""")

    # За туннелем заголовок Host содержит публичный домен, и встроенная
    # защита от подмены адреса отвергает такие запросы кодом 421.
    # Домен приходится назвать явно — угадать его нельзя, у бесплатного
    # туннеля он меняется при каждом запуске.
    security = None
    hosts = settings.allowed_hosts()
    if hosts:
        from mcp.server.transport_security import TransportSecuritySettings

        security = TransportSecuritySettings(
            allowed_hosts=hosts,
            allowed_origins=[f"https://{h}" for h in hosts] + hosts,
        )

    # stateless: удалённый сервер обслуживает нескольких агентов сразу,
    # и привязка к сеансу здесь только мешает
    app = mcp.streamable_http_app(stateless_http=True,
                                  transport_security=security)
    log.info("http_ready", host=settings.http_host, port=settings.http_port,
             path="/mcp", auth="bearer", allowed_hosts=hosts or ["localhost"])
    uvicorn.run(TokenAuth(app, settings.mcp_token),
                host=settings.http_host, port=settings.http_port,
                log_level="info")


def main() -> None:
    transport = os.getenv("OSINT_MCP_TRANSPORT", "stdio").lower()
    log.info("server_start", server=SERVER_NAME, version=VERSION,
             transport=transport, tools=TOOLS)

    if transport in ("http", "streamable-http"):
        _serve_http()
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
