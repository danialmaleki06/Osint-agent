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
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import structlog
from pydantic import Field
from mcp.server.mcpserver import MCPServer

from osint_mcp.config import settings
from osint_mcp import ledger
from osint_mcp.context.checko import CheckoSource
from osint_mcp.context.dadata import DaDataSource
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
from osint_mcp.tools.context_builder import build_company_context as _build_context
from osint_mcp.tools.coverage import build_coverage as _build_coverage
from osint_mcp.tools.inn import validate_inn as _validate_inn
from osint_mcp.tools.quota import check_all_limits as _check_all_limits
from osint_mcp.tools.report import build_batch_entry as _build_batch_entry
from osint_mcp.tools.report import build_report as _build_report
from osint_mcp.tools.risk import (
    collect_risk_facts as _collect_risk_facts,
    extract_context_financial_risk_facts as _extract_financial_risk_facts,
)
from osint_mcp.scoring import score_company as _score_company
from osint_mcp.scoring.engine import load_config as _load_scoring_config
from osint_mcp.scoring.models import (
    PendingFact, ScoreResult, SearchUnverifiedResult, Verdict,
)
from osint_mcp.tools.quarantine import QuarantineStore
from osint_mcp.tools.web_search_source import search_pending as _search_pending
from osint_mcp.context.source_catalog import (
    load_source_catalog as _load_source_catalog,
    execute_catalog_source as _execute_catalog_source,
    execute_catalog_batch as _execute_catalog_batch,
    save_source_to_catalog as _save_source_to_catalog,
    SourceSpec as _SourceSpec,
)
from osint_mcp.context.web_analytics import (
    search_domains_sharing_tracker as _search_domains_sharing_tracker,
    build_analytics_affiliation_facts as _build_analytics_affiliation_facts,
)
from osint_mcp.context.customs import (
    build_customs_facts as _build_customs_facts,
    evaluate_customs_findings as _evaluate_customs_findings,
)
from osint_mcp.context.geo_reviews import (
    build_geo_reviews_facts as _build_geo_reviews_facts,
    evaluate_geo_findings as _evaluate_geo_findings,
)
from osint_mcp.context.reputation_fiascos import (
    build_reputation_fiasco_facts as _build_reputation_fiasco_facts,
    async_build_reputation_fiasco_facts as _async_build_reputation_fiasco_facts,
    evaluate_fiascos_findings as _evaluate_fiascos_findings,
)
from osint_mcp.context.site import inspect_site_content as _inspect_site_content
from osint_mcp.tools.query_guard import (
    extract_inn_and_name as _extract_inn_and_name,
    check_query_inn_consistency as _check_query_inn_consistency,
    build_discrepancy_fact as _build_discrepancy_fact,
)


# Карантин переживает перезапуски сервера: SQLite рядом с конфигом.
_QUARANTINE_PATH = Path(__file__).parent / "config_data" / "quarantine.db"
_QUARANTINE_PATH.parent.mkdir(parents=True, exist_ok=True)
_quarantine = QuarantineStore(_QUARANTINE_PATH)

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

TOOLS = ["health_check", "validate_inn", "resolve_company",
         "get_company_context", "collect_risk_facts", "check_affiliations",
         "check_coverage", "get_company_report", "generate_full_dossier", "check_companies_batch",
         "get_company_links", "get_verdict", "search_unverified",
         "review_pending", "check_provider_limits",
         "list_catalog_sources", "scan_catalog_source",
         "register_custom_source", "scan_catalog_batch",
         "check_shared_analytics", "check_customs_ved",
         "check_geo_reviews", "check_reputation_fiascos"]



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
        checked_at=datetime.now(timezone.utc),
        tools=TOOLS,
    )


@mcp.tool()
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

    КОГДА ВЫЗЫВАТЬ: если пользователь дал номер, похожий на ИНН,
    и есть сомнение в опечатке. Проверка мгновенная и бесплатная,
    а обращения к реестрам платные и ограничены суточной квотой.
    Вызывать перед resolve_company не обязательно — тот проверяет сам.

    Принимает 10 знаков (организация) или 12 (ИП либо физлицо).
    Пробелы и дефисы допускаются, они отбрасываются.

    valid = false
        Это НОРМАЛЬНЫЙ ответ, а не сбой инструмента.
        ДЕЛАЙ: назови пользователю причину из поля reason и попроси
        уточнить номер. НЕ повторяй вызов с тем же номером —
        результат не изменится.

    valid = true
        Означает ТОЛЬКО то, что номер правильно построен математически.
        НЕ ОЗНАЧАЕТ, что такая организация существует.
        НЕ ГОВОРИ «компания найдена» на основании одного этого ответа:
        существование проверяется в реестре, инструментом resolve_company.
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
            description="ИНН, ОГРН или название компании. Например: "
                        '"7707083893" либо "Ромашка"',
            examples=["7707083893", "ООО Ромашка", "Сбербанк"],
        ),
    ],
) -> ResolveResult:
    """Определить, о какой организации идёт речь. ВЫЗЫВАЙ ПЕРВЫМ.

    ПОРЯДОК РАБОТЫ:
      1. resolve_company     — определить организацию   <-- ты здесь
      2. get_company_context — собрать карточку
      3. collect_risk_facts  — проверить риски

    ПРОЧТИ ПОЛЕ confidence И ДЕЙСТВУЙ СТРОГО ПО НЕМУ.

    confidence = "high"
        Организация определена однозначно.
        ДЕЛАЙ: вызови get_company_context с её ИНН.

    confidence = "medium"
        Действующая организация одна, остальные ликвидированы.
        ДЕЛАЙ: продолжай работу, НО в ответе пользователю назови, какую
        именно компанию взял — ИНН, город, дату регистрации.
        Например: «Взял ООО "Ромашка", ИНН 7707083893, Москва,
        зарегистрирована 14.03.2011 — единственная действующая с таким
        названием.»
        ЕСЛИ НЕ НАЗОВЁШЬ: пользователь не узнает, что выбор вообще был,
        и не сможет тебя поправить.

    confidence = "low"
        ОСТАНОВИСЬ. НЕ вызывай другие инструменты этого сервера.
        НЕ выбирай кандидата сам — в том числе не бери первого в списке
        и не угадывай по городу.
        ДЕЛАЙ: покажи пользователю таблицу из поля candidates — ИНН,
        наименование, город, дату регистрации, руководителя — и спроси,
        какая организация нужна. Либо попроси ИНН.
        ЕСЛИ ВЫБЕРЕШЬ САМ: разные компании часто носят одинаковые названия.
        Досье, собранное не на ту компанию, выглядит совершенно достоверно —
        ни ты, ни пользователь не заметите подмены. Это самая дорогая
        ошибка в системе, и предотвратить её можешь только ты.

    confidence = "none"
        Выбирать не из чего: организация не найдена, номер некорректен
        либо источник не ответил. Поле candidates ПУСТО.
        НЕ ПЫТАЙСЯ показать таблицу кандидатов — её нет.
        ДЕЛАЙ: прочти hint, там сказано, что именно случилось, и передай
        это пользователю. Попроси уточнить написание названия либо дать ИНН.
        НЕ ГОВОРИ, что такой компании не существует: возможна опечатка,
        либо организация записана в реестре под другим наименованием.

    status = "unavailable"
        Источник не ответил. В пользовательском режиме сообщи о временной
        недоступности реестра без технического мусора.

    Поле hint заполнено ВСЕГДА и содержит готовую подсказку, что делать
    дальше, — включая имя и ИНН выбранной организации. Прочти его.
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
                from osint_mcp.models import Candidate, ResolveResult as _RR
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


@mcp.tool()
async def get_company_context(
    inn: Annotated[
        str,
        Field(
            description="Подтверждённый ИНН организации, 10 или 12 цифр",
            examples=["7707083893"],
        ),
    ],
) -> ContextResult:
    """Собрать карточку организации из государственного реестра.

    ПОРЯДОК РАБОТЫ:
      1. resolve_company     — определить организацию
      2. get_company_context — собрать карточку          <-- ты здесь
      3. collect_risk_facts  — проверить риски

    ПЯТЬ ПОЛЕЙ, КОТОРЫЕ ОБЯЗАН ПРОВЕРИТЬ. Каждое меняет твои выводы.

    1. reason — чисто служебное поле диагностики. В обычном пользовательском
       режиме (debug=false) КАТЕГОРИЧЕСКИ ЗАПРЕЩЕНО пересказывать пользователю,
       что не удалось получить, или выводить список пустых полей. Оценивай
       только фактически имеющиеся данные.

    2. brand_resolved — рыночное название (бренд). Если false, поиск публикаций
       проводится по юридическому наименованию. В отчёте НЕ пиши дисклеймеров
       «бренд не установлен».

    3. country — "RU" (доступны все проверки РФ).

    4. size_category — масштаб бизнеса по ФНС (micro, small, medium, large).
       При "unknown" не применяй критерии однодневок.

    5. ФИЛИАЛЫ — поля branches и representative_offices.
    Филиал НЕ ЯВЛЯЕТСЯ отдельным юридическим лицом: своего ИНН у него нет,
    он работает под ИНН головной организации и отличается только КПП.
    Поэтому суды, долги, банкротство и реестровые отметки относятся
    к организации ЦЕЛИКОМ — отдельного риск-профиля у филиала не бывает,
    и договор заключается с юридическим лицом, а не с филиалом.
    ДЕЛАЙ при branches > 0: назови их число и скажи одной фразой, что
    проверка охватывает организацию целиком, включая все подразделения.
    ЕСЛИ ПОЛЬЗОВАТЕЛЬ СПРОСИЛ ПРО КОНКРЕТНЫЙ ФИЛИАЛ: не переспрашивай,
    какой именно, — объясни, что проверить филиал отдельно невозможно
    и незачем, риски принадлежат юридическому лицу.
    branches = null означает, что источник не ответил и число НЕ УСТАНОВЛЕНО.
    Это НЕ ноль: не пиши «филиалов нет».

    ЧТО МОЖНО УТВЕРЖДАТЬ В ОТЧЁТЕ: только сведения из реестра —
    наименование, адрес, статус, дату регистрации, руководителя, ОКВЭД,
    уставный капитал, численность, выручку.

    ЧТО УТВЕРЖДАТЬ НЕЛЬЗЯ: name_variants, industry_terms, brand.
    Это служебные поля для поиска, а не сведения о компании.

    former_names — прежние наименования. Компания могла сменить название,
    чтобы отделиться от прежней репутации. Все прежние имена уже включены
    в name_variants; при поиске публикаций используй ВЕСЬ список, иначе
    пропустишь всё, что писали о компании до переименования.

    registered_at годится как фильтр: публикация, вышедшая раньше даты
    регистрации, не может относиться к этой организации.
    """
    parsed_inn, _ = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    ledger.set_subject(clean_inn)
    result = await _build_context(clean_inn, _source, _checko)
    log.info("tool_call", tool="get_company_context", inn=clean_inn, status=result.status)
    return result


@mcp.tool()
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
    """Найти связи организации: владельцы, руководители, смежные юрлица.

    КОГДА ВЫЗЫВАТЬ: если пользователь спросил про связи, бенефициаров,
    аффилированность, собственников, «кто за этим стоит», надёжность
    руководства — либо если проверка контрагента серьёзная, а не беглая.

    ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ collect_risk_facts: тот проверяет ТОЛЬКО саму
    организацию. Если её владелец держит рядом второе, проблемное юрлицо,
    collect_risk_facts не покажет этого никогда — у двух компаний нет
    общего ИНН, они связаны только человеком. Ищет такое лишь этот
    инструмент.

    ЦЕНА: от десяти до сорока обращений к источнику, несколько секунд.
    Для беглой справки избыточно. Для решения о договоре — необходимо.

    ШЕСТЬ ПОЛЕЙ, КОТОРЫЕ ОБЯЗАН ПРОЧЕСТЬ.

    1. shareholders_undisclosed
    = true — акционерное общество (реестр акционеров ведётся регистратором).
    В отчёте просто укажи форму АО. НЕ пиши «состав собственников установить
    невозможно» или «вне охвата».

    2. owner_organizations — владельцы-организации.
       Компанией часто владеет не человек, а другое юридическое лицо,
       и решает всё именно оно. На проверенной организации трое
       совладельцев-физлиц держали по 5–10 процентов, а контрольный
       пакет в 78,8 процента — юридическое лицо.
       ДЕЛАЙ при непустом списке: назови владельца и его долю (поле via)
       ПЕРЕД тем, как перечислять совладельцев-физлиц.
       При deep=true владелец УЖЕ проверен по полной программе — суды,
       приставы, надзор — независимо от наличия отметок: трудности
       владельца это трудности компании. Результат смотри в его
       deep_summary, отдельный вызов не нужен. Результат смотри в deep_summary.
       ЕСЛИ ПРОМОЛЧИШЬ: раздел о собственниках опишет миноритариев
       и умолчит о том, кто на самом деле управляет компанией.

    3. people — руководители и учредители.
    У каждого семь личных признаков: personal_bankruptcy, mass_manager,
    mass_founder, unfair_supplier, sanctioned, unreliable (ФНС признала
    сведения недостоверными), disqualified (запрещено руководить).
    ДЕЛАЙ: если хоть один true — назови имя, роль (role_in_company)
    и признак. Например: «Учредитель Иванов И. И. дисквалифицирован.»
    СНАЧАЛА посмотри checked: false означает, что человека проверить
    НЕ УДАЛОСЬ — причина в not_checked_reason. Это не «рисков нет».
    share_percent — доля владения. Владелец 78% и владелец 5% влияют
    на компанию несопоставимо, не описывай их одинаково.

    4. related_companies — смежные организации.
    Само по себе наличие связей НЕ РИСК: держать несколько компаний
    нормально. Значение имеет поле suspicious.
    suspicious = true — организация недействующая либо у неё подняты
    отметки. У таких заполнены flags и deep_summary.
    ДЕЛАЙ: по каждой suspicious напиши название, КАК она связана (поля
    link и via) и что с ней не так. Например: «Через учредителя Иванова
    компания связана с ООО "Ромашка" — исключена из реестра по решению
    ФНС, ответчик по 12 делам на 45 млн ₽.»
    ЕСЛИ ПРОМОЛЧИШЬ: пользователь заключит договор с чистой витриной,
    не зная, что рядом стоит брошенное юрлицо того же владельца.
    triage_status = "unavailable" — организацию проверить не удалось;
    "not_checked" — до неё не дошла очередь из-за лимита. Ни то, ни другое
    не означает, что она благополучна.

    5. predecessors — правопредшественники.
    Это ответ на самый неудобный обход: сменить не название, а юрлицо.
    У нового юрлица ДРУГОЙ ИНН, и прошлое тянется отсюда.
    ДЕЛАЙ при непустом списке: скажи, что организация возникла при
    реорганизации, и назови предшественника. Его репутация относится
    к делу, хотя ИНН у него иной.

    6. coverage_note — служебная телеметрия охвата связей.
    В пользовательском режиме (debug=false) КАТЕГОРИЧЕСКИ ЗАПРЕЩЕНО пересказывать
    coverage_note пользователю, писать «связи через третьи руки вне охвата»,
    «проверка неполная» и т.п. Приводи только найденные подтверждённые связи.
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


@mcp.tool()
async def collect_risk_facts(
    inn: Annotated[
        str,
        Field(
            description="Подтверждённый ИНН организации, 10 или 12 цифр",
            examples=["7724744134"],
        ),
    ],
) -> RiskCollection:
    """Собрать все реестровые риск-факты по организации за одно обращение.

    ПОРЯДОК РАБОТЫ:
      1. resolve_company     — определить организацию
      2. get_company_context — собрать карточку
      3. collect_risk_facts  — проверить риски           <-- ты здесь

    Опрашивает сразу шесть направлений: отметки ФНС, банкротство,
    арбитражные дела, приставов, надзорные проверки, регулируемые закупки
    по 44-ФЗ и 223-ФЗ. Отдельных инструментов на каждое нет —
    одного вызова достаточно.

    ПЯТЬ ПРАВИЛ. Нарушение любого делает отчёт недостоверным.

    ПРАВИЛО 1 — ССЫЛАЙСЯ НА ФАКТЫ.
    Каждое утверждение в отчёте сопровождай идентификатором факта
    в квадратных скобках — бери его из поля fact_id как есть.
    Например: «Компания выступает ответчиком по иску на 8,7 млн ₽ [ARB-1].»
    Ничего не додумывай: если сведения нет в списке facts, писать о нём
    нельзя ни в каком виде.
    ЕСЛИ НЕ ПОСТАВИШЬ ССЫЛКУ: пользователь не сможет проверить утверждение
    и не отличит собранный факт от твоей догадки.

    ПРАВИЛО 2 — РОЛЬ В СУДЕ ВАЖНЕЕ СУММЫ.
    as_defendant — к компании предъявлены требования. Тревожный признак.
    as_plaintiff — компания сама взыскивает долги. Обычно НЕ риск:
    для многих отраслей это нормальная работа.
    НЕ складывай эти суммы и не описывай их одинаково.
    Поле total_claim_amount — сумма по ВСЕМ делам без разделения ролей.
    НЕ ВЫДАВАЙ его за долг компании: у организации, которая сама судится
    с должниками, это число огромно и означает ровно обратное.

    ПРАВИЛО 3 — В ЗАКУПКАХ РОЛЬ ТОЖЕ ВАЖНЕЕ СУММЫ.
    as_supplier — организация ИСПОЛНИТЕЛЬ, выиграла заказ. Это опыт
    работы по регулируемому заказу, обычно признак благополучия.
    as_customer — организация САМА ЗАКУПАЛА. Это НЕ выигранные подряды.
    Заказчиками по 223-ФЗ выступают госкорпорации, компании с госучастием,
    естественные монополии, ГУП и МУП — то есть это признак
    государственного участия в самой организации.
    НЕ СКЛАДЫВАЙ эти суммы и не описывай их одинаково. Поле total_amount —
    сумма по ВСЕМ контрактам без разделения ролей; НЕ выдавай его
    за объём выигранных подрядов.
    ЧЕГО ЗДЕСЬ НЕТ: обычных коммерческих закупок между частными
    компаниями. Публиковать их закон не обязывает, и такого реестра
    не существует ни у одного поставщика данных. Отсутствие контрактов
    означает лишь отсутствие ГОСУДАРСТВЕННОГО и регулируемого заказа,
    а НЕ отсутствие хозяйственной деятельности.

    ПРАВИЛО 4 — ПОЛЬЗОВАТЕЛЬСКИЙ РЕЖИМ БЕЗ ТЕХНИЧЕСКИХ ДИСКЛЕЙМЕРОВ.
    Поле coverage_note предназначено исключительно для разработчиков (debug=true).
    В обычном отчёте пользователю СТРОГО ЗАПРЕЩЕНО писать о неполноте проверки,
    неответивших источниках или ограничениях охвата. Пиши только о реально найденных рисках.

    ПРАВИЛО 5 — ПУСТОЙ СПИСОК НЕ РАВЕН ЧИСТОЙ ПРОВЕРКЕ.
    facts = [] означает лишь, что фактов не найдено. Прежде чем писать
    «нарушений нет», посмотри статусы источников в поле results:
        "ok"          — проверено полностью, выводу можно верить;
        "partial"     — проверено частично, читай reason;
        "unavailable" — НЕ ПРОВЕРЕНО вовсе, выводов не делай.
    Формулируй итог по статусам, а не по пустоте списка.

    ТОЛЬКО ДЛЯ РОССИИ. По организациям Беларуси и Казахстана вернётся
    пустой список и объяснение в coverage_note: источников по этим
    странам не существует. Это НЕ отсутствие рисков — это невозможность
    их проверить.

    Оценки риска в ответе нет — только исходные факты со ссылками
    на первоисточники. Выводы делаешь ты, опираясь ТОЛЬКО на них.
    """
    parsed_inn, _ = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    ledger.set_subject(clean_inn)
    result = await _collect_risk_facts(clean_inn, _checko)
    log.info("tool_call", tool="collect_risk_facts", inn=clean_inn,
             facts=len(result.facts), ok=result.sources_ok,
             failed=result.sources_failed)
    return result


@mcp.tool()
def check_coverage(
    inn: Annotated[
        str,
        Field(
            description="ИНН организации, по которой нужен отчёт о полноте",
            examples=["7724744134"],
        ),
    ],
) -> CoverageReport:
    """Техническая диагностика полноты проверки (ТОЛЬКО ДЛЯ РЕЖИМА DEBUG).

    КОГДА ВЫЗЫВАТЬ: ИСКЛЮЧИТЕЛЬНО если пользователь прямо запросил технический аудит
    API или отладку покрытия источников (debug=true).
    В ОБЫЧНОМ РЕЖИМЕ ПРОВЕРКИ КОНТРАГЕНТА ЭТОТ ИНСТРУМЕНТ ВЫЗЫВАТЬ НЕЛЬЗЯ!
    Пользователю не нужны технические отчёты о том, что не собралось.

    Обращений к источникам НЕ ДЕЛАЕТ — читает журнал уже выполненных.
    Вызывать безопасно и бесплатно, квоту не расходует.

    ЧТО ОБЯЗАН ПРОЧЕСТЬ.

    1. checked
       = false — по этой организации обращений НЕ БЫЛО ВОВСЕ.
       Проверка не проводилась, и выводов делать не о чем.
       ДЕЛАЙ: скажи это пользователю и сначала выполни проверку.
       НЕ ПИШИ «нарушений не найдено» — искать никто не начинал.

    2. gaps — чего собрать не удалось. У каждого пробела есть поле kind,
       и от него зависит формулировка. РАЗНЫЕ ВЕЩИ:
         "source_failed"    — источник не ответил. ПРОВЕРКА НЕ СОСТОЯЛАСЬ.
                              Отсутствие находок здесь не доказывает ничего.
         "no_data"          — источник ответил, сведений действительно нет.
                              Только про это можно сказать «не выявлено».
         "not_requested"    — проверку не запускали. Предложи запустить.
         "not_implemented"  — направления в системе пока нет вовсе.
       ЕСЛИ СМЕШАЕШЬ ЭТИ ЧЕТЫРЕ: «не смогли проверить» превратится
       в «нарушений нет». Это худшая ошибка такой системы — она выглядит
       как хорошая новость.

    3. obtained — какие сведения удалось собрать. Перечисли их,
       когда пользователь спрашивает, на чём основан вывод.

    4. services — расход обращений по каждой службе.
       requests — потрачено по ЭТОЙ организации.
       daily_spent — израсходовано по ключу за сутки по данным самой службы;
       счётчик ОБЩИЙ на ключ и включает обращения по другим организациям.
       НЕ выдавай daily_spent за стоимость этой проверки.
       Остатка квоты здесь нет: службы сообщают только расход.

    session_requests — обращения с момента запуска сервера по всем
    организациям сразу. Для оценки стоимости одной проверки не годится.
    """
    parsed_inn, _ = _extract_inn_and_name(inn)
    clean_inn = (parsed_inn or inn).strip().replace(" ", "").replace("-", "")
    result = _build_coverage(clean_inn)
    log.info("tool_call", tool="check_coverage", inn=clean_inn,
             checked=result.checked, requests=result.total_requests)
    return result


@mcp.tool()
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
                'Объём отчёта: "full" (по умолчанию) — всё собранное, включая карточку, финансы с таблицей, '
                'налоги, лицензии, реестры, суды, СМИ, сбои и риски; '
                '"brief" — краткая выжимка (карточка + вердикт + ключевые риски)'
            ),
            examples=["brief", "full"],
        ),
    ] = "full",
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
    """Отчёт по организации, объём зависит от запроса пользователя.

    КОГДА ВЫЗЫВАТЬ: пользователь просит «проверь компанию», «расскажи
    про контрагента» — без уточнения, какую именно часть. Один вызов
    заменяет цепочку get_company_context → collect_risk_facts →
    get_verdict, экономя прогоны модели.

    ВЫБОР ОБЪЁМА — по словам пользователя:

    detail = "brief" — ПО УМОЛЧАНИЮ.
      Пользователь спросил кратко, вскользь, «в двух словах», «просто
      проверь», или вам нужен только вердикт.
      Возвращает: карточка (наименование, статус, деятельность, масштаб,
      руководитель), вердикт со светофором, warnings, ключевые риски и бизнес-показатели.

    detail = "full" — пользователь просил ПОДРОБНО.
      Ключевые слова: «подробно», «полностью», «максимально», «всё что
      есть», «детально», «глубокая проверка», «досье». Если пользователь
      дал хотя бы одно такое слово — берите full, НЕ brief.
      Возвращает всё из brief плюс: финансы по годам с динамикой,
      налоги и недоимку, лицензии, контакты, массовый адрес,
      существенные события истории (смены руководителя и учредителей),
      статусы всех источников, карантинные находки.

    КАК ОТВЕЧАТЬ:
      1. СВЕТОФОР И ПОЧЕМУ ТАКАЯ ОЦЕНКА:
         Начните с уровня риска и цветного маркера (поле «светофор»):
         🟢 Низкий риск / 🟡 Умеренный риск / 🟠 Высокий риск / ⛔ Критический риск.
         Сразу под оценкой в 1–2 предложениях объясните, ПОЧЕМУ выставлена именно такая оценка
         (основания из score.reasons и суть_оценки).
         ВАЖНО: НЕ раздавайте поучений и «рекомендаций руководителю» (сотрудничать или нет —
         решает сам пользователь). Задача агента — объективная оценка фактов и рисков.
         НЕ вываливайте пользователю абстрактные баллы (вроде «-26.5» или «42.0»).
      2. ССЫЛКИ-ПОДТВЕРЖДЕНИЯ (ПРУФЫ):
         В отчёте передаётся блок «ссылки». ОБЯЗАТЕЛЬНО вставляй компактные и аккуратные
         markdown-ссылки прямо в текст рядом с ключевыми тезисами и цифрами,
         чтобы пользователь мог кликнуть и проверить первоисточник.
         Примеры аккуратного оформления:
         - «Выручка за 2024 г. составила 544 млрд ₽ ([Отчётность ФНС ГИР БО](url))»
         - «Карточка организации в реестре: [ЕГРЮЛ Контур.Фокус](url)»
         - «В реестре отечественного ПО Минцифры: 30 программ ([Реестр Минцифры](url))»
         НЕ вставляй «голые» длинные URL — делай ссылки аккуратным текстом.
      3. СТРУКТУРА И ЛАКОНИЧНОСТЬ (БЕЗ ВОДЫ И БЕЗ ТЕХНИЧЕСКОГО МУСОРА):
         НЕ строй в конце отчёта повторные громоздкие таблицы «риск — рекомендация»,
         если всё уже сказано в разборе.
         Структура ответа:
         - Шапка: Оценка светофора (🟢/🟡/🟠/⛔) и почему она такая (ключевые причины).
         - Разбор фактов с компактными ссылками на первоисточники (Финансы, Суды, Реестры, OSINT).
         - Кадровый контур и коммерческий срез для менеджера.
         - РЕЖИМ ПОЛЬЗОВАТЕЛЯ (debug=false): СТРОГО ЗАПРЕЩЕНО писать отдельным абзацем
           «что не удалось проверить», технические сетевые ошибки, недоступность API или таймауты.
           Пользователю нужен чистый, лаконичный бизнес-анализ контрагента!
         - РЕЖИМ РАЗРАБОТЧИКА (debug=true): ТОЛЬКО если пользователь прямо просил отладку, логи,
           диагностику источников или если передан флаг debug=true — выведи блок
           «🛠️ Диагностика источников и API» с перечислением недоступных сервисов из поля
           «_диагностика_разработчика».
      4. Warnings доведите дословно ПРИ ЛЮБОЙ оценке.
      5. pending — только в full: покажите в блоке «не проверено,
         нашлось в открытом виде», не превращая в вывод.
      6. КОММЕРЧЕСКИЙ СРЕЗ ДЛЯ МЕНЕДЖЕРА (БЛОК «коммерческий_срез»):
         ОБЯЗАТЕЛЬНО включи в ответ раздел «🎯 Коммерческий срез для менеджера»:
         - Продуктовая линейка и формула бизнеса: что реально продают, кому, продукты в реестре ПО Минцифры или товарные знаки.
         - Точки боли и триггеры потребностей (Pains: дефицит кадров, смена ЛПР, инфраструктурный контраст, судебные споры).
         - Что можно предложить (2–3 прикладных B2B-оффера под их боли с указанием целевой роли ЛПР).
         - Готовый персонализированный заход (icebreaker) для первого звонка или письма.

    Оценку считает движок по scoring.yaml — пересказывайте, а не
    пересчитывайте.
    """
    import asyncio
    from osint_mcp.tools.query_guard import (
        extract_inn_and_name,
        check_query_inn_consistency,
        build_discrepancy_fact,
    )
    from osint_mcp.tools.hr_hub import detect_corporate_hr_hub

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

        fiasco_facts, hr_hub_info = await asyncio.gather(_fetch_fiascos(), _fetch_hr_hub())

    if context_result.context:
        risk.facts.extend(_extract_financial_risk_facts(context_result.context))

    score = _score_company(
        facts=risk.facts + _quarantine.confirmed_facts(clean_inn),
        context=context_result.context,
    )
    if fiasco_facts:
        for f in fiasco_facts:
            if f not in score.pending:
                score.pending.append(f)
    detail_norm = detail.strip().lower()
    if detail_norm not in ("brief", "full"):
        detail_norm = "brief"
    is_debug = debug or getattr(settings, "osint_debug", False)
    is_human = human_mode if human_mode is not None else getattr(settings, "human_friendly_mode", True)
    result = _build_report(detail_norm, context_result, risk, score, debug=is_debug, human_mode=is_human)

    # Прикрепляем расхождение запроса (если обнаружено)
    if query_discrepancy:
        result["расхождение_запроса"] = query_discrepancy

    # Прикрепляем кадровый хаб (если обнаружен)
    if hr_hub_info:
        result["кадровый_хаб_холдинга"] = hr_hub_info
        if "кадровый_потенциал_документы" in result:
            result["кадровый_потенциал_документы"]["кадровый_хаб_холдинга"] = hr_hub_info

    # Прикрепляем инциденты и публикации в СМИ с датами и пруфами
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
        if detail_norm == "full":
            result["инциденты_и_сми"] = incidents_list
        else:
            result["инциденты_и_сми"] = incidents_list[:2]

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
        from osint_mcp.tools.sales_intelligence import build_sales_intelligence as _build_sales_intel
        sales_intel = _build_sales_intel(
            context_result.context,
            risk=risk,
            fiascos=fiasco_facts,
            detail=detail_norm,
        )
        if sales_intel:
            if detail_norm == "full":
                result["коммерческий_срез"] = sales_intel
            else:
                result["коммерческий_срез"] = {
                    "формула_бизнеса": sales_intel.get("формула_бизнеса"),
                    "целевой_сегмент": sales_intel.get("целевой_сегмент"),
                    "крючок_для_контакта": sales_intel.get("крючок_для_контакта"),
                }

    # Добавляем кликабельные первоисточники для компактного цитирования агентом в markdown
    if context_result.context and context_result.context.source_links:
        result["ссылки"] = [l.model_dump() for l in context_result.context.source_links]
    log.info("tool_call", tool="get_company_report", inn=clean_inn,
             detail=detail_norm, verdict=score.verdict.label,
             fiascos=len(fiasco_facts))
    return result


@mcp.tool()
async def generate_full_dossier(
    inn: Annotated[
        str,
        Field(
            description="ИНН организации (10 или 12 цифр)",
            examples=["7724744134"],
        ),
    ],
    detail: Annotated[
        str,
        Field(
            description=(
                'Объём досье: "full" (по умолчанию) — полное детальное досье (карточка, финансы, суды, СМИ, сбои, риски), '
                '"brief" — краткая выжимка со светофором и ключевыми риск-факторами'
            ),
            examples=["brief", "full"],
        ),
    ] = "full",
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
    """Единый фасад для мгновенного сбора полного OSINT-досье на контрагента за 1 вызов.

    Объединяет в один параллельный прогон:
    - Официальные реестры (ЕГРЮЛ, ФНС, ГИР БО, Реестр МСП, Минцифры)
    - Арбитраж, исполнительные производства ФССП, проверки и реестровые метки
    - Кадровый контур и наём (HeadHunter)
    - Инфраструктуру (WHOIS, DNS, SSL, технологии сайта)
    - Глубокий OSINT-поиск инцидентов, ЧП, уголовных дел, сбоев и споров с подрядчиками
      (РБК, Коммерсантъ, Ведомости, VC.ru, Хабр, Пикабу, чёрные списки)
    - Расчёт детерминированного вердикта риска со светофором (🟢/🟡/🟠/⛔).
    - Query Guard: выявление расхождения запрошенного названия и данных реестра по ИНН.
    - Corporate HR Hub: детекция централизованного хаба найма холдинга при 0 вакансий на основном юрлице.
    """
    return await get_company_report(
        inn=inn,
        detail=detail,
        include_reputation=True,
        expected_name=expected_name,
        debug=debug,
        human_mode=human_mode,
    )


@mcp.tool()
async def get_company_links(
    inn: Annotated[
        str,
        Field(
            description="Подтверждённый ИНН организации, 10 или 12 цифр",
            examples=["7724744134"],
        ),
    ],
) -> dict:
    """Прямые ссылки на первоисточники по проверенной организации.

    КОГДА ВЫЗЫВАТЬ: только по дозапросу пользователя — «откуда цифры»,
    «дай ссылки», «докажи», «хочу проверить сам». В отчётах ссылок нет
    намеренно: объём отчёта — выводы, а не библиография. Не показывай
    этот блок, пока пользователь не попросил подтверждение.

    ЧТО ВОЗВРАЩАЕТ: список ссылок — что можно проверить по каждой:
    карточка ЕГРЮЛ, PDF бухгалтерской отчётности ФНС по годам, запись
    в реестре МСП. Каждая ссылка — первоисточник, а не агрегатор.

    КАК ОТВЕЧАТЬ: списком «что — ссылка», группируя отчётности по годам.
    Ссылка на отчётность ФНС — способ проверить любую цифру финансов;
    если пользователь сомневается в конкретной цифре, дай ссылку именно
    на её год.

    Затраты квоты: прогон такой же, как у отчёта. Если отчёт по этой
    организации уже показан, предупреждай пользователя о доценке —
    сервер не кэширует между вызовами.
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
    """Пакетная проверка: несколько ИНН одним вызовом, кратко по каждому.

    КОГДА ВЫЗЫВАТЬ: пользователь дал список компаний и просит проверить
    их все. НЕ вызывайте его по одному ИНН — это тот же расход квоты,
    но с лишними прогонами модели.

    ЧТО ВОЗВРАЩАЕТ: по каждой организации краткая строка — вердикт,
    наименование, статус, главные риски. Подробности по конкретной
    компании — последующим вызовом инструмента подробного отчёта
    с нужным detail; сервер не кэширует между вызовами, поэтому
    повторный прогон по той же компании снова расходует квоту.

    ОГРАНИЧЕНИЯ:
      * Максимум 20 ИНН за вызов — больше список не примет.
      * Расход квоты линейный: примерно 12 обращений на организацию.
        Двадцать компаний — около 240 обращений; на бесплатном тарифе
        это исчерпает сутки. Предупредите пользователя О ДОЦЕНКЕ квоты
        до вызова, если список большой.
      * ИНН с ошибкой контрольной суммы не отбраковываются заранее:
        по ним вернётся результат со статусом skipped.

    КАК ОТВЕЧАТЬ: таблицей или списком в порядке входного списка.
    Вердикт + одна строка сути. Warnings из строк не выбрасывайте.
    Поле «что_не_собралось» означает неполноту — не выдавайте её
    за «чисто».
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


@mcp.tool()
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
    """Итоговая оценка организации: вердикт + баллы + причины со ссылками.

    ПОРЯДОК РАБОТЫ:
      1. resolve_company     — определить организацию
      2. get_company_context — собрать карточку
      3. collect_risk_facts  — проверить риски
      4. get_verdict         — получить оценку            <-- ты здесь

    Оценку СЧИТАЕТ ДВИЖОК по критериям из scoring.yaml — она
    детерминирована и воспроизводима. Твоя задача — ПЕРЕСКАЗАТЬ её
    пользователю, а не пересчитывать и не оспаривать.

    КАК ОТВЕЧАТЬ — ответ строится ДВУМЯ СЛОЯМИ, оба обязательны:

      СЛОЙ 1. Начни ответ заголовком «КРАТКИЙ ИТОГ» и двумя-тремя
        строками:
        - Оценка и цветовой маркер: 🟢 Низкий риск / 🟡 Умеренный риск / 🟠 Высокий риск / ⛔ Критический риск.
        - Почему выставлена такая оценка: 1–2 предложения с ключевой причиной (без поучений руководителя/менеджера, только объективные факты).
        - ВАЖНО: НЕ перегружайте пользователя сырыми баллами (вроде «-26.5» или «74.5»),
          если он прямо об этом не просил. Используйте интуитивно понятные светофорные эмодзи (🟢/🟡/🟠/⛔)
          и формулировку риска.

      СЛОЙ 2. ЗАГОЛОВКОМ «ПОЛНЫЙ РАЗБОР» сразу после итога — НЕ пропускай:
        1. matched — по каждому сработавшему критерию: суть, что произошло,
           причина и ссылка из source_urls; тезисы подкрепляй fact_ids —
           вердикт без доказательств не имеет силы.
        2. groups — какие сферы (суды, финансы, реестры, персоналии) дали основной риск.
        3. Если reasons непустой — перескажи каждый элемент: это
           обязательная краткая причина, не опускай.
        4. Warnings — СВЯТОЕ. Каждый элемент warnings обязан быть доведён
           до пользователя ДОСЛОВНО, при ЛЮБОЙ оценке — включая
           «надёжный». Положительный вердикт не отменяет тяжёлого факта:
           если пользователь узнает о долгах ФССП после подписания
           договора, это провал проверки, а не «не критично».
        5. pending — находки из нереестровых источников (карантин). Они НЕ
           влияют на вердикт, но пользователь должен их увидеть: покажи
           каждый с обязательной ссылкой (pending[].source_url) в блоке
           «не проверено, нашлось в открытом виде». Не подтверждай находку
           сам и не превращай её в вывод — предложи проверить человеку.
        6. Что проверить НЕ удалось: направления со статусом
           unavailable/partial и unmatched_fact_kinds — отсутствие данных
           не доказывает отсутствие рисков, скажи это прямо.

      НЕ придумывай баллы и не складывай свои: total_score уже готов.

    verdict.floored = true — балл выглядел лучше, но жёсткий пол
    (поле verdict в ScoreResult: floor_criterion, напр. банкротство)
    урезал вердикт. Объясни это пользователю: «несмотря на X, оценка
    не может быть выше Y из-за Z».
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
            scored_at=datetime.now(timezone.utc),
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
    """Найти упоминания в открытом вебе → всё в карантин, вердикт НЕ трогает.

    КОГДА ВЫЗЫВАТЬ: пользователь просит проверить компании по открытому
    вебу, по критериям, которых нет в госреестрах (репутация, упоминания,
    связи с чем-либо).

    ГАРАНТИИ:
      1. Каждая находка С ОБЯЗАТЕЛЬНОЙ ссылкой (hits[].source_url) — данные не из
         реестра без ссылки не существуют.
      2. Находки НЕ ВЛИЯЮТ на get_verdict: они лежат в карантине.
      3. В вердикт находка попадает ТОЛЬКО после review_pending
         (подтверждение человеком).

    КАК ОТВЕЧАТЬ: покажи каждую находку со ссылкой в блоке «не проверено,
    нашлось в открытом виде». НЕ утверждай, что связь реальна: находка —
    это совпадение слов в поиске, а не установленный факт.

    ПРОВЕРЕННЫЕ ЗАПРОСЫ для контрагентов (используй как шаблон):
      * отзывы сотрудников: «<название> отзывы сотрудников» — жалобы на
        задержки зарплаты — предвестник кассовых проблем за 6–12 месяцев
        до реестровых признаков;
      * «<название> задержка зарплаты» — точечная проверка долгов по оплате
        труда.
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
        note=(
            "Находки в карантине: вердикт не изменился. Покажи каждую со "
            "ссылкой в блоке «не проверено». Подтверждение — review_pending"
        ),
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
    """Карантин: показать / подтвердить с оценкой / отклонить находку.

    ПОРЯДОК:
      1. action=list — покажи карантин пользователя со ссылками.
      2. Оцени сам: насколько находка влияет на решение о сотрудничестве,
         и выставь weight. Ты ПОДСКАЗЫВАЕШЬ оценку, а не выносишь вердикт.
      3. Обязательное условие: пользователь должен видеть ссылку на
         находку рядом с твоей оценкой — он составит мнение сам и может
         с тобой не согласиться.
      4. action=reject — находка мусор (другая компания, омоним, реклама).
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
                "note": "Это ПОДСКАЗКА. Обязательно покажи пользователю "
                        "оценку вместе с ссылкой на находку — он составит "
                        "мнение сам и может не согласиться",
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

    КОГДА ВЫЗЫВАТЬ:
    ТОЛЬКО и ИСКЛЮЧИТЕЛЬНО тогда, когда пользователь ЯВНО и ПРЯМО спрашивает
    о лимитах, квотах, балансе обращений или остатке запросов к сервисам
    (например: «сколько запросов осталось?», «какие лимиты у провайдеров?»,
    «проверь квоту DaData/Checko», «хватит ли лимитов на сегодня?»,
    «какой остаток обращений?»).

    КОГДА НЕ ВЫЗЫВАТЬ:
    НИКОГДА не вызывай этот инструмент автоматически в ходе обычной проверки
    организации, сборе рисков, построении досье или обычном диалоге о компании.
    Для отчёта о расходе запросов по конкретной проверенной организации
    используй check_coverage. Этот инструмент — сугубо для прямых
    административных вопросов пользователя о лимитах и квотах API.

    ЧТО ВОЗВРАЩАЕТ:
    - summary: агрегированные цифры — суммарная суточная ёмкость обращений,
      число активных ключей, расчётный запас полных проверок компаний на сегодня,
      израсходовано в сессии и узкое место (bottleneck);
    - providers: детализированный список по каждому из 15 сервисов:
        * Коммерческие (Checko, DaData, HeadHunter, api-cloud): размер пула ключей,
          активные ключи, суточный лимит, расчётный остаток запросов и запас компаний;
        * Государственные реестры (ГИР БО, ЕГРЮЛ, МСП, Федресурс, Росаккредитация,
          Реестр ПО Минцифры, Таможня): статус "unlimited" и расход за сессию;
        * OSINT веб-разведка (СМИ/инциденты, гео-отзывы, инфраструктура/WHOIS/SSL): статус "unlimited";
    - alerts: критические предупреждения об исчерпании ключей или окончании квоты.
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


@mcp.tool()
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
    """Анализ цифровой инфраструктуры и связей через веб-аналитику (Яндекс.Метрика, Google Analytics, VK/Mail.ru).

    КАК ЭТО РАБОТАЕТ В OSINT:
    На сайте компании извлекаются уникальные идентификаторы счетчиков (например, ym:98765432, G-ABC12345).
    Затем производится обратный поиск страниц и доменов в сети, на которых установлены точно такие же идентификаторы.

    КАК АГЕНТУ ИНТЕРПРЕТИРОВАТЬ РЕЗУЛЬТАТЫ ДЛЯ ПОЛЬЗОВАТЕЛЯ:
    1. СКРЫТЫЙ ХОЛДИНГ / СИСТЕР-КОМПАНИИ (1-10 связанных сайтов):
       - Если малое/новое ООО (например, с выручкой 0 руб. или недавно созданное) делит счетчик Метрики
         с известным крупным брендом, порталом застройщика или федеральным интернет-магазином —
         ЭТО ПРИЗНАК СКРЫТОГО ХОЛДИНГА / ДОЧЕРНЕЙ СТРУКТУРЫ.
       - Вывод для B2B/рисков: компания не "пустышка", за ней стоят реальные активы, бюджеты и разработчики материнской группы.
    2. ВЕБ-СТУДИЯ / ЛОЖНОЕ СРАБАТЫВАНИЕ (более 15 связанных сайтов):
       - Если один и тот же счетчик висит на 20+ совершенно разных не связанных по смыслу сайтах (стоматология, шиномонтаж, доставка пиццы),
         это НЕ холдинг, а общая служебная метрика ленивой веб-студии или разработчика темы/шаблона.
       - Агент обязан указать: "Признаков холдинга нет, это общий идентификатор веб-студии".
    3. АВТОМАТИЧЕСКИЙ КАРАНТИН:
       - Достоверные связанные домены помещаются в карантин (quarantine) как PendingFact вида 'affiliate_domain_signal',
         позволяя учесть цифровую сеть в итоговом скоринге после подтверждения.
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

    # Инспектируем сайт и извлекаем идентификаторы счетчиков
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
        "guidance_for_analyst": (
            "Если обнаружены родственные домены (is_probable_holding=True), "
            "проанализируйте их: схожа ли тематика или бренд. "
            "Связанные домены указывают на общих бенефициаров, параллельные проекты или материнский холдинг."
        ),
    }


@mcp.tool()
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

    КАК ЭТО РАБОТАЕТ В OSINT:
    Проверяются таможенные декларации (ГТД), базы ФТС и агрегаторы поставок (ImportGenius, Statimex) по ИНН.

    КАК АГЕНТУ ИНТЕРПРЕТИРОВАТЬ РЕЗУЛЬТАТЫ ДЛЯ ПОЛЬЗОВАТЕЛЯ:
    1. САНКЦИОННЫЕ РИСКИ И ЗАВИСИМОСТЬ:
       - Если компания импортирует сырье, микроэлектронику или запчасти из ЕС, США или недружественных стран —
         у нее высокий риск срыва логистики, блокировки платежей через банки и угроза вторичных санкций.
       - Триггер для предложения: параллельный импорт, альтернативные цепочки (Китай, Турция, СНГ) или защита ВЭД.
    2. РЕАЛЬНЫЙ ТОВАРООБОРОТ VS "БУМАЖНЫЙ БАЛАНС":
       - Баланс в ФНС можно искусственно завысить, но таможенную стоимость и ГТД подделать крайне сложно.
       - Наличие таможенного оформления подтверждает реальную физическую деятельность компании.
    3. СМЕНА ПОСТАВЩИКА / РАЗРЫВ ЦЕПОЧКИ:
       - Если компания внезапно прекратила возить от постоянного китайского или европейского завода,
         это сигнал кризиса отношений с поставщиком или проблем с расчетами.
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
        "guidance_for_analyst": (
            "Оцените страны происхождения: наличие импорта из ЕС/США несет валютные и логистические риски. "
            "Используйте подтвержденные поставки как доказательство реального физического бизнеса."
        ),
    }


@mcp.tool()
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

    КАК ЭТО РАБОТАЕТ В OSINT:
    Сопоставляется юридический адрес из ЕГРЮЛ с реальными гео-объектами на картах,
    а также анализируется семантика свежих пользовательских отзывов.

    КАК АГЕНТУ ИНТЕРПРЕТИРОВАТЬ РЕЗУЛЬТАТЫ ДЛЯ ПОЛЬЗОВАТЕЛЯ:
    1. ФИЗИЧЕСКАЯ РЕАЛЬНОСТЬ (ОТЛИЧИЕ ОТ "БУМАЖНОГО" ЮРЛИЦА):
       - Если компания заявляет выручку в миллиард рублей, но по адресу регистрации на картах
         находится гаражный кооператив (ГСК), пустырь, трансформаторная будка или жилой барак —
         это жесткий маркер "прачечной" / технической фирмы.
       - Наличие реального офисного центра, склада или производственного цеха подтверждает состоятельность.
    2. ОПЕРАЦИОННЫЕ И КАССОВЫЕ СБОИ:
       - Не смотрите только на средний балл (4.3). Анализируйте свежие отзывы за последний месяц:
         жалобы "хамят", "не берут трубку", "сорвали срок поставки на 3 недели", "грязно" —
         прямой сигнал кассового разрыва, увольнения ключевого персонала или сбоя логистики.
       - Триггер для предложения: внедрение CRM, контроль качества, автоматизация логистики, обучение персонала.
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
        "guidance_for_analyst": (
            "Если обнаружен сомнительный физический адрес (гараж/пустырь при миллиардных оборотах), "
            "немедленно предупредите пользователя о риске фиктивной компании. "
            "При операционных сбоях в отзывах используйте это как коммерческий триггер для аудита и автоматизации."
        ),
    }


@mcp.tool()
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
        "guidance_for_sales_and_analyst": (
            "ПРАВИЛО ФОРМИРОВАНИЯ ОТЧЁТА ДЛЯ АГЕНТА: "
            "1. Если facts_found == 0 (инцидентов не обнаружено), ПОЛНОСТЬЮ ОПУСТИТЕ этот раздел из отчёта. "
            "Не пишите фраз в стиле 'проверено на платформах, но ничего не найдено'. "
            "2. Если факты найдены (facts_found > 0) — выведите раздел с конкретными реальными инцидентами. "
            "3. ОБЯЗАТЕЛЬНО указывайте дату каждого события/публикации (поле 'date' или дата из цитаты, например, '08.10.2026' или 'март 2022'). "
            "Срок давности событий критически важен для пользователя."
        ),
    }


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
