"""Проверка суточных квот, лимитов и состояния ключей внешних провайдеров.

Предоставляет единый сводный отчёт о доступности всех источников системы:
- Коммерческие справочники с пулами ключей (Checko, DaData, api-cloud.ru, HeadHunter);
- Государственные открытые реестры (ГИР БО, ЕГРЮЛ, МСП, Федресурс, ФСА, Реестр ПО Минцифры, Таможня);
- OSINT веб-разведка (СМИ и инциденты, гео-отзывы, сетевая инфраструктура сайтов).
"""

from datetime import UTC, datetime

import structlog

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.context.dadata import DaDataSource
from osint_mcp.keys import checko as checko_pool
from osint_mcp.keys import dadata as dadata_pool
from osint_mcp.models import (
    KeyStatus,
    ProviderLimit,
    ProvidersLimitsReport,
    ServiceQuota,
)

log = structlog.get_logger()


async def check_all_limits(dadata_source: DaDataSource | None = None) -> ProvidersLimitsReport:
    """Собрать детальную информацию о лимитах, квотах, ключах и запасе проверок всех провайдеров."""
    source = dadata_source or DaDataSource()
    providers: list[ProviderLimit] = []
    alerts: list[str] = []

    session = ledger.session_totals()
    daily_seen = ledger.daily_totals()

    # ── 1. Checko ──────────────────────────────────────────────────────────
    checko_keys_status = [
        KeyStatus(key=k["key"], state=k["state"]) for k in checko_pool.status()
    ]
    checko_active = sum(1 for k in checko_keys_status if k.state == "ok")
    checko_total = len(checko_keys_status)
    checko_daily_spent = daily_seen.get("checko")
    checko_session_spent = session.get("checko", 0)
    checko_limit_per_key = 100  # Базовый суточный лимит бесплатного ключа Checko
    checko_pool_capacity = checko_total * checko_limit_per_key
    checko_cost_per_company = 10  # В среднем 8-12 запросов на полный срез (карточка, суды, проверки, связи, финансы)

    spent_for_checko = checko_daily_spent if checko_daily_spent is not None else checko_session_spent
    checko_remaining_reqs = max(0, (checko_active * checko_limit_per_key) - (spent_for_checko or 0)) if checko_active > 0 else 0
    checko_companies_remaining = checko_remaining_reqs // checko_cost_per_company if checko_cost_per_company > 0 else 0

    checko_status = "ok"
    if not checko_pool.has_keys():
        checko_status = "not_configured"
        alerts.append("Checko: ключи не заданы в .env (CHECKO_API_KEY / CHECKO_API_KEYS).")
    elif checko_active == 0:
        checko_status = "exhausted"
        alerts.append("Checko: все ключи в пуле исчерпаны (ответили 401/403/429).")
    elif checko_active < checko_total:
        checko_status = "warning"
        alerts.append(f"Checko: часть ключей пула исчерпана ({checko_total - checko_active} из {checko_total}).")

    providers.append(
        ProviderLimit(
            provider="checko",
            name="Checko (риск-факторы, арбитраж, приставы, проверки, связи, отчётность)",
            status=checko_status,
            category="commercial",
            keys_total=checko_total,
            keys_active=checko_active,
            keys=checko_keys_status,
            daily_limit_per_key=checko_limit_per_key,
            pool_daily_capacity=checko_pool_capacity,
            daily_spent=checko_daily_spent,
            session_spent=checko_session_spent,
            estimated_remaining_requests=checko_remaining_reqs,
            cost_per_company_requests=checko_cost_per_company,
            estimated_companies_remaining=checko_companies_remaining,
            notes=(
                f"Базовый тариф бесплатного ключа Checko — {checko_limit_per_key} запросов/сутки. "
                f"Пул из {checko_total} ключей обеспечивает суммарно {checko_pool_capacity} запросов в день "
                f"(расчётный запас: ~{checko_companies_remaining} полных проверок контрагентов)."
            ),
        )
    )

    # ── 2. DaData ──────────────────────────────────────────────────────────
    dadata_keys_status = [
        KeyStatus(key=k["key"], state=k["state"]) for k in dadata_pool.status()
    ]
    dadata_active = sum(1 for k in dadata_keys_status if k.state == "ok")
    dadata_total = len(dadata_keys_status)
    dadata_limit_per_key = 10000  # Стандартный суточный лимит базового тарифа DaData
    dadata_pool_capacity = dadata_total * dadata_limit_per_key
    dadata_session_spent = session.get("dadata", 0)
    dadata_cost_per_company = 4  # findById/party, suggest/party, okved2, findById/brand

    methods: dict[str, ServiceQuota] = {}
    dadata_error = None
    dadata_status = "ok"
    dadata_remaining_reqs = max(0, (dadata_active * dadata_limit_per_key) - dadata_session_spent) if dadata_active > 0 else 0

    if not dadata_pool.has_keys():
        dadata_status = "not_configured"
        dadata_remaining_reqs = 0
        alerts.append("DaData: ключи не заданы в конфигурации (.env).")
    elif dadata_active == 0:
        dadata_status = "exhausted"
        dadata_remaining_reqs = 0
        alerts.append("DaData: все ключи в пуле исчерпаны (вернули 401/403/429).")
    elif not settings.dadata_secret_key:
        dadata_status = "ok"
        dadata_error = (
            "API-ключ активен. Для получения точной разбивки остатка по эндпоинтам нужен DADATA_SECRET_KEY в .env. "
            f"Стандартный лимит бесплатного тарифа — {dadata_limit_per_key} подсказок в сутки."
        )
    else:
        try:
            quota = await source.get_quota()
            for method_name, q in quota.items():
                used = q.get("used", 0)
                remaining = q.get("remaining", 0)
                methods[method_name] = ServiceQuota(used=used, remaining=remaining)
                if 0 < remaining <= 10:
                    alerts.append(
                        f"DaData ({method_name}): критически мало запросов (осталось {remaining})."
                    )
                elif remaining == 0 and used > 0:
                    alerts.append(f"DaData ({method_name}): суточная квота полностью исчерпана.")
            if methods:
                dadata_remaining_reqs = min(q.remaining for q in methods.values())
        except Exception as e:  # noqa: BLE001
            dadata_error = f"Не удалось запросить статистику: {type(e).__name__}: {e}"
            dadata_status = "warning"
            log.warning("dadata_quota_check_failed", error=str(e))

    dadata_companies_remaining = dadata_remaining_reqs // dadata_cost_per_company if dadata_cost_per_company > 0 else 0

    providers.append(
        ProviderLimit(
            provider="dadata",
            name="DaData (реестровые данные, поиск организаций, бренд, коды ОКВЭД)",
            status=dadata_status,
            category="commercial",
            keys_total=dadata_total,
            keys_active=dadata_active,
            keys=dadata_keys_status,
            daily_limit_per_key=dadata_limit_per_key,
            pool_daily_capacity=dadata_pool_capacity,
            daily_spent=daily_seen.get("dadata"),
            session_spent=dadata_session_spent,
            estimated_remaining_requests=dadata_remaining_reqs,
            cost_per_company_requests=dadata_cost_per_company,
            estimated_companies_remaining=dadata_companies_remaining,
            methods=methods,
            notes=(
                f"Суточный лимит базового тарифа — {dadata_limit_per_key} подсказок на ключ. "
                f"Суммарная ёмкость пула: {dadata_pool_capacity} запросов/сутки (~{dadata_companies_remaining} проверок)."
            ),
            error=dadata_error,
        )
    )

    # ── 3. HeadHunter ──────────────────────────────────────────────────────
    has_hh = bool(settings.hh_app_token)
    hh_session_spent = session.get("hh", 0)
    hh_daily_limit = 5000  # Стандартная квота приложения dev.hh.ru
    hh_remaining = max(0, hh_daily_limit - hh_session_spent) if has_hh else 0
    hh_cost_per_company = 2
    hh_companies_remaining = hh_remaining // hh_cost_per_company if has_hh else 0

    providers.append(
        ProviderLimit(
            provider="hh",
            name="HeadHunter (поиск вакансий, кадровый профиль, холдинговые HR-хабы)",
            status="ok" if has_hh else "not_configured",
            category="commercial",
            keys_total=1 if has_hh else 0,
            keys_active=1 if has_hh else 0,
            daily_limit_per_key=hh_daily_limit if has_hh else None,
            pool_daily_capacity=hh_daily_limit if has_hh else 0,
            session_spent=hh_session_spent,
            estimated_remaining_requests=hh_remaining,
            cost_per_company_requests=hh_cost_per_company,
            estimated_companies_remaining=hh_companies_remaining,
            notes=(
                f"Токен приложения dev.hh.ru активен. Суточный лимит: {hh_daily_limit} запросов "
                f"(расчётный запас: ~{hh_companies_remaining} проверок кадрового контура)."
                if has_hh
                else "Токен HH_APP_TOKEN не задан: при прямом запросе вакансий API отвечает 403."
            ),
        )
    )

    # ── 4. api-cloud.ru (резервный агрегатор) ──────────────────────────────
    has_apicloud = bool(settings.apicloud_key)
    apicloud_session_spent = session.get("apicloud", 0)
    apicloud_monthly_limit = 200
    apicloud_remaining = max(0, apicloud_monthly_limit - apicloud_session_spent) if has_apicloud else 0
    apicloud_cost = 3
    apicloud_companies = apicloud_remaining // apicloud_cost if has_apicloud else 0

    providers.append(
        ProviderLimit(
            provider="apicloud",
            name="api-cloud.ru (резервный агрегатор ФССП, арбитража, банкротств)",
            status="ok" if has_apicloud else "not_configured",
            category="aggregator",
            keys_total=1 if has_apicloud else 0,
            keys_active=1 if has_apicloud else 0,
            daily_limit_per_key=None,
            pool_daily_capacity=apicloud_monthly_limit if has_apicloud else 0,
            session_spent=apicloud_session_spent,
            estimated_remaining_requests=apicloud_remaining,
            cost_per_company_requests=apicloud_cost,
            estimated_companies_remaining=apicloud_companies,
            notes=(
                f"Резервный эшелон: опрашивается только при сбое прямого канала. Бесплатный лимит: {apicloud_monthly_limit} запр./мес."
                if has_apicloud
                else "Ключ APICLOUD_KEY не задан. Резервный эшелон отключён (не критично при работающем Checko)."
            ),
        )
    )

    # ── 5. Официальные государственные реестры (безлимитные) ───────────────
    # 5.1 ГИР БО
    bo_session = session.get("bo_nalog", 0)
    providers.append(
        ProviderLimit(
            provider="bo_nalog",
            name="ФНС ГИР БО (бухгалтерская отчётность всех лет, балансы, ГИР БО PDF)",
            status="unlimited",
            category="official_registry",
            session_spent=bo_session,
            cost_per_company_requests=2,
            notes="Государственный информационный ресурс бухгалтерской отчетности (bo.nalog.gov.ru). Открытый доступ без ключей и квот.",
        )
    )

    # 5.2 ЕГРЮЛ
    egrul_session = session.get("egrul", 0)
    providers.append(
        ProviderLimit(
            provider="egrul",
            name="ФНС ЕГРЮЛ (официальные регистрационные данные, учредители, руководство)",
            status="unlimited",
            category="official_registry",
            session_spent=egrul_session,
            cost_per_company_requests=1,
            notes="Официальный сервис выписок ЕГРЮЛ ФНС России (egrul.nalog.ru). Безлимитный открытый доступ без ключей.",
        )
    )

    # 5.3 Реестр МСП
    rmsp_session = session.get("rmsp", 0)
    providers.append(
        ProviderLimit(
            provider="rmsp",
            name="Реестр субъектов МСП (категория масштаба бизнеса и численность)",
            status="unlimited",
            category="official_registry",
            session_spent=rmsp_session,
            cost_per_company_requests=1,
            notes="Единый реестр субъектов малого и среднего предпринимательства ФНС (rmsp.nalog.ru). Безлимитный доступ.",
        )
    )

    # 5.4 Федресурс
    fedresurs_session = session.get("fedresurs", 0)
    providers.append(
        ProviderLimit(
            provider="fedresurs",
            name="Федресурс (лизинг, залоги движимого имущества, факторинг, банкротства, СРО)",
            status="unlimited",
            category="official_registry",
            session_spent=fedresurs_session,
            cost_per_company_requests=2,
            notes="Единый федеральный реестр юридически значимых сведений (fedresurs.ru). Открытый REST API без ограничений.",
        )
    )

    # 5.5 Росаккредитация
    fsa_session = session.get("fsa", 0)
    providers.append(
        ProviderLimit(
            provider="fsa",
            name="ФГИС Росаккредитация (сертификаты и декларации соответствия на продукцию)",
            status="unlimited",
            category="official_registry",
            session_spent=fsa_session,
            cost_per_company_requests=1,
            notes="Федеральная государственная информационная система Росаккредитации (pub.fsa.gov.ru). Безлимитный государственный реестр.",
        )
    )

    # 5.6 Реестр ПО Минцифры
    sw_session = session.get("software_registry", 0)
    providers.append(
        ProviderLimit(
            provider="software_registry",
            name="Реестр отечественного ПО Минцифры (реестровые продукты и решения)",
            status="unlimited",
            category="official_registry",
            session_spent=sw_session,
            cost_per_company_requests=1,
            notes="Единый реестр российских программ для ЭВМ и БД (reestr.digital.gov.ru / proreestr.ru). Безлимитный доступ.",
        )
    )

    # 5.7 Таможня ВЭД
    customs_session = session.get("customs", 0)
    providers.append(
        ProviderLimit(
            provider="customs",
            name="Таможенная статистика ВЭД (декларации импорта/экспорта и зарубежные поставщики)",
            status="unlimited",
            category="official_registry",
            session_spent=customs_session,
            cost_per_company_requests=1,
            notes="Таможенная статистика ФТС и декларации ВЭД. Безлимитный доступ.",
        )
    )

    # ── 6. OSINT веб-разведка и мониторинг ──────────────────────────────────
    # 6.1 Гео-отзывы
    geo_session = session.get("geo_reviews", 0)
    providers.append(
        ProviderLimit(
            provider="geo_reviews",
            name="Гео-сервисы и отзывы (Яндекс.Карты, 2ГИС, Zoon, Отзовик)",
            status="unlimited",
            category="osint_web",
            session_spent=geo_session,
            cost_per_company_requests=2,
            notes="Публичные картографические сервисы и платформы отзывов. Безлимитный открытый веб-сбор.",
        )
    )

    # 6.2 OSINT СМИ и факапы
    fiascos_session = session.get("web_search", 0) + session.get("reputation_fiascos", 0)
    providers.append(
        ProviderLimit(
            provider="reputation_fiascos",
            name="OSINT СМИ и медиа-инциденты (РБК, Ведомости, Коммерсантъ, VC, Хабр, Пикабу)",
            status="unlimited",
            category="osint_web",
            session_spent=fiascos_session,
            cost_per_company_requests=6,
            notes="Глубокий мониторинг негатива, уголовных дел, аварий и споров с подрядчиками через открытые поисковые движки (DuckDuckGo Lite). Безлимитно.",
        )
    )

    # 6.3 Инфраструктура сайта
    site_session = session.get("site", 0)
    providers.append(
        ProviderLimit(
            provider="site_infrastructure",
            name="Сетевая инфраструктура (WHOIS, DNS, SSL-сертификаты, веб-технологии сайта)",
            status="unlimited",
            category="osint_web",
            session_spent=site_session,
            cost_per_company_requests=3,
            notes="Прямой опрос DNS, WHOIS и TLS-сокетов целевых доменов организации. Безлимитно.",
        )
    )

    # ── 7. Сводный эшелон (для обратной совместимости) ─────────────────────
    reg_session_total = (
        bo_session + egrul_session + rmsp_session + fedresurs_session + fsa_session + sw_session + customs_session
    )
    providers.append(
        ProviderLimit(
            provider="open_registries",
            name="Государственные реестры (ГИР БО, Реестр МСП, ЕГРЮЛ, Федресурс, Росаккредитация, Реестр ПО Минцифры)",
            status="unlimited",
            category="official_registry",
            session_spent=reg_session_total,
            notes="7 официальных государственных реестров: не требуют API-ключей и не имеют суточных квот на обращения.",
        )
    )

    # ── Сводная статистика (Summary) ───────────────────────────────────────
    total_active_keys = (
        checko_active + dadata_active + (1 if has_hh else 0) + (1 if has_apicloud else 0)
    )
    total_daily_capacity = checko_pool_capacity + dadata_pool_capacity + (hh_daily_limit if has_hh else 0)

    # Расчётный лимит компаний определяется узким местом платных реестров (Checko)
    bottleneck_service = "Checko API" if checko_total > 0 else "DaData API"
    companies_capacity = checko_companies_remaining if checko_total > 0 else dadata_companies_remaining

    summary = {
        "всего_провайдеров": len(providers),
        "активных_ключей_всего": total_active_keys,
        "суммарная_суточная_емкость_запросов": total_daily_capacity,
        "расчетный_остаток_запросов_коммерческих_апи": checko_remaining_reqs + dadata_remaining_reqs + hh_remaining,
        "расчетный_запас_полных_проверок_компаний": companies_capacity,
        "узкое_горлышко_квоты": bottleneck_service,
        "израсходовано_запросов_за_сессию": sum(session.values()),
        "проверено_компаний_за_сессию": len(ledger._calls),
        "эшелоны": {
            "коммерческие_справочники": 4,
            "государственные_реестры": 7,
            "osint_веб_разведка": 3,
        },
    }

    return ProvidersLimitsReport(
        summary=summary,
        providers=providers,
        alerts=alerts,
        checked_at=datetime.now(UTC),
    )
