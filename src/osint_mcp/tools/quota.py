"""Проверка суточных квот, лимитов и состояния ключей внешних провайдеров.

Предоставляет единый сводный отчёт о доступности всех источников:
- DaData: актуальные остатки суточной квоты по каждому эндпоинту;
- Checko: состав пула ключей и суточный расход;
- Резервные агрегаторы (api-cloud.ru) и HeadHunter;
- Официальные открытые реестры (безлимитные).
"""

from datetime import datetime, timezone

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
    """Собрать информацию о лимитах, квотах и ключах всех провайдеров системы."""
    source = dadata_source or DaDataSource()
    providers: list[ProviderLimit] = []
    alerts: list[str] = []

    # ── 1. DaData ──────────────────────────────────────────────────────────
    dadata_keys_status = [
        KeyStatus(key=k["key"], state=k["state"]) for k in dadata_pool.status()
    ]
    dadata_active = sum(1 for k in dadata_keys_status if k.state == "ok")
    dadata_total = len(dadata_keys_status)

    methods: dict[str, ServiceQuota] = {}
    dadata_error = None
    dadata_status = "ok"

    if not dadata_pool.has_keys():
        dadata_status = "not_configured"
        alerts.append("DaData: ключи не заданы в конфигурации (.env).")
    elif dadata_active == 0:
        dadata_status = "exhausted"
        alerts.append("DaData: все ключи в пуле исчерпаны (вернули 401/403/429).")
    elif not settings.dadata_secret_key:
        dadata_status = "ok"
        dadata_error = (
            "API-ключ активен. Для получения точной разбивки остатка по эндпоинтам нужен DADATA_SECRET_KEY в .env. "
            "Стандартный лимит бесплатного тарифа — 10 000 подсказок в сутки."
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
        except Exception as e:  # noqa: BLE001
            dadata_error = f"Не удалось запросить статистику: {type(e).__name__}: {e}"
            dadata_status = "warning"
            log.warning("dadata_quota_check_failed", error=str(e))

    providers.append(
        ProviderLimit(
            provider="dadata",
            name="DaData (реестровые данные, поиск, бренд)",
            status=dadata_status,
            keys_total=dadata_total,
            keys_active=dadata_active,
            keys=dadata_keys_status,
            methods=methods,
            notes="Суточный лимит базового тарифа — 10 000 подсказок. Метод бренда тарифицируется отдельно.",
            error=dadata_error,
        )
    )

    # ── 2. Checko ──────────────────────────────────────────────────────────
    checko_keys_status = [
        KeyStatus(key=k["key"], state=k["state"]) for k in checko_pool.status()
    ]
    checko_active = sum(1 for k in checko_keys_status if k.state == "ok")
    checko_total = len(checko_keys_status)
    checko_daily = ledger.daily_totals().get("checko")
    checko_status = "ok"

    if not checko_pool.has_keys():
        checko_status = "not_configured"
        alerts.append("Checko: ключ не задан в .env (CHECKO_API_KEY).")
    elif checko_active == 0:
        checko_status = "exhausted"
        alerts.append("Checko: все ключи в пуле исчерпаны (ответили 401/403/429).")

    providers.append(
        ProviderLimit(
            provider="checko",
            name="Checko (риск-факторы, арбитраж, приставы, связи)",
            status=checko_status,
            keys_total=checko_total,
            keys_active=checko_active,
            keys=checko_keys_status,
            daily_spent=checko_daily,
            notes=(
                f"Служба сообщает расход за сутки (сегодня: {checko_daily if checko_daily is not None else 'нет данных'}). "
                "Точный остаток квоты определяется тарифным планом в личном кабинете Checko."
            ),
        )
    )

    # ── 3. api-cloud.ru (резервный агрегатор) ──────────────────────────────
    has_apicloud = bool(settings.apicloud_key)
    providers.append(
        ProviderLimit(
            provider="apicloud",
            name="api-cloud.ru (резервный агрегатор ФССП, арбитража, банкротств)",
            status="ok" if has_apicloud else "not_configured",
            keys_total=1 if has_apicloud else 0,
            keys_active=1 if has_apicloud else 0,
            notes=(
                "Резервный эшелон: опрашивается только при сбое прямого канала. "
                "Бесплатный лимит: ~200 запросов в месяц."
                if has_apicloud
                else "Ключ APICLOUD_KEY не задан. Резервный эшелон отключён (не критично)."
            ),
        )
    )

    # ── 4. HeadHunter ──────────────────────────────────────────────────────
    has_hh = bool(settings.hh_app_token)
    providers.append(
        ProviderLimit(
            provider="hh",
            name="HeadHunter (поиск вакансий по работодателю)",
            status="ok" if has_hh else "not_configured",
            keys_total=1 if has_hh else 0,
            keys_active=1 if has_hh else 0,
            notes=(
                "Токен приложения dev.hh.ru активен."
                if has_hh
                else "Токен HH_APP_TOKEN не задан: при запросе найма API отвечает 403."
            ),
        )
    )

    # ── 5. Бесплатные официальные реестры ─────────────────────────────────
    providers.append(
        ProviderLimit(
            provider="open_registries",
            name="Государственные реестры (ГИР БО, Реестр МСП, ЕГРЮЛ, Федресурс, Росаккредитация, Реестр ПО Минцифры)",
            status="unlimited",
            notes="Официальные открытые реестры: не требуют API-ключей и не имеют квот на обращения.",
        )
    )

    return ProvidersLimitsReport(
        providers=providers,
        alerts=alerts,
        checked_at=datetime.now(timezone.utc),
    )
