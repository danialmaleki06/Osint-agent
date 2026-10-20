"""Детектор централизованных HR-хабов холдинговых структур.

Выявляет случаи, когда на проверяемое финансовое/балансовое юридическое лицо
прямой найм не ведётся (0 вакансий), но холдинг ведёт активный подбор персонала
через консолидированный профиль или специализированную кадровою компанию.
"""

import httpx
import structlog
from typing import Any

from osint_mcp.config import settings
from osint_mcp.context.hh import _HEADERS, _find_best_employer
from osint_mcp.models import CompanyContext

log = structlog.get_logger()


async def detect_corporate_hr_hub(
    ctx: CompanyContext | None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any] | None:
    """Проверяет наличие активного кадрового хаба холдинга при отсутствии вакансий на основном юрлице."""
    if not ctx:
        return None

    # Проверяем только если на текущем юрлице нет вакансий
    vacancies_on_entity = ctx.hiring.open_vacancies if (ctx.hiring and ctx.hiring.open_vacancies is not None) else 0
    if vacancies_on_entity > 0:
        return None

    # Компания должна быть заметным бизнесом
    is_substantial = (
        ctx.size_category in ("medium", "large")
        or (ctx.revenue_latest and ctx.revenue_latest >= 200_000_000)
        or (ctx.employees and ctx.employees >= 50)
    )
    if not is_substantial:
        return None

    # Требуется установленный бренд или рыночное имя
    brand = ctx.brand
    if not brand or len(brand.strip()) < 2:
        return None

    brand_clean = brand.strip()

    headers = dict(_HEADERS)
    if settings.hh_app_token:
        headers["Authorization"] = f"Bearer {settings.hh_app_token}"

    url = f"{settings.hh_base_url}/employers"
    params = {"text": brand_clean, "per_page": 20}

    try:
        if client is not None:
            resp = await client.get(url, params=params, headers=headers)
        else:
            async with httpx.AsyncClient(timeout=settings.request_timeout) as c:
                resp = await c.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            return None

        data = resp.json()
        items = data.get("items") or []
        best = _find_best_employer(brand_clean, items)

        if best and (best.get("open_vacancies") or 0) > 0:
            hub_name = best.get("name")
            hub_id = str(best.get("id"))
            hub_vacancies = best.get("open_vacancies")

            # Проверяем, что найденный профиль не совпадает с тем, что уже проверялся
            if ctx.hiring and ctx.hiring.employer_id == hub_id:
                return None

            log.info("hr_hub.detected", brand=brand_clean, hub_name=hub_name,
                     hub_id=hub_id, vacancies=hub_vacancies)

            company_label = ctx.name_short or ctx.name_legal
            return {
                "обнаружен": True,
                "бренд": brand_clean,
                "наименование_хаба": hub_name,
                "employer_id": hub_id,
                "вакансий_в_хабе": hub_vacancies,
                "пояснение": (
                    f"На проверяемое балансовое юрлицо ({company_label}) открытых вакансий не найдено. "
                    f"Однако холдинг ведёт активный подбор под брендом «{hub_name}» "
                    f"({hub_vacancies} открытых вакансий). Найм консолидирован в централизованном HR-хабе."
                ),
            }
    except Exception as exc:  # noqa: BLE001
        log.debug("hr_hub.check_failed", brand=brand_clean, error=str(exc))
        return None

    return None
