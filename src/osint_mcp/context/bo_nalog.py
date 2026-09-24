"""Финансовая отчётность из ГИР БО (bo.nalog.gov.ru).

Бесплатный официальный источник ФНС: ключи и суточные квоты не нужны.
Одним запросом отдаёт все годы отчётности: выручку, активы, валюту
баланса. Это позволяет собирать финансовую историю даже тогда, когда
квоты платных справочников исчерпаны, и делает краткий отчёт и пакетную
проверку доступными без расхода платной квоты вовсе.

Ограничения источника:
  * отчётность сдают не все: банки, страховые и часть крупных компаний
    публикуют её в своих формах, а не в ГИР БО — пустой ответ означает
    «в ресурсе не значится», а не «компания без денег»;
  * суммы приходят в ТЫСЯЧАХ рублей — переводим в рубли сразу,
    чтобы не плодить два масштаба в одной модели;
  * поиск только по ИНН; точное соответствие обязательно.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.models import FinancialYear

log = structlog.get_logger()

# Суммы ГИР БО приходят в тысячах рублей
_THOUSANDS = 1_000.0


class BoNalogSource:
    """Бухгалтерская отчётность напрямую из ресурса ФНС."""

    name = "bo_nalog"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def _get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        """GET с учётом в журнале. Ошибки наружу — их смысл знает вызывающий."""
        service, method = self.name, "request"
        if self._client is not None:
            resp = await self._client.get(url, params=params)
        else:
            async with httpx.AsyncClient(
                timeout=settings.request_timeout,
                headers={"User-Agent": "Mozilla/5.0 (compatible; osint-mcp)"},
            ) as client:
                resp = await client.get(url, params=params)
        if resp.status_code >= 400:
            ledger.record(service, method, "failed", f"HTTP {resp.status_code}")
            resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            ledger.record(service, method, "failed", "ответ не JSON")
            raise

    async def find_organization(self, inn: str) -> dict | None:
        """Найти организацию в ресурсе по ИНН. None — в ресурсе не значится."""
        data = await self._get(
            f"{settings.bo_nalog_base_url}/advanced-search/organizations/search",
            params={"query": inn, "page": 0},
        )
        content = data.get("content") if isinstance(data, dict) else None
        for row in content or []:
            # В выдаче ИНН подсвечен тегами: <strong>7724744134</strong>
            found = str(row.get("inn") or "").replace("<strong>", "").replace("</strong>", "")
            if found == inn:
                return row
        ledger.record(self.name, "request", "empty", "в ресурсе БФО не значится")
        return None

    async def get_finances(self, inn: str) -> tuple[list[FinancialYear] | None, str | None]:
        """Финансовая история по годам. Возвращает (годы, причина отказа).

        None при отказе источника; пустой список при отказе источника не
        возвращаем — пустота означала бы «отчётности нет», что неверно,
        когда источник просто молчал.
        """
        try:
            org = await self.find_organization(inn)
        except (httpx.HTTPError, ValueError) as e:
            return None, f"ГИР БО недоступен: {type(e).__name__}"

        if not org:
            # Пустой ответ валиден: часть организаций отчётность не сдаёт
            return None, "организация в ресурсе БФО не значится (отчётность не сдана либо не публикуется)"

        org_id = org.get("id")
        if not org_id:
            return None, "ГИР БО ответил без идентификатора организации"

        try:
            reports = await self._get(f"{settings.bo_nalog_base_url}/nbo/organizations/{org_id}/bfo")
        except (httpx.HTTPError, ValueError) as e:
            return None, f"ГИР БО недоступен: {type(e).__name__}"

        if not isinstance(reports, list):
            return None, "ГИР БО вернул неожиданный формат отчётности"

        now = datetime.now(timezone.utc)
        years: list[FinancialYear] = []
        for rep in reports:
            period = str(rep.get("period") or "")
            if not period.isdigit():
                continue
            gain = rep.get("gainSum")
            actives = rep.get("actives")
            years.append(FinancialYear(
                year=int(period),
                # Суммы приходят в тысячах рублей — переводим сразу
                revenue=float(gain) * _THOUSANDS if gain is not None else None,
                assets=float(actives) * _THOUSANDS if actives is not None else None,
                report_url=(
                    f"https://bo.nalog.gov.ru/bfo/pdf/{org_id}?period={period}&detailId={rep.get('id')}"
                    if rep.get("id") else None
                ),
            ))

        years.sort(key=lambda y: y.year, reverse=True)
        ledger.record(self.name, "request", "ok")
        log.info("bo_nalog.finances", inn=inn, years=len(years))
        return years[:5], None


# ─────────────────────────  слияние с Checko  ─────────────────────────


def merge_financial_years(
    primary: list[FinancialYear] | None,
    fallback: list[FinancialYear] | None,
) -> list[FinancialYear]:
    """Слить финансовые истории двух источников по году.

    Используется, когда Checko не ответил (квота, сбой), а ГИР БО ответил:
    тогда отчёт всё равно содержит динамику. При конфликте за один год
    значения primary приоритетны, но пустые у primary поля дозаполняются
    из резерва: у платного источника разбор строк полнее, зато у ГИР БО
    есть прямая ссылка на отчётность ФНС.
    """
    merged: dict[int, FinancialYear] = {}
    for fy in (fallback or []):
        merged[fy.year] = fy
    for fy in (primary or []):
        base = merged.get(fy.year)
        if base is None:
            merged[fy.year] = fy
            continue
        # Дозаполнение по полям: None у primary не затирает данные резерва
        merged[fy.year] = FinancialYear(
            year=fy.year,
            revenue=fy.revenue if fy.revenue is not None else base.revenue,
            profit=fy.profit if fy.profit is not None else base.profit,
            assets=fy.assets if fy.assets is not None else base.assets,
            balance=fy.balance if fy.balance is not None else base.balance,
            equity=fy.equity if fy.equity is not None else base.equity,
            report_url=fy.report_url if fy.report_url is not None else base.report_url,
        )
    return sorted(merged.values(), key=lambda y: y.year, reverse=True)[:5]


async def fetch_finances_with_fallback(
    checko_get_finances, inn: str
) -> tuple[list[FinancialYear], str | None]:
    """Финансы с автоматическим переходом на ГИР БО.

    checko_get_finances — awaitable-фабрика (обычно связанный метод
    CheckoSource.get_finances). ГИР БО вызывается, только когда платный
    источник не дал данных: бесплатный эшелон расходуем экономно, резерв
    вообще не трогаем.
    """
    summary, failure = await checko_get_finances(inn)
    if summary and summary.years:
        return summary.years, None

    bo = BoNalogSource()
    bo_years, bo_failure = await bo.get_finances(inn)
    if bo_years:
        return bo_years, failure or None

    # Оба молчат: причина последнего отказа важнее
    return [], bo_failure or failure
