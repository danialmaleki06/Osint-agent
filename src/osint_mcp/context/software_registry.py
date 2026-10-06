"""Единый реестр российских программ для ЭВМ и баз данных (Минцифры России).

Официальный реестр (reestr.digital.gov.ru) ведётся по постановлению
Правительства № 1236. Включение продукта в реестр:
  1. Подтверждает реальную разработку собственного ПО и статус IT-вендора;
  2. Освобождает реализацию прав от НДС (пп. 26 п. 2 ст. 149 НК РФ);
  3. Открывает доступ к госзакупкам по 44-ФЗ и 223-ФЗ в рамках импортозамещения.

Прямой доступ к reestr.digital.gov.ru требует национальных корневых
сертификатов и часто фильтруется по сети. Для надёжного бесплатного сбора
используется ежедневная выгрузка через открытый интерфейс proreestr.ru.
"""

from datetime import date, datetime, timezone

import httpx
import structlog
from selectolax.parser import HTMLParser

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.models import Fact, SoftwareProduct, SourceResult

log = structlog.get_logger()

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    # Формат в карточке: "DD.MM.YYYY"
    parts = value.strip().split(".")
    if len(parts) == 3:
        try:
            return date(int(parts[2]), int(parts[1]), int(parts[0]))
        except ValueError:
            pass
    return None


class SoftwareRegistrySource:
    """Проверка наличия продуктов в едином реестре российского ПО."""

    name = "software_registry"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def get_software_products(
        self, inn: str
    ) -> tuple[list[SoftwareProduct], list[Fact], str | None]:
        """Собрать записи реестра ПО Минцифры по ИНН правообладателя."""
        url = f"https://proreestr.ru/reestr-po/?q={inn}"
        headers = {"User-Agent": _UA, "Accept": "text/html,application/xhtml+xml"}

        try:
            if self._client is not None:
                resp = await self._client.get(url, headers=headers)
            else:
                async with httpx.AsyncClient(
                    timeout=max(settings.request_timeout, 10.0), headers=headers
                ) as client:
                    resp = await client.get(url)
            resp.raise_for_status()
            html = resp.text
        except httpx.HTTPStatusError as e:
            ledger.record(self.name, "search", "failed", f"HTTP {e.response.status_code}")
            return [], [], f"Реестр ПО вернул HTTP {e.response.status_code}"
        except (httpx.TransportError, httpx.TimeoutException) as e:
            ledger.record(self.name, "search", "failed", f"сеть: {type(e).__name__}")
            return [], [], f"Реестр ПО недоступен ({type(e).__name__})"

        doc = HTMLParser(html)
        products: list[SoftwareProduct] = []
        facts: list[Fact] = []
        now = datetime.now(timezone.utc)

        for i, card in enumerate(doc.css("article"), 1):
            title_el = card.css_first("h3")
            if not title_el:
                continue
            name = title_el.text().strip()
            status_el = card.css_first("span")
            status = status_el.text().strip() if status_el else "В реестре"

            details: dict[str, str] = {}
            for row in card.css("div.flex"):
                dt = row.css_first("dt")
                dd = row.css_first("dd")
                if dt and dd:
                    details[dt.text().strip()] = dd.text().strip()

            link_el = card.css_first("a[href*='reestr.digital.gov.ru']")
            link = link_el.attrs.get("href") if link_el else None
            reg_number = details.get("Запись №")
            date_str = details.get("Включено")
            event_dt = _parse_date(date_str)
            software_class = details.get("Класс ПО")

            prod = SoftwareProduct(
                name=name,
                reg_number=reg_number,
                reg_date=date_str,
                status=status,
                software_class=software_class,
                url=link or (f"https://reestr.digital.gov.ru/reestr/{reg_number}/" if reg_number else None),
            )
            products.append(prod)

            facts.append(Fact(
                fact_id=f"SW-{i}",
                kind="software_registry",
                statement=(
                    f"Продукт «{name}» в реестре российского ПО Минцифры "
                    f"(№{reg_number or 'б/н'}"
                    + (f", класс: {software_class}" if software_class else "")
                    + f", статус: {status})"
                ),
                source_url=prod.url or "https://reestr.digital.gov.ru/",
                source_type="registry_api",
                retrieved_at=now,
                event_date=event_dt,
                payload={
                    "name": name,
                    "reg_number": reg_number,
                    "status": status,
                    "class": software_class,
                },
            ))

        ledger.record(self.name, "search", "ok" if products else "empty")
        log.info("software_registry.search", inn=inn, found=len(products))
        return products, facts, None

    async def check_software_registry(self, inn: str) -> SourceResult:
        """Метод для включения в параллельный сбор риск-фактов."""
        products, facts, failure = await self.get_software_products(inn)
        if failure:
            return SourceResult(
                source="software_registry",
                status="unavailable",
                reason=failure,
            )
        return SourceResult(
            source="software_registry",
            status="ok" if products else "partial",
            reason=None if products else "Программных продуктов в реестре Минцифры не найдено",
            facts=facts,
        )
