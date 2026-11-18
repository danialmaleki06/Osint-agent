"""Поиск по ИНН правообладателя в официальном реестре ПО Минцифры."""

import ssl
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from urllib.parse import urljoin

import httpx
import structlog
from selectolax.parser import HTMLParser

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.context.registry_http import registry_client
from osint_mcp.models import Fact, SoftwareProduct, SourceResult

log = structlog.get_logger()

_REGISTRY_URL = "https://reestr.digital.gov.ru/reestr/"
_TABS = (
    ("registry_active", "PAGE_N", "/reestr/", "В реестре"),
    ("registry_excluded", "EX_PAGE_N", "/excluded/", "Исключено"),
)
_MAX_PAGES = 50


@cache
def _registry_tls() -> ssl.SSLContext:
    # Корневой сертификат опубликован на https://www.gosuslugi.ru/crt.
    # Доверие этому УЦ нужно только при обращении к реестру Минцифры.
    ca = Path(__file__).parents[1] / "config_data" / "russian_trusted_root_ca.pem"
    return ssl.create_default_context(cafile=str(ca))


def _parse_tab(doc: HTMLParser, inn: str, tab: str, prefix: str, status: str) -> tuple[int, list[SoftwareProduct]]:
    filter_field = doc.css_first(f'#{tab} input[name="OWNER_INN"]')
    counter = doc.css_first(f'[data-target="{tab}"] .tabs-list__item-counter')
    container = doc.css_first(f'.tabs-content__item[data-tab="{tab}"]')
    if not filter_field or filter_field.attributes.get("value") != inn or not counter or not container:
        raise ValueError("реестр не подтвердил фильтр по ИНН")
    total = "".join(counter.text().split())
    if not total.isascii() or not total.isdecimal():
        raise ValueError("реестр вернул неизвестный формат счётчика записей")
    rows = container.css(".collection-registry .collection-item[data-href]")
    products = []
    for row in rows:
        number = row.css_first('[data-name="№ реестровой записи"]')
        title = row.css_first('[data-name="Наименование ПО"]')
        date_node = row.css_first('[data-name="Дата регистрации"]')
        path = row.attributes.get("data-href", "")
        name = title.text(strip=True) if title else ""
        reg_number = number.text(strip=True) if number else ""
        record_id = path.removeprefix(prefix).strip("/")
        if not (name and reg_number.isdecimal() and path.startswith(prefix) and record_id.isdecimal()):
            raise ValueError("реестр вернул запись без номера, названия или корректной ссылки")
        classes = row.css('[data-name="Класс ПО"] .class-item span:last-child')
        products.append(SoftwareProduct(
            name=name,
            reg_number=reg_number,
            reg_date=date_node.text(strip=True) if date_node else None,
            status=status,
            software_class=", ".join(node.text(strip=True) for node in classes) or None,
            url=urljoin(_REGISTRY_URL, path),
        ))
    return int(total), products


class SoftwareRegistrySource:
    """Действующие и исключённые записи официального реестра ПО."""

    name = "software_registry"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def _get(self, client: httpx.AsyncClient, params: dict) -> HTMLParser:
        response = await client.get(_REGISTRY_URL, params=params)
        response.raise_for_status()
        return HTMLParser(response.text)

    async def _products(self, client: httpx.AsyncClient, inn: str) -> list[SoftwareProduct]:
        query = {"OWNER_INN": inn, "tab": "registry_active"}
        first = await self._get(client, query)
        products = []
        for tab, page_param, prefix, status in _TABS:
            total, first_rows = _parse_tab(first, inn, tab, prefix, status)
            entries = {p.reg_number: p for p in first_rows}
            page = 1
            while first_rows and len(entries) < total and page < _MAX_PAGES:
                page += 1
                doc = await self._get(client, {**query, "tab": tab, page_param: page})
                current_total, rows = _parse_tab(doc, inn, tab, prefix, status)
                if current_total != total or not rows or any(p.reg_number in entries for p in rows):
                    break
                entries.update((p.reg_number, p) for p in rows)
            if len(entries) != total:
                raise ValueError(f"неполная выдача ({len(entries)} из {total}, {status})")
            products.extend(entries.values())
        return products

    async def get_software_products(
        self, inn: str
    ) -> tuple[list[SoftwareProduct], list[Fact], str | None]:
        """Записи официального реестра и факты по действующим продуктам."""
        try:
            if self._client is not None:
                products = await self._products(self._client, inn)
            else:
                async with registry_client(
                    timeout=max(settings.request_timeout, 10.0),
                    verify=_registry_tls(),
                    headers={"User-Agent": "Mozilla/5.0 (compatible; osint-mcp)"},
                ) as client:
                    products = await self._products(client, inn)
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            ledger.record(self.name, "search", "failed", f"HTTP {code}")
            return [], [], f"Официальный реестр ПО Минцифры вернул HTTP {code}"
        except (httpx.TransportError, ValueError, OSError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            ledger.record(self.name, "search", "failed", reason)
            return [], [], f"Официальный реестр ПО Минцифры недоступен: {reason}"

        now = datetime.now(UTC)
        facts = []
        for product in products:
            if product.status != "В реестре":
                continue
            try:
                event_date = datetime.strptime(product.reg_date or "", "%d.%m.%Y").date()
            except ValueError:
                event_date = None
            facts.append(Fact(
                fact_id=f"SW-{product.reg_number}",
                kind="software_registry",
                statement=f"Продукт «{product.name}» в реестре российского ПО Минцифры №{product.reg_number}",
                source_url=product.url or _REGISTRY_URL,
                source_type="registry_api",
                retrieved_at=now,
                event_date=event_date,
                payload={"name": product.name, "reg_number": product.reg_number,
                         "status": product.status, "class": product.software_class},
            ))
        ledger.record(self.name, "search", "ok" if products else "empty")
        log.info("software_registry.search", inn=inn, found=len(products))
        return products, facts, None

    async def check_software_registry(self, inn: str) -> SourceResult:
        """Передать действующие записи в оценку рисков."""
        products, facts, failure = await self.get_software_products(inn)
        if failure:
            return SourceResult(source=self.name, status="unavailable", reason=failure)
        return SourceResult(
            source=self.name,
            status="ok" if products else "partial",
            reason=None if products else "Программных продуктов в реестре Минцифры не найдено",
            facts=facts,
        )
