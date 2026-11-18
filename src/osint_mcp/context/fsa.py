"""ФГИС Росаккредитация (pub.fsa.gov.ru) — сертификаты и декларации.

Единый реестр сертификатов соответствия и деклараций о соответствии
(ЕАЭС и национальные). Реестр отвечает на вопрос, чем компания реально
торгует: декларация оформляется на каждую партию или серийный выпуск,
и в ней всегда указаны заявитель, изготовитель и продукция.

Официального открытого API нет; SPA реестра общается с бэкендом JSON'ом:

  POST /api/v1/rds/common/declarations/get   — декларации
  POST /api/v1/rss/common/certificates/get   — сертификаты

Тело запроса: {"size": N, "page": 0, "filter": {"columnsSearch": [...]}}.
Поиск по организации ведётся по колонкам «заявитель» и «изготовитель»:
декларация, где компания изготовитель, раскрывает её производство,
где заявитель — что и для чего она возит.

Из этой сети pub.fsa.gov.ru может быть недоступен. Отказ одного
эндпоинта оставляет в результате данные от второго. Поиск по колонкам
идёт по ИНН и, если передано, по наименованию.
"""

import asyncio
from datetime import UTC, date, datetime

import httpx
import structlog

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.context.registry_http import registry_client
from osint_mcp.models import Fact, SourceResult

log = structlog.get_logger()

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# Колонки поиска реестра: idColumn соответствует колонке интерфейса
# «Единый реестр сертификатов и деклараций». 1 — заявитель, 2 —
# изготовитель (проверено по запросам SPA).
_DECL_SEARCH_URL = "https://pub.fsa.gov.ru/api/v1/rds/common/declarations/get"
_CERT_SEARCH_URL = "https://pub.fsa.gov.ru/api/v1/rss/common/certificates/get"

MAX_RECORDS = 15


def _search_body(inn: str, name: str | None, page: int = 0) -> dict:
    """Тело поиска по двум колонкам сразу."""
    needles = [inn] + ([name] if name else [])
    return {
        "size": MAX_RECORDS,
        "page": page,
        "filter": {
            "idTechReg": [],
            "regDate": {"minDate": "", "maxDate": ""},
            "endDate": {"minDate": "", "maxDate": ""},
            "columnsSearch": [
                {"idColumn": col, "searchString": needle}
                for col in (1, 2)          # 1 — заявитель, 2 — изготовитель
                for needle in needles
            ],
        },
        "columnsSort": [{"column": "declDate", "sort": "DESC"}],
    }


def _parse_date(value) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    raw = value[:10]
    try:
        return date.fromisoformat(raw)
    except ValueError:
        return None


_FOREIGN_MARKERS = {
    "Китай": (
        "CHINA", "CHINESE", "КИТАЙ", "ZHEJIANG", "GUANGDONG", "SHENZHEN",
        "SHANGHAI", "BEIJING", "NINGBO", "YIWU", "JIANGSU", "CO., LTD",
        "CO.,LTD", "COMPANY LIMITED", "HONG KONG",
    ),
    "Турция": (
        "TURKEY", "TÜRKIYE", "TURKIYE", "ТУРЦИЯ", "ISTANBUL", "SANAYI",
        "TICARET", "LTD. STI", "LTD.ŞTI", "A.S.", "ANONIM",
    ),
    "Германия": ("GERMANY", "DEUTSCHLAND", "ГЕРМАНИЯ", "GMBH"),
    "Италия": ("ITALY", "ITALIA", "ИТАЛИЯ", "S.R.L.", "S.P.A."),
    "Франция": ("FRANCE", "ФРАНЦИЯ", "SAS", "SARL"),
    "Польша": ("POLAND", "ПОЛЬША", "SP. Z O.O.", "SP. Z O. O."),
    "Беларусь": ("БЕЛАРУСЬ", "БЕЛАРУС", "МИНСК"),
    "Казахстан": ("КАЗАХСТАН", "АЛМАТЫ", "ТОО "),
}

_FOREIGN_LEGAL_FORMS = (
    "LTD", "INC", "CORP", "LLC", "B.V.", "AG", "PLC", "LIMITED", "KFT",
)


def detect_manufacturer_origin(name: str) -> tuple[bool, str | None]:
    """Определить, является ли изготовитель зарубежным, и указать страну."""
    if not name:
        return False, None
    upper = name.upper()
    for country, markers in _FOREIGN_MARKERS.items():
        if any(m in upper for m in markers):
            return True, country

    is_russian_org = any(
        token in upper for token in ("ООО", "АО ", "ПАО", "ЗАО", "ИП ", "OOO ")
    )
    if any(lf in upper for lf in _FOREIGN_LEGAL_FORMS):
        return True, "Импорт"

    has_latin = any("A" <= ch <= "Z" for ch in upper)
    if has_latin and not is_russian_org:
        return True, "Импорт"

    return False, None


class FsaSource:
    """Сертификаты и декларации соответствия из ФГИС Росаккредитации."""

    name = "fsa"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def _post(self, url: str, body: dict) -> dict:
        """POST с журналом. Ошибки наружу — их смысл знает вызывающий."""
        headers = {
            "User-Agent": _UA,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Referer": "https://pub.fsa.gov.ru/rds/declaration",
            "Origin": "https://pub.fsa.gov.ru",
        }
        if self._client is not None:
            resp = await self._client.post(url, json=body, headers=headers)
        else:
            async with registry_client(
                timeout=min(settings.request_timeout, 3.5), headers=headers,
            ) as client:
                resp = await client.post(url, json=body)
        resp.raise_for_status()
        return resp.json()

    async def _search(self, url: str, body: dict) -> tuple[list[dict], int]:
        try:
            data = await self._post(url, body)
        except ValueError as exc:
            raise ValueError("ответ не JSON") from exc

        items = data.get("items") if isinstance(data, dict) else None
        if items is None and isinstance(data, dict):
            items = data.get("pageData")
        if not isinstance(items, list) or any(
            not isinstance(rec, dict) or not (rec.get("id") or rec.get("number"))
            for rec in items
        ):
            raise ValueError("неожиданный формат списка записей")
        raw_total = data.get("total")
        if raw_total is None:
            return items, len(items)
        if type(raw_total) is int or (isinstance(raw_total, str) and raw_total.isdigit()):
            total = int(raw_total)
            if total >= len(items) and (items or not total):
                return items, total
        raise ValueError("некорректное количество записей")

    async def check_certificates(self, inn: str, name: str | None = None) -> SourceResult:
        """Сертификаты и декларации, где организация заявитель или изготовитель.

        Статус partial при пустом результате: не у всякой торговли есть
        обязательная сертификация, отсутствие записей законно.
        """
        facts: list[Fact] = []
        total = 0
        answered = 0
        gaps: list[str] = []
        now = datetime.now(UTC)

        endpoints = (
            ("declarations", _DECL_SEARCH_URL, "декларация о соответствии",
             "https://pub.fsa.gov.ru/rds/declaration/view/{rid}/common"),
            ("certificates", _CERT_SEARCH_URL, "сертификат соответствия",
             "https://pub.fsa.gov.ru/rss/certificate/view/{rid}/baseInfo"),
        )
        body = _search_body(inn, name)
        responses = await asyncio.gather(
            *(self._search(url, body) for _, url, _, _ in endpoints),
            return_exceptions=True,
        )
        for (method, _, label, view), response in zip(endpoints, responses, strict=True):
            if isinstance(response, BaseException):
                if isinstance(response, httpx.HTTPStatusError):
                    error = f"HTTP {response.response.status_code}"
                elif isinstance(response, httpx.TransportError):
                    error = f"сеть: {type(response).__name__}"
                elif isinstance(response, ValueError):
                    error = str(response)
                else:
                    raise response
                ledger.record(self.name, method, "failed", error)
                gaps.append(f"{label} — {error}")
                continue

            items, found = response
            answered += 1
            total += found
            ledger.record(self.name, method, "ok" if items else "empty")
            if found > min(len(items), MAX_RECORDS):
                gaps.append(f"{label} — получено {min(len(items), MAX_RECORDS)} из {found}")
            for rec in items[:MAX_RECORDS]:
                rid = rec.get("id") or ""
                product = str(rec.get("productFullName") or rec.get("fullName")
                              or rec.get("productName") or "")
                manufacturer = str(rec.get("manufacterName") or "")
                number = str(rec.get("number") or "")
                end_date = _parse_date(rec.get("declEndDate") or rec.get("endDate"))
                is_foreign, country_hint = detect_manufacturer_origin(manufacturer)
                # Скорing-порог смотрит на endDate: истёкший документ — сигнал,
                # что партия выпущена, а подтверждение не продлено.
                origin_suffix = f" (импорт: {country_hint})" if is_foreign and country_hint else ""
                facts.append(Fact(
                    fact_id=f"FSA-{len(facts) + 1}",
                    kind="fsa_certificate",
                    statement=(f"{label.capitalize()} №{number or 'б/н'}: "
                               f"{product[:150] or 'продукция не указана'}"
                               + (f"; изготовитель {manufacturer[:100]}{origin_suffix}" if manufacturer else "")),
                    source_url=view.format(rid=rid) if rid else "https://pub.fsa.gov.ru/",
                    source_type="registry_api",
                    retrieved_at=now,
                    event_date=end_date,
                    payload={
                        "record_id": rid,
                        "number": number,
                        "product": product,
                        "manufacturer": manufacturer,
                        "is_foreign": is_foreign,
                        "origin_country": country_hint,
                        "end_date": end_date.isoformat() if end_date else None,
                        "doc_type": "declaration" if method == "declarations" else "certificate",
                        "via": "fsa",
                    },
                ))

        log.info("fsa.certificates", inn=inn, found=total, facts=len(facts))
        reason = None
        if gaps:
            summary = "Сертификаты и декларации НЕ ПРОВЕРЕНЫ" if not answered else "Проверка выполнена частично"
            reason = f"{summary}: {', '.join(gaps)}"
        elif not total:
            reason = (
                "Сертификатов и деклараций по этому ИНН не найдено. "
                "Обязательная сертификация есть не у всякой продукции — "
                "пустой результат означает «в реестре не значится», "
                "а не «не торгует»"
            )
        return SourceResult(
            source="fsa.certificates",
            status="unavailable" if not answered else ("partial" if reason else "ok"),
            reason=reason,
            facts=facts,
        )
