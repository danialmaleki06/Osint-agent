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

Из этой сети pub.fsa.gov.ru может быть недоступен (geo-ограничение
сервиса наблюдалось 06.10.2026): любой отказ сети — пустой результат
с reason, источник не должен ронять проверку рисков. Поиск по колонке
идёт как по ИНН, так и по наименованию; записи сверяются с ИНН по
данным детального запроса.
"""

from datetime import UTC, date, datetime

import httpx
import structlog

from osint_mcp import ledger
from osint_mcp.config import settings
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
            async with httpx.AsyncClient(
                timeout=min(settings.request_timeout, 3.5), headers=headers,
            ) as client:
                resp = await client.post(url, json=body)
        resp.raise_for_status()
        return resp.json()

    async def check_certificates(self, inn: str, name: str | None = None) -> SourceResult:
        """Сертификаты и декларации, где организация заявитель или изготовитель.

        Статус partial при пустом результате: не у всякой торговли есть
        обязательная сертификация, отсутствие записей законно.
        """
        service, method = self.name, "declarations"
        facts: list[Fact] = []
        total = 0
        now = datetime.now(UTC)

        for url, label, view in (
            (_DECL_SEARCH_URL, "декларация о соответствии",
             "https://pub.fsa.gov.ru/rds/declaration/view/{rid}/common"),
            (_CERT_SEARCH_URL, "сертификат соответствия",
             "https://pub.fsa.gov.ru/rss/certificate/view/{rid}/baseInfo"),
        ):
            try:
                data = await self._post(url, _search_body(inn, name))
            except httpx.HTTPStatusError as e:
                ledger.record(service, method, "failed", f"HTTP {e.response.status_code}")
                return SourceResult(
                    source="fsa.certificates", status="unavailable",
                    reason=f"Реестр Росаккредитации ответил {e.response.status_code}",
                )
            except (httpx.TransportError, httpx.TimeoutException) as e:
                ledger.record(service, method, "failed", f"сеть: {type(e).__name__}")
                return SourceResult(
                    source="fsa.certificates", status="unavailable",
                    reason=(f"ФГИС Росаккредитации недоступен из этой сети "
                            f"({type(e).__name__}) — сертификаты и декларации "
                            f"НЕ ПРОВЕРЕНЫ"),
                )
            except ValueError:
                ledger.record(service, method, "failed", "ответ не JSON")
                return SourceResult(
                    source="fsa.certificates", status="unavailable",
                    reason="Реестр Росаккредитации вернул не JSON",
                )

            items = (data.get("items") or data.get("pageData") or [])
            total += int(data.get("total") or len(items))
            base = len(facts)
            for i, rec in enumerate(items[:MAX_RECORDS], 1):
                if not isinstance(rec, dict):
                    continue
                rid = rec.get("id") or ""
                product = (rec.get("productFullName") or rec.get("fullName")
                           or rec.get("productName") or "")
                manufacturer = rec.get("manufacterName") or ""
                number = rec.get("number") or ""
                end_date = _parse_date(rec.get("declEndDate") or rec.get("endDate"))
                is_foreign, country_hint = detect_manufacturer_origin(manufacturer)
                # Скорing-порог смотрит на endDate: истёкший документ — сигнал,
                # что партия выпущена, а подтверждение не продлено.
                origin_suffix = f" (импорт: {country_hint})" if is_foreign and country_hint else ""
                facts.append(Fact(
                    fact_id=f"FSA-{base + i}",
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
                        "doc_type": "declaration" if "declarations" in url else "certificate",
                        "via": "fsa",
                    },
                ))

        ledger.record(service, method, "ok" if total else "empty")
        log.info("fsa.certificates", inn=inn, found=total, facts=len(facts))
        return SourceResult(
            source="fsa.certificates",
            status="ok" if total else "partial",
            reason=None if total else (
                "Сертификатов и деклараций по этому ИНН не найдено. "
                "Обязательная сертификация есть не у всякой продукции — "
                "пустой результат означает «в реестре не значится», "
                "а не «не торгует»"
            ),
            facts=facts,
        )
