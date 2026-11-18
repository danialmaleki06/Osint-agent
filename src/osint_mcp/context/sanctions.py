"""Пакетная проверка российских ИНН по официальным XML-выгрузкам OFAC и ЕС."""

import asyncio
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from xml.etree import ElementTree

import httpx
import structlog

from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.inn import validate_inn

_OFAC_URL = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/"
_EU_URL = ("https://webgate.ec.europa.eu/fsd/fsf/public/files/"
           "xmlFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw")
_FEEDS = {
    "OFAC SDN": _OFAC_URL + "SDN.XML",
    "OFAC Non-SDN": _OFAC_URL + "CONSOLIDATED.XML",
    "EU Financial Sanctions": _EU_URL,
}
_TTL = timedelta(hours=1)
_HEADERS = {"User-Agent": "osint-mcp/0.4 (sanctions registry client)", "Accept": "application/xml,text/xml"}
_RETRY_DELAYS = (0.0, 0.5, 1.5)
_RETRY_HTTP = {500, 502, 503, 504}
_RETRY_NETWORK = (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError)
log = structlog.get_logger()
SCOPE_NOTE = (
    "Сверка выполнена по точному ИНН РФ в опубликованных выгрузках OFAC SDN, OFAC Non-SDN и ЕС. "
    "Сопоставляются записи с указанным ИНН. Отсутствие совпадения не исключает санкций по имени, "
    "через владение или по спискам других юрисдикций."
)


class SanctionsUnavailable(RuntimeError):
    """Обязательная выгрузка недоступна или не прошла проверку формата."""


@dataclass(frozen=True, slots=True)
class _Entry:
    uid: str
    name: str
    programs: tuple[str, ...]
    url: str
    reference: str | None = None


@dataclass(slots=True)
class SanctionsSnapshot:
    entries: dict[str, list[PendingFact]]
    datasets: list[dict]
    fetched_at: datetime


def _valid_tax_ids(values) -> set[str]:
    return {value for raw in values if raw and (value := raw.strip()).isascii()
            and value.isdecimal() and validate_inn(value).valid}


def _parse_ofac(root: ElementTree.Element) -> tuple[str, int, list[tuple[set[str], _Entry]]]:
    if not root.tag.endswith("}sdnList"):
        raise ValueError("неожиданный корень XML")
    entities = root.findall("{*}sdnEntry")
    if not entities or int(root.findtext("{*}publshInformation/{*}Record_Count", "0")) != len(entities):
        raise ValueError("число записей не совпадает с заголовком")
    published = datetime.strptime(root.findtext("{*}publshInformation/{*}Publish_Date", ""), "%m/%d/%Y")
    indexed = []
    for entity in entities:
        tax_ids = _valid_tax_ids(
            identity.findtext("{*}idNumber") for identity in entity.findall("{*}idList/{*}id")
            if identity.findtext("{*}idCountry") == "Russia"
            and identity.findtext("{*}idType") == "Tax ID No."
        )
        if not tax_ids:
            continue
        uid = entity.findtext("{*}uid", "")
        name = " ".join(x for tag in ("firstName", "lastName") if (x := entity.findtext(f"{{*}}{tag}")))
        if not uid.isdecimal() or not name.strip():
            raise ValueError("у записи с ИНН нет имени или идентификатора")
        programs = tuple(p.text for p in entity.findall("{*}programList/{*}program") if p.text)
        indexed.append((tax_ids, _Entry(uid, name, programs, f"https://sanctionssearch.ofac.treas.gov/Details.aspx?id={uid}")))
    return published.date().isoformat(), len(entities), indexed


def _parse_eu(root: ElementTree.Element) -> tuple[str, int, list[tuple[set[str], _Entry]]]:
    if root.tag != "{http://eu.europa.ec/fpi/fsd/export}export":
        raise ValueError("неожиданный корень XML")
    published = datetime.fromisoformat(root.get("generationDate", ""))
    entities = root.findall("{*}sanctionEntity")
    if not entities:
        raise ValueError("пустая выгрузка")
    indexed = []
    for entity in entities:
        tax_ids = _valid_tax_ids(
            identity.get("number") for identity in entity.findall("{*}identification")
            if identity.get("countryIso2Code") == "RU"
            and identity.get("identificationTypeCode") in {"taxid", "fiscalcode"}
            and identity.get("knownFalse") != "true" and identity.get("revokedByIssuer") != "true"
        )
        if not tax_ids:
            continue
        uid = entity.get("logicalId", "")
        names = [n.get("wholeName", "").strip() for n in entity.findall("{*}nameAlias") if n.get("wholeName")]
        if not uid.isdecimal() or not names:
            raise ValueError("у записи с ИНН нет имени или идентификатора")
        regulations = entity.findall("{*}regulation")
        programs = tuple(sorted({r.get("programme") for r in regulations if r.get("programme")}))
        reference = entity.get("euReferenceNumber")
        indexed.append((tax_ids, _Entry(uid, names[0], programs, _EU_URL, reference)))
    return published.date().isoformat(), len(entities), indexed


def _build_snapshot(responses: dict[str, bytes]) -> SanctionsSnapshot:
    fetched_at = datetime.now(UTC)
    grouped: dict[str, list[PendingFact]] = {}
    datasets = []
    for label, content in responses.items():
        try:
            root = ElementTree.fromstring(content)
            parse = _parse_eu if label == "EU Financial Sanctions" else _parse_ofac
            published, total, entries = parse(root)
            if not entries:
                raise ValueError("не найдено записей с проверяемыми ИНН РФ")
        except (ValueError, ElementTree.ParseError) as exc:
            raise SanctionsUnavailable(f"{label}: {exc}") from exc
        datasets.append({"source": label, "url": _FEEDS[label], "published_at": published,
                         "fetched_at": fetched_at.isoformat(), "total_records": total,
                         "records_with_ru_tax_id": len(entries)})
        for tax_ids, entry in entries:
            for inn in tax_ids:
                grouped.setdefault(inn, []).append(PendingFact(
                    fact_id=f"SANCTIONS-{label.replace(' ', '-')}-{entry.uid}",
                    kind="international_sanction", source_url=entry.url, trust="reference",
                    statement=f"{label}: {entry.name}, совпадение по ИНН {inn} (запись {entry.reference or entry.uid}).",
                    found_by=f"sanctions:{label}", found_at=fetched_at,
                    payload={"dataset": label, "published_at": published, "record_id": entry.uid,
                             "name": entry.name, "matched_inn": inn, "programs": list(entry.programs),
                             "reference": entry.reference or entry.uid},
                ))
    return SanctionsSnapshot(grouped, datasets, fetched_at)


def _certificate_failure(error: httpx.RequestError) -> bool:
    cause: BaseException | None = error
    while cause is not None:
        if isinstance(cause, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(cause):
            return True
        cause = cause.__cause__
    return False


async def _download_feed(client: httpx.AsyncClient, label: str, url: str) -> bytes:
    retry_after = 0.0
    for attempt, delay in enumerate(_RETRY_DELAYS, 1):
        if delay or retry_after:
            await asyncio.sleep(max(delay, retry_after))
        try:
            # A fresh request to the official URL also obtains a fresh download redirect.
            response = await client.get(url)
        except httpx.RequestError as error:
            host = error.request.url.host
            certificate_failure = _certificate_failure(error)
            detail = "ошибка проверки сертификата TLS" if certificate_failure else type(error).__name__
            reason = f"{label}: {detail} ({host})"
            retryable = isinstance(error, _RETRY_NETWORK) and not certificate_failure
            retry_after = 0.0
        else:
            host = response.url.host
            if response.status_code == 200:
                if attempt > 1:
                    log.info("sanctions_download_recovered", feed=label, host=host, attempts=attempt)
                return response.content
            reason = f"{label}: HTTP {response.status_code} ({host})"
            wait = response.headers.get("Retry-After", "0")
            # A long or absolute Retry-After is left to a later tool call.
            retryable = response.status_code in _RETRY_HTTP and wait.isascii() and wait.isdecimal() and int(wait) <= 2
            retry_after = float(wait) if retryable else 0.0
        if not retryable or attempt == len(_RETRY_DELAYS):
            raise SanctionsUnavailable(f"{reason}; попыток: {attempt}")
        log.info("sanctions_download_retry", feed=label, host=host, attempt=attempt, reason=reason)
    raise AssertionError("Выгрузка требует хотя бы одной попытки")


class SanctionsRegistry:
    """Единая выгрузка каждого списка на период TTL и поиск всех ИНН в одном индексе."""

    def __init__(self) -> None:
        self._snapshot: SanctionsSnapshot | None = None
        self._lock = asyncio.Lock()

    async def snapshot(self) -> SanctionsSnapshot:
        async with self._lock:
            if self._snapshot and datetime.now(UTC) - self._snapshot.fetched_at < _TTL:
                return self._snapshot
            timeout = httpx.Timeout(18, connect=7)
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=_HEADERS) as client:
                replies = await asyncio.gather(
                    *(_download_feed(client, label, url) for label, url in _FEEDS.items()),
                    return_exceptions=True,
                )
            files = {}
            errors = []
            for label, reply in zip(_FEEDS, replies, strict=True):
                if isinstance(reply, SanctionsUnavailable):
                    errors.append(str(reply))
                elif isinstance(reply, BaseException):
                    raise reply
                else:
                    files[label] = reply
            if errors:
                raise SanctionsUnavailable(", ".join(errors))
            self._snapshot = await asyncio.to_thread(_build_snapshot, files)
            return self._snapshot
