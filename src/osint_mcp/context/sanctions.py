"""Пакетная проверка российских ИНН по официальным XML-выгрузкам OFAC и ЕС."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from xml.etree import ElementTree

import httpx

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


class SanctionsRegistry:
    """Единая выгрузка каждого списка на период TTL и поиск всех ИНН в одном индексе."""

    def __init__(self) -> None:
        self._snapshot: SanctionsSnapshot | None = None
        self._lock = asyncio.Lock()

    async def snapshot(self) -> SanctionsSnapshot:
        async with self._lock:
            if self._snapshot and datetime.now(UTC) - self._snapshot.fetched_at < _TTL:
                return self._snapshot
            async with httpx.AsyncClient(timeout=25, follow_redirects=True, headers=_HEADERS) as client:
                replies = await asyncio.gather(*(client.get(url) for url in _FEEDS.values()), return_exceptions=True)
            files = {}
            errors = []
            for label, reply in zip(_FEEDS, replies, strict=True):
                if isinstance(reply, httpx.RequestError):
                    errors.append(f"{label}: {type(reply).__name__}")
                elif isinstance(reply, BaseException):
                    raise reply
                elif reply.status_code != 200:
                    errors.append(f"{label}: HTTP {reply.status_code}")
                else:
                    files[label] = reply.content
            if errors:
                raise SanctionsUnavailable(", ".join(errors))
            self._snapshot = await asyncio.to_thread(_build_snapshot, files)
            return self._snapshot
