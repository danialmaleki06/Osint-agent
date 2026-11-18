"""Открытые выгрузки ЕРКНМ по контрольным мероприятиям Роспотребнадзора."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from tempfile import TemporaryFile
from typing import BinaryIO
from urllib.parse import urlsplit
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile

import httpx

from osint_mcp.scoring.models import PendingFact

_BASE = "https://proverki.gov.ru"
_API = _BASE + "/public/api/opendata/"
_TTL = timedelta(hours=1)
_MAX_DOWNLOAD = 350 * 1024 * 1024
_MAX_EXPANDED = 3 * 1024 * 1024 * 1024
_FULL_AUTHORITY = "по надзору в сфере защиты прав потребителей и благополучия человека"


class ErknmUnavailable(RuntimeError):
    """Генпрокуратура не предоставила проверяемую выгрузку."""


@dataclass(slots=True)
class ErknmSnapshot:
    period: str
    fetched_at: datetime
    entries: dict[str, list[PendingFact]]
    datasets: list[dict]
    empty_files: list[str]


def _extract_archive(
    archive: BinaryIO, *, period: str, monthly: bool, published: date, url: str,
) -> ErknmSnapshot:
    fetched = datetime.now(UTC)
    matches: dict[str, dict[str, PendingFact]] = {}
    source_id = "rospotrebnadzor_inspections" if monthly else "rospotrebnadzor_plan"
    expected_root = ("{https://proverki.gov.ru/opendata/3.0/20220125}INSPECTIONS" if monthly
                     else "{https://proverki.gov.ru/opendata/3.0/20220115}PLAN")
    total = 0
    rpn_records = 0
    empty_files = []
    with ZipFile(archive) as z:
        xmls = [info for info in z.infolist() if info.filename.endswith(".xml")]
        if not xmls or sum(info.file_size for info in xmls) > _MAX_EXPANDED:
            raise ValueError("неожиданный состав или размер архива")
        for info in xmls:
            if not info.file_size:
                empty_files.append(info.filename)
                continue
            with z.open(info) as xml:
                events = ElementTree.iterparse(xml, events=("start", "end"))
                _, root = next(events)
                year, _, month = period.partition("-")
                if (root.tag != expected_root or root.get("YEAR") != year
                        or (monthly and int(root.get("MONTH", "0")) != int(month))):
                    raise ValueError("неожиданная схема XML или период выгрузки")
                for event, item in events:
                    if event != "end" or not item.tag.endswith("}INSPECTION"):
                        continue
                    total += 1
                    authorities = [a.get("VALUE", "").strip() for a in item.findall("{*}KNO_ORGANIZATION")]
                    authority = next((a for a in authorities if "роспотребнадзор" in a.casefold()
                                      or _FULL_AUTHORITY in a.casefold()), None)
                    if authority:
                        rpn_records += 1
                        number = item.get("ERPID", "").strip()
                        if not number.isascii() or not number.isdecimal():
                            raise ValueError("у мероприятия Роспотребнадзора нет учётного номера")
                        status = item.get("STATUS") or "статус не опубликован"
                        kind = item.get("TYPE_NAME") or "КНМ"
                        start = item.get("START_DATE")
                        subjects = {s.get("INN", "").strip() for s in item.findall("{*}SUBJECT")}
                        for inn in subjects:
                            if len(inn) not in (10, 12) or not inn.isascii() or not inn.isdecimal():
                                continue
                            matches.setdefault(inn, {})[number] = PendingFact(
                                fact_id=f"ERKNM-{number}", kind="rospotrebnadzor_inspection",
                                statement=(f"Роспотребнадзор: {kind} № {number}, {status}"
                                           + (f", начало {start}" if start else "") + "."),
                                # Фрагмент различает записи в карантине. Архив содержит строку с этим ERPID.
                                source_url=f"{url}#ERPID={number}", found_by=source_id, trust="reference",
                                found_at=fetched,
                                payload={"number": number, "inn": inn, "authority": authority,
                                         "status": status, "type": kind, "start_date": start,
                                         "end_date": item.get("STOP_DATE"), "period": period,
                                         "archive_url": url, "published_at": published.isoformat()},
                            )
                    root.remove(item)
                    item.clear()
    if not total:
        raise ValueError("в архиве нет записей о контрольных мероприятиях")
    datasets = [{"source": "ЕРКНМ, Генеральная прокуратура РФ", "scope": source_id,
                 "period": period, "url": url, "published_at": published.isoformat(),
                 "fetched_at": fetched.isoformat(), "total_records": total,
                 "rospotrebnadzor_records": rpn_records, "xml_files": len(xmls), "empty_files": empty_files}]
    entries = {inn: [items[number] for number in sorted(items)] for inn, items in matches.items()}
    return ErknmSnapshot(period, fetched, entries, datasets, empty_files)


class ErknmRegistry:
    def __init__(self, *, monthly: bool = False) -> None:
        self.monthly = monthly
        self._lock = asyncio.Lock()
        self._snapshot: ErknmSnapshot | None = None

    @property
    def note(self) -> str:
        scope = "месячная выгрузка мероприятий" if self.monthly else "годовая выгрузка плановых мероприятий"
        return f"Сверка по ИНН РФ, {scope} по 248-ФЗ. В выдаче только мероприятия Роспотребнадзора."

    async def snapshot(self) -> ErknmSnapshot:
        now = datetime.now(UTC)
        moscow = now + timedelta(hours=3)
        period = moscow.strftime("%Y-%m" if self.monthly else "%Y")
        async with self._lock:
            current = self._snapshot
            if current and current.period == period and now - current.fetched_at < _TTL:
                return current
            path = f"{moscow.year}/{moscow.month}" if self.monthly else f"plans/{moscow.year}"
            try:
                async with httpx.AsyncClient(timeout=25) as client:
                    response = await client.get(_API + path, params={"isFederalLaw248": "true"})
                    data = response.raise_for_status().json()
                    url = data["dataZipUrl"]
                    parsed = urlsplit(url)
                    prefix = "/blob/erknm-opendata/" if self.monthly else "/blob/erknm-plan/"
                    if (parsed.netloc != "proverki.gov.ru" or parsed.scheme != "https"
                            or not ("/" + parsed.path.lstrip("/")).startswith(prefix)
                            or not parsed.path.endswith(".zip")):
                        raise ValueError("неожиданный адрес выгрузки")
                    published = date.fromisoformat(next(item["published"] for item in data["history"]
                                                        if item.get("fileUrl") == url))
                    with TemporaryFile() as archive:
                        size = 0
                        async with client.stream("GET", url) as stream:
                            stream.raise_for_status()
                            async for chunk in stream.aiter_bytes(512 * 1024):
                                size += len(chunk)
                                if size > _MAX_DOWNLOAD:
                                    raise ValueError("архив превышает допустимый размер")
                                archive.write(chunk)
                        archive.seek(0)
                        self._snapshot = await asyncio.to_thread(
                            _extract_archive, archive, period=period, monthly=self.monthly,
                            published=published, url=url,
                        )
            except httpx.HTTPStatusError as exc:
                raise ErknmUnavailable(f"ЕРКНМ: HTTP {exc.response.status_code} при загрузке выгрузки {period}") from exc
            except httpx.RequestError as exc:
                raise ErknmUnavailable(f"ЕРКНМ: {type(exc).__name__} при загрузке выгрузки {period}") from exc
            except (ValueError, TypeError, KeyError, StopIteration, BadZipFile, ElementTree.ParseError, OSError) as exc:
                raise ErknmUnavailable(f"ЕРКНМ: некорректная выгрузка {period} ({type(exc).__name__})") from exc
            return self._snapshot
