"""Discover customs mentions once, then refresh verified source pages directly."""

import re
import time
from collections import OrderedDict
from threading import Lock
from urllib.parse import urlparse

import httpx
from selectolax.parser import HTMLParser
from osint_mcp import ledger

from osint_mcp.tools.web_search_source import SearchResults, SearchUnavailable, search_web

DOMAINS = {"customs.gov.ru", "stat.customs.gov.ru", "importgenius.com", "statimex.ru"}
_LINKS: OrderedDict[str, tuple[float, list[str]]] = OrderedDict()
_LOCK = Lock()
_TRADE = re.compile(r"импорт|экспорт|таможенн|\bгтд\b|\bimport\b|\bexport\b", re.I)


class PageReadDeadline(ValueError):
    pass


class UnrelatedPage(ValueError):
    pass


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise PageReadDeadline("Исчерпан общий срок чтения первоисточников ВЭД")
    return min(4.0, left)


def _allowed(url: str) -> bool:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return (parsed.scheme == "https" and parsed.port in (None, 443)
                and not parsed.username and not parsed.password
                and any(host == domain or host.endswith("." + domain) for domain in DOMAINS))
    except ValueError:
        return False


def _related(text: str, inn: str) -> bool:
    return bool(re.search(rf"(?<!\d){re.escape(inn)}(?!\d)", text) and _TRADE.search(text))


def _read(url: str, inn: str, deadline: float | None = None) -> dict:
    if not _allowed(url):
        raise ValueError("URL вне списка таможенных источников")
    # Follow redirects manually so an indexed URL cannot send requests to an
    # arbitrary host. Every redirect must stay within the same trusted set.
    deadline = min(deadline if deadline is not None else float("inf"), time.monotonic() + 6)
    with httpx.Client(timeout=4, headers={"User-Agent": "Mozilla/5.0"}) as client:
        target = url
        for _ in range(4):
            for attempt in range(3):
                try:
                    with client.stream("GET", target, timeout=_remaining(deadline)) as incoming:
                        if incoming.status_code in {408, 500, 502, 503, 504}:
                            incoming.raise_for_status()
                        chunks, size = [], 0
                        if not incoming.is_redirect:
                            incoming.raise_for_status()
                            for chunk in incoming.iter_bytes():
                                _remaining(deadline)
                                size += len(chunk)
                                if size > 5_000_000:
                                    raise ValueError("Слишком большая страница")
                                chunks.append(chunk)
                        response = httpx.Response(incoming.status_code, headers=incoming.headers,
                                                  content=b"".join(chunks), request=incoming.request)
                    break
                except (httpx.TransportError, httpx.HTTPStatusError):
                    if attempt == 2:
                        raise
                    time.sleep(min(0.5 * (attempt + 1), _remaining(deadline)))
            if response.is_redirect:
                from urllib.parse import urljoin
                target = urljoin(target, response.headers.get("location", ""))
                if not _allowed(target):
                    raise ValueError("Перенаправление вне списка источников")
                continue
            response.raise_for_status()
            break
        else:
            raise ValueError("Слишком много перенаправлений")
    if len(response.content) > 5_000_000 or "html" not in response.headers.get("content-type", "").lower():
        raise ValueError("Неподдерживаемый формат страницы")
    tree = HTMLParser(response.text)
    for element in tree.css("script, style, nav, footer"):
        element.decompose()
    text = " ".join(tree.text(separator=" ").split())
    if not _related(text, inn):
        raise UnrelatedPage("Страница не подтверждает связанное с ИНН упоминание ВЭД")
    position = text.find(inn)
    title = tree.css_first("title")
    ledger.record("customs_pages", "read", "ok")
    return {"url": target, "title": title.text(strip=True) if title else "Упоминание ВЭД",
            "snippet": text[max(0, position - 150):position + 450], "evidence_type": "source_page"}


def find_customs_mentions(inn: str) -> SearchResults:
    if not inn.isascii() or not inn.isdecimal() or len(inn) not in (10, 12):
        raise SearchUnavailable("Для поиска ВЭД требуется ИНН РФ")
    with _LOCK:
        saved = _LINKS.get(inn)
    if saved and saved[0] > time.monotonic():
        refreshed, errors = [], []
        deadline = time.monotonic() + 12
        for url in saved[1]:
            try:
                refreshed.append(_read(url, inn, deadline))
            except (httpx.HTTPError, ValueError):
                errors.append("Ранее найденная страница не прошла повторную проверку")
        # Reuse only a completely refreshed set; never replace a broken source
        # with its stale body or silently drop it from the next discovery.
        if refreshed and not errors:
            return SearchResults(refreshed)
    sites = " OR ".join(f"site:{domain}" for domain in sorted(DOMAINS))
    query = f'"{inn}" ("декларация" OR "импорт" OR "экспорт" OR "таможенная база" OR "ГТД") ({sites})'
    raw = search_web(query, limit=20, retries=1, raise_on_unavailable=True)
    mentions, verified, notes = [], [], []
    if getattr(raw, "partial_reason", None):
        notes.append(raw.partial_reason)
    deadline = time.monotonic() + 12
    for hit in raw:
        url = hit.get("url") or ""
        if not _allowed(url):
            continue
        try:
            document = _read(url, inn, deadline)
            mentions.append(document)
            verified.append(document["url"])
        except UnrelatedPage:
            continue
        except (httpx.HTTPError, ValueError) as exc:
            notes.append(str(exc) if isinstance(exc, PageReadDeadline) else "Не все страницы первоисточников удалось прочитать")
            text = f"{hit.get('title') or ''} {hit.get('snippet') or ''}"
            if _related(text, inn):
                mentions.append({**hit, "evidence_type": "search_snippet"})
                notes.append("Часть упоминаний доступна только в поисковой выдаче; первоисточник не подтверждён")
    if verified and len(verified) == len(mentions) and not notes:
        with _LOCK:
            _LINKS[inn] = (time.monotonic() + 3600, list(dict.fromkeys(verified)))
            _LINKS.move_to_end(inn)
            while len(_LINKS) > 64:
                _LINKS.popitem(last=False)
    return SearchResults(mentions, partial_reason="; ".join(dict.fromkeys(notes)) if notes else None)
