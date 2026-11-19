"""Веб-поиск как пополняемый источник фактов.

Честный конвейер: реальный HTTP-запрос → парсинг HTML → находки.
Каждая находка — PendingFact с ОБЯЗАТЕЛЬНОЙ ссылкой на страницу.
В скоринг находки не попадают: карантин решает человек.

Это прототип уровня trust=mention. Фальшивых фактов не создаёт:
что нашлось в HTML, то и вернётся, с сырыми ссылками.
"""

import re
import base64
import binascii
import time
from collections import OrderedDict
from concurrent.futures import Future
from copy import deepcopy
from threading import Lock, Semaphore
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from hashlib import sha256
from html import unescape
from urllib.parse import parse_qs, unquote, urlparse
from xml.etree import ElementTree

import httpx
import structlog
from selectolax.parser import HTMLParser

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.search_budget import SearchBudgetExceeded, reserve_yandex_attempt, search_budget

SEARCH_URL = "https://lite.duckduckgo.com/lite/"
YAHOO_SEARCH_URL = "https://search.yahoo.com/search"
NEWS_SEARCH_URL = "https://news.google.com/rss/search"
YANDEX_SEARCH_URL = "https://searchapi.api.cloud.yandex.net/v2/web/search"
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
log = structlog.get_logger()
_SEARCH_LOCK = Lock()
_SEARCH_GATE = Semaphore(2)
_YANDEX_RATE_LOCK = Lock()
_YANDEX_NEXT_REQUEST = 0.0
_SEARCH_CACHE: OrderedDict[tuple, tuple[float, list[dict]]] = OrderedDict()
_SEARCH_PENDING: dict[tuple, Future] = {}


def clear_search_cache() -> None:
    with _SEARCH_LOCK:
        _SEARCH_CACHE.clear()

# Домены, которые не считаем первоисточником (агрегаторы новостей
# не проверяемые страницы).
_SKIP_HOSTS = {"duckduckgo.com", "google.com", "search.yahoo.com"}


class SearchUnavailable(RuntimeError):
    """Поисковый источник не вернул выдачу в распознаваемом формате."""


class SearchResults(list):
    """Usable hits with an explicit warning when some result cards are broken."""

    def __init__(self, items=(), *, partial_reason: str | None = None):
        super().__init__(items)
        self.partial_reason = partial_reason


def _checked_results(hits: list[dict], rejected: int, provider: str) -> SearchResults:
    usable = [hit for hit in hits if (hit.get("title") or "").strip() or (hit.get("snippet") or "").strip()]
    rejected += len(hits) - len(usable)
    hits = usable
    if rejected and not hits:
        raise SearchUnavailable(f"{provider}: все карточки результатов повреждены")
    return SearchResults(hits, partial_reason=(f"{provider}: повреждено карточек — {rejected}" if rejected else None))


def _check_challenge(html: str, provider: str) -> None:
    tree = HTMLParser(html)
    if tree.css_first('.anomaly-modal, #challenge-form, form[action*="captcha"], form[action*="challenge"]'):
        raise SearchUnavailable(f"{provider}: проверка бота вместо выдачи")


def _result_url(href: str) -> str | None:
    url = unescape(href).strip()
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = parsed.hostname or ""
    if (not host or host == "duckduckgo.com" or host.endswith(".duckduckgo.com")) and parsed.path == "/l/":
        url = (parse_qs(parsed.query).get("uddg") or [""])[0]
    elif host == "r.search.yahoo.com":
        match = re.search(r"/RU=(.+?)/RK=", parsed.path)
        url = unquote(match.group(1)) if match else ""

    try:
        target = urlparse(url)
    except ValueError:
        return None
    host = target.hostname
    if target.scheme not in {"http", "https"} or not host:
        return None
    if any(host == skip or host.endswith("." + skip) for skip in _SKIP_HOSTS):
        return None
    if (host == "yandex.ru" or host.endswith((".yandex.ru", ".yandex.com"))) and target.path.startswith("/search"):
        return None
    return url


def _parse_duckduckgo(html: str) -> list[dict]:
    _check_challenge(html, "DuckDuckGo Lite")
    # Lite иногда возвращает невалидную таблицу. Сниппет ищем между соседними
    # ссылками, чтобы результат без сниппета не сдвигал последующие описания.
    links = list(re.finditer(
        r"""<a\b(?=[^>]*\bclass=['"]result-link['"])[^>]*\bhref=['"]([^'"]+)['"][^>]*>(.*?)</a>""",
        html,
        re.S,
    ))
    if not links and not re.search(r"no results (?:found|for)", html, re.I):
        raise SearchUnavailable("DuckDuckGo Lite: нет распознаваемой выдачи")

    results: list[dict] = []
    starts = len(re.findall(r"""<a\b[^>]*\bclass=['"]result-link['"]""", html, re.I))
    rejected = max(0, starts - len(links))
    for index, link in enumerate(links):
        url = _result_url(link.group(1))
        if not url:
            rejected += 1
            continue
        end = links[index + 1].start() if index + 1 < len(links) else len(html)
        snippet = re.search(r"""class=['"]result-snippet['"][^>]*>(.*?)</td>""", html[link.end():end], re.S)
        results.append({
            "title": HTMLParser(link.group(2)).text().strip(),
            "url": url,
            "snippet": HTMLParser(snippet.group(1)).text().strip() if snippet else "",
        })
    return _checked_results(results, rejected, "DuckDuckGo Lite")


def _parse_yahoo(html: str) -> list[dict]:
    _check_challenge(html, "Yahoo Search")
    tree = HTMLParser(html)
    cards = tree.css(".algo-sr")
    if not cards:
        empty = tree.css_first(".no-results, .noResults")
        if empty is None or not re.search(r"no results|did not find|not find|ничего не|не найден", empty.text(), re.I):
            raise SearchUnavailable("Yahoo Search: нет распознаваемой выдачи")

    results: list[dict] = []
    rejected = 0
    for card in cards:
        heading = card.css_first(".compTitle h3")
        if heading is None:
            rejected += 1
            continue
        anchor = heading.parent if heading.parent.tag == "a" else heading.css_first("a")
        url = _result_url(anchor.attributes.get("href", "")) if anchor else None
        if not url:
            rejected += 1
            continue
        snippet = card.css_first(".compText")
        results.append({
            "title": heading.text().strip(),
            "url": url,
            "snippet": snippet.text(separator=" ", strip=True) if snippet else "",
        })
    return _checked_results(results, rejected, "Yahoo Search")


def _request_yahoo(query: str, timeout: float) -> httpx.Response:
    for attempt in range(3):
        try:
            response = httpx.get(
                YAHOO_SEARCH_URL, params={"p": query}, headers=_HEADERS,
                timeout=timeout, follow_redirects=True,
            )
            if response.status_code not in {500, 502, 503, 504} or attempt == 2:
                return response
            _log_provider_failure(
                "yahoo", httpx.HTTPStatusError(
                    "temporary search failure", request=response.request, response=response,
                ),
            )
        except httpx.TransportError as exc:
            if attempt == 2:
                raise
            _log_provider_failure("yahoo", exc)
        time.sleep(0.5 * (attempt + 1))
    raise SearchUnavailable("Yahoo Search: временный отказ")


def _search_yandex(query: str, limit: int, timeout: float) -> list[dict]:
    key = settings.yandex_search_api_key.strip()
    folder = settings.yandex_search_folder_id.strip()
    if not key or not folder:
        raise SearchUnavailable("Для Yandex Search API нужны YANDEX_SEARCH_API_KEY и YANDEX_SEARCH_FOLDER_ID")
    try:
        for attempt in range(3):
            _reserve_yandex_request_slot()
            log.debug("paid_search_http_attempt", provider="yandex_search_api", attempt=attempt + 1)
            try:
                response = httpx.post(
                    YANDEX_SEARCH_URL,
                    headers={"Authorization": f"Api-Key {key}"},
                    json={
                        "query": {"searchType": "SEARCH_TYPE_RU", "queryText": query},
                        "folderId": folder,
                        "responseFormat": "FORMAT_XML",
                        "groupSpec": {
                            "groupMode": "GROUP_MODE_FLAT",
                            "groupsOnPage": str(min(limit, 100)), "docsInGroup": "1",
                        },
                    },
                    timeout=max(timeout, 15),
                )
                response.raise_for_status()
                break
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code not in {408, 500, 502, 503, 504}:
                    raise
                if attempt == 2:
                    raise
                reason = f"HTTP {exc.response.status_code}" if isinstance(exc, httpx.HTTPStatusError) else type(exc).__name__
                ledger.record("yandex_search_api", "web_search", "failed", reason)
                time.sleep(0.5 * (attempt + 1))
        payload = response.json()
        raw = payload.get("rawData") if isinstance(payload, dict) else None
        if not isinstance(raw, str):
            raise ValueError("нет XML в rawData")
        root = ElementTree.fromstring(base64.b64decode(raw, validate=True))
        if root.tag != "yandexsearch" or root.find("response") is None:
            raise ValueError("неизвестная схема XML")
        error = root.find(".//error")
        if error is not None:
            if error.get("code") == "15":
                return []
            raise ValueError(f"ошибка поискового API {error.get('code')}")
        hits = []
        rejected = 0
        for doc in root.findall(".//doc"):
            url = _result_url(doc.findtext("url", ""))
            if not url:
                rejected += 1
                continue
            title = doc.find("title")
            hits.append({
                "title": "".join(title.itertext()) if title is not None else "",
                "url": url,
                "snippet": " ".join("".join(p.itertext()) for p in doc.findall(".//passage")),
            })
        if not hits and (root.find(".//found") is None or root.findtext(".//found", "").strip() != "0"):
            raise ValueError("нет результатов или подтверждения пустой выдачи")
        return _checked_results(hits[:limit], rejected, "Yandex Search API")
    except (httpx.HTTPError, ValueError, binascii.Error, ElementTree.ParseError) as exc:
        reason = f"HTTP {exc.response.status_code}" if isinstance(exc, httpx.HTTPStatusError) else type(exc).__name__
        raise SearchUnavailable(f"Yandex Search API: {reason}") from exc


def _reserve_yandex_request_slot() -> None:
    """Space starts across threads for the default one-request/second quota."""
    global _YANDEX_NEXT_REQUEST
    with _YANDEX_RATE_LOCK:
        delay = _YANDEX_NEXT_REQUEST - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        reserve_yandex_attempt()
        _YANDEX_NEXT_REQUEST = time.monotonic() + 1.05


def search_web(
    query: str, limit: int = 5, timeout: float = 5.0, retries: int = 1,
    retry_delay: float = 0.5, *, raise_on_unavailable: bool = False,
) -> list[dict]:
    with search_budget(settings.yandex_search_budget_rub):
        return _search_web_cached(query, limit, timeout, retries, retry_delay,
                                  raise_on_unavailable=raise_on_unavailable)


def _search_web_cached(
    query: str, limit: int = 5, timeout: float = 5.0, retries: int = 1,
    retry_delay: float = 0.5, *, raise_on_unavailable: bool = False,
) -> list[dict]:
    """Reuse identical successful searches and bound concurrent provider calls."""
    if limit <= 0:
        return []
    configured = bool(settings.yandex_search_api_key or settings.yandex_search_folder_id)
    mode = settings.yandex_search_mode
    provider = f"yandex_{mode}" if configured and mode != "disabled" else "html"
    account = sha256(
        f"{settings.yandex_search_folder_id}\0{settings.yandex_search_api_key}".encode()
    ).hexdigest() if provider != "html" else ""
    key = (provider, account, query, limit, timeout, retries, retry_delay)
    with _SEARCH_LOCK:
        cached = _SEARCH_CACHE.get(key)
        if cached and cached[0] > time.monotonic():
            _SEARCH_CACHE.move_to_end(key)
            ledger.record("web_search_cache", "web_search", "ok" if cached[1] else "empty", cached=True)
            return deepcopy(cached[1])
        pending = _SEARCH_PENDING.get(key)
        owner = pending is None
        if owner:
            pending = Future()
            _SEARCH_PENDING[key] = pending
    try:
        if owner:
            try:
                with _SEARCH_GATE:
                    use_paid = configured and mode == "primary"
                    if not use_paid:
                        try:
                            hits = _search_web(query, limit, timeout, retries, retry_delay, raise_on_unavailable=True)
                        except SearchUnavailable:
                            if not configured or mode == "disabled":
                                raise
                            use_paid = True
                    if use_paid:
                        log.info("paid_search_requested", provider="yandex_search_api", mode=mode,
                                 reason="free_sources_unavailable" if mode == "fallback" else "explicit_primary")
                        hour = datetime.now(timezone(timedelta(hours=3))).hour
                        price = 0.366 if hour < 8 else 0.488
                        try:
                            hits = _search_yandex(query, limit, timeout)
                        except SearchBudgetExceeded as exc:
                            raise SearchUnavailable(str(exc)) from exc
                        except SearchUnavailable as exc:
                            ledger.record("yandex_search_api", "web_search", "failed", str(exc))
                            raise
                        # Public synchronous RU tariff, VAT included. This is
                        # an estimate for successful responses, not billing data.
                        ledger.record("yandex_search_api", "web_search", "ok" if hits else "empty",
                                      estimated_cost_rub=price, partial_reason=getattr(hits, "partial_reason", None))
                with _SEARCH_LOCK:
                    if not getattr(hits, "partial_reason", None):
                        _SEARCH_CACHE[key] = (time.monotonic() + 300, deepcopy(hits))
                        _SEARCH_CACHE.move_to_end(key)
                    while len(_SEARCH_CACHE) > 256:
                        _SEARCH_CACHE.popitem(last=False)
                pending.set_result(hits)
            except BaseException as exc:
                pending.set_exception(exc)
            finally:
                with _SEARCH_LOCK:
                    _SEARCH_PENDING.pop(key, None)
        hits = deepcopy(pending.result())
        if not owner:
            ledger.record("web_search_cache", "web_search", "ok" if hits else "empty", cached=True,
                          partial_reason=getattr(hits, "partial_reason", None))
        return hits
    except SearchUnavailable:
        if raise_on_unavailable:
            raise
        return []


def _search_web(
    query: str, limit: int = 5, timeout: float = 5.0, retries: int = 1,
    retry_delay: float = 0.5, *, raise_on_unavailable: bool = False,
) -> list[dict]:
    """Веб-поиск со вторым источником при сетевом отказе или блокировке выдачи."""
    if limit <= 0:
        return []
    for attempt in range(retries):
        try:
            response = httpx.post(
                SEARCH_URL, data={"q": query}, headers=_HEADERS,
                timeout=timeout, follow_redirects=True,
            )
            if response.status_code == 202:
                raise SearchUnavailable("DuckDuckGo Lite: HTTP 202")
            response.raise_for_status()
            parsed = _parse_duckduckgo(response.text)
            hits = SearchResults(parsed[:limit], partial_reason=parsed.partial_reason)
            ledger.record("duckduckgo", "web_search", "ok" if hits else "empty", partial_reason=hits.partial_reason)
            return hits
        except (httpx.HTTPError, SearchUnavailable) as exc:
            _log_provider_failure("duckduckgo", exc)

        try:
            response = _request_yahoo(query, timeout)
            response.raise_for_status()
            parsed = _parse_yahoo(response.text)
            hits = SearchResults(parsed[:limit], partial_reason=parsed.partial_reason)
            ledger.record("yahoo", "web_search", "ok" if hits else "empty", partial_reason=hits.partial_reason)
            return hits
        except (httpx.HTTPError, SearchUnavailable) as exc:
            _log_provider_failure("yahoo", exc)

        if attempt + 1 < retries:
            time.sleep(retry_delay)

    if raise_on_unavailable:
        raise SearchUnavailable("Источники веб-поиска недоступны.")
    log.debug("web_search_unavailable")
    return []


def _log_provider_failure(provider: str, error: Exception) -> None:
    reason = f"HTTP {error.response.status_code}" if isinstance(error, httpx.HTTPStatusError) else type(error).__name__
    if provider in ("duckduckgo", "yahoo"):
        if isinstance(error, SearchUnavailable):
            reason = str(error)
        ledger.record(provider, "web_search", "failed", reason)
    log.debug("web_search_provider_failed", provider=provider, error=reason)


def search_news(query: str, limit: int = 5, timeout: float = 5.0) -> list[dict]:
    """Поиск публикаций и метаданных СМИ через Google News RSS."""
    if limit <= 0:
        return []
    response = httpx.get(
        NEWS_SEARCH_URL, params={"q": query, "hl": "ru", "gl": "RU", "ceid": "RU:ru"},
        headers=_HEADERS, timeout=timeout, follow_redirects=True,
    )
    response.raise_for_status()
    root = ElementTree.fromstring(response.content)
    channel = root.find("channel")
    if root.tag != "rss" or channel is None:
        raise SearchUnavailable("Google News: отсутствует канал RSS")

    results: list[dict] = []
    rejected = 0
    for item in channel.findall("item"):
        url = item.findtext("link", "").strip()
        title = item.findtext("title", "").strip()
        try:
            parsed = urlparse(url)
        except ValueError:
            rejected += 1
            continue
        if not title or parsed.scheme not in {"http", "https"} or not parsed.hostname:
            rejected += 1
            continue

        source = item.find("source")
        publisher = (source.text or "").strip() if source is not None else ""
        publisher_url = source.get("url", "") if source is not None else ""
        if publisher and title.endswith(f" - {publisher}"):
            title = title.removesuffix(f" - {publisher}")

        published_at = item.findtext("pubDate", "")
        try:
            date = parsedate_to_datetime(published_at).strftime("%d.%m.%Y")
        except ValueError:
            date = None
        results.append({
            "url": url,
            "title": title,
            "snippet": "",
            "publisher": publisher,
            "publisher_url": publisher_url,
            "published_date": date,
        })
        if len(results) >= limit:
            break
    return _checked_results(results, rejected, "Google News RSS")


def make_pending_facts(
    query: str, hits: list[dict], kind: str,
    now: datetime | None = None,
) -> list[PendingFact]:
    """Сырые находки → карантинные факты. Ссылка обязательна: без URL
    находка не превращается в факт — это проверка честности конвейера."""
    now = now or datetime.now(timezone.utc)
    facts: list[PendingFact] = []
    for hit in hits:
        url = hit.get("url")
        if not url:
            continue
        source_id = sha256(url.encode("utf-8")).hexdigest()[:16]
        facts.append(PendingFact(
            fact_id=f"SRCH-{source_id}",
            kind=kind,
            statement=": ".join(part for part in (hit.get("title"), hit.get("snippet")) if part),
            source_url=url,
            found_by="web_search",
            trust="mention",
            found_at=now,
        ))
    return SearchResults(facts, partial_reason=getattr(hits, "partial_reason", None))


def search_pending(query: str, kind: str, limit: int = 5) -> list[PendingFact]:
    """Поиск → карантин. Пример: search_pending('ООО Ромашка собаки', 'dog_connection')."""
    if kind == "news_mention":
        try:
            return make_pending_facts(query, search_news(query, limit), kind)
        except (httpx.HTTPError, ElementTree.ParseError, SearchUnavailable) as exc:
            _log_provider_failure("google_news", exc)
    return make_pending_facts(query, search_web(query, limit, raise_on_unavailable=True), kind)
