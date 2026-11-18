"""Веб-поиск как пополняемый источник фактов.

Честный конвейер: реальный HTTP-запрос → парсинг HTML → находки.
Каждая находка — PendingFact с ОБЯЗАТЕЛЬНОЙ ссылкой на страницу.
В скоринг находки не попадают: карантин решает человек.

Это прототип уровня trust=mention. Фальшивых фактов не создаёт:
что нашлось в HTML, то и вернётся, с сырыми ссылками.
"""

import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from hashlib import sha256
from html import unescape
from urllib.parse import parse_qs, unquote, urlparse
from xml.etree import ElementTree

import httpx
import structlog
from selectolax.parser import HTMLParser

from osint_mcp import ledger
from osint_mcp.scoring.models import PendingFact

SEARCH_URL = "https://lite.duckduckgo.com/lite/"
YAHOO_SEARCH_URL = "https://search.yahoo.com/search"
NEWS_SEARCH_URL = "https://news.google.com/rss/search"
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
log = structlog.get_logger()

# Домены, которые не считаем первоисточником (агрегаторы новостей
# не проверяемые страницы).
_SKIP_HOSTS = {"duckduckgo.com", "google.com", "search.yahoo.com"}


class SearchUnavailable(RuntimeError):
    """Поисковый источник не вернул выдачу в распознаваемом формате."""


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
    for index, link in enumerate(links):
        url = _result_url(link.group(1))
        if not url:
            continue
        end = links[index + 1].start() if index + 1 < len(links) else len(html)
        snippet = re.search(r"""class=['"]result-snippet['"][^>]*>(.*?)</td>""", html[link.end():end], re.S)
        results.append({
            "title": HTMLParser(link.group(2)).text().strip(),
            "url": url,
            "snippet": HTMLParser(snippet.group(1)).text().strip() if snippet else "",
        })
    return results


def _parse_yahoo(html: str) -> list[dict]:
    tree = HTMLParser(html)
    cards = tree.css(".algo-sr")
    if not cards and not tree.css_first(".no-results, .noResults"):
        raise SearchUnavailable("Yahoo Search: нет распознаваемой выдачи")

    results: list[dict] = []
    for card in cards:
        heading = card.css_first(".compTitle h3")
        if heading is None:
            continue
        anchor = heading.parent if heading.parent.tag == "a" else heading.css_first("a")
        url = _result_url(anchor.attributes.get("href", "")) if anchor else None
        if not url:
            continue
        snippet = card.css_first(".compText")
        results.append({
            "title": heading.text().strip(),
            "url": url,
            "snippet": snippet.text(separator=" ", strip=True) if snippet else "",
        })
    return results


def search_web(
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
            hits = _parse_duckduckgo(response.text)[:limit]
            ledger.record("duckduckgo", "web_search", "ok" if hits else "empty")
            return hits
        except (httpx.HTTPError, SearchUnavailable) as exc:
            _log_provider_failure("duckduckgo", exc)

        try:
            response = httpx.get(
                YAHOO_SEARCH_URL, params={"p": query}, headers=_HEADERS,
                timeout=timeout, follow_redirects=True,
            )
            response.raise_for_status()
            hits = _parse_yahoo(response.text)[:limit]
            ledger.record("yahoo", "web_search", "ok" if hits else "empty")
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
    channel = ElementTree.fromstring(response.content).find("channel")
    if channel is None:
        raise SearchUnavailable("Google News: отсутствует канал RSS")

    results: list[dict] = []
    for item in channel.findall("item"):
        url = item.findtext("link", "").strip()
        title = item.findtext("title", "").strip()
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        if not title or parsed.scheme not in {"http", "https"} or not parsed.hostname:
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
    return results


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
    return facts


def search_pending(query: str, kind: str, limit: int = 5) -> list[PendingFact]:
    """Поиск → карантин. Пример: search_pending('ООО Ромашка собаки', 'dog_connection')."""
    if kind == "news_mention":
        try:
            return make_pending_facts(query, search_news(query, limit), kind)
        except (httpx.HTTPError, ElementTree.ParseError, SearchUnavailable) as exc:
            _log_provider_failure("google_news", exc)
    return make_pending_facts(query, search_web(query, limit, raise_on_unavailable=True), kind)
