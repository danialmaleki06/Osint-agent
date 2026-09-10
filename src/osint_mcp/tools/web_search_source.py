"""Веб-поиск как пополняемый источник фактов.

Честный конвейер: реальный HTTP-запрос → парсинг HTML → находки.
Каждая находка — PendingFact с ОБЯЗАТЕЛЬНОЙ ссылкой на страницу.
В скоринг находки не попадают: карантин решает человек.

Это прототип уровня trust=mention. Фальшивых фактов не создаёт:
что нашлось в HTML, то и вернётся, с сырыми ссылками.
"""

import re
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse, parse_qs

import httpx

from osint_mcp.scoring.models import PendingFact

SEARCH_URL = "https://lite.duckduckgo.com/lite/"
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

# Домены, которые не считаем первоисточником (агрегаторы новостей
# не проверяемые страницы).
_SKIP_HOSTS = {"duckduckgo.com", "google.com", "yandex.ru"}


def _clean_ddg_url(href: str) -> str | None:
    """DuckDuckGo оборачивает ссылки в /l/?uddg=<encoded> — распаковать."""
    if not href:
        return None
    if "uddg=" in href:
        qs = parse_qs(urlparse(href).query)
        target = (qs.get("uddg") or [""])[0]
        return unquote(target) or None
    if href.startswith("http"):
        return href
    return None


def search_web(query: str, limit: int = 5,
               timeout: float = 10.0, retries: int = 3,
               retry_delay: float = 8.0) -> list[dict]:
    """Реальный поиск. Возвращает сырые находки: title, url, snippet.

    DDG троттлит серии запросов с одного IP: после 1-2 быстрых запросов
    начинает отдавать пустую выдачу (len ~8K, без result-link) с HTTP 200.
    Лечится паузой и повтором. Ошибок сети наружу не бросаем: поиск —
    вспомогательный источник, его отказ не роняет проверку.
    """
    html = ""
    for attempt in range(retries):
        try:
            resp = httpx.post(
                SEARCH_URL, data={"q": query}, headers=_HEADERS,
                timeout=timeout, follow_redirects=True,
            )
            resp.raise_for_status()
            html = resp.text
        except httpx.HTTPError:
            return []
        if "result-link" in html:
            break
        if attempt < retries - 1:
            import time
            time.sleep(retry_delay)
    if "result-link" not in html:
        return []

    # selectolax ломает DOM lite-выдачи (невалидная таблица: <tr> без
    # пары <td> местами), поэтому разбор идёт регэкспом по raw HTML.
    # Порядок атрибутов в <a> не фиксирован — пробуем оба.
    links = re.findall(
        r"<a[^>]*class=['\"]result-link['\"][^>]*href=['\"]([^'\"]+)['\"]"
        r"[^>]*>(.*?)</a>", html, re.S)
    if not links:
        links = re.findall(
            r"<a[^>]*href=['\"]([^'\"]+)['\"][^>]*class=['\"]result-link['\"]"
            r"[^>]*>(.*?)</a>", html, re.S)

    # Snippets: <td class="result-snippet"> идёт после своей ссылки.
    snippets = re.findall(
        r"class=['\"]result-snippet['\"][^>]*>(.*?)</td>", html, re.S)

    results: list[dict] = []
    for i, link in enumerate(links[:limit]):
        # Порядок href/title зависит от того, какой из двух регэкспов сработал.
        if isinstance(link, tuple):
            url_raw, title = link
        else:
            url_raw, title = link, ""
        url = _clean_ddg_url(url_raw)
        if not url:
            continue
        host = urlparse(url).netloc.lower()
        if any(host.endswith(skip) for skip in _SKIP_HOSTS):
            continue
        snippet = re.sub(r"<[^>]+>", "", snippets[i]) if i < len(snippets) else ""
        results.append({
            "title": re.sub(r"<[^>]+>", "", title).strip(),
            "url": url,
            "snippet": snippet.strip(),
        })
    return results


def make_pending_facts(
    query: str, hits: list[dict], kind: str,
    now: datetime | None = None,
) -> list[PendingFact]:
    """Сырые находки → карантинные факты. Ссылка обязательна: без URL
    находка не превращается в факт — это проверка честности конвейера."""
    now = now or datetime.now(timezone.utc)
    facts: list[PendingFact] = []
    for i, hit in enumerate(hits, 1):
        if not hit.get("url"):
            continue
        facts.append(PendingFact(
            fact_id=f"SRCH-{i}",
            kind=kind,
            statement=f"{hit.get('title', '')}: {hit.get('snippet', '')}".strip(),
            source_url=hit["url"],
            found_by="web_search",
            trust="mention",
            found_at=now,
        ))
    return facts


def search_pending(query: str, kind: str, limit: int = 5) -> list[PendingFact]:
    """Поиск → карантин. Пример: search_pending('ООО Ромашка собаки', 'dog_connection')."""
    return make_pending_facts(query, search_web(query, limit), kind)
