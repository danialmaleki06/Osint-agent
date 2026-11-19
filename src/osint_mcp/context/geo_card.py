"""Read a public 2GIS card and verify its link to the company's website."""

import ast
import json
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from threading import Lock
from urllib.parse import quote, urlparse

import httpx
from selectolax.parser import HTMLParser

from osint_mcp import ledger
from osint_mcp.tools.names import core_name


class GeoCardUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class GeoCard:
    url: str
    name: str
    address: str
    rating: float | None
    review_count: int


_STATE = re.compile(r'''\binitialState\s*=\s*JSON\.parse\(\s*('(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")\s*\)''', re.S)
_CACHE: OrderedDict[tuple, tuple[float, GeoCard]] = OrderedDict()
_CACHE_LOCK = Lock()


def _host(url: str) -> str:
    return (urlparse(url if "://" in url else "https://" + url).hostname or "").lower().removeprefix("www.")


def parse_card(html: str, url: str, website: str) -> GeoCard:
    match = _STATE.search(html)
    if not match:
        raise GeoCardUnavailable("2ГИС: неизвестный формат карточки или проверка бота")
    try:
        state = json.loads(ast.literal_eval(match.group(1)))
        card_id = re.search(r"/firm/(\d+)", url).group(1)
        data = state["data"]["entity"]["profile"][card_id]["data"]
        if str(data["id"]) != card_id or data["type"] != "branch":
            raise ValueError("не карточка организации")
        target = _host(website)
        contacts = [contact for group in data.get("contact_groups", []) for contact in group.get("contacts", [])]
        if not target or not any(contact.get("type") == "website" and _host(contact.get("url") or "") == target for contact in contacts):
            raise GeoCardUnavailable("2ГИС: принадлежность карточки компании не подтверждена по сайту")
        name, address = data["name"], data["address_name"]
        if not isinstance(name, str) or not name.strip() or not isinstance(address, str) or not address.strip():
            raise ValueError("не указаны название или адрес")
        reviews = data.get("reviews") or {}
        rating = reviews.get("general_rating")
        if rating is not None:
            rating = float(rating)
            if not 0 <= rating <= 5:
                raise ValueError("некорректный рейтинг")
        count = int(reviews.get("general_review_count", 0))
        if count < 0:
            raise ValueError("некорректное число отзывов")
        return GeoCard(url, name, address, rating, count)
    except GeoCardUnavailable:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, SyntaxError) as exc:
        raise GeoCardUnavailable("2ГИС: карточка не прошла проверку структуры") from exc


def _get(client: httpx.Client, url: str) -> httpx.Response:
    for attempt in range(3):
        try:
            response = client.get(url)
            response.raise_for_status()
            if response.url.host != "2gis.ru" or len(response.content) > 5_000_000:
                raise GeoCardUnavailable("2ГИС: неожиданное перенаправление или размер страницы")
            return response
        except (httpx.TransportError, httpx.HTTPStatusError) as exc:
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code not in {408, 500, 502, 503, 504}:
                raise
            if attempt == 2:
                raise
            time.sleep(0.5 * (attempt + 1))
    raise GeoCardUnavailable("2ГИС: запрос не завершён")


def fetch_geo_card(company: str, address: str, website: str) -> GeoCard:
    key = (company, address, _host(website))
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
    if cached and cached[0] > time.monotonic():
        ledger.record("2gis", "card", "ok", cached=True)
        return cached[1]
    query = f"{core_name(company) or company} {address}"
    try:
        with httpx.Client(timeout=10, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as client:
            search = _get(client, "https://2gis.ru/search/" + quote(query, safe=""))
            tree = HTMLParser(search.text)
            links = list(dict.fromkeys(
                anchor.attributes["href"] for anchor in tree.css("a[href]")
                if re.fullmatch(r"/[a-z0-9_-]+/firm/\d+", anchor.attributes["href"])
            ))
            if not links:
                raise GeoCardUnavailable("2ГИС: поиск не вернул проверяемую карточку")
            for path in links[:5]:
                url = "https://2gis.ru" + path
                response = _get(client, url)
                try:
                    card = parse_card(response.text, url, website)
                except GeoCardUnavailable:
                    continue
                with _CACHE_LOCK:
                    _CACHE[key] = (time.monotonic() + 300, card)
                    _CACHE.move_to_end(key)
                    while len(_CACHE) > 64:
                        _CACHE.popitem(last=False)
                ledger.record("2gis", "card", "ok")
                return card
        raise GeoCardUnavailable("2ГИС: ни одна карточка не совпала с официальным сайтом")
    except (httpx.HTTPError, GeoCardUnavailable) as exc:
        reason = f"HTTP {exc.response.status_code}" if isinstance(exc, httpx.HTTPStatusError) else str(exc) if isinstance(exc, GeoCardUnavailable) else type(exc).__name__
        ledger.record("2gis", "card", "failed", reason)
        raise GeoCardUnavailable(reason) from exc
