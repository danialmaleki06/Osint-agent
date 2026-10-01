"""Обогащение по собственному сайту компании: возраст домена и самоназвание.

Два бесплатных приёма, оба — косвенные сигналы, а не факты:

  * дата создания домена (WHOIS через порт 43 — протокол без ключей и
    квот). Домен младше обещанного возраста бизнеса значит перерегистрацию:
    под новое юрлицо переписали живой бизнес, вместе с репутацией или
    от долгов. Мёртвый DNS у «действующей» компании — тоже ответ;
  * H1 и meta description главной страницы — как компания называет
    себя сама. Одна строка самопрезентации полезнее десятка строк
    ОКВЭДов: «AI-driven low-code платформа» информативнее «разработка ПО».

Источник опционален во всех смыслах: любой отказ — пустой результат с
reason, никогда не падение проверки.
"""

import asyncio
import socket
from datetime import date, datetime

import httpx
import structlog
from selectolax.parser import HTMLParser

from osint_mcp import ledger
from osint_mcp.config import settings

log = structlog.get_logger()

# WHOIS-серверы по зонам: .ru и .рф обслуживает tcinet. Для прочих зон
# asking whois.iana.org — усложнение, а выгода мала: домены прочих
# зон и так редки у российских контрагентов.
_WHOIS_SERVERS = {
    "ru": "whois.tcinet.ru",
    "рф": "whois.tcinet.ru",
    "su": "whois.tcinet.ru",
}

_UA = "Mozilla/5.0 (compatible; osint-mcp)"


def _domain_of(url: str | None) -> str | None:
    """Имя домена из URL сайта: https://www.bpmsoft.ru/... -> bpmsoft.ru."""
    if not url:
        return None
    host = url.split("//", 1)[-1].split("/", 1)[0].strip().lower()
    host = host.removeprefix("www.")
    if not host or "." not in host:
        return None
    return host


def _query_whois(domain: str, server: str) -> str:
    """Синхронный WHOIS-запрос через порт 43.

    Вынос наружу отдельной функцией: тесты подменяют её через
    monkeypatch, не поднимая настоящий сокет.
    """
    with socket.create_connection((server, 43), timeout=settings.request_timeout) as s:
        s.sendall((domain + "\r\n").encode())
        chunks = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


async def domain_age(url: str | None) -> tuple[date | None, str | None]:
    """Дата создания домена сайта. (None, None) — домена просто нет.

    Отказ сети — (None, reason): молчание источника не путается с
    «домен молодой».
    """
    domain = _domain_of(url)
    if not domain:
        return None, None
    tld = domain.rsplit(".", 1)[-1]
    server = _WHOIS_SERVERS.get(tld)
    if server is None:
        return None, f"WHOIS для зоны .{tld} не настроен"

    service, method = "whois", "domain_age"
    ledger.record(service, method, "started")

    # Запрос выполняется в отдельном потоке: событийный цикл не должен
    # ждать порт 43.
    try:
        text = await asyncio.to_thread(_query_whois, domain, server)
    except OSError as e:
        ledger.record(service, method, "failed", f"сеть: {type(e).__name__}")
        return None, f"WHOIS недоступен: {type(e).__name__}"

    created: date | None = None
    for line in text.splitlines():
        if "created" not in line.lower() or ":" not in line:
            continue
        raw = line.split(":", 1)[1].strip()
        raw = raw.split()[0] if raw else ""
        try:
            created = datetime.fromisoformat(raw).date()
            break
        except ValueError:
            continue
    if created is None:
        # Ответ есть, даты нет: свободный домен или приватный формат —
        # это не отказ, домена у компании действительно нет
        ledger.record(service, method, "empty")
        return None, None
    ledger.record(service, method, "ok")
    return created, None


async def site_self_description(url: str | None) -> tuple[str | None, str | None]:
    """Как компания называет себя: H1 или meta description главной.

    Один запрос, никакой обходной логики: главная, редиректы — ок,
    отказ — reason. Текст режется до пары сотен символов: это
    самоназвание, а не копия сайта.
    """
    if not url:
        return None, None
    service, method = "site", "self_description"
    try:
        async with httpx.AsyncClient(
            timeout=settings.request_timeout, headers={"User-Agent": _UA},
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
        resp.raise_for_status()
    except (httpx.HTTPError, ValueError) as e:
        ledger.record(service, method, "failed", f"{type(e).__name__}")
        return None, f"сайт недоступен: {type(e).__name__}"

    tree = HTMLParser(resp.text)
    h1 = tree.css_first("h1")
    meta = tree.css_first('meta[name="description"]')
    text = None
    if h1 and h1.text(strip=True):
        text = h1.text(strip=True)
    elif meta and meta.attributes.get("content"):
        text = meta.attributes["content"].strip()
    if not text:
        ledger.record(service, method, "empty")
        return None, None
    ledger.record(service, method, "ok")
    return text[:200], None
