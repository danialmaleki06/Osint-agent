"""Обогащение по собственному сайту компании: возраст домена, технологии, SSL и самоназвание.

Приёмы цифрового следа (бесплатные косвенные сигналы):
  * дата создания домена (WHOIS через порт 43 — протокол без ключей и квот);
  * проверка SSL-сертификата (срок действия, эмитент, валидность);
  * стек технологий и маркетинга (аналитика, рекламные пиксели, CRM-виджеты, CMS);
  * H1 и meta description главной страницы — как компания называет себя сама.

Источник опционален: любой отказ — пустой результат с reason, никогда не сбой проверки.
"""

import asyncio
import re
import socket
import ssl
from datetime import UTC, date, datetime

import httpx
import structlog
from selectolax.parser import HTMLParser

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.context.registry_http import resolve_public_ipv4
from osint_mcp.models import SiteTechInfo, SslInfo

log = structlog.get_logger()

# WHOIS-серверы по зонам: .ru и .рф обслуживает tcinet.
_WHOIS_SERVERS = {
    "ru": "whois.tcinet.ru",
    "xn--p1ai": "whois.tcinet.ru",
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
    # отрезаем порт, если указан
    if ":" in host:
        host = host.split(":", 1)[0]
    return host


def _query_whois(domain: str, server: str, bind: str | None = None) -> str:
    """Синхронный WHOIS-запрос через порт 43."""
    local_address = (bind, 0) if bind is not None else None
    with socket.create_connection(
        (server, 43), timeout=settings.request_timeout, source_address=local_address,
    ) as s:
        s.sendall((domain + "\r\n").encode())
        chunks = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


async def domain_age(url: str | None) -> tuple[date | None, str | None]:
    """Дата создания домена сайта. (None, None) — домена просто нет."""
    domain = _domain_of(url)
    if not domain:
        return None, None
    try:
        ascii_domain = domain.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return None, "Некорректное имя домена для WHOIS"
    if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", ascii_domain, re.ASCII):
        return None, "Некорректное имя домена для WHOIS"
    tld = ascii_domain.rsplit(".", 1)[-1]
    server = _WHOIS_SERVERS.get(tld)
    if server is None:
        return None, f"WHOIS для зоны .{tld} не настроен"

    service, method = "whois", "domain_age"

    try:
        bind = settings.registry_bind_ipv4
        if bind is None:
            text = await asyncio.to_thread(_query_whois, ascii_domain, server)
        else:
            address = await resolve_public_ipv4(server, str(bind))
            text = await asyncio.to_thread(_query_whois, ascii_domain, address, str(bind))
    except (OSError, httpx.HTTPError, ValueError) as e:
        ledger.record(service, method, "failed", f"сеть: {type(e).__name__}")
        return None, f"WHOIS недоступен: {type(e).__name__}"

    created: date | None = None
    for line in text.splitlines():
        field, delimiter, value = line.partition(":")
        if not delimiter or field.strip().casefold() != "created":
            continue
        raw = value.strip()
        raw = raw.split()[0] if raw else ""
        try:
            created = datetime.fromisoformat(raw).date()
            break
        except ValueError:
            continue
    if created is None:
        ledger.record(service, method, "empty")
        return None, None
    ledger.record(service, method, "ok")
    return created, None


def _check_ssl_sync(hostname: str, address: str | None = None, bind: str | None = None) -> SslInfo:
    """Синхронная проверка SSL-сертификата хоста на 443 порту."""
    ctx = ssl.create_default_context()
    with socket.create_connection(
        (address or hostname, 443), timeout=settings.request_timeout,
        source_address=(bind, 0) if bind else None,
    ) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            issuer_name = None
            for rdn in cert.get("issuer", ()):
                for k, v in rdn:
                    if k in ("organizationName", "commonName") and v:
                        issuer_name = v
                        break
                if issuer_name:
                    break

            not_after = cert.get("notAfter")
            if not_after:
                exp_ts = ssl.cert_time_to_seconds(not_after)
                exp_date = datetime.fromtimestamp(exp_ts, tz=UTC).date()
                days_left = (exp_date - date.today()).days
            else:
                exp_date = None
                days_left = None

            return SslInfo(
                valid=True,
                issuer=issuer_name,
                expires_at=exp_date,
                days_left=days_left,
            )


async def ssl_info(url: str | None) -> tuple[SslInfo | None, str | None]:
    """Проверка SSL-сертификата сайта (срок действия, эмитент, валидность)."""
    domain = _domain_of(url)
    if not domain:
        return None, None

    service, method = "ssl", "check"
    try:
        bind = settings.registry_bind_ipv4
        if bind is None:
            info = await asyncio.to_thread(_check_ssl_sync, domain)
        else:
            address = await resolve_public_ipv4(domain, str(bind))
            info = await asyncio.to_thread(_check_ssl_sync, domain, address, str(bind))
        ledger.record(service, method, "ok")
        return info, None
    except ssl.SSLCertVerificationError as e:
        ledger.record(service, method, "failed", "недействительный сертификат")
        return SslInfo(valid=False, error=f"Сертификат не прошёл проверку: {e}"), None
    except (OSError, httpx.HTTPError, ValueError) as e:
        ledger.record(service, method, "failed", f"сеть: {type(e).__name__}")
        return None, f"SSL-порт недоступен: {type(e).__name__}"


# Сигнатуры для детекции технологий на веб-странице
_ANALYTICS_RULES: tuple[tuple[str, str], ...] = (
    ("mc.yandex.ru", "Яндекс.Метрика"),
    ("yandex.metrika", "Яндекс.Метрика"),
    ("googletagmanager.com", "Google Tag Manager"),
    ("google-analytics.com", "Google Analytics"),
    ("top-fwz1.mail.ru", "VK/Mail.ru счетчик"),
    ("vk-pixel", "VK Рекламный пиксель"),
    ("vk.com/rtrg", "VK Рекламный пиксель"),
    ("roistat", "Roistat (сквозная аналитика)"),
)

_CRM_RULES: tuple[tuple[str, str], ...] = (
    ("bitrix24", "Битрикс24 (CRM-виджет)"),
    ("b24-", "Битрикс24 (CRM-виджет)"),
    ("b24.ru", "Битрикс24 (CRM-виджет)"),
    ("jivosite", "Jivo (онлайн-консультант)"),
    ("code.jivo.ru", "Jivo (онлайн-консультант)"),
    ("carrotquest", "Carrot quest"),
    ("calltouch", "Calltouch (коллтрекинг)"),
    ("envybox", "Envybox (виджет)"),
    ("mango-office", "Mango Office"),
    ("amocrm", "amoCRM (виджет)"),
)

_CMS_RULES: tuple[tuple[str, str], ...] = (
    ("bitrix/templates", "1C-Битрикс"),
    ("bitrix/js", "1C-Битрикс"),
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("tilda.ws", "Tilda"),
    ("tilda-blocks", "Tilda"),
    ("opencart", "OpenCart"),
    ("shopify", "Shopify"),
    ("webflow", "Webflow"),
)


def extract_tracker_ids(html: str) -> dict[str, list[str]]:
    """Извлечение идентификаторов счетчиков аналитики (Яндекс.Метрика, Google Analytics, VK/Mail.ru)."""
    trackers: dict[str, list[str]] = {}
    if not html:
        return trackers

    # 1. Яндекс.Метрика (mc.yandex.ru/watch/XXXX, ym(XXXX, "init"), w.yaCounterXXXX)
    ym_patterns = [
        r"ym\(\s*(\d{6,10})\s*,",
        r"yaCounter(\d{6,10})",
        r"mc\.yandex\.ru/watch/(\d{6,10})",
        r"mc\.yandex\.ru/metrika/tag\.js\?id=(\d{6,10})",
    ]
    ym_ids: set[str] = set()
    for pat in ym_patterns:
        for match in re.finditer(pat, html, flags=re.IGNORECASE):
            ym_ids.add(match.group(1))
    if ym_ids:
        trackers["yandex_metrika"] = sorted(ym_ids)

    # 2. Google Analytics (UA-XXXXX-Y, G-XXXXXXX, GT-XXXXXXX)
    ga_patterns = [
        r"\b(UA-\d+-\d+)\b",
        r"\b(G-[A-Z0-9]{6,12})\b",
        r"\b(GT-[A-Z0-9]{6,12})\b",
    ]
    ga_ids: set[str] = set()
    for pat in ga_patterns:
        for match in re.finditer(pat, html, flags=re.IGNORECASE):
            ga_ids.add(match.group(1).upper())
    if ga_ids:
        trackers["google_analytics"] = sorted(ga_ids)

    # 3. VK / Mail.ru Top counter (_tmr.push({id: "XXXX"}), top-fwz1.mail.ru/js/code.js?id=XXXX)
    tmr_patterns = [
        r"_tmr\.push\(\s*\{\s*id:\s*['\"](\d{5,10})['\"]",
        r"top-fwz1\.mail\.ru/(?:counter|js/code\.js)\?id=(\d{5,10})",
    ]
    tmr_ids: set[str] = set()
    for pat in tmr_patterns:
        for match in re.finditer(pat, html, flags=re.IGNORECASE):
            tmr_ids.add(match.group(1))
    if tmr_ids:
        trackers["mailru_top"] = sorted(tmr_ids)

    return trackers


def detect_site_tech(html: str) -> SiteTechInfo:
    """Анализ HTML-страницы на наличие технологий, CMS, CRM и маркетинговых пикселей."""
    lowered = (html or "").lower()
    analytics: list[str] = []
    crm: list[str] = []
    cms: list[str] = []

    for needle, label in _ANALYTICS_RULES:
        if needle in lowered and label not in analytics:
            analytics.append(label)

    for needle, label in _CRM_RULES:
        if needle in lowered and label not in crm:
            crm.append(label)

    for needle, label in _CMS_RULES:
        if needle in lowered and label not in cms:
            cms.append(label)

    trackers = extract_tracker_ids(html)
    if trackers.get("yandex_metrika") and "Яндекс.Метрика" not in analytics:
        analytics.append("Яндекс.Метрика")
    if trackers.get("google_analytics") and "Google Analytics" not in analytics:
        analytics.append("Google Analytics")
    if trackers.get("mailru_top") and "VK/Mail.ru счетчик" not in analytics:
        analytics.append("VK/Mail.ru счетчик")

    marketing_active = bool(
        len(analytics) >= 2 or any("roistat" in a.lower() for a in analytics) or bool(trackers)
    )

    return SiteTechInfo(
        analytics=analytics,
        crm_widgets=crm,
        cms=cms,
        marketing_active=marketing_active,
        tracker_ids=trackers,
    )


async def inspect_site_content(
    url: str | None,
) -> tuple[str | None, SiteTechInfo | None, str | None]:
    """Загрузить главную страницу, определить самоназвание и технологический стек."""
    if not url:
        return None, None, None

    clean_url = url.strip()
    if not clean_url:
        return None, None, None

    candidates: list[str] = []
    if clean_url.startswith(("http://", "https://")):
        candidates.append(clean_url)
    else:
        candidates.append(f"https://{clean_url}")
        candidates.append(f"http://{clean_url}")

    service, method = "site", "inspect"
    resp = None
    last_err: Exception | None = None

    try:
        async with httpx.AsyncClient(
            timeout=settings.request_timeout,
            headers={"User-Agent": _UA},
            follow_redirects=True,
            verify=True,
        ) as client:
            for candidate in candidates:
                for attempt in range(3):
                    try:
                        r = await client.get(candidate)
                        r.raise_for_status()
                        resp = r
                        break
                    except (httpx.HTTPError, ValueError, ssl.SSLError, OSError) as e:
                        last_err = e
                        transient = isinstance(e, httpx.TransportError)
                        if isinstance(e, httpx.HTTPStatusError):
                            transient = e.response.status_code in {408, 500, 502, 503, 504}
                        # Certificate failures require correction, not repeated requests.
                        if "CERTIFICATE_VERIFY_FAILED" in str(e):
                            transient = False
                        if not transient or attempt == 2:
                            break
                        await asyncio.sleep(0.5 * (attempt + 1))
                if resp is not None:
                    break
    except Exception as e:  # noqa: BLE001
        last_err = e

    if resp is None:
        err_msg = f"{type(last_err).__name__}" if last_err else "недоступен"
        ledger.record(service, method, "failed", err_msg)
        return None, None, f"сайт недоступен: {err_msg}"

    tree = HTMLParser(resp.text)
    h1 = tree.css_first("h1")
    meta = tree.css_first('meta[name="description"]')
    text = None
    if h1 and h1.text(strip=True):
        text = h1.text(strip=True)
    elif meta and meta.attributes.get("content"):
        text = meta.attributes["content"].strip()

    tech = detect_site_tech(resp.text)
    ledger.record(service, method, "ok")
    return (text[:200] if text else None), tech, None


async def site_self_description(url: str | None) -> tuple[str | None, str | None]:
    """Как компания называет себя: H1 или meta description главной (обратная совместимость)."""
    text, _, err = await inspect_site_content(url)
    return text, err
