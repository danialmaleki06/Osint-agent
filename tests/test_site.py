"""Тесты источника обогащения по сайту: WHOIS-возраст домена, самоназвание.

Офлайн: socket-запрос WHOIS и HTTP к сайту подменяются заглушками.
Проверяются парсинг дат tcinet, приоритет H1 над meta, честность отказов.
"""

from ipaddress import IPv4Address
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
import respx

from osint_mcp.context.site import _domain_of, domain_age, site_self_description

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_domain_of_strips_www_and_path():
    assert _domain_of("https://www.bpmsoft.ru/platform/x") == "bpmsoft.ru"
    assert _domain_of("http://cardsmile.ru") == "cardsmile.ru"
    assert _domain_of(None) is None
    assert _domain_of("мусор без точки") is None


async def test_domain_age_parses_tcinet(monkeypatch):
    """Ответ tcinet: строка 'created: ...' — дата извлекается."""
    captured = {}

    def fake_query(domain: str, server: str) -> str:
        captured["domain"] = domain
        captured["server"] = server
        return (
            "domain:     BPMSOFT.RU\n"
            "nserver:    ns1.reg.ru.\n"
            "created:       2023-04-18T10:00:00Z\n"
            "paid-till:     2026-11-08T21:00:10Z\n"
        )

    monkeypatch.setattr("osint_mcp.context.site._query_whois", fake_query)
    created, reason = await domain_age("https://bpmsoft.ru")

    assert reason is None
    assert created is not None and created.year == 2023 and created.month == 4
    assert captured["domain"] == "bpmsoft.ru"
    assert captured["server"] == "whois.tcinet.ru"


async def test_domain_age_unknown_zone_is_reason_not_crash(monkeypatch):
    """Зона без настроенного WHOIS-сервера — честная причина, не ошибка."""
    created, reason = await domain_age("https://example.com")
    assert created is None
    assert reason and "WHOIS" in reason


async def test_domain_age_network_failure_reported(monkeypatch):
    """Отказ сети — (None, reason), молчание не путается с «домен молодой»."""

    def fail_query(domain: str, server: str) -> str:
        raise ConnectionRefusedError()

    monkeypatch.setattr("osint_mcp.context.site._query_whois", fail_query)
    created, reason = await domain_age("https://bpmsoft.ru")
    assert created is None
    assert reason and "WHOIS недоступен" in reason


async def test_domain_age_uses_configured_interface(monkeypatch):
    from osint_mcp.config import settings
    from osint_mcp.context import site

    monkeypatch.setattr(settings, "registry_bind_ipv4", IPv4Address("192.0.2.12"))
    resolver = AsyncMock(return_value="193.232.156.17")
    query = Mock(return_value="domain: BPMSOFT.RU\ncreated: 2023-04-18T10:00:00Z\n")
    monkeypatch.setattr(site, "resolve_public_ipv4", resolver)
    monkeypatch.setattr(site, "_query_whois", query)

    created, reason = await site.domain_age("https://bpmsoft.ru")

    assert reason is None and str(created) == "2023-04-18"
    resolver.assert_awaited_once_with("whois.tcinet.ru", "192.0.2.12")
    query.assert_called_once_with("bpmsoft.ru", "193.232.156.17", "192.0.2.12")


async def test_self_description_prefers_h1_over_meta(respx_mock=None):
    """H1 информативнее meta: берём заголовок, meta — запасной вариант."""
    async with respx.mock:
        respx.get("https://bpmsoft.ru").mock(return_value=httpx.Response(200, text="""
        <html><head>
          <title>Заголовок вкладки</title>
          <meta name="description" content="мета-описание сайта">
        </head><body>
          <h1>AI-driven low-code платформа для автоматизации бизнес-процессов</h1>
          <p>текст страницы</p>
        </body></html>
        """))
        desc, reason = await site_self_description("https://bpmsoft.ru")

    assert reason is None
    assert desc == "AI-driven low-code платформа для автоматизации бизнес-процессов"


async def test_self_description_falls_back_to_meta():
    async with respx.mock:
        respx.get("https://bpmsoft.ru").mock(return_value=httpx.Response(200, text="""
        <html><head>
          <meta name="description" content="Российская low-code платформа BPMSoft">
        </head><body><p>без h1</p></body></html>
        """))
        desc, reason = await site_self_description("https://bpmsoft.ru")

    assert reason is None
    assert desc == "Российская low-code платформа BPMSoft"


async def test_self_description_dead_site_is_reason_not_crash():
    """Мёртвый DNS — (None, reason). Для «действующей» компании это сигнал,
    и он обязан дойти до отчёта, а не утонуть в исключении."""
    async with respx.mock:
        respx.get("http://cardsmile.ru").mock(side_effect=httpx.ConnectError("dns"))
        desc, reason = await site_self_description("http://cardsmile.ru")

    assert desc is None
    assert reason and "недоступен" in reason


def test_detect_site_tech_analytics_crm_cms():
    """Детектор технологий находит CMS, CRM, аналитику и пиксели."""
    from osint_mcp.context.site import detect_site_tech

    html = """
    <html>
      <head>
        <link rel="stylesheet" href="/bitrix/templates/main/styles.css">
        <script src="https://mc.yandex.ru/metrika/tag.js"></script>
        <script src="https://cloud.roistat.com/api/site.js"></script>
      </head>
      <body>
        <script src="//code.jivo.ru/widget/12345"></script>
        <div class="b24-widget-button"></div>
      </body>
    </html>
    """
    tech = detect_site_tech(html)

    assert "1C-Битрикс" in tech.cms
    assert "Яндекс.Метрика" in tech.analytics
    assert "Roistat (сквозная аналитика)" in tech.analytics
    assert "Jivo (онлайн-консультант)" in tech.crm_widgets
    assert "Битрикс24 (CRM-виджет)" in tech.crm_widgets
    assert tech.marketing_active is True


def test_extract_tracker_ids_yandex_google_mailru():
    """Проверка извлечения реальных ID Метрики, Google Analytics и VK/Mail.ru."""
    from osint_mcp.context.site import extract_tracker_ids, detect_site_tech

    html = """
    <html>
      <head>
        <script>
          (function(m,e,t,r,i,k,a){m[i]=m[i]||function(){(m[i].a=m[i].a||[]).push(arguments)};
          ym(91234567, "init", {clickmap:true, trackLinks:true, accurateTrackBounce:true});
          })(window, document, "script", "https://mc.yandex.ru/metrika/tag.js", "ym");
        </script>
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC1234567"></script>
        <script>
          window.dataLayer = window.dataLayer || [];
          function gtag(){dataLayer.push(arguments);}
          gtag('js', new Date());
          gtag('config', 'G-ABC1234567');
          gtag('config', 'UA-987654-1');
        </script>
        <script type="text/javascript">
          var _tmr = window._tmr || (window._tmr = []);
          _tmr.push({id: "3123456", type: "pageView", start: (new Date()).getTime()});
        </script>
      </head>
      <body>
        <noscript><div><img src="https://mc.yandex.ru/watch/91234567" style="position:absolute; left:-9999px;" alt="" /></div></noscript>
      </body>
    </html>
    """
    trackers = extract_tracker_ids(html)
    assert trackers["yandex_metrika"] == ["91234567"]
    assert "G-ABC1234567" in trackers["google_analytics"]
    assert "UA-987654-1" in trackers["google_analytics"]
    assert trackers["mailru_top"] == ["3123456"]

    tech = detect_site_tech(html)
    assert tech.tracker_ids == trackers
    assert "Яндекс.Метрика" in tech.analytics
    assert "Google Analytics" in tech.analytics
    assert "VK/Mail.ru счетчик" in tech.analytics


async def test_ssl_info_mocked(monkeypatch):
    """Проверка SSL возвращает срок действия и эмитента."""
    from datetime import date
    from osint_mcp.context.site import ssl_info
    from osint_mcp.models import SslInfo

    fake = SslInfo(
        valid=True,
        issuer="Let's Encrypt",
        expires_at=date(2027, 1, 1),
        days_left=85,
    )
    monkeypatch.setattr("osint_mcp.context.site._check_ssl_sync", lambda host: fake)

    info, err = await ssl_info("https://bpmsoft.ru")
    assert err is None
    assert info is not None
    assert info.valid is True
    assert info.issuer == "Let's Encrypt"
    assert info.days_left == 85

