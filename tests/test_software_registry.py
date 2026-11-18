"""Тесты единого реестра отечественного ПО Минцифры (SoftwareRegistrySource)."""

import httpx
import pytest
import respx

from osint_mcp.context.software_registry import SoftwareRegistrySource

pytestmark = pytest.mark.anyio

INN = "7724744134"

HTML_SAMPLE = """
<!DOCTYPE html>
<html>
<body>
<main>
  <article>
    <h3><a href="https://reestr.digital.gov.ru/reestr/17372/">BPMSoft</a></h3>
    <span>В реестре</span>
    <div class="flex">
      <dt>Запись №</dt><dd>17372</dd>
    </div>
    <div class="flex">
      <dt>Включено</dt><dd>18.04.2023</dd>
    </div>
    <div class="flex">
      <dt>Класс ПО</dt><dd>Системы управления процессами организации (BPM)</dd>
    </div>
    <a href="https://reestr.digital.gov.ru/reestr/17372/">Ссылка</a>
  </article>
</main>
</body>
</html>
"""


@pytest.fixture
def anyio_backend():
    return "asyncio"


@respx.mock
async def test_software_registry_success_parsing():
    respx.get(f"https://proreestr.ru/reestr-po/?q={INN}").mock(
        return_value=httpx.Response(200, text=HTML_SAMPLE)
    )

    src = SoftwareRegistrySource()
    products, facts, failure = await src.get_software_products(INN)

    assert failure is None
    assert len(products) == 1
    p = products[0]
    assert p.name == "BPMSoft"
    assert p.reg_number == "17372"
    assert p.reg_date == "18.04.2023"
    assert p.status == "В реестре"
    assert "BPM" in (p.software_class or "")
    assert p.url == "https://reestr.digital.gov.ru/reestr/17372/"

    assert len(facts) == 1
    f = facts[0]
    assert f.kind == "software_registry"
    assert "BPMSoft" in f.statement
    assert "17372" in f.statement
    assert f.event_date is not None
    assert f.payload["name"] == "BPMSoft"


@respx.mock
async def test_software_registry_check_method_ok():
    respx.get(f"https://proreestr.ru/reestr-po/?q={INN}").mock(
        return_value=httpx.Response(200, text=HTML_SAMPLE)
    )

    src = SoftwareRegistrySource()
    res = await src.check_software_registry(INN)

    assert res.status == "ok"
    assert res.source == "software_registry"
    assert len(res.facts) == 1


@respx.mock
async def test_software_registry_empty_is_partial():
    respx.get(f"https://proreestr.ru/reestr-po/?q={INN}").mock(
        return_value=httpx.Response(200, text="<html><body><main>Ничего не найдено</main></body></html>")
    )

    src = SoftwareRegistrySource()
    res = await src.check_software_registry(INN)

    assert res.status == "partial"
    assert res.reason and "не найдено" in res.reason
    assert res.facts == []


@respx.mock
async def test_software_registry_unrecognized_html_is_unavailable():
    respx.get(f"https://proreestr.ru/reestr-po/?q={INN}").mock(
        return_value=httpx.Response(200, text="<html><main>Услуга временно недоступна</main></html>")
    )

    result = await SoftwareRegistrySource().check_software_registry(INN)

    assert result.status == "unavailable"
    assert result.facts == []


@respx.mock
async def test_software_registry_http_error_is_unavailable():
    respx.get(f"https://proreestr.ru/reestr-po/?q={INN}").mock(
        return_value=httpx.Response(500)
    )

    src = SoftwareRegistrySource()
    res = await src.check_software_registry(INN)

    assert res.status == "unavailable"
    assert "500" in (res.reason or "")


@respx.mock
async def test_software_registry_network_error_is_unavailable():
    respx.get(f"https://proreestr.ru/reestr-po/?q={INN}").mock(
        side_effect=httpx.ConnectTimeout("timeout")
    )

    src = SoftwareRegistrySource()
    res = await src.check_software_registry(INN)

    assert res.status == "unavailable"
    assert "недоступен" in (res.reason or "").lower()
