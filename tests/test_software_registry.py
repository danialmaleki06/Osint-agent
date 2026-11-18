"""Проверки разбора страниц официального реестра ПО Минцифры."""

import httpx
import pytest
import respx

from osint_mcp.context.software_registry import SoftwareRegistrySource

pytestmark = pytest.mark.anyio

INN = "7724744134"
URL = "https://reestr.digital.gov.ru/reestr/"
ACTIVE_QUERY = {"OWNER_INN": INN, "tab": "registry_active"}


def _entry(name, number, path="/reestr/1435439/"):
    return f"""
    <div class="collection-item" data-href="{path}">
      <div data-name="№ реестровой записи">{number}</div>
      <div data-name="Дата регистрации">17.04.2023</div>
      <div data-name="Наименование ПО">{name}</div>
      <div data-name="Класс ПО"><div class="class-item"><span>09.01</span>
        <span>Средства управления бизнес-процессами (BPM)</span></div></div>
    </div>
    """


def _tab(name, total, rows):
    return f"""
    <div data-target="registry_{name}"><span class="tabs-list__item-counter">{total}</span></div>
    <div class="tabs-content__item" data-tab="registry_{name}">
      <div class="collection-registry">{rows}</div>
    </div>
    <form id="registry_{name}"><input name="OWNER_INN" value="{INN}"></form>
    """


def _page(active="", excluded="", *, total=0, excluded_total=0):
    return f"<html><body>{_tab('active', total, active)}{_tab('excluded', excluded_total, excluded)}</body></html>"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@respx.mock
async def test_software_registry_success_parsing():
    html = _page(
        _entry("BPMSoft", "17372"),
        _entry("ПС Контроль и оценка", "3545", "/excluded/304895/"),
        total=1,
        excluded_total=1,
    )
    respx.get(URL, params=ACTIVE_QUERY).respond(text=html)

    products, facts, failure = await SoftwareRegistrySource().get_software_products(INN)

    assert failure is None
    active, excluded = products
    assert active.name == "BPMSoft"
    assert active.reg_number == "17372"
    assert active.reg_date == "17.04.2023"
    assert active.status == "В реестре"
    assert "BPM" in (active.software_class or "")
    assert active.url == f"{URL}1435439/"
    assert excluded.status == "Исключено"
    assert [f.fact_id for f in facts] == ["SW-17372"]
    assert facts[0].event_date is not None


@respx.mock
async def test_software_registry_reads_remaining_pages():
    respx.get(URL, params={**ACTIVE_QUERY, "PAGE_N": 2}).respond(
        text=_page(_entry("Второй", "2"), total=2),
    )
    respx.get(URL, params=ACTIVE_QUERY).respond(text=_page(_entry("Первый", "1"), total=2))

    result = await SoftwareRegistrySource().check_software_registry(INN)

    assert result.status == "ok"
    assert [f.fact_id for f in result.facts] == ["SW-1", "SW-2"]


@respx.mock
async def test_software_registry_empty_is_partial():
    respx.get(URL, params=ACTIVE_QUERY).respond(text=_page())

    result = await SoftwareRegistrySource().check_software_registry(INN)

    assert result.status == "partial"
    assert result.reason and "не найдено" in result.reason
    assert result.facts == []


@respx.mock
async def test_software_registry_unrecognized_html_is_unavailable():
    respx.get(URL, params=ACTIVE_QUERY).respond(text=_page().replace(INN, "0"))

    result = await SoftwareRegistrySource().check_software_registry(INN)

    assert result.status == "unavailable"
    assert result.facts == []


@respx.mock
async def test_software_registry_http_error_is_unavailable():
    respx.get(URL, params=ACTIVE_QUERY).respond(status_code=503)

    result = await SoftwareRegistrySource().check_software_registry(INN)

    assert result.status == "unavailable"
    assert "503" in (result.reason or "")


@respx.mock
async def test_software_registry_network_error_is_unavailable():
    respx.get(URL, params=ACTIVE_QUERY).mock(side_effect=httpx.ConnectTimeout("timeout"))

    result = await SoftwareRegistrySource().check_software_registry(INN)

    assert result.status == "unavailable"
    assert "недоступен" in (result.reason or "").lower()
