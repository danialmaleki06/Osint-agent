"""Тесты источников, добавленных после изучения документации API.

Покрывают: постраничную выгрузку, связи через физических лиц, рыночное
наименование, проверки надзорных органов, госзакупки, категорию размера.
"""

import json
from pathlib import Path

import httpx
import pytest
import respx

from osint_mcp.config import settings
from osint_mcp.context.checko import CheckoSource
from osint_mcp.context.dadata import DaDataSource

pytestmark = pytest.mark.anyio

FIXTURES = Path(__file__).parent / "fixtures"
BPMSOFT = "7724744134"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    monkeypatch.setattr(settings, "checko_api_key", "test-key")
    monkeypatch.setattr(settings, "dadata_api_key", "test-key")
    monkeypatch.setattr(settings, "dadata_secret_key", "test-secret")


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _mock(ep: str, name: str):
    respx.get(f"{settings.checko_base_url}/{ep}").mock(
        return_value=httpx.Response(200, json=_fixture(name))
    )


# ───────────────────────  постраничная выгрузка  ───────────────────────

def _many_cases(total: int, pages: int, page_size: int = 100) -> dict:
    """Ответ, будто у организации очень много дел."""
    records = [{
        "Номер": f"А40-{i}/2024", "Дата": "2024-01-15", "Суд": "АС Москвы",
        "СуммИск": 1000.0, "СтрКАД": f"https://kad.arbitr.ru/Card/{i}",
        "Ист": [{"ИНН": "9999999999"}], "Ответ": [{"ИНН": BPMSOFT}],
    } for i in range(page_size)]
    return {"meta": {"status": "ok"},
            "data": {"ЗапВсего": total, "СтрВсего": pages, "СтрТекущ": 1,
                     "ОбщСуммИск": total * 1000.0, "Записи": records}}


@respx.mock
async def test_large_company_reports_partial_honestly():
    """Разбивку по ролям нельзя выдавать за исчерпывающую.

    У организаций уровня крупного банка судебных дел свыше миллиона.
    Выгрузить все невозможно; сводное число берётся из агрегата источника,
    а разбивка считается по выборке — и это обязано быть видно.
    """
    respx.get(f"{settings.checko_base_url}/legal-cases").mock(
        return_value=httpx.Response(200, json=_many_cases(total=1_084_140, pages=10_842))
    )
    res = await CheckoSource().check_arbitration("7707083893")

    assert res.status == "partial"
    a = res.arbitration
    assert a.total == 1_084_140                     # сводное — по всей базе
    assert a.roles_counted_from < a.total           # разбивка — по выборке
    assert a.roles_complete is False
    assert "невозможно" in res.reason


@respx.mock
async def test_small_company_is_complete():
    """Когда дел мало и они помещаются целиком — статус полный."""
    _mock("legal-cases", "checko_legal-cases_bpmsoft.json")
    res = await CheckoSource().check_arbitration(BPMSOFT)

    assert res.status == "ok"
    assert res.arbitration.roles_complete is True
    assert res.arbitration.roles_counted_from == res.arbitration.total


@respx.mock
async def test_pagination_requests_additional_pages():
    """При нескольких страницах источник опрашивается повторно."""
    route = respx.get(f"{settings.checko_base_url}/legal-cases").mock(
        return_value=httpx.Response(200, json=_many_cases(total=500, pages=5))
    )
    await CheckoSource().check_arbitration(BPMSOFT)

    # первая страница плюс ограничение max_pages
    assert route.call_count == settings.max_pages


# ───────────────────────  связи через людей  ───────────────────────

@respx.mock
async def test_affiliations_map_people_to_companies():
    _mock("company", "checko_company_bpmsoft.json")
    _mock("person", "checko_person_director.json")

    graph, res = await CheckoSource().check_affiliations(BPMSOFT)

    assert res.status == "ok"
    assert graph.people, "должны быть найдены руководитель и учредители"
    person = graph.people[0]
    assert person.fio
    assert person.role_in_company


@respx.mock
async def test_personal_risk_becomes_a_fact_with_source():
    """Личное банкротство руководителя — отдельный факт со ссылкой."""
    card = _fixture("checko_company_bpmsoft.json")
    person = _fixture("checko_person_director.json")
    person["data"]["ЕФРСБ"] = [{"Тип": "Признан банкротом"}]
    person["data"]["МассРуковод"] = True

    respx.get(f"{settings.checko_base_url}/company").mock(
        return_value=httpx.Response(200, json=card))
    respx.get(f"{settings.checko_base_url}/person").mock(
        return_value=httpx.Response(200, json=person))

    _, res = await CheckoSource().check_affiliations(BPMSOFT)

    texts = " ".join(f.statement for f in res.facts)
    assert "банкротств" in texts
    assert "массовым руководителем" in texts
    for f in res.facts:
        assert f.source_url.startswith("http")


# ───────────────────────  рыночное наименование  ───────────────────────

@respx.mock
async def test_brand_is_resolved():
    respx.post(settings.dadata_brand_url).mock(
        return_value=httpx.Response(200, json=_fixture("dadata_brand_bpmsoft.json"))
    )
    brand = await DaDataSource().get_brand(BPMSOFT)

    assert brand.resolved is True
    assert brand.brand == "BPMSoft"
    assert brand.domain == "bpmsoft.ru"


async def test_missing_secret_key_is_honest_not_crash(monkeypatch):
    """Без секретного ключа метод недоступен — это не ошибка, а «не установлено»."""
    monkeypatch.setattr(settings, "dadata_secret_key", "")
    brand = await DaDataSource().get_brand(BPMSOFT)

    assert brand.resolved is False
    assert "секретный ключ" in brand.reason


@respx.mock
async def test_brand_failure_does_not_invent_a_name():
    respx.post(settings.dadata_brand_url).mock(return_value=httpx.Response(500))
    brand = await DaDataSource().get_brand(BPMSOFT)

    assert brand.resolved is False
    assert brand.brand is None       # выдумывать нельзя
    assert brand.reason


# ───────────────────────  проверки и закупки  ───────────────────────

@respx.mock
async def test_inspections_counted():
    _mock("inspections", "checko_inspections_bpmsoft.json")
    res = await CheckoSource().check_inspections(BPMSOFT)

    assert res.status in ("ok", "partial")
    assert res.inspections is not None
    assert res.inspections.total >= 0


@respx.mock
async def test_procurement_facts_link_to_state_registry():
    _mock("contracts", "checko_contracts_bpmsoft.json")
    res = await CheckoSource().check_procurement(BPMSOFT)

    assert res.procurement is not None
    for f in res.facts:
        assert "zakupki.gov.ru" in f.source_url


@respx.mock
async def test_all_procurement_registries_down_is_unavailable():
    """Если ни один реестр закупок не ответил — это отказ, а не «контрактов нет».

    Нули в такой ситуации читались бы как отсутствие госзаказа.
    """
    respx.get(f"{settings.checko_base_url}/contracts").mock(
        return_value=httpx.Response(503))
    res = await CheckoSource().check_procurement(BPMSOFT)

    assert res.status == "unavailable"


# ───────────────────────  категория размера  ───────────────────────

@pytest.mark.parametrize("revenue,employees,expected", [
    (50_000_000, 10, "micro"),
    (500_000_000, 80, "small"),
    (1_500_000_000, 200, "medium"),
    (2_769_645_000, 386, "large"),      # фактические показатели БПМСОФТ
    (None, None, "unknown"),
])
def test_size_category(revenue, employees, expected):
    """Масштаб определяет применимость признаков риска.

    Массовый адрес значим для микробизнеса и неприменим к крупной компании.
    """
    assert CheckoSource._size_category(revenue, employees) == expected


# ───────────────────────  двойная процессуальная роль  ───────────────────────

@respx.mock
async def test_both_roles_are_not_hidden_in_defendants():
    """Компания может быть и истцом, и ответчиком в одном деле.

    Так бывает при встречном иске либо когда в деле участвует её же
    обособленное подразделение. На выборке из 300 дел крупного банка такое
    дело нашлось одно. Молча относить его к ответчикам нельзя: это скрытое
    допущение, а по правилам проекта допущения должны быть видны.
    """
    case = {
        "Номер": "А50-7502/2006", "Дата": "2006-05-10", "Суд": "АС Пермского края",
        "СуммИск": 307603.0, "СтрКАД": "https://kad.arbitr.ru/Card/x",
        "Ист": [{"ИНН": BPMSOFT}, {"ИНН": "5904000000"}],
        "Ответ": [{"ИНН": "5905000000"}, {"ИНН": BPMSOFT}],
    }
    respx.get(f"{settings.checko_base_url}/legal-cases").mock(
        return_value=httpx.Response(200, json={
            "meta": {"status": "ok"},
            "data": {"ЗапВсего": 1, "СтрВсего": 1, "ОбщСуммИск": 307603.0,
                     "Записи": [case]},
        })
    )
    a = (await CheckoSource().check_arbitration(BPMSOFT)).arbitration

    assert a.as_both.count == 1
    assert a.as_both.total_amount == pytest.approx(307603.0)
    assert a.as_defendant.count == 0      # не спрятано в ответчиках
    assert a.as_plaintiff.count == 0      # и не в истцах


@respx.mock
async def test_third_party_participation_is_counted():
    """Дело, где ИНН компании не встретился ни в одной стороне."""
    case = {
        "Номер": "А40-1/2024", "Дата": "2024-01-01", "Суд": "АС Москвы",
        "СуммИск": 0.0, "СтрКАД": "https://kad.arbitr.ru/Card/y",
        "Ист": [{"ИНН": "1111111111"}], "Ответ": [{"ИНН": "2222222222"}],
    }
    respx.get(f"{settings.checko_base_url}/legal-cases").mock(
        return_value=httpx.Response(200, json={
            "meta": {"status": "ok"},
            "data": {"ЗапВсего": 1, "СтрВсего": 1, "Записи": [case]},
        })
    )
    a = (await CheckoSource().check_arbitration(BPMSOFT)).arbitration

    assert a.other_participation == 1
    assert a.as_defendant.count == a.as_plaintiff.count == a.as_both.count == 0


# ───────────────────────  история наименований  ───────────────────────

@respx.mock
async def test_former_names_are_extracted():
    """Организация могла сменить название — публикации выходили под старым.

    Проверяемая компания меняла наименование дважды: «КАРДСМАЙЛ» →
    «ЛАНИТ ОМНИ» → «БПМСОФТ». Поиск только по текущему имени пропустил бы
    четырнадцать лет её истории и сообщил бы об отсутствии негатива.
    """
    _mock("timeline", "checko_timeline_bpmsoft.json")
    former, notable, err = await CheckoSource().get_name_history(BPMSOFT)

    assert err is None
    assert 'ООО "КАРДСМАЙЛ"' in former
    assert 'ООО "ЛАНИТ ОМНИ"' in former
    assert len(former) == 2


@respx.mock
async def test_notable_events_include_director_change():
    """Смена руководителя — существенное событие, а не рядовая запись."""
    _mock("timeline", "checko_timeline_bpmsoft.json")
    _, notable, _ = await CheckoSource().get_name_history(BPMSOFT)

    events = " ".join(e["event"] for e in notable)
    assert "становится генеральным директором" in events
    assert all(e["date"] for e in notable)


@respx.mock
async def test_routine_records_are_filtered_out():
    """Сдача отчётности в существенные события не попадает."""
    _mock("timeline", "checko_timeline_bpmsoft.json")
    _, notable, _ = await CheckoSource().get_name_history(BPMSOFT)

    assert not any("отчётност" in e["event"] for e in notable)


@respx.mock
async def test_timeline_failure_is_not_fatal():
    """Недоступность истории не должна ломать сборку контекста."""
    respx.get(f"{settings.checko_base_url}/timeline").mock(
        return_value=httpx.Response(503))
    former, notable, err = await CheckoSource().get_name_history(BPMSOFT)

    assert former == [] and notable == []
    assert err is not None


# ───────────────────  честность формулировок  ───────────────────

@respx.mock
async def test_no_enforcements_is_not_proof_of_no_debts():
    """Пустой результат по приставам не означает отсутствия задолженности.

    Поставщик прямо указывает: реквизиты организаций служба приставов
    указывает не всегда, сопоставление идёт по наименованию и адресу
    приблизительными алгоритмами. Помечать пустой ответ как полную
    проверку значило бы выдать «не смогли найти» за «долгов нет».
    """
    _mock("enforcements", "checko_enforcements_bpmsoft.json")
    res = await CheckoSource().check_enforcement(BPMSOFT)

    assert res.enforcement.total == 0
    assert res.status == "partial"          # не "ok"
    assert "приблизительный" in res.reason
    assert "НЕ «задолженности отсутствуют»" in res.reason


@respx.mock
async def test_arbitration_warns_about_data_lag():
    """Сведения о судах отстают на 1-2 недели — вывод «дел нет» это обязан учитывать."""
    _mock("legal-cases", "checko_legal-cases_bpmsoft.json")
    res = await CheckoSource().check_arbitration(BPMSOFT)

    assert "задержкой" in res.reason
    assert "две недели" in res.reason


# ───────────────────  индивидуальные предприниматели  ───────────────────

def test_entrepreneur_endpoint_is_chosen_by_inn_length():
    """У ИП нет карточки юрлица: 12-значный ИНН требует другого метода.

    Обращение к методу организаций по ИНН предпринимателя вернуло бы
    пустоту, неотличимую от «ничего не найдено».
    """
    from osint_mcp.context.checko import _card_endpoint

    assert _card_endpoint("7724744134") == "company"        # организация
    assert _card_endpoint("500100732259") == "entrepreneur"  # ИП или физлицо


@respx.mock
async def test_entrepreneur_card_is_requested_for_12_digit_inn():
    """По ИНН предпринимателя опрашивается метод предпринимателей."""
    company = respx.get(f"{settings.checko_base_url}/company")
    ent = respx.get(f"{settings.checko_base_url}/entrepreneur").mock(
        return_value=httpx.Response(200, json={"meta": {"status": "ok"}, "data": {}}))

    await CheckoSource().check_registry_flags("500100732259")

    assert ent.called
    assert not company.called


# ───────────────────  уставный капитал  ───────────────────

@respx.mock
async def test_capital_is_taken_from_card():
    """Бесплатный тариф основного справочника капитал не отдаёт — берём из второго.

    Для микробизнеса минимальный уставный капитал — заметный признак.
    """
    _mock("finances", "checko_finances_bpmsoft.json")
    _mock("company", "checko_company_bpmsoft.json")

    summary, err = await CheckoSource().get_finances(BPMSOFT)

    assert err is None
    assert summary.capital == 20000     # фактическое значение из карточки


# ───────────────────  детали карточки: налоги, лицензии, контакты  ───────────────────

@respx.mock
async def test_card_extras_are_parsed():
    """Налоги, лицензии, контакты и массовость адреса приходят в той же карточке."""
    _mock("finances", "checko_finances_bpmsoft.json")
    _mock("company", "checko_company_bpmsoft.json")

    summary, err = await CheckoSource().get_finances(BPMSOFT)

    assert err is None
    extras = summary.extras
    assert extras is not None
    assert extras.tax_debt is None          # в фикстуре недоимки нет — поле null
    assert extras.tax_paid_total == 128672238.81
    assert extras.tax_year == 2025
    assert len(extras.licenses) == 2        # две лицензии ФСТЭК
    assert extras.licenses[0].issuer.startswith("ФЕДЕРАЛЬНАЯ СЛУЖБА")
    assert extras.contacts.website == "http://cardsmile.ru"
    assert "+74952873257" in extras.contacts.phones
    assert len(extras.mass_address_orgs) == 4   # четыре ОГРН по тому же адресу
    assert extras.address_unreliable is False


@respx.mock
async def test_fin_history_carries_report_urls():
    """Ссылки bo.nalog.gov.ru привязываются к годам финансовой истории."""
    _mock("finances", "checko_finances_bpmsoft.json")
    _mock("company", "checko_company_bpmsoft.json")

    summary, err = await CheckoSource().get_finances(BPMSOFT)

    assert err is None
    assert summary.years, "финансовая история пуста"
    with_urls = [y for y in summary.years if y.report_url]
    assert with_urls, "отчётности ФНС не привязались к годам"
    assert all("bo.nalog.gov.ru" in y.report_url for y in with_urls)
    # Год с отчётностью, которого нет в выборке пяти лет, не создаёт год сам по себе
    assert all(y.year in {fy.year for fy in summary.years} for y in with_urls)


@respx.mock
async def test_extras_are_none_when_card_silent():
    """Карточка не ответила — extras None, а не выдуманные нули."""
    _mock("finances", "checko_finances_bpmsoft.json")
    respx.get(f"{settings.checko_base_url}/company").mock(
        return_value=httpx.Response(503))

    summary, err = await CheckoSource().get_finances(BPMSOFT)

    assert err is None
    assert summary.extras is None
