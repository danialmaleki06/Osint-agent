"""Тесты реестровых проверок.

Образцы ответов записаны с живого API Checko и лежат в tests/fixtures.
Прогон идёт офлайн: квота сервиса не расходуется, результат воспроизводим.
"""

import json
from pathlib import Path

import httpx
import pytest
import respx

from osint_mcp.config import settings
from osint_mcp.context.checko import CheckoSource
from osint_mcp.tools.risk import collect_risk_facts

pytestmark = pytest.mark.anyio

FIXTURES = Path(__file__).parent / "fixtures"
BPMSOFT = "7724744134"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setattr(settings, "checko_api_key", "test-key")


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


SOURCES = 5   # registry_flags, arbitration, enforcement, inspections, procurement


def _mock_all():
    """Подменить все эндпоинты записанными с живого API ответами."""
    for ep, name in [
        ("company", "checko_company_bpmsoft.json"),
        ("legal-cases", "checko_legal-cases_bpmsoft.json"),
        ("enforcements", "checko_enforcements_bpmsoft.json"),
        ("inspections", "checko_inspections_bpmsoft.json"),
        ("contracts", "checko_contracts_bpmsoft.json"),
        ("person", "checko_person_director.json"),
    ]:
        respx.get(f"{settings.checko_base_url}/{ep}").mock(
            return_value=httpx.Response(200, json=_fixture(name))
        )


# ───────────────────────────  арбитраж  ───────────────────────────

@respx.mock
async def test_role_is_separated():
    """Роль важнее суммы: истца и ответчика нельзя складывать.

    У этой компании три дела. Сервис отдаёт общую сумму 8,68 млн одним
    числом, не разделяя роли. Вся сумма относится к единственному делу,
    где компания — ОТВЕТЧИК. Разделение обязано делаться у нас.
    """
    _mock_all()
    res = await CheckoSource().check_arbitration(BPMSOFT)

    assert res.status == "ok"
    a = res.arbitration
    assert a.total == 3
    assert a.as_defendant.count == 1
    assert a.as_defendant.total_amount == pytest.approx(8_682_384.89)
    assert a.as_plaintiff.count == 2
    assert a.as_plaintiff.total_amount == 0.0


@respx.mock
async def test_defendant_case_ranks_first():
    """Дело, где компания отвечает, важнее дел, где она взыскивает."""
    _mock_all()
    facts = (await CheckoSource().check_arbitration(BPMSOFT)).facts
    assert "ответчик" in facts[0].statement


@respx.mock
async def test_every_fact_has_real_source():
    """Ключевое требование проекта: факт без источника не существует."""
    _mock_all()
    facts = (await CheckoSource().check_arbitration(BPMSOFT)).facts

    assert facts
    for f in facts:
        assert f.source_url.startswith("http")
        assert "kad.arbitr.ru" in f.source_url   # ссылка ведёт в картотеку
        assert f.fact_id
        assert f.event_date is not None


# ───────────────────────────  отметки  ───────────────────────────

@respx.mock
async def test_registry_flags_are_read():
    _mock_all()
    res = await CheckoSource().check_registry_flags(BPMSOFT)

    assert res.status == "ok"
    # у благополучной компании отметки присутствуют, но не подняты
    assert set(res.flags) >= {"НедобПост", "МассРуковод", "Санкции", "Банкротство"}
    assert not any(res.flags.values())
    assert res.facts == []


# ───────────────────────────  сводный сбор  ───────────────────────────

@respx.mock
async def test_collect_runs_all_sources():
    _mock_all()
    r = await collect_risk_facts(BPMSOFT)

    assert r.sources_ok == SOURCES
    assert r.sources_failed == 0
    assert {"ARB-1", "ARB-2", "ARB-3"} <= {f.fact_id for f in r.facts}
    # У этой организации производств нет, поэтому источник приставов
    # помечается как неполный — см. test_no_enforcements_is_not_proof
    assert "приблизительный" in r.coverage_note
    assert "checko.enforcement" in r.coverage_note


@respx.mock
async def test_one_failed_source_does_not_stop_others():
    """Отказ одного источника не должен обрывать сбор из остальных."""
    _mock_all()
    respx.get(f"{settings.checko_base_url}/enforcements").mock(
        return_value=httpx.Response(500)
    )
    r = await collect_risk_facts(BPMSOFT)

    assert r.sources_ok == SOURCES - 1
    assert r.sources_failed == 1
    assert r.facts                          # арбитраж всё равно собран
    assert "НЕПОЛНАЯ" in r.coverage_note     # и об этом сказано явно


@respx.mock
async def test_unavailable_is_not_silence():
    """Недоступность источника обязана быть видна, а не выглядеть как «чисто»."""
    for ep in ("company", "legal-cases", "enforcements", "inspections", "contracts"):
        respx.get(f"{settings.checko_base_url}/{ep}").mock(
            return_value=httpx.Response(503)
        )
    r = await collect_risk_facts(BPMSOFT)

    assert r.sources_ok == 0
    assert r.facts == []
    assert r.coverage_note is not None
    assert "ничего не доказывает" in r.coverage_note


async def test_bad_inn_never_reaches_api():
    with respx.mock:
        route = respx.get(f"{settings.checko_base_url}/legal-cases")
        r = await collect_risk_facts("7707083899")
        assert not route.called
        assert "контрольная сумма" in r.coverage_note.lower()


# ───────────────────────────  роли в закупках  ───────────────────────────

@respx.mock
async def test_procurement_role_is_separated():
    """Заказчик и исполнитель означают противоположное.

    Организация-исполнитель выиграла заказ. Организация-заказчик закупала
    сама — по 223-ФЗ это признак государственного участия, а не портфеля
    подрядов. Прежде роли не различались вовсе, и закупки организации
    попадали в отчёт как её выигранные контракты.
    """
    _mock_all()
    res = await CheckoSource().check_procurement(BPMSOFT)

    p = res.procurement
    assert p.as_supplier.count == 2, "контракт исполнителя не распознан"
    assert p.as_customer.count == 0
    assert "исполнитель" in res.facts[0].statement


@respx.mock
async def test_customer_contracts_are_not_won_tenders():
    """Организация закупала сама — это не выигранный подряд."""
    body = {"meta": {"status": "ok"}, "data": {
        "ЗапВсего": 1, "СтрВсего": 1,
        "Записи": [{
            "РегНомер": "1", "Дата": "2024-01-01", "Цена": 5_000_000,
            "СтрЕИС": "https://zakupki.gov.ru/x",
            "Заказ": {"ИНН": BPMSOFT, "НаимСокр": "ООО Проверяемая"},
            "Постав": [{"ИНН": "7700000001", "НаимСокр": "ООО Чужая"}],
        }]}}
    respx.get(f"{settings.checko_base_url}/contracts").mock(
        return_value=httpx.Response(200, json=body))

    res = await CheckoSource().check_procurement(BPMSOFT)

    p = res.procurement
    assert p.as_customer.count == 2      # один и тот же ответ на 44 и 223
    assert p.as_supplier.count == 0
    assert p.as_supplier.total_amount == 0.0
    assert "заказчик" in res.facts[0].statement
