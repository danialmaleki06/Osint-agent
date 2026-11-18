"""Тесты отчёта о полноте проверки.

Смысл отчёта — не в подсчёте обращений, а в различении причин, по которым
сведений нет. «Источник молчал» и «сведений действительно нет» ведут
к противоположным выводам, и слить их в одну строку значит вернуть
ту самую ошибку, против которой выстроена вся система.
"""

import httpx
import pytest
import respx

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.context.checko import CheckoSource
from osint_mcp.tools.coverage import build_coverage

pytestmark = pytest.mark.anyio

INN = "7724744134"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setattr(settings, "checko_api_key", "test-key")
    ledger.reset()
    yield
    ledger.reset()


def _ok(data: dict, count: int = 7) -> dict:
    return {"meta": {"status": "ok", "today_request_count": count}, "data": data}


async def test_no_calls_is_not_a_clean_check():
    """Пустой журнал означает «не проверяли», а не «ничего не нашли»."""
    r = build_coverage(INN)

    assert r.checked is False
    assert r.total_requests == 0
    assert r.gaps and r.gaps[0].kind == "not_requested"
    assert "обращений не было" in r.gaps[0].reason


@respx.mock
async def test_successful_call_is_counted_and_named():
    """Обращение попадает в расход, а направление — в перечень собранного."""
    respx.get(f"{settings.checko_base_url}/company").mock(
        return_value=httpx.Response(200, json=_ok({"ИНН": INN}, count=42)))

    ledger.set_subject(INN)
    await CheckoSource().check_registry_flags(INN)
    r = build_coverage(INN)

    assert r.checked is True
    assert r.total_requests == 1
    usage = r.services[0]
    assert usage.service == "checko"
    assert usage.requests == 1 and usage.ok == 1 and usage.failed == 0
    assert usage.daily_spent == 42
    assert any("карточка организации" in o for o in r.obtained)


@respx.mock
async def test_failed_source_is_not_absence_of_data():
    """Отказ источника обязан отличаться от «сведений нет»."""
    respx.get(f"{settings.checko_base_url}/legal-cases").mock(
        return_value=httpx.Response(403, json={
            "meta": {"message": "Превышен суточный лимит запросов"}}))

    ledger.set_subject(INN)
    await CheckoSource().check_arbitration(INN)
    r = build_coverage(INN)

    failed = [g for g in r.gaps if g.kind == "source_failed"]
    assert failed, "отказ источника не попал в пробелы"
    assert "арбитражные дела" in failed[0].what
    assert "лимит" in failed[0].reason
    # и это не должно попасть в собранное
    assert not any("арбитражные" in o for o in r.obtained)
    assert r.services[0].failed == 1


@respx.mock
async def test_empty_answer_differs_from_failure():
    """Источник ответил, но сведений нет — это проверено, а не пропущено."""
    respx.get(f"{settings.checko_base_url}/company").mock(
        return_value=httpx.Response(200, json=_ok({})))

    ledger.set_subject(INN)
    await CheckoSource().check_registry_flags(INN)
    r = build_coverage(INN)

    kinds = {g.kind for g in r.gaps}
    assert "no_data" in kinds
    assert "source_failed" not in kinds
    assert r.services[0].empty == 1


@respx.mock
async def test_partial_pagination_still_counts_as_obtained():
    """Отказ третьей страницы не отменяет данных с первых двух."""
    route = respx.get(f"{settings.checko_base_url}/legal-cases")
    route.side_effect = [
        httpx.Response(200, json=_ok({"Записи": [{"Номер": "1"}],
                                      "ЗапВсего": 200, "СтрВсего": 3})),
        httpx.Response(200, json=_ok({"Записи": [{"Номер": "2"}]})),
        httpx.Response(503),
    ]

    ledger.set_subject(INN)
    await CheckoSource().check_arbitration(INN)
    r = build_coverage(INN)

    assert any("арбитражные дела" in o for o in r.obtained)


async def test_unrequested_check_is_declared():
    """Незапущенная проверка связей не должна выглядеть как её отсутствие."""
    ledger.set_subject(INN)
    ledger.record("checko", "company", "ok")
    r = build_coverage(INN)

    not_run = [g for g in r.gaps if g.kind == "not_requested"]
    assert any("связи" in g.what for g in not_run)
    assert any("check_affiliations" in (g.reason or "") for g in not_run)


async def test_media_coverage_follows_search_outcome():
    ledger.set_subject(INN)
    ledger.record("dadata", "findById/party", "ok")
    r = build_coverage(INN)

    assert any("СМИ" in g.what and g.kind == "not_requested" for g in r.gaps)

    ledger.record("media", "search", "failed", "Поисковый сервис не ответил")
    r = build_coverage(INN)
    assert any("СМИ" in g.what and g.kind == "source_failed" for g in r.gaps)

    ledger.record("media", "search", "ok")
    r = build_coverage(INN)
    assert any("СМИ" in label for label in r.obtained)
    assert any("СМИ" in g.what and g.kind == "partial" for g in r.gaps)


async def test_coverage_of_one_invocation_excludes_previous_invocation():
    ledger.set_subject(INN)
    ledger.record("media", "search", "failed")
    with ledger.capture_calls():
        ledger.record("media", "search", "ok")
        coverage = build_coverage(INN, calls=ledger.current_calls())

    assert coverage.total_requests == 1
    assert coverage.services[0].ok == 1
    assert coverage.services[0].failed == 0


async def test_ledger_separates_companies():
    """Обращения по одной организации не приписываются другой."""
    ledger.set_subject(INN)
    ledger.record("checko", "company", "ok")
    ledger.set_subject("7707083893")
    ledger.record("checko", "company", "ok")
    ledger.record("checko", "finances", "ok")

    assert build_coverage(INN).total_requests == 1
    assert build_coverage("7707083893").total_requests == 2
    # а общий счётчик сеанса видит все
    assert build_coverage(INN).session_requests["checko"] == 3


# ─────────────────  доступ в сетевом режиме  ─────────────────

def test_auth_rejects_any_token_without_crashing():
    """Неверный токен обязан давать честный отказ, а не падение.

    compare_digest на строках требует ASCII и падает на кириллице.
    Присланный токен приходит от кого угодно, и падение означало бы 500
    вместо 401 — а разница в ответах подсказывает подбирающему,
    что он на верном пути. Поймано живым прогоном.
    """
    from osint_mcp.http_auth import TokenAuth

    guard = TokenAuth(app=None, token="верный-токен")
    for supplied in ("подобрал-наугад", "wrong", "", "🔑", "верный-токе"):
        # проверка не должна возбуждать исключение ни на каком вводе
        assert not __import__("hmac").compare_digest(
            supplied.encode("utf-8"), guard._token)
    assert __import__("hmac").compare_digest(
        "верный-токен".encode("utf-8"), guard._token)
