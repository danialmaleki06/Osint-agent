"""Тесты бесплатного эшелона источников: ГИР БО, реестр МСП, ЕГРЮЛ, резерв.

Офлайн на живых фикстурах: ответы записаны с реальных API 24.09.2026.
Проверяются парсинг, единицы измерения (тысячи рублей ГИР БО), перевёрнутые
флаги реестра МСП, а также честность оговорок при отказах.
"""

import json
from datetime import date
from pathlib import Path

import httpx
import pytest
import respx

from osint_mcp.config import settings
from osint_mcp.context.apicloud import ApiCloudSource
from osint_mcp.context.bo_nalog import BoNalogSource, merge_financial_years
from osint_mcp.context.egrul import EgrulSource, brief_from_egrul
from osint_mcp.context.rmsp import RmspSource
from osint_mcp.models import FinancialYear

pytestmark = pytest.mark.anyio

FIXTURES = Path(__file__).parent / "fixtures"
BPMSOFT = "7724744134"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# ───────────────────────────  ГИР БО  ───────────────────────────


def _mock_bo(search_status=200, bfo_status=200):
    respx.get(f"{settings.bo_nalog_base_url}/advanced-search/organizations/search").mock(
        return_value=httpx.Response(search_status, json=_fixture("bo_nalog_search_bpmsoft.json"))
    )
    respx.get(f"{settings.bo_nalog_base_url}/nbo/organizations/4578289/bfo").mock(
        return_value=httpx.Response(bfo_status, json=_fixture("bo_nalog_bfo_bpmsoft.json"))
    )


@respx.mock
async def test_bo_finances_parsed():
    """Все годы приходят одним запросом, суммы переводятся в рубли."""
    _mock_bo()
    years, failure = await BoNalogSource().get_finances(BPMSOFT)

    assert failure is None
    assert years is not None and len(years) == 5
    # Свежие первыми
    assert [y.year for y in years] == [2025, 2024, 2023, 2022, 2021]
    latest = years[0]
    # gainSum 2769645 тыс. руб -> 2 769 645 000 руб (сходится с Checko)
    assert latest.revenue == pytest.approx(2_769_645_000.0)
    assert latest.assets == pytest.approx(2_113_081_000.0)
    # Ссылка на официальную отчётность есть
    assert latest.report_url and "bo.nalog.gov.ru" in latest.report_url
    assert "period=2025" in latest.report_url


@respx.mock
async def test_bo_inn_matched_after_tag_strip():
    """ИНН в выдаче подсвечен тегами — сопоставление должно их снимать."""
    _mock_bo()
    org = await BoNalogSource().find_organization(BPMSOFT)
    assert org is not None
    assert org.get("id") == 4578289


@respx.mock
async def test_bo_unknown_company_is_valid_empty():
    """«Не значится в ресурсе» — валидная пустота с причиной, не отказ."""
    respx.get(f"{settings.bo_nalog_base_url}/advanced-search/organizations/search").mock(
        return_value=httpx.Response(200, json={"content": [], "totalElements": 0})
    )
    years, failure = await BoNalogSource().get_finances(BPMSOFT)

    assert years is None
    assert failure and "не значится" in failure


@respx.mock
async def test_bo_outage_is_reported_not_empty():
    """Отказ ресурса — отказ, а не «отчётности нет»."""
    respx.get(f"{settings.bo_nalog_base_url}/advanced-search/organizations/search").mock(
        return_value=httpx.Response(503)
    )
    years, failure = await BoNalogSource().get_finances(BPMSOFT)

    assert years is None
    assert failure and "недоступен" in failure


def test_merge_prefers_primary_on_conflict():
    """При конфликте за год побеждает платный источник."""
    primary = [FinancialYear(year=2024, revenue=100.0, profit=10.0)]
    fallback = [FinancialYear(year=2024, revenue=999.0, assets=500.0),
                FinancialYear(year=2023, revenue=50.0)]
    merged = merge_financial_years(primary, fallback)

    assert [y.year for y in merged] == [2024, 2023]
    assert merged[0].revenue == 100.0          # primary победил
    assert merged[0].assets == 500.0           # но данные резерва не выброшены


# ───────────────────────────  реестр МСП  ───────────────────────────


@respx.mock
async def test_rmsp_parsed_direct_active_flag():
    """is_active — прямой флаг: 0 значит «исключён».

    Проверено живьём на двух записях: у исключённой БПМСОФТ
    is_active=0 при заполненной дате исключения, у действующего
    ЛАНСОФТ is_active=1 и даты исключения нет. Раньше флаг считался
    перевёрнутым, и исключённая компания выглядела действующей.
    """
    respx.get(f"{settings.rmsp_base_url}/search-proc.json").mock(
        return_value=httpx.Response(200, json=_fixture("rmsp_bpmsoft.json"))
    )
    msp, failure = await RmspSource().get_msp(BPMSOFT)

    assert failure is None
    assert msp is not None and msp.in_registry
    assert msp.employees == 386
    assert msp.is_active is False              # is_active=0 -> исключён
    assert msp.excluded_at is not None and msp.excluded_at.year == 2024
    assert msp.included_at is not None and msp.included_at.year == 2018


@respx.mock
async def test_rmsp_not_in_registry_is_valid_empty():
    respx.get(f"{settings.rmsp_base_url}/search-proc.json").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    msp, failure = await RmspSource().get_msp(BPMSOFT)

    # Крупные компании в реестре не значятся по определению — это не отказ
    assert msp is None
    assert failure is None


@respx.mock
async def test_rmsp_outage_reported():
    respx.get(f"{settings.rmsp_base_url}/search-proc.json").mock(
        return_value=httpx.Response(500)
    )
    msp, failure = await RmspSource().get_msp(BPMSOFT)

    assert msp is None
    assert failure and "недоступен" in failure


# ───────────────────────────  ЕГРЮЛ  ───────────────────────────


def test_brief_from_egrul_parses_row():
    row = _fixture("egrul_result_bpmsoft.json")["rows"][0]
    brief = brief_from_egrul(row)

    assert brief["inn"] == BPMSOFT
    assert brief["ogrn"] == "1107746293049"
    assert brief["name_legal"].startswith("ОБЩЕСТВО")
    assert brief["registered_at"].year == 2010
    assert brief["director_fio"] == "Востриков Юрий Викторович"
    assert brief["director_post"] == "ГЕНЕРАЛЬНЫЙ ДИРЕКТОР"


# ───────────────────────  резервный агрегатор  ───────────────────────


@respx.mock
async def test_apicloud_without_key_is_unavailable():
    """Без ключа резерв честно недоступен — сервер не падает."""
    monkey_key = getattr(settings, "apicloud_key", "")
    respx.get(f"{settings.apicloud_base_url}/fssp.php").mock(
        return_value=httpx.Response(200, json={})
    )
    res = await ApiCloudSource().check_enforcement(BPMSOFT)

    assert res.status == "unavailable"
    assert "APICLOUD_KEY" in (res.reason or "") or "не ответил" in (res.reason or "")


@respx.mock
async def test_apicloud_enforcement_parses(monkeypatch):
    body = {
        "status": 200, "countAll": "1", "count": 1,
        "records": [{
            "process_title": "12345/26/77015-ИП", "process_date": "10.02.2026",
            "subject": "Взыскание задолженности", "sum": "150000.00",
        }],
    }
    monkeypatch.setattr(settings, "apicloud_key", "test-key")
    respx.get(f"{settings.apicloud_base_url}/fssp.php").mock(
        return_value=httpx.Response(200, json=body)
    )
    res = await ApiCloudSource().check_enforcement(BPMSOFT)

    assert res.status == "ok"
    assert res.enforcement.total == 1
    assert res.enforcement.total_amount == pytest.approx(150000.0)
    assert res.facts[0].fact_id == "REN-1"
    assert "[резервный источник]" in res.facts[0].statement


# ─────────────  баги, пойманные живым прогоном агента  ─────────────

@respx.mock
async def test_excluded_msp_record_does_not_set_category():
    """Исключённая из МСП запись не задаёт категорию.

    Живой прогон: БПМСОФТ исключена из реестра МСП в 2024 (переросла:
    386 сотрудников), но реестр хранит историческую запись, и карточка
    выходила «micro» при 386 сотрудниках и выручке 2,77 млрд.
    """
    from osint_mcp.tools.context_builder import build_company_context as _build_context

    class _Dead:
        name = "dead"

        async def get_context(self, inn):
            from osint_mcp.models import CompanyContext, ContextResult
            return ContextResult(status="ok", context=CompanyContext(
                inn=inn, country="RU", name_legal="ООО Т", name_short="Т",
                registered_at=date(2020, 1, 1)))

        async def get_brand(self, inn):
            from osint_mcp.models import BrandInfo
            return BrandInfo(resolved=False, reason="заглушка")

        async def get_finances(self, inn):
            from osint_mcp.models import FinancialSummary
            return FinancialSummary(inn=inn), None

        async def get_name_history(self, inn):
            return [], [], None

    msp_row = {"inn": BPMSOFT, "category": 0, "od2_sschr": 386,
               "dtregistry": "10.08.2018 00:00:00",
               "dtregistryout": "10.07.2024 00:00:00", "is_active": 0}
    respx.get("https://rmsp.nalog.ru/search-proc.json").mock(
        return_value=httpx.Response(200, json={"data": [msp_row]}))

    result = await _build_context(BPMSOFT, _Dead(), _Dead())
    ctx = result.context
    assert ctx.msp is not None and ctx.msp.is_active is False
    assert ctx.size_category == "unknown", \
        f"категория взята из устаревшей записи: {ctx.size_category}"
    assert ctx.employees == 386, "численность — факт, её терять не надо"
    assert "ИСКЛЮЧЕНА" in result.reason


@respx.mock
async def test_placeholder_keys_are_dropped_not_sent():
    """Заглушка-плейсхолдер не должна доходить до сервиса.

    Кириллический плейсхолдер из примера конфига ронял DaData на
    кодировании заголовка (UnicodeEncodeError наружу, инструмент падал),
    латинский — возвращал 401, который пул докладывал как «исчерпано».
    """
    from osint_mcp.keys import KeyPool

    pool = KeyPool("test", lambda: ["<подставь свой ключ>", "key2", "key2"])
    assert pool.keys() == ["key2"]


async def test_invalid_checko_key_is_not_reported_as_quota():
    """401 — неверный ключ, а не кончившаяся квота: текст различает.

    «Исчерпаны» звучит как «придите завтра», неверный ключ не
    починится и завтра — смысл у причин разный.
    """
    import respx as _respx
    from osint_mcp.context.checko import CheckoSource
    from osint_mcp.config import settings as _s

    with _respx.mock:
        _respx.get(f"{_s.checko_base_url}/company").mock(
            return_value=httpx.Response(401, json={"meta": {"message": "bad key"}}))
        data, failure = await CheckoSource()._fetch("company", BPMSOFT, "test")
    assert failure is not None and failure.status == "unavailable"
    assert "не принят" in failure.reason
    assert "исчерпаны" not in failure.reason
