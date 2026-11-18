"""Тесты источников Федресурса и ФГИС Росаккредитации — офлайн, respx.

Живые прогоны против Федресурса выполнялись 06.10.2026: поиск по ИНН
требует и code, и searchString одновременно (без второго сервис
возвращает первые попавшие записи), заголовок Referer обязателен.
Формат ФСА восстановлен по открытым парсерам; live-доступ из части
сетей закрыт geo-ограничением — отказ сети обязан быть честным
«не проверено», а не пустотой.
"""

import json
from datetime import date, datetime, timezone
from pathlib import Path

import httpx
import pytest
import respx

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.context.fedresurs import FedresursSource, classify_publication
from osint_mcp.context.fsa import FsaSource

pytestmark = pytest.mark.anyio

FIXTURES = Path(__file__).parent / "fixtures"
BPMSOFT = "7724744134"
GUID = "92cc1e6c-371c-4f6b-94de-72f8478a6166"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# ───────────────────────  Федресурс: классификатор  ───────────────────────


def test_classify_leasing():
    assert classify_publication(
        "Уведомление о заключении договора лизинга. Лизингополучатель: ООО X"
    ) == "leasing"


def test_classify_pledge():
    assert classify_publication(
        "Уведомление о возникновении залога движимого имущества"
    ) == "pledge"


def test_classify_factoring():
    assert classify_publication(
        "Уведомление о факторинге. Клиент: ООО X"
    ) == "factoring"


def test_classify_guarantee():
    assert classify_publication(
        "Сообщение о выдаче независимой гарантии"
    ) == "guarantee"


def test_classify_sro():
    assert classify_publication(
        "Сообщение о членстве в саморегулируемой организации"
    ) == "sro_membership"


def test_classify_unknown_returns_none():
    """Опознанное остаётся опознанным, остальное не притягивается."""
    assert classify_publication("Объявление о проведении торгов") is None
    assert classify_publication(None) is None
    # «перестройка» содержит «строй» — но не СРО: регистр и подслова
    # не должны ловить лишнее
    assert classify_publication("Регистрация изменений в уставе") is None


# ───────────────────────  Федресурс: источник  ───────────────────────


def _mock_fedresurs(company=None, publications=None, company_status=200,
                    pub_status=200):
    search_url = (f"{settings.fedresurs_base_url}/backend/companies")
    respx.get(search_url).mock(
        return_value=httpx.Response(
            company_status,
            json=company if company is not None else _fixture("fedresurs_company_bpmsoft.json"),
        )
    )
    respx.get(
        f"{settings.fedresurs_base_url}/backend/companies/{GUID}/publications"
    ).mock(
        return_value=httpx.Response(
            pub_status,
            json=(publications if publications is not None
                  else _fixture("fedresurs_publications_bpmsoft.json")),
        )
    )


@respx.mock
async def test_fedresurs_parses_commercial_facts():
    """Лизинг, залог, факторинг и СРО распознаются; банкротные сообщения
    не дублируются (они приходят с карточкой Checko)."""
    _mock_fedresurs()
    result = await FedresursSource().check_commercial_facts(BPMSOFT)

    assert result.status == "ok"
    kinds = [f.kind for f in result.facts]
    assert "pledge" in kinds
    assert "leasing" in kinds
    assert "factoring" in kinds
    assert "sro_membership" in kinds
    # Нераспознанный существенный факт сохраняется — не выбрасывается
    assert "fedresurs_publication" in kinds
    # Банкротные торги отсюда не берутся
    assert kinds.count("bankruptcy") == 0
    # Каждому факту — ссылка на Федресурс
    assert all("fedresurs.ru" in f.source_url for f in result.facts)


@respx.mock
async def test_fedresurs_fact_statement_carries_details():
    """Заголовок с предметом залога доходит до утверждения — там парк
    оборудования, по которому видно, чем компания занимается."""
    _mock_fedresurs()
    result = await FedresursSource().check_commercial_facts(BPMSOFT)
    pledge = next(f for f in result.facts if f.kind == "pledge")
    assert "ЧПУ" in pledge.statement or "станки" in pledge.statement.lower()


@respx.mock
async def test_fedresurs_unknown_company_is_valid_empty():
    """Организации в реестре нет — это валидная пустота, не отказ."""
    _mock_fedresurs(company={"pageData": [], "found": 0})
    result = await FedresursSource().check_commercial_facts(BPMSOFT)
    assert result.status == "ok"
    assert result.facts == []


@respx.mock
async def test_fedresurs_no_publications_is_partial():
    """Компания есть, публикаций нет — partial с оговоркой о смысле пустоты."""
    _mock_fedresurs(publications={"pageData": [], "found": 0})
    result = await FedresursSource().check_commercial_facts(BPMSOFT)
    assert result.status == "partial"
    assert result.reason and "означает" in result.reason


@respx.mock
async def test_fedresurs_http_error_is_unavailable():
    _mock_fedresurs(company_status=451)
    result = await FedresursSource().check_commercial_facts(BPMSOFT)
    assert result.status == "unavailable"
    assert result.reason


@respx.mock
async def test_fedresurs_network_error_is_unavailable():
    respx.get(f"{settings.fedresurs_base_url}/backend/companies").mock(
        side_effect=httpx.ConnectError("refused")
    )
    result = await FedresursSource().check_commercial_facts(BPMSOFT)
    assert result.status == "unavailable"
    assert result.reason


# ───────────────────────  Росаккредитация  ───────────────────────


def _mock_fsa(decl=None, certs=None, status=200):
    respx.post("https://pub.fsa.gov.ru/api/v1/rds/common/declarations/get").mock(
        return_value=httpx.Response(
            status, json=decl if decl is not None else _fixture("fsa_declarations_bpmsoft.json"),
        )
    )
    respx.post("https://pub.fsa.gov.ru/api/v1/rss/common/certificates/get").mock(
        return_value=httpx.Response(
            status, json=certs if certs is not None else _fixture("fsa_certificates_bpmsoft.json"),
        )
    )


@respx.mock
async def test_fsa_parses_declarations_and_certificates():
    """Декларации и сертификаты по ИНН приходят с продукцией и датами."""
    _mock_fsa()
    result = await FsaSource().check_certificates(BPMSOFT, "БПМСОФТ")

    assert result.status == "ok"
    assert len(result.facts) == 3  # 2 декларации + 1 сертификат
    assert all(f.kind == "fsa_certificate" for f in result.facts)
    # Даты окончания распарсены и попали в payload (порог скоринга смотрит туда)
    ends = [f.payload["end_date"] for f in result.facts]
    assert "2028-01-19" in ends
    assert "2026-08-31" in ends
    assert "2029-02-09" in ends
    # Продукция видна в утверждении
    assert any("Светильники" in f.statement for f in result.facts)
    # Ссылки ведут на карточки реестра
    assert any("/rds/declaration/view/18725645/" in f.source_url for f in result.facts)
    assert any("/rss/certificate/view/2790610/" in f.source_url for f in result.facts)
    # Зарубежный изготовитель (Китай) распознан
    zhejiang = next(f for f in result.facts if "ZHEJIANG" in f.payload.get("manufacturer", ""))
    assert zhejiang.payload["is_foreign"] is True
    assert zhejiang.payload["origin_country"] == "Китай"
    assert "импорт: Китай" in zhejiang.statement


@respx.mock
async def test_fsa_empty_result_is_partial_with_caveat():
    """Не у всякой продукции есть обязательная сертификация — пустой
    результат честно оговаривается."""
    _mock_fsa(decl={"items": [], "total": 0}, certs={"items": [], "total": 0})
    result = await FsaSource().check_certificates(BPMSOFT)
    assert result.status == "partial"
    assert result.reason and "означает" in result.reason


@respx.mock
async def test_fsa_geo_block_is_unavailable():
    """Недоступность из сети — НЕ «сертификатов нет», а «не проверено»."""
    respx.post("https://pub.fsa.gov.ru/api/v1/rds/common/declarations/get").mock(
        side_effect=httpx.ConnectTimeout("timeout")
    )
    respx.post("https://pub.fsa.gov.ru/api/v1/rss/common/certificates/get").mock(
        return_value=httpx.Response(403)
    )
    result = await FsaSource().check_certificates(BPMSOFT)
    assert result.status == "unavailable"
    assert result.reason and "НЕ ПРОВЕРЕНЫ" in result.reason
    assert "ConnectTimeout" in result.reason and "HTTP 403" in result.reason


@pytest.mark.parametrize("failed", ["declarations", "certificates"])
@respx.mock
async def test_fsa_keeps_facts_when_one_endpoint_fails(failed):
    urls = {
        "declarations": "https://pub.fsa.gov.ru/api/v1/rds/common/declarations/get",
        "certificates": "https://pub.fsa.gov.ru/api/v1/rss/common/certificates/get",
    }
    for method, url in urls.items():
        response = (
            httpx.Response(403) if method == failed
            else httpx.Response(200, json=_fixture(f"fsa_{method}_bpmsoft.json"))
        )
        respx.post(url).mock(return_value=response)

    with ledger.capture_calls():
        result = await FsaSource().check_certificates(BPMSOFT)
        statuses = {call.method: call.outcome for call in ledger.current_calls() or []}

    assert result.status == "partial"
    assert result.reason and "HTTP 403" in result.reason
    available = next(method for method in urls if method != failed)
    assert statuses == {failed: "failed", available: "ok"}
    assert len(result.facts) == (2 if available == "declarations" else 1)
    assert all(f.payload["doc_type"] == available[:-1] for f in result.facts)


@respx.mock
async def test_fsa_error_json_is_failed_and_page_limit_is_reported():
    declarations = _fixture("fsa_declarations_bpmsoft.json")
    declarations["total"] = 19
    _mock_fsa(decl=declarations, certs={"error": "Сервис недоступен"})

    result = await FsaSource().check_certificates(BPMSOFT)

    assert result.status == "partial"
    assert result.reason and "получено 2 из 19" in result.reason
    assert "неожиданный формат" in result.reason
    assert len(result.facts) == 2


def test_detect_manufacturer_origins():
    from osint_mcp.context.fsa import detect_manufacturer_origin

    assert detect_manufacturer_origin("ZHEJIANG INDUSTRIAL CO., LTD") == (True, "Китай")
    assert detect_manufacturer_origin("ISTANBUL SANAYI VE TICARET A.S.") == (True, "Турция")
    assert detect_manufacturer_origin("SIEMENS AG, GERMANY") == (True, "Германия")
    assert detect_manufacturer_origin("FABRIQUE SARL, FRANCE") == (True, "Франция")
    assert detect_manufacturer_origin("ООО \"ПРИБОР-ЛАБ\"") == (False, None)
    assert detect_manufacturer_origin("OOO \"BPM SOFT\"") == (False, None)

