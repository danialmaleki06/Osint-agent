from unittest.mock import Mock

import pytest
import respx

from osint_mcp.context import customs, customs_mentions as source
from osint_mcp.tools.web_search_source import SearchResults

INN = "7724744134"
URL = "https://customs.gov.ru/company/7724744134"


@pytest.fixture(autouse=True)
def clear_links():
    source._LINKS.clear()
    yield
    source._LINKS.clear()


@respx.mock
def test_verified_pages_are_refreshed_without_another_search(monkeypatch):
    search = Mock(return_value=[{"url": URL, "title": "Export", "snippet": INN}])
    monkeypatch.setattr(source, "search_web", search)
    route = respx.get(URL).respond(text=f"<html><title>First</title><p>{INN} экспорт продукции</p></html>", content_type="text/html")
    first = customs.build_customs_facts(INN)
    route.respond(text=f"<html><title>Updated</title><p>{INN} импорт оборудования</p></html>", content_type="text/html")
    second = customs.build_customs_facts(INN)
    assert search.call_count == 1 and route.call_count == 2
    assert first[0].trust == second[0].trust == "mention"
    assert "Updated" in second[0].statement
    assert "не подтверждение" in second[0].statement
    assert second[0].payload["evidence_type"] == "source_page"


@respx.mock
def test_broken_saved_page_rediscovered_without_using_stale_body(monkeypatch):
    second_url = "https://customs.gov.ru/new/7724744134"
    search = Mock(side_effect=[[{"url": URL}], [{"url": second_url}]])
    monkeypatch.setattr(source, "search_web", search)
    route = respx.get(URL).respond(text=f"<html>{INN} экспорт</html>", content_type="text/html")
    customs.build_customs_facts(INN)
    route.respond(404)
    respx.get(second_url).respond(text=f"<html>{INN} импорт</html>", content_type="text/html")
    result = customs.build_customs_facts(INN)
    assert search.call_count == 2
    assert len(result) == 1 and result[0].source_url == second_url


@respx.mock
def test_generic_statistics_is_not_a_company_mention(monkeypatch):
    monkeypatch.setattr(source, "search_web", Mock(return_value=[{"url": URL, "title": "Экспорт России"}]))
    respx.get(URL).respond(text="<html>Экспорт России</html>", content_type="text/html")
    assert customs.build_customs_facts(INN) == []


def test_explicit_empty_declarations_do_not_trigger_search(monkeypatch):
    search = Mock(side_effect=AssertionError("Data already provided"))
    monkeypatch.setattr(customs, "find_customs_mentions", search)
    assert customs.build_customs_facts(INN, declarations=[]) == []
    assert search.call_count == 0


@respx.mock
def test_unverified_snippets_are_partial_and_not_saved_as_verified_pages(monkeypatch):
    monkeypatch.setattr(source, "search_web", Mock(return_value=SearchResults([
        {"url": URL, "title": f"Компания {INN}: экспорт"},
    ])))
    respx.get(URL).respond(403)
    result = customs.build_customs_facts(INN)
    assert len(result) == 1 and result.partial_reason
    assert result[0].payload["evidence_type"] == "search_snippet"
    assert INN not in source._LINKS


def test_expired_page_deadline_prevents_http_request():
    with pytest.raises(source.PageReadDeadline):
        source._read(URL, INN, deadline=-1)


def test_exhausted_read_budget_keeps_completed_documents(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(source.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(source, "search_web", Mock(return_value=[{"url": URL}, {"url": URL + "/second"}]))
    def read(url, inn, deadline):
        source._remaining(deadline)
        clock[0] += 13
        return {"url": url, "title": "Company export", "snippet": INN, "evidence_type": "source_page"}
    monkeypatch.setattr(source, "_read", read)
    result = source.find_customs_mentions(INN)
    assert len(result) == 1 and result.partial_reason
    assert "общий срок" in result.partial_reason
    assert INN not in source._LINKS
