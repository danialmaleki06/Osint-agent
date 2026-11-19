import json

import httpx
import pytest
import respx

from osint_mcp.context.geo_card import GeoCardUnavailable, fetch_geo_card, parse_card, _CACHE
from osint_mcp.context.geo_reviews import build_geo_reviews_facts
from osint_mcp.tools.search_budget import search_budget
from osint_mcp.tools.web_search_source import SearchUnavailable


CARD = "https://2gis.ru/moscow/firm/123456789"


def html(website="https://company.example"):
    state = {"data": {"entity": {"profile": {"123456789": {"data": {
        "id": "123456789", "type": "branch", "name": "Компания", "address_name": "Улица, 1",
        "contact_groups": [{"contacts": [{"type": "website", "url": website}]}],
        "reviews": {"general_rating": 3.1, "general_review_count": 4},
    }}}}}}
    return "<script>var initialState = JSON.parse(" + repr(json.dumps(state)) + ");</script>"


def test_card_requires_matching_official_domain():
    card = parse_card(html(), CARD, "https://www.company.example")
    assert card.rating == 3.1 and card.review_count == 4
    with pytest.raises(GeoCardUnavailable):
        parse_card(html("https://other.example"), CARD, "company.example")


@pytest.mark.parametrize("page", ["<html>Captcha</html>", "<script>var initialState = JSON.parse('{}');</script>"])
def test_unknown_card_format_is_unavailable(page):
    with pytest.raises(GeoCardUnavailable):
        parse_card(page, CARD, "company.example")


@respx.mock
def test_direct_card_uses_source_search_and_verified_card():
    _CACHE.clear()
    search = respx.get(url__startswith="https://2gis.ru/search/").respond(text='<a href="/moscow/firm/123456789">Company</a>')
    card = respx.get(CARD).respond(text=html())
    assert fetch_geo_card("Company", "Москва", "company.example").url == CARD
    assert fetch_geo_card("Company", "Москва", "company.example").url == CARD
    assert search.call_count == card.call_count == 1
    _CACHE.clear()


@respx.mock
def test_verified_card_survives_unavailable_web_search(monkeypatch):
    from osint_mcp.context import geo_reviews

    _CACHE.clear()
    respx.get(url__startswith="https://2gis.ru/search/").respond(text='<a href="/moscow/firm/123456789">Company</a>')
    respx.get(CARD).respond(text=html())
    def fail(*args, **kwargs):
        raise SearchUnavailable("Бюджет исчерпан")
    monkeypatch.setattr(geo_reviews, "search_web", fail)
    with search_budget(0):
        result = build_geo_reviews_facts("7724744134", "Компания", "Москва", website="company.example")
    assert len(result) == 1 and result[0].kind == "geo_card_signal"
    assert result[0].source_url == CARD and result.partial_reason
    assert "3.1" in result[0].statement
    _CACHE.clear()
