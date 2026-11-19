import httpx
import pytest
import respx
from concurrent.futures import ThreadPoolExecutor
import time
import base64

from osint_mcp.tools.web_search_source import (
    NEWS_SEARCH_URL,
    SEARCH_URL,
    YAHOO_SEARCH_URL,
    SearchUnavailable,
    search_pending,
    search_web,
    clear_search_cache,
    YANDEX_SEARCH_URL,
)
from osint_mcp.config import settings


@pytest.fixture
def yandex_primary(monkeypatch):
    monkeypatch.setattr(settings, "yandex_search_mode", "primary")


@respx.mock
def test_ddg_challenge_falls_back_to_yahoo_with_direct_publisher_url():
    respx.post(SEARCH_URL).mock(return_value=httpx.Response(202, text="<html>Challenge</html>"))
    respx.get(YAHOO_SEARCH_URL).mock(return_value=httpx.Response(200, text="""
        <div class="algo-sr">
          <div class="compTitle">
            <a href="https://r.search.yahoo.com/foo/RU=https%3A%2F%2Fexample.org%2Fitem%3Fid%3D42/RK=2/RS=x">
              <h3>Заголовок &amp; текст</h3>
            </a>
          </div>
          <div class="compText">Сниппет <b>издания</b></div>
        </div>
    """))

    assert search_web("query") == [{
        "title": "Заголовок & текст",
        "url": "https://example.org/item?id=42",
        "snippet": "Сниппет издания",
    }]


@respx.mock
def test_pending_search_distinguishes_provider_failure_from_empty_results():
    respx.post(SEARCH_URL).mock(return_value=httpx.Response(202, text="<html>Challenge</html>"))
    respx.get(YAHOO_SEARCH_URL).mock(side_effect=[
        httpx.Response(200, text='<div class="no-results">No results</div>'),
        httpx.Response(503),
        httpx.Response(503),
        httpx.Response(503),
    ])

    assert search_pending("query", "web_mention") == []
    clear_search_cache()
    with pytest.raises(SearchUnavailable):
        search_pending("query", "web_mention")


@respx.mock
def test_pending_news_search_uses_rss():
    respx.get(NEWS_SEARCH_URL).mock(return_value=httpx.Response(
        200,
        text="""<rss><channel><item>
        <title>Актуальная новость</title>
        <link>https://example.org/news/1</link>
        </item></channel></rss>""",
    ))
    fact, = search_pending("query", "news_mention")
    assert fact.source_url == "https://example.org/news/1"


@respx.mock
def test_identical_parallel_searches_share_network_request():
    def respond(request):
        time.sleep(0.03)
        return httpx.Response(200, text='<a class="result-link" href="https://example.org/">Result</a>')

    route = respx.post(SEARCH_URL).mock(side_effect=respond)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: search_web("same query"), range(8)))
    assert route.call_count == 1
    assert all(result[0]["url"] == "https://example.org/" for result in results)
    results[0][0]["title"] = "changed"
    assert search_web("same query")[0]["title"] == "Result"


@respx.mock
def test_yahoo_recovers_after_temporary_502():
    respx.post(SEARCH_URL).respond(202)
    yahoo = respx.get(YAHOO_SEARCH_URL).mock(side_effect=[
        httpx.Response(502),
        httpx.Response(200, text='<div class="algo-sr"><div class="compTitle"><a href="https://example.org/"><h3>Found</h3></a></div></div>'),
    ])
    assert search_web("retry query", raise_on_unavailable=True)[0]["title"] == "Found"
    assert yahoo.call_count == 2


@respx.mock
def test_official_yandex_api_returns_publisher_urls(monkeypatch, yandex_primary):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    xml = '<yandexsearch><response><results><grouping><group><doc><url>https://example.org/page</url><title>A <hlword>title</hlword></title><passages><passage>Real snippet</passage></passages></doc></group></grouping></results></response></yandexsearch>'
    route = respx.post(YANDEX_SEARCH_URL).respond(
        json={"rawData": base64.b64encode(xml.encode()).decode()},
    )
    results = search_web("official query", raise_on_unavailable=True)
    assert results == [{"title": "A title", "url": "https://example.org/page", "snippet": "Real snippet"}]
    assert route.calls.last.request.headers["Authorization"] == "Api-Key test-key"


@respx.mock
def test_official_yandex_api_failure_is_explicit(monkeypatch, yandex_primary):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    route = respx.post(YANDEX_SEARCH_URL).respond(403)
    with pytest.raises(SearchUnavailable, match="HTTP 403"):
        search_web("official query", raise_on_unavailable=True)
    assert route.call_count == 1


@respx.mock
def test_yandex_recovers_from_temporary_server_error(monkeypatch, yandex_primary):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    xml = '<yandexsearch><response><found>0</found></response></yandexsearch>'
    route = respx.post(YANDEX_SEARCH_URL).mock(side_effect=[
        httpx.Response(502),
        httpx.Response(200, json={"rawData": base64.b64encode(xml.encode()).decode()}),
    ])
    assert search_web("query", raise_on_unavailable=True) == []
    assert route.call_count == 2


@respx.mock
def test_yandex_malformed_json_is_unavailable(monkeypatch, yandex_primary):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    respx.post(YANDEX_SEARCH_URL).respond(json=[])
    with pytest.raises(SearchUnavailable):
        search_web("query", raise_on_unavailable=True)


@respx.mock
@pytest.mark.parametrize("empty", [False, True])
def test_free_success_or_empty_never_calls_paid_yandex(monkeypatch, empty):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    html = ('<div class="no-results">No results found</div>' if empty else
            '<a class="result-link" href="https://example.org/">Found</a>')
    respx.post(SEARCH_URL).respond(text=html)
    paid = respx.post(YANDEX_SEARCH_URL).respond(403)
    result = search_web("query", raise_on_unavailable=True)
    assert len(result) == (0 if empty else 1)
    assert paid.call_count == 0


@respx.mock
def test_yahoo_success_does_not_call_yandex(monkeypatch):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    respx.post(SEARCH_URL).respond(202)
    respx.get(YAHOO_SEARCH_URL).respond(text='<div class="no-results">No results</div>')
    paid = respx.post(YANDEX_SEARCH_URL).respond(403)
    assert search_web("query", raise_on_unavailable=True) == []
    assert paid.call_count == 0


@respx.mock
def test_yandex_only_after_both_free_providers_fail_and_cache_is_free(monkeypatch):
    from osint_mcp import ledger
    from osint_mcp.tools.coverage import build_coverage

    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    respx.post(SEARCH_URL).respond(202)
    respx.get(YAHOO_SEARCH_URL).respond(403)
    xml = '<yandexsearch><response><found>0</found></response></yandexsearch>'
    paid = respx.post(YANDEX_SEARCH_URL).respond(json={"rawData": base64.b64encode(xml.encode()).decode()})
    with ledger.capture_calls():
        assert search_web("query", raise_on_unavailable=True) == []
        assert search_web("query", raise_on_unavailable=True) == []
        coverage = build_coverage("7724744134", calls=ledger.current_calls())
    assert paid.call_count == 1
    usage = next(service for service in coverage.services if service.service == "yandex_search_api")
    assert usage.requests == 1 and usage.estimated_cost_rub in (0.366, 0.488)
    cache = next(service for service in coverage.services if service.service == "web_search_cache")
    assert cache.cached == 1 and cache.estimated_cost_rub == 0


@respx.mock
def test_disabled_yandex_is_not_called_even_when_free_search_fails(monkeypatch):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    monkeypatch.setattr(settings, "yandex_search_mode", "disabled")
    respx.post(SEARCH_URL).respond(202)
    respx.get(YAHOO_SEARCH_URL).respond(403)
    paid = respx.post(YANDEX_SEARCH_URL).respond(200)
    with pytest.raises(SearchUnavailable):
        search_web("query", raise_on_unavailable=True)
    assert paid.call_count == 0


@respx.mock
def test_partial_free_result_keeps_hits_without_paid_fallback_or_complete_cache(monkeypatch):
    from osint_mcp import ledger
    from osint_mcp.tools.coverage import build_coverage

    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    good = '<a class="result-link" href="https://example.org/">Found</a>'
    route = respx.post(SEARCH_URL).mock(side_effect=[
        httpx.Response(200, text=good + '<a class="result-link" href="javascript:void(0)">Broken</a>'),
        httpx.Response(200, text=good),
    ])
    paid = respx.post(YANDEX_SEARCH_URL).respond(403)
    with ledger.capture_calls():
        partial = search_web("query", raise_on_unavailable=True)
        coverage = build_coverage("7724744134", calls=ledger.current_calls())
    assert len(partial) == 1 and partial.partial_reason
    assert coverage.total_requests == 1
    assert sum(service.cached for service in coverage.services) == 0
    assert any(gap.kind == "partial" for gap in coverage.gaps)
    assert sum(service.partial for service in coverage.services) == 1
    assert not search_web("query", raise_on_unavailable=True).partial_reason
    assert route.call_count == 2 and paid.call_count == 0


@respx.mock
@pytest.mark.parametrize("html", [
    '<a class="result-link" href="javascript:void(0)">Broken</a>',
    '<html>Verify that you are human</html>',
    '<form id="challenge-form"></form><div>No results found</div>',
])
def test_bad_free_response_switches_to_next_free_source_first(monkeypatch, html):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    respx.post(SEARCH_URL).respond(text=html)
    yahoo = respx.get(YAHOO_SEARCH_URL).respond(text='<div class="no-results">No results</div>')
    paid = respx.post(YANDEX_SEARCH_URL).respond(403)
    assert search_web("query", raise_on_unavailable=True) == []
    assert yahoo.call_count == 1 and paid.call_count == 0


@respx.mock
def test_yahoo_cards_without_valid_links_are_not_successful_empty_results(monkeypatch):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    respx.post(SEARCH_URL).respond(202)
    respx.get(YAHOO_SEARCH_URL).respond(text='<div class="algo-sr"><div class="compTitle"><h3>No link</h3></div></div>')
    xml = '<yandexsearch><response><found>0</found></response></yandexsearch>'
    paid = respx.post(YANDEX_SEARCH_URL).respond(json={"rawData": base64.b64encode(xml.encode()).decode()})
    assert search_web("query", raise_on_unavailable=True) == []
    assert paid.call_count == 1


@respx.mock
@pytest.mark.parametrize("raw", ["invalid-base64!", base64.b64encode(b"<yandexsearch><response>").decode(),
    base64.b64encode(b'<yandexsearch><response><found>2</found></response></yandexsearch>').decode(),
    base64.b64encode(b'<yandexsearch><response><found>2</found><doc><url>javascript:void(0)</url></doc></response></yandexsearch>').decode(),
])
def test_broken_yandex_payload_is_unavailable_and_not_cached(monkeypatch, yandex_primary, raw):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    route = respx.post(YANDEX_SEARCH_URL).respond(json={"rawData": raw})
    for _ in range(2):
        with pytest.raises(SearchUnavailable):
            search_web("query", raise_on_unavailable=True)
    assert route.call_count == 2


@respx.mock
def test_fewer_than_requested_results_is_not_itself_partial(monkeypatch):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    respx.post(SEARCH_URL).respond(text='<a class="result-link" href="https://example.org/">Only result</a>')
    paid = respx.post(YANDEX_SEARCH_URL).respond(403)
    hits = search_web("query", limit=10, raise_on_unavailable=True)
    assert len(hits) == 1 and not hits.partial_reason and paid.call_count == 0


@respx.mock
def test_partial_news_keeps_valid_article():
    respx.get(NEWS_SEARCH_URL).respond(text='<rss><channel><item><title>Good</title><link>https://example.org/news</link></item><item><title>Broken</title></item></channel></rss>')
    facts = search_pending("query", "news_mention")
    assert len(facts) == 1 and facts.partial_reason


@respx.mock
def test_paid_failure_after_free_failures_does_not_turn_into_successful_empty(monkeypatch):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    respx.post(SEARCH_URL).respond(202)
    respx.get(YAHOO_SEARCH_URL).respond(403)
    paid = respx.post(YANDEX_SEARCH_URL).respond(403)
    for _ in range(2):
        with pytest.raises(SearchUnavailable):
            search_web("query", raise_on_unavailable=True)
    assert paid.call_count == 2


@respx.mock
def test_loading_placeholder_is_not_a_confirmed_empty_yahoo_response(monkeypatch):
    monkeypatch.setattr(settings, "yandex_search_mode", "disabled")
    respx.post(SEARCH_URL).respond(202)
    respx.get(YAHOO_SEARCH_URL).respond(text='<div class="no-results"></div>')
    with pytest.raises(SearchUnavailable):
        search_web("query", raise_on_unavailable=True)


@respx.mock
def test_links_without_any_descriptive_text_are_not_facts():
    respx.post(SEARCH_URL).respond(text='<a class="result-link" href="https://example.org/"></a>')
    respx.get(YAHOO_SEARCH_URL).respond(text='<div class="no-results">No results</div>')
    assert search_pending("query", "web_mention") == []


@respx.mock
def test_partial_yandex_keeps_valid_hits_and_counts_one_paid_request(monkeypatch, yandex_primary):
    from osint_mcp import ledger
    from osint_mcp.tools.coverage import build_coverage

    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    xml = '<yandexsearch><response><found>2</found><doc><url>https://example.org/</url><title>Good</title></doc><doc><title>Broken</title></doc></response></yandexsearch>'
    route = respx.post(YANDEX_SEARCH_URL).respond(json={"rawData": base64.b64encode(xml.encode()).decode()})
    with ledger.capture_calls():
        result = search_web("query", raise_on_unavailable=True)
        coverage = build_coverage("7724744134", calls=ledger.current_calls())
    assert len(result) == 1 and result.partial_reason
    usage, = coverage.services
    assert route.call_count == usage.requests == usage.partial == 1
    assert usage.cached == 0 and usage.estimated_cost_rub in (0.366, 0.488)


@respx.mock
def test_parallel_failover_has_one_paid_request(monkeypatch):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    respx.post(SEARCH_URL).respond(202)
    respx.get(YAHOO_SEARCH_URL).respond(403)
    xml = '<yandexsearch><response><found>0</found></response></yandexsearch>'
    def respond(request):
        time.sleep(0.05)
        return httpx.Response(200, json={"rawData": base64.b64encode(xml.encode()).decode()})
    paid = respx.post(YANDEX_SEARCH_URL).mock(side_effect=respond)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: search_web("query", raise_on_unavailable=True), range(8)))
    assert all(result == [] for result in results) and paid.call_count == 1


@respx.mock
def test_search_limits_and_timeouts_share_one_paid_response(monkeypatch, yandex_primary):
    from osint_mcp.tools.search_budget import search_budget

    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    docs = "".join(f'<doc><url>https://example.org/{i}</url><title>Result {i}</title></doc>' for i in range(10))
    xml = f'<yandexsearch><response><found>10</found>{docs}</response></yandexsearch>'
    paid = respx.post(YANDEX_SEARCH_URL).respond(json={"rawData": base64.b64encode(xml.encode()).decode()})
    with search_budget(4) as budget:
        assert len(search_web("query", limit=3, timeout=5, raise_on_unavailable=True)) == 3
        assert len(search_web("query", limit=5, timeout=8, retries=2, raise_on_unavailable=True)) == 5
        assert len(search_web("query", limit=10, raise_on_unavailable=True)) == 10
    assert paid.call_count == budget.snapshot()["http_попыток"] == 1
