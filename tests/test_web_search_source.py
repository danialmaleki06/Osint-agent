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
def test_official_yandex_api_returns_publisher_urls(monkeypatch):
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
def test_official_yandex_api_failure_is_explicit(monkeypatch):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    route = respx.post(YANDEX_SEARCH_URL).respond(403)
    with pytest.raises(SearchUnavailable, match="HTTP 403"):
        search_web("official query", raise_on_unavailable=True)
    assert route.call_count == 1


@respx.mock
def test_yandex_recovers_from_temporary_server_error(monkeypatch):
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
def test_yandex_malformed_json_is_unavailable(monkeypatch):
    monkeypatch.setattr(settings, "yandex_search_api_key", "test-key")
    monkeypatch.setattr(settings, "yandex_search_folder_id", "test-folder")
    respx.post(YANDEX_SEARCH_URL).respond(json=[])
    with pytest.raises(SearchUnavailable):
        search_web("query", raise_on_unavailable=True)
