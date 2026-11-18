import httpx
import pytest
import respx

from osint_mcp.tools.web_search_source import (
    NEWS_SEARCH_URL,
    SEARCH_URL,
    YAHOO_SEARCH_URL,
    SearchUnavailable,
    search_pending,
    search_web,
)


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
    ])

    assert search_pending("query", "web_mention") == []
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
