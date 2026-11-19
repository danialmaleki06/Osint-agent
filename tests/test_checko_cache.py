import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest

from osint_mcp import ledger
from osint_mcp.context import checko
from osint_mcp.context.checko import CheckoSource


@pytest.mark.asyncio
async def test_identical_parallel_calls_share_one_request_and_keep_copies():
    ledger.reset()
    source = CheckoSource()
    response = httpx.Response(
        200, json={"meta": {"status": "ok"}, "data": {"name": "original"}},
    )

    async def request(*args):
        await asyncio.sleep(0.01)
        return response

    source._request = AsyncMock(side_effect=request)
    with ledger.capture_calls():
        first, second = await asyncio.gather(
            source._get("company", {"inn": "7724744134"}),
            source._get("company", {"inn": "7724744134"}),
        )
        first["data"]["name"] = "changed"
        third = await source._get("company", {"inn": "7724744134"})
        calls = ledger.current_calls()
    assert source._request.await_count == 1
    assert second["data"]["name"] == third["data"]["name"] == "original"
    assert ledger.session_totals()["checko"] == 1
    assert sum(c.cached for c in calls) == 2


@pytest.mark.asyncio
async def test_cache_expires_and_preserves_pagination(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(checko, "monotonic", lambda: clock[0])
    source = CheckoSource()
    source._request = AsyncMock(return_value=httpx.Response(
        200, json={"meta": {"status": "ok"}, "data": {"rows": []}},
    ))
    await source._get("legal-cases", {"inn": "7724744134", "page": 1})
    await source._get("legal-cases", {"inn": "7724744134", "page": 2})
    clock[0] = 301
    await source._get("legal-cases", {"inn": "7724744134", "page": 1})
    assert source._request.await_count == 3


@pytest.mark.asyncio
async def test_failed_response_is_not_cached():
    source = CheckoSource()
    source._request = AsyncMock(side_effect=[
        httpx.Response(200, json={"meta": {"status": "error"}}),
        httpx.Response(200, json={"meta": {"status": "ok"}, "data": {"found": True}}),
    ])
    await source._get("company", {"inn": "7724744134"})
    result = await source._get("company", {"inn": "7724744134"})
    assert result["data"]["found"]
    assert source._request.await_count == 2
