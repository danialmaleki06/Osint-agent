"""Тесты пула ключей: ротация при исчерпании лимита, форматы списков в .env.

Сценарий из жизни: суточный лимит одного ключа кончается посреди проверки.
Сервис отвечает 403, пул молча переходит к следующему ключу, и досье
собирается целиком — вместо пяти источников со статусом unavailable.
"""

import httpx
import pytest
import respx

from osint_mcp import keys as keys_mod
from osint_mcp.config import settings
from osint_mcp.context.checko import CheckoSource
from osint_mcp.keys import KeyPool

pytestmark = pytest.mark.anyio

BPMSOFT = "7724744134"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _clean_pools():
    keys_mod.dadata.reset()
    keys_mod.checko.reset()
    yield
    keys_mod.dadata.reset()
    keys_mod.checko.reset()


def _fixture(name: str) -> dict:
    import json
    from pathlib import Path

    return json.loads(
        (Path(__file__).parent / "fixtures" / name).read_text(encoding="utf-8")
    )


# ───────────────────────  форматы ключей в настройках  ───────────────────────

def test_pool_prefers_list_over_single(monkeypatch):
    monkeypatch.setattr(settings, "checko_api_keys", "aaa,bbb")
    monkeypatch.setattr(settings, "checko_api_key", "ccc")
    assert keys_mod.checko.keys() == ["aaa", "bbb"]


def test_pool_falls_back_to_single(monkeypatch):
    monkeypatch.setattr(settings, "checko_api_keys", "")
    monkeypatch.setattr(settings, "checko_api_key", "ccc")
    assert keys_mod.checko.keys() == ["ccc"]


def test_pool_skips_empty_and_duplicates(monkeypatch):
    monkeypatch.setattr(settings, "checko_api_keys", "aaa, ,aaa,bbb,")
    assert keys_mod.checko.keys() == ["aaa", "bbb"]


def test_validator_accepts_json_list():
    assert settings._allow_list('["aaa", "bbb"]') == "aaa,bbb"


def test_validator_keeps_plain_list():
    assert settings._allow_list("aaa, bbb") == "aaa, bbb"


# ───────────────────────  поведение пула  ───────────────────────

def test_current_without_keys_raises(monkeypatch):
    monkeypatch.setattr(settings, "checko_api_keys", "")
    monkeypatch.setattr(settings, "checko_api_key", "")
    with pytest.raises(RuntimeError, match="CHECKO"):
        keys_mod.checko.current()


def test_rotate_moves_to_next_and_marks_exhausted(monkeypatch):
    pool = KeyPool("test", lambda: ["aaa", "bbb"])
    assert pool.current() == "aaa"

    assert pool.rotate("HTTP 403") is True
    assert pool.current() == "bbb"

    states = {s["key"]: s["state"] for s in pool.status()}
    assert states["…aaa"] == "exhausted"
    assert states["…bbb"] == "ok"


def test_rotate_returns_false_when_depleted():
    pool = KeyPool("test", lambda: ["aaa"])
    assert pool.rotate("HTTP 403") is False


def test_exhausted_key_revives_after_ttl():
    """Пометка не вечная: истекла — ключ снова первый кандидат.

    Курсор прилипает к последнему рабочему ключу, поэтому в pristine
    состоянии выбор падает на 'aaa' только когда список один.
    """
    pool = KeyPool("test", lambda: ["aaa", "bbb"], ttl=0.01)
    pool.mark_exhausted("aaa")
    assert pool.current() == "bbb"       # пока пометка жива — второй ключ
    import time

    time.sleep(0.02)
    pool._cursor = None                  # имитация нового цикла выбора
    assert pool.current() == "aaa"       # пометка истекла — ключ вернулся


def test_current_falls_back_when_all_exhausted(monkeypatch):
    """Когда помечены все, пул пробует первый: пусть сервис откажет ещё раз."""
    pool = KeyPool("test", lambda: ["aaa"])
    pool.mark_exhausted("aaa")
    assert pool.current() == "aaa"


# ───────────────────────  ротация в живом запросе  ───────────────────────

def _checko_handler():
    """Первый ключ — 403, остальные — живой ответ из образца."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("key") == "keyA":
            return httpx.Response(
                403,
                json={"meta": {"message": "Превышен суточный лимит запросов"}},
            )
        return httpx.Response(200, json=_fixture("checko_company_bpmsoft.json"))

    return handler


@respx.mock
async def test_checko_rotates_to_second_key_on_403(monkeypatch):
    monkeypatch.setattr(settings, "checko_api_keys", "keyA,keyB")
    route = respx.get(f"{settings.checko_base_url}/company").mock(
        side_effect=_checko_handler()
    )

    res = await CheckoSource().check_registry_flags(BPMSOFT)

    assert res.status == "ok"                        # досье собрано, а не отказано
    assert route.call_count == 2                     # первый ключ отвергнут, второй сработал
    assert route.calls.last.request.url.params["key"] == "keyB"


@respx.mock
async def test_checko_reports_honestly_when_all_keys_depleted(monkeypatch):
    monkeypatch.setattr(settings, "checko_api_keys", "keyA,keyB")

    def always_403(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"meta": {"message": "Превышен суточный лимит запросов"}},
        )

    respx.get(f"{settings.checko_base_url}/company").mock(side_effect=always_403)

    res = await CheckoSource().check_registry_flags(BPMSOFT)

    assert res.status == "unavailable"
    assert "исчерпаны" in res.reason
