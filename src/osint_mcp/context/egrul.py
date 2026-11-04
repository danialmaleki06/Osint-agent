"""Сведения ЕГРЮЛ напрямую (egrul.nalog.ru) — бесплатный резерв карточки.

Официальный сервис ФНС «Предоставление сведений из ЕГРЮЛ/ЕГРИП».
Официального API у него нет, но веб-интерфейс общается через JSON,
и тот же флоу воспроизводится программно:

  1. POST на главную с параметром query (ИНН/ОГРН) -> в ответе токен `t`;
  2. GET /search-result/{t} -> карточка в поле rows[0].

Источник — резерв DaData и Checko: структура скромнее (наименование,
руководитель, ОГРН, КПП, дата регистрации, регион), но её хватает,
чтобы краткий отчёт и пакетный режим работали при исчерпанных квотах
обоих основных источников.

Сервис чувствител к частоте обращений и иногда требует капчу — тогда
запрос честно помечается недоступным, никакой обход не применяется.
"""

import time

import httpx
import structlog

from osint_mcp import ledger
from osint_mcp.config import settings

log = structlog.get_logger()

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


class EgrulSource:
    """Резервная карточка ЕГРЮЛ с официального сервиса ФНС."""

    name = "egrul"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def _search(self, inn: str) -> dict | None:
        """Флоу POST -> токен -> search-result. None — не найдено."""
        if self._client is not None:
            resp = await self._client.post(
                settings.egrul_base_url,
                data={
                    "vyp3CaptchaToken": "", "page": "", "query": inn,
                    "region": "", "PreventChromeAutocomplete": "",
                },
            )
        else:
            async with httpx.AsyncClient(
                timeout=settings.request_timeout,
                headers={"User-Agent": _UA, "Referer": f"{settings.egrul_base_url}/"},
            ) as client:
                resp = await client.post(
                    settings.egrul_base_url,
                    data={
                        "vyp3CaptchaToken": "", "page": "", "query": inn,
                        "region": "", "PreventChromeAutocomplete": "",
                    },
                )
        resp.raise_for_status()
        token = (resp.json() or {}).get("t")
        if not token:
            # Сервис иногда отдаёт пустой токен при подозрительной частоте
            # обращений — это отказ, а не «не найдено»
            ledger.record(self.name, "card", "failed", "сервис не выдал токен поиска")
            raise RuntimeError("egrul: пустой токен поиска (возможно, требуется капча)")

        stamp = int(time.time() * 1000)
        result = await self._client.get(
            f"{settings.egrul_base_url}/search-result/{token}",
            params={"r": stamp, "_": stamp},
        ) if self._client is not None else None
        if result is None:
            async with httpx.AsyncClient(
                timeout=settings.request_timeout,
                headers={"User-Agent": _UA, "Referer": f"{settings.egrul_base_url}/"},
            ) as client:
                result = await client.get(
                    f"{settings.egrul_base_url}/search-result/{token}",
                    params={"r": stamp, "_": stamp},
                )
        result.raise_for_status()
        rows = (result.json() or {}).get("rows") or []
        for row in rows:
            if str(row.get("i")) == inn:
                return row
        return None

    async def get_card(self, inn: str) -> tuple[dict | None, str | None]:
        """Краткая карточка ЕГРЮЛ. Возвращает (данные, причина отказа)."""
        try:
            row = await self._search(inn)
        except RuntimeError as e:
            return None, str(e)
        except (httpx.HTTPError, ValueError) as e:
            ledger.record(self.name, "card", "failed", f"сеть/формат: {type(e).__name__}")
            return None, f"Сервис ЕГРЮЛ недоступен: {type(e).__name__}"

        if not row:
            ledger.record(self.name, "card", "empty", "в реестре не найдена")
            return None, "организация в ЕГРЮЛ не найдена"

        ledger.record(self.name, "card", "ok")
        log.info("egrul.found", inn=inn, name=row.get("c"))
        return row, None


def brief_from_egrul(row: dict) -> dict:
    """Разобрать строку выдачи в краткую карточку.

    Поля выдачи: n — полное наименование, c — краткое, i — ИНН,
    o — ОГРН, p — КПП, r — дата регистрации (дд.мм.гггг),
    g — руководитель с должностью, rn — регион.
    """
    def _d(value):
        if not isinstance(value, str) or not value:
            return None
        try:
            day, month, year = value.split(".")[:3]
            from datetime import date as _date
            return _date(int(year), int(month), int(day))
        except (ValueError, IndexError):
            return None

    director = row.get("g") or ""
    # Формат: "ГЕНЕРАЛЬНЫЙ ДИРЕКТОР: Иванов Иван Иванович"
    post, _, fio = director.partition(":")
    return {
        "name_legal": row.get("n") or row.get("c") or "",
        "name_short": row.get("c"),
        "inn": row.get("i"),
        "ogrn": row.get("o"),
        "kpp": row.get("p"),
        "registered_at": _d(row.get("r")),
        "director_fio": fio.strip() or None,
        "director_post": post.strip() or None,
        "region": row.get("rn") or None,
    }
