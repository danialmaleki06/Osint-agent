"""Единый реестр субъектов МСП (rmsp.nalog.ru) — бесплатный источник ФНС.

Реестр подтверждает масштаб организации независимо от нашей оценки:
категорию выставляет сама ФНС по выручке и численности. Бесплатно,
без ключей. Метод недокументированный веб-API — при изменении формата
источник честно помечается недоступным, не молча.

Тонкость: в ответе категория числом (0 — микро, 1 — малое, 2 — среднее).
Признак is_active прямое: 1 — действующий, 0 — исключён (у исключённого
заполнена и дата dtregistryout). Раньше признак считался перевёрнутым,
и исключённая из реестра компания приходила как действующая — поймано
живым прогоном: у исключённой БПМСОФТ is_active=0 при заполненной дате
исключения, у действующего ЛАНСОФТ is_active=1 и даты исключения нет.
"""

from datetime import date

import httpx
import structlog

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.models import MspInfo

log = structlog.get_logger()

# Категория реестра: число -> наша запись
_CATEGORIES = {0: "micro", 1: "small", 2: "medium"}


class RmspSource:
    """Реестр субъектов малого и среднего предпринимательства."""

    name = "rmsp"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def get_msp(self, inn: str) -> tuple[MspInfo | None, str | None]:
        """Сведения реестра МСП. Возвращает (данные, причина отказа).

        None при отказе источника; «в реестре не значится» — валидный
        результат (крупные организации там не значатся по определению).
        """
        service, method = self.name, "request"
        try:
            if self._client is not None:
                resp = await self._client.get(
                    f"{settings.rmsp_base_url}/search-proc.json",
                    params={"query": inn},
                )
            else:
                async with httpx.AsyncClient(
                    timeout=settings.request_timeout,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; osint-mcp)"},
                ) as client:
                    resp = await client.get(
                        f"{settings.rmsp_base_url}/search-proc.json",
                        params={"query": inn},
                    )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as e:
            ledger.record(service, method, "failed", f"сеть: {type(e).__name__}")
            return None, f"Реестр МСП недоступен: {type(e).__name__}"
        except ValueError:
            ledger.record(service, method, "failed", "ответ не JSON")
            return None, "Реестр МСП вернул не JSON"

        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            ledger.record(service, method, "failed", "неожиданный формат ответа")
            return None, "Реестр МСП вернул неожиданный формат"

        row = next((r for r in rows if str(r.get("inn")) == inn), None)
        if row is None:
            ledger.record(service, method, "empty", "в реестре не значится")
            # Валидная пустота: крупный бизнес в реестре не значится по определению
            return None, None

        def _d(value) -> date | None:
            if not isinstance(value, str) or not value:
                return None
            try:
                day, month, year = value.split(".")[:3]
                # Время в конце строки («10.08.2018 00:00:00») срезаем:
                # реестр отдаёт дату вместе со временем
                return date(int(year.split()[0]), int(month), int(day))
            except (ValueError, IndexError):
                return None

        raw_active = row.get("is_active")
        if raw_active is None:
            # Поля нет — выводим из даты исключения: нет даты, значит
            # не исключён
            active = not row.get("dtregistryout")
        else:
            active = raw_active in (1, "1", True)
        try:
            msp = MspInfo(
                in_registry=True,
                category=_CATEGORIES.get(row.get("category")),
                employees=int(row["od2_sschr"]) if row.get("od2_sschr") is not None else None,
                included_at=_d(row.get("dtregistry")),
                excluded_at=_d(row.get("dtregistryout")),
                is_active=active,
            )
        except (TypeError, ValueError) as e:
            ledger.record(service, method, "failed", f"неожиданные данные: {e}")
            return None, f"Реестр МСП вернул неожиданные данные: {e}"

        ledger.record(service, method, "ok")
        log.info("rmsp.found", inn=inn, category=msp.category,
                 active=msp.is_active)
        return msp, None
