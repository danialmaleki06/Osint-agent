"""Резервный агрегатор api-cloud.ru — третий эшелон проверок.

Подключается, когда прямой источник по направлению не ответил: квоты
Checko исчерпаны, сервис лежит. Бесплатный тариф агрегатора — около
200 запросов в месяц, поэтому источник дёргается ТОЛЬКО при реальном
отказе прямого канала и помечается в отчёте как резервный.

Ключ задается в .env (APICLOUD_KEY). Без ключа источники просто
помечаются недоступными — сервер не падает, резерв не обязателен.

Разбор ответов защитный: документация агрегатора полна примеров,
но форматы полей от случая к случаю гуляют, а падать на резервном
источнике недопустимо.
"""

from datetime import datetime, timezone

import httpx
import structlog

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.models import (
    ArbitrationSummary,
    EnforcementSummary,
    Fact,
    RoleCounts,
    SourceResult,
)

log = structlog.get_logger()


def _num(value) -> float:
    """Число из того, что агрегатор называет числом: '12 345.67 руб.' и т.п."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    digits = "".join(ch for ch in str(value) if ch.isdigit() or ch == ".")
    try:
        return float(digits) if digits else 0.0
    except ValueError:
        return 0.0


def _d(value):
    """Дата из дд.мм.гггг — без падений на пустом и кривом."""
    if not isinstance(value, str) or not value:
        return None
    try:
        day, month, year = value.split(".")[:3]
        from datetime import date as _date
        return _date(int(year), int(month), int(day))
    except (ValueError, IndexError):
        return None


class ApiCloudSource:
    """Резервные проверки через агрегатор api-cloud.ru."""

    name = "apicloud"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def _get(self, method: str, params: dict, *, record_success: bool = True) -> dict | None:
        """GET к агрегатору. None при любой неудаче — источник резервный."""
        key = settings.apicloud_key
        if not key:
            ledger.record(self.name, method, "failed", "ключ APICLOUD_KEY не задан")
            return None
        params = {**params, "token": key}
        try:
            if self._client is not None:
                resp = await self._client.get(
                    f"{settings.apicloud_base_url}/{method}", params=params
                )
            else:
                async with httpx.AsyncClient(
                    timeout=max(settings.request_timeout, 30.0),
                    headers={"User-Agent": "Mozilla/5.0 (compatible; osint-mcp)"},
                ) as client:
                    resp = await client.get(
                        f"{settings.apicloud_base_url}/{method}", params=params
                    )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            ledger.record(self.name, method, "failed", f"{type(e).__name__}")
            return None
        if not isinstance(data, dict):
            ledger.record(self.name, method, "failed", "неожиданный формат")
            return None
        if "error" in data and data.get("status") != 200:
            ledger.record(self.name, method, "failed", str(data.get("message") or "ошибка агрегатора"))
            return None
        if record_success:
            ledger.record(self.name, method, "ok")
        return data

    # ─────────────────────────  ФССП  ─────────────────────────

    async def check_enforcement(self, inn: str) -> SourceResult:
        """Исполнительные производства по ИНН. Прямой аналог checko.enforcement."""
        method = "fssp.php"
        source = "apicloud.enforcement"
        if len(inn) != 10 or not inn.isascii() or not inn.isdecimal():
            return SourceResult(
                source=source, status="unavailable",
                reason="Поиск ФССП через api-cloud требует 10-значный ИНН организации",
            )
        data = await self._get(
            method, {"type": "inn", "inn": inn, "region": "-1"}, record_success=False,
        )
        if data is None:
            reason = (
                "Резервный источник ФССП не ответил"
                if settings.apicloud_key else "Для подключения к ФССП через api-cloud не задан APICLOUD_KEY"
            )
            return SourceResult(source=source, status="unavailable", reason=reason)

        count = str(data.get("countAll", data.get("count", "")))
        records = data.get("records", [] if count == "0" else None)
        if (
            str(data.get("status")) != "200" or data.get("error")
            or not (count.isascii() and count.isdecimal())
            or not isinstance(records, list)
            or any(not isinstance(rec, dict) or not str(rec.get("process_title") or "").strip() for rec in records)
            or int(count) < len(records) or (int(count) > 0 and not records)
        ):
            reason = "api-cloud вернул непроверяемую выдачу ФССП"
            ledger.record(self.name, method, "failed", reason)
            return SourceResult(source=source, status="unavailable", reason=reason)

        total = int(count)
        total_amount = sum(_num(rec.get("sum")) for rec in records)
        outstanding = sum(
            _num(rec.get("sum")) for rec in records
            if not (rec.get("stopIP") or rec.get("stopIPDate"))
        )
        now = datetime.now(timezone.utc)
        facts: list[Fact] = []
        for i, rec in enumerate(records[:10], 1):
            amount = _num(rec.get("sum"))
            facts.append(Fact(
                fact_id=f"REN-{i}",
                kind="enforcement",
                statement=(f"[резервный источник] Исполнительное производство "
                           f"{rec.get('process_title') or 'б/н'}: "
                           f"{rec.get('subject') or 'предмет не указан'}, "
                           f"сумма {amount:,.0f} ₽".replace(",", " ")),
                source_url="https://fssp.gov.ru/iss/ip",
                source_type="registry_api",
                retrieved_at=now,
                event_date=_d(rec.get("process_date")),
                payload={"number": rec.get("process_title"), "amount": amount,
                         "subject": rec.get("subject"), "via": "apicloud"},
            ))
        reason = None
        if not total:
            reason = "По запросу ФССП через api-cloud совпадений не найдено"
        elif len(records) < total:
            reason = f"Получено {len(records)} из {total} производств. Суммы по полученным записям"
        ledger.record(self.name, method, "ok" if total else "empty")
        return SourceResult(
            source=source,
            status="partial" if reason else "ok",
            reason=reason,
            facts=facts,
            enforcement=EnforcementSummary(
                total=total, total_amount=total_amount, outstanding=outstanding,
            ),
        )

    # ─────────────────────────  банкротство  ─────────────────────────

    async def check_bankruptcy(self, inn: str, name: str | None = None) -> SourceResult:
        """Сообщения о банкротстве. Поиск агрегатора ведёт по наименованию."""
        if not name:
            return SourceResult(
                source="apicloud.bankruptcy", status="skipped",
                reason="Для резервной проверки банкротства нужно наименование",
            )
        data = await self._get("bankrot.php", {"type": "search", "searchstring": name})
        if data is None:
            return SourceResult(
                source="apicloud.bankruptcy", status="unavailable",
                reason="Резервный источник банкротств не ответил",
            )
        # Структура ответа гуляет: записи могут лежать в result, items или напрямую
        records = (
            data.get("result") or data.get("items")
            or data.get("records") or data.get("data") or []
        )
        if isinstance(records, dict):
            records = list(records.values())
        now = datetime.now(timezone.utc)
        facts: list[Fact] = []
        for i, rec in enumerate(records[:10], 1):
            if not isinstance(rec, dict):
                continue
            text = (rec.get("text") or rec.get("message") or rec.get("type")
                    or rec.get("title") or "сообщение реестра банкротств")
            facts.append(Fact(
                fact_id=f"RBK-{i}",
                kind="bankruptcy",
                statement=f"[резервный источник] Сообщение ЕФРСБ: {str(text)[:200]}",
                source_url="https://bankrot.fedresurs.ru/",
                source_type="registry_api",
                retrieved_at=now,
                event_date=_d(rec.get("date") or rec.get("publish_date")),
                payload={"via": "apicloud", "raw_title": str(text)[:200]},
            ))
        found = bool(facts)
        return SourceResult(
            source="apicloud.bankruptcy",
            status="ok" if found else "partial",
            reason=None if found else (
                "Резервный источник сообщений о банкротстве не вернул записей "
                "по наименованию. Поиск по строке приблизителен: пустой "
                "результат означает «не найдено», а НЕ «банкротства нет»"
            ),
            facts=facts,
        )

    # ─────────────────────────  арбитраж  ─────────────────────────

    async def check_arbitration(self, inn: str) -> SourceResult:
        """Арбитражные дела. Резерв для kad.arbitr.ru, у которого нет API."""
        data = await self._get("kad_arbitr.php", {
            "type": "search", "inn": inn, "page": 1,
            "first": "true", "filter": "sideType",
        })
        if data is None:
            return SourceResult(
                source="apicloud.arbitration", status="unavailable",
                reason="Резервный источник арбитражных дел не ответил",
            )
        items = (
            data.get("result") or data.get("items")
            or data.get("records") or data.get("cases") or []
        )
        if isinstance(items, dict):
            items = list(items.values())
        now = datetime.now(timezone.utc)
        facts: list[Fact] = []
        defendant = RoleCounts()
        plaintiff = RoleCounts()
        for item in items[:50]:
            if not isinstance(item, dict):
                continue
            amount = _num(item.get("claimSum") or item.get("sum"))
            role = str(item.get("sideType") or item.get("role") or "").lower()
            is_def = "ответчик" in role or "defendant" in role
            is_pl = "истец" in role or "plaintiff" in role
            if is_def:
                defendant.count += 1
                defendant.total_amount += amount
            elif is_pl:
                plaintiff.count += 1
                plaintiff.total_amount += amount
        for i, item in enumerate([x for x in items if isinstance(x, dict)][:10], 1):
            amount = _num(item.get("claimSum") or item.get("sum"))
            facts.append(Fact(
                fact_id=f"RAR-{i}",
                kind="arbitration",
                statement=(f"[резервный источник] Арбитражное дело "
                           f"{item.get('caseNumber') or item.get('number') or 'б/н'}: "
                           f"цена иска {amount:,.0f} ₽".replace(",", " ")),
                source_url=("https://kad.arbitr.ru/Card/"
                            + str(item.get("caseNumber") or item.get("number") or "")),
                source_type="court",
                retrieved_at=now,
                event_date=_d(item.get("date") or item.get("regDate")),
                payload={"number": item.get("caseNumber") or item.get("number"),
                         "amount": amount, "via": "apicloud"},
            ))
        return SourceResult(
            source="apicloud.arbitration",
            status="ok" if items else "partial",
            reason=None if items else (
                "Резервный источник дел не вернул записей. Пустой результат "
                "означает «не найдено», а НЕ «судебных дел нет»"
            ),
            facts=facts,
            arbitration=ArbitrationSummary(
                total=len(items),
                as_defendant=defendant,
                as_plaintiff=plaintiff,
                roles_counted_from=len(items[:50]),
                roles_complete=len(items) <= 50,
            ),
        )
