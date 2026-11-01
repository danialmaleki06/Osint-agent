"""Федресурс (fedresurs.ru) — коммерческие сведения о фактах деятельности.

Помимо банкротств (они уже приходят с карточкой Checko) в реестре
публикуется масса сведений, говорящих о реальной деятельности:

  * договоры лизинга — у компании есть физические активы, она
    платёжеспособна и работает;
  * залоги движимого имущества — кредит под развитие (или спасение),
    в описании часто виден конкретный парк оборудования;
  * факторинг — работа с крупными сетями на отсрочке, кассовые
    разрывы встроены в модель бизнеса;
  * независимые гарантии — участие в тендерах и контрактных
    отношениях, требующих обеспечения;
  * членство в СРО — допуск к строительству, проектированию,
    инженерным изысканиям.

Источник бесплатный и официальный. Официального API нет, но SPA
реестра общается с бэкендом JSON'ом, и тот же флоу воспроизводится
программно:

  1. GET /backend/companies?code=<ИНН>&searchString=<ИНН> -> guid;
  2. GET /backend/companies/<guid>/publications?limit=&offset= ->
     список сообщений (слишком широкие флаги поиска сервис встречает
     451, поэтому запрашивается минимальный набор).

Без searchString сервис игнорирует фильтр code и возвращает первые
попавшие записи — проверено живым запросом; двойное указание ИНН
обязательно. Требуются заголовки браузера и Referer: без них nginx
отвечает отказом ещё до маршрутизации.

Классификация сообщений ведётся по заголовку: лизинг, залог,
факторинг, гарантия, СРО опознаются по ключевым словам. Всё, что не
опознано, но относится к существенным фактам, сохраняется отдельным
видом — молча выбрасывать публикации значит терять сигналы.

Любой отказ сети — пустой результат с reason: коммерческие сведения
не должны ронять проверку рисков в целом.
"""

import asyncio
from datetime import datetime, timezone

import httpx
import structlog

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.models import Fact, SourceResult

log = structlog.get_logger()

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# Максимум сообщений за один проход. Федресурс отдаёт постранично,
# но для оценки контрагента достаточно свежих публикаций.
MAX_PUBLICATIONS = 15

# Заголовки сообщений, опознаваемые без разбора текста. Порядок важен:
# проверяется сверху вниз, первое совпадение определяет вид факта.
_TITLE_KINDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("лизинг", "финансовая аренда"), "leasing"),
    (("залог", "обременение"), "pledge"),
    (("факторинг", "уступка денежного требования"), "factoring"),
    (("независимая гарантия", "независимых гарантий", "независимой гарантии"), "guarantee"),
    (("членство в сро", "саморегулируемой организаци", "саморегулируемая организация"), "sro_membership"),
    (
        (
            "конкурсн",
            "введение наблюдения",
            "признание должника банкротом",
            "признании должника банкротом",
            "ходе конкурсного производства",
            "арбитражн управляющ",
            "требований кредитора",
            "собрания кредиторов",
            "комитета кредиторов",
            "имущества должника",
            "оспаривании сделок",
            "результатах торгов",
            "объявлении торгов",
        ),
        "bankruptcy",
    ),
    (("недостоверност",), "registry_flag"),
)

# Классификация только по заголовку: в тексте сообщения слова «залог»
# и «лизинг» встречаются в самых неожиданных контекстах (отчёты
# управляющих, торговые объявления), и ложные виды фактов хуже
# неполного списка.
_KIND_TITLES: dict[str, str] = {
    "leasing": "Договор лизинга",
    "pledge": "Залог движимого имущества",
    "factoring": "Договор факторинга",
    "guarantee": "Независимая гарантия",
    "sro_membership": "Членство в СРО",
    "bankruptcy": "Банкротство (сообщение ЕФРСБ)",
    "registry_flag": "Недостоверность сведений",
}


def _classify(title: str | None) -> str | None:
    """Вид факта по заголовку сообщения. None — не опознано."""
    if not title:
        return None
    lowered = title.lower()
    # Уведомления о намерениях («Намерение кредитора/должника обратиться в суд»)
    # являются обязательным информационным шагом по ст. 7.1 127-ФЗ, но НЕ
    # означают открытую процедуру банкротства.
    if "намерени" in lowered:
        return "fedresurs_publication"
    for needles, kind in _TITLE_KINDS:
        if any(n in lowered for n in needles):
            return kind
    return None


def _fact_kind(kind: str | None) -> str:
    return kind or "fedresurs_publication"


def _statement(kind: str | None, title: str | None, publisher: str | None) -> str:
    label = _KIND_TITLES.get(kind or "", None)
    if label:
        text = title or "без заголовка"
        return f"{label}: {text}" + (f" (публикатор: {publisher})" if publisher else "")
    return title or "сообщение Федресурса без заголовка"


class FedresursSource:
    """Коммерческие публикации Федресурса: лизинг, залоги, факторинг."""

    name = "fedresurs"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    def _headers(self, referer: str) -> dict[str, str]:
        return {
            "User-Agent": _UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "Referer": referer,
            "Sec-Ch-Ua": '"Not A(Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }

    async def _get_json(self, url: str, referer: str) -> dict:
        """GET с журналом. Ошибки наружу — их смысл знает вызывающий."""
        if self._client is not None:
            resp = await self._client.get(url, headers=self._headers(referer))
        else:
            async with httpx.AsyncClient(
                timeout=min(settings.request_timeout, 3.5),
                headers=self._headers(referer),
            ) as client:
                resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()

    async def _company_guid(self, inn: str) -> str | None:
        """Guid организации в Федресурсе. None — не значится."""
        url = (f"{settings.fedresurs_base_url}/backend/companies"
               f"?limit=15&offset=0&code={inn}&searchString={inn}")
        referer = f"{settings.fedresurs_base_url}/search/entity?code={inn}"
        data = await self._get_json(url, referer)
        page = data.get("pageData") or []
        for row in page:
            if str(row.get("inn") or "") == inn:
                return row.get("guid")
        return None

    async def check_commercial_facts(self, inn: str) -> SourceResult:
        """Коммерческие сведения: лизинг, залоги, факторинг, гарантии, СРО.

        Статус partial при пустом результате — реестр обязателен не для
        всех организаций, отсутствие записей законно; но и источник
        бывает недоступен, и это различие несёт reason.
        """
        service, method = self.name, "publications"
        try:
            guid = await self._company_guid(inn)
        except httpx.HTTPStatusError as e:
            ledger.record(service, method, "failed", f"HTTP {e.response.status_code}")
            return SourceResult(
                source="fedresurs.commercial", status="unavailable",
                reason=f"Федресурс ответил {e.response.status_code}",
            )
        except (httpx.TransportError, httpx.TimeoutException) as e:
            ledger.record(service, method, "failed", f"сеть: {type(e).__name__}")
            return SourceResult(
                source="fedresurs.commercial", status="unavailable",
                reason=f"Федресурс недоступен: {type(e).__name__}",
            )
        except ValueError:
            ledger.record(service, method, "failed", "ответ не JSON")
            return SourceResult(
                source="fedresurs.commercial", status="unavailable",
                reason="Федресурс вернул не JSON",
            )

        if not guid:
            # Организация в реестре не значится: публикаций о ней не было.
            # Это валидная пустота — для большинства компаний так и есть.
            ledger.record(service, method, "empty", "в реестре не значится")
            return SourceResult(
                source="fedresurs.commercial", status="ok",
                reason=None,
            )

        url = (f"{settings.fedresurs_base_url}/backend/companies/{guid}"
               f"/publications?limit={MAX_PUBLICATIONS}&offset=0")
        referer = f"{settings.fedresurs_base_url}/company/{guid}"
        try:
            data = await self._get_json(url, referer)
        except httpx.HTTPStatusError as e:
            ledger.record(service, method, "failed", f"HTTP {e.response.status_code}")
            return SourceResult(
                source="fedresurs.commercial", status="unavailable",
                reason=f"Федресурс ответил {e.response.status_code} на список публикаций",
            )
        except (httpx.TransportError, httpx.TimeoutException) as e:
            ledger.record(service, method, "failed", f"сеть: {type(e).__name__}")
            return SourceResult(
                source="fedresurs.commercial", status="unavailable",
                reason=f"Федресурс недоступен: {type(e).__name__}",
            )
        except ValueError:
            ledger.record(service, method, "failed", "ответ не JSON")
            return SourceResult(
                source="fedresurs.commercial", status="unavailable",
                reason="Федресурс вернул не JSON",
            )

        records = data.get("pageData") or []
        total = int(data.get("found") or 0)
        now = datetime.now(timezone.utc)

        facts: list[Fact] = []
        for i, rec in enumerate(records[:MAX_PUBLICATIONS], 1):
            if not isinstance(rec, dict):
                continue
            if rec.get("isAnnuled") or rec.get("isRefuted"):
                continue
            title = rec.get("title") or rec.get("type") or None
            kind = _classify(title)
            pub_guid = rec.get("guid") or ""
            message_type = rec.get("type") or ""
            if not kind and message_type not in ("SfactMessage",):
                continue
            if not kind and message_type == "SfactMessage":
                # Существенный факт без опознанного вида — сохраняем как есть
                kind = None
            if not kind and not title:
                continue
            facts.append(Fact(
                fact_id=f"FR-{i}",
                kind=_fact_kind(kind),
                statement=_statement(kind, title, rec.get("publisherName")),
                source_url=(f"{settings.fedresurs_base_url}/sfactmessage/{pub_guid}"
                            if message_type == "SfactMessage" and pub_guid
                            else f"{settings.fedresurs_base_url}/company/{guid}"),
                source_type="registry_api",
                retrieved_at=now,
                event_date=None,
                payload={
                    "kind": kind or "publication",
                    "title": title,
                    "flag": title or "Недостоверность",
                    "status": title or "",
                    "Тип": title or "банкротство",
                    "message_type": message_type,
                    "publisher": rec.get("publisherName"),
                    "published_at": rec.get("datePublish"),
                    "via": "fedresurs",
                },
            ))

        ledger.record(service, method, "ok" if total else "empty")
        log.info("fedresurs.publications", inn=inn, found=total,
                 classified=len(facts))
        return SourceResult(
            source="fedresurs.commercial",
            status="ok" if total else "partial",
            reason=None if total else (
                "Публикаций в Федресурсе не найдено. Лизинг, залоги и "
                "факторинг публикуют не все организации — пустой результат "
                "означает «публикаций нет», а не «активов нет»"
            ),
            facts=facts,
        )


def classify_publication(title: str | None) -> str | None:
    """Публичная обёртка классификатора — для тестов и переиспользования."""
    return _classify(title)


# ── Отложенный импорт для тяжёлого разбора: не нужен на горячем пути ──

async def fetch_commercial_facts(inn: str) -> SourceResult:
    """Удобная обёртка: сбор фактов Федресурса одним вызовом."""
    return await FedresursSource().check_commercial_facts(inn)
