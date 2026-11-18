"""Источник риск-данных: Checko.

Три эндпоинта:
  company      — карточка, реестровые отметки, банкротство, учредители;
  legal-cases  — арбитражные дела;
  enforcements — исполнительные производства ФССП.

Особенности, выявленные при работе с живым API:
  * поля названы по-русски;
  * агрегаты (общая сумма исков, остаток задолженности) сервис считает сам,
    НО без разделения по процессуальной роли — разделение делаем здесь;
  * у каждого дела есть прямая ссылка на карточку в картотеке арбитражных
    дел, она и становится источником факта.
"""

import asyncio
import re
from datetime import UTC, date, datetime
from typing import Any

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.keys import ROTATE_STATUS_CODES, QuotaExhausted
from osint_mcp.keys import checko as checko_pool
from osint_mcp.models import (
    AffiliationGraph,
    ArbitrationSummary,
    CardExtras,
    ContactInfo,
    ContextResult,
    EnforcementSummary,
    Fact,
    FinancialSummary,
    FinancialYear,
    InspectionSummary,
    LicenseInfo,
    PersonProfile,
    PlannedInspection,
    ProcurementSummary,
    RelatedCompany,
    RoleCounts,
    SourceResult,
)
from osint_mcp.tools.country import detect_country

log = structlog.get_logger()

MAX_CASES_IN_FACTS = 10  # крупнейшие дела; остальные попадают только в агрегат

# Реестровые отметки: поле API -> человекочитаемое пояснение
RISK_FLAGS = {
    "НедобПост": "Включена в реестр недобросовестных поставщиков",
    "ДисквЛица": "Среди руководителей есть дисквалифицированные лица",
    "МассРуковод": "Руководитель значится массовым",
    "МассУчред": "Учредитель значится массовым",
    "НелегалФин": "Признаки нелегальной финансовой деятельности",
    "Санкции": "Компания в санкционных списках",
    "СанкцУчр": "Учредители в санкционных списках",
}


# Значимость связи для очерёдности проверки. Меньше — важнее.
_LINK_RANK = {
    "правопредшественник": 0, "правопреемник": 0,
    "управляющая организация": 1,
    "владелец-организация": 1, "иностранный владелец": 1,
    "через владельца-организацию": 2,
    "общий учредитель": 3, "общая управляющая организация": 3,
}


def _card_endpoint(inn: str) -> str:
    """Какой метод отдаёт карточку: у ИП нет карточки юридического лица.

    Организация имеет 10-значный ИНН, индивидуальный предприниматель —
    12-значный. Обращение к методу организаций по ИНН предпринимателя
    вернёт пустоту, неотличимую от «ничего не найдено».
    """
    return "entrepreneur" if len(inn.strip()) == 12 else "company"


def _why(error: httpx.HTTPStatusError) -> str:
    """Человеческая причина отказа вместо голого кода ответа.

    Сервис объясняет отказ в теле ответа: исчерпан суточный лимит,
    неверный ключ, метод недоступен на тарифе. Код 403 сам по себе
    не говорит, чинить тариф или искать ошибку в коде.
    """
    return _why_like(error.response)


def _why_like(resp: httpx.Response) -> str:
    """То же по готовому ответу — для отказов до raise_for_status."""
    code = resp.status_code
    try:
        message = ((resp.json() or {}).get("meta") or {}).get("message")
    except Exception:                                       # noqa: BLE001
        message = None
    return f"Checko ответила {code}: {message}" if message else f"Checko ответила {code}"


def _parse_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _text(value: Any, key: str = "Наим") -> str | None:
    """Достать текст из поля, которое бывает то строкой, то объектом.

    В полной карточке статус приходит как {"Код": "001", "Наим": "Действует"},
    а в кратких записях о связанных организациях — просто строкой. То же
    с видом деятельности. Разбирать это в каждом месте отдельно — верный
    способ однажды положить в отчёт словарь вместо названия.
    """
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        got = value.get(key)
        return got if isinstance(got, str) and got else None
    return None


def _brief(obj: dict, link: str, via: str | None = None) -> RelatedCompany:
    """Краткая запись об организации из любого блока карточки.

    Один и тот же формат приходит в связях учредителей, в списке компаний
    физического лица и в правопреемстве, поэтому разбор общий.
    """
    inn = obj.get("ИНН")
    ogrn = obj.get("ОГРН")
    return RelatedCompany(
        inn=inn,
        ogrn=ogrn,
        name=obj.get("НаимСокр") or obj.get("НаимПолн"),
        status=_text(obj.get("Статус")),
        registered_at=_parse_date(obj.get("ДатаРег")),
        okved_text=_text(obj.get("ОКВЭД")),
        link=link,
        via=via,
        # Карточка Контура: ИНН/ОГРН-форматы Checko без слага отдают 404,
        # Контур по ОГРН открывается всегда (проверено живьём 30.09.2026)
        source_url=(f"https://focus.kontur.ru/entity?query={ogrn}" if ogrn
                    else (f"https://focus.kontur.ru/entity?query={inn}" if inn else None)),
    )


class CheckoSource:
    """Реестровые проверки через Checko."""

    name = "checko"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, max=6),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    async def _request(self, url: str, params: dict[str, Any]) -> httpx.Response:
        """Запрос с автоподстановкой ключа из пула.

        Отказ «ключ не годится» (401/403/429) повторяется со следующим
        ключом, пока пул не исчерпается — тогда наружу выходит
        QuotaExhausted с причиной последнего отказа.
        """
        params = {**params, "key": checko_pool.current()}
        for attempt in range(len(checko_pool.keys()) + 1):
            if self._client is not None:
                resp = await self._client.get(url, params=params)
            else:
                async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
                    resp = await client.get(url, params=params)
            if resp.status_code in ROTATE_STATUS_CODES and attempt < len(checko_pool.keys()):
                if not checko_pool.rotate(f"HTTP {resp.status_code}", failed_key=params["key"]):
                    break
                params = {**params, "key": checko_pool.current()}
                continue
            break
        if resp.status_code in ROTATE_STATUS_CODES:
            raise QuotaExhausted(_why_like(resp))
        resp.raise_for_status()
        return resp

    async def _get(self, endpoint: str, params: dict[str, Any]) -> dict:
        url = f"{settings.checko_base_url}/{endpoint}"
        try:
            resp = await self._request(url, params)
        except QuotaExhausted as e:
            # Пометку об исчерпании делает пул; журналу же нужен сам факт
            # отказа — иначе coverage примет источник за непроверенный.
            ledger.record("checko", endpoint, "failed", str(e))
            raise
        except httpx.HTTPStatusError as e:
            ledger.record("checko", endpoint, "failed", _why(e))
            raise
        except (httpx.TransportError, httpx.TimeoutException) as e:
            ledger.record("checko", endpoint, "failed", f"сеть: {type(e).__name__}")
            raise

        body = resp.json()
        meta = body.get("meta") or {}
        # Служба сообщает суточный расход в каждом ответе — считать его
        # отдельным запросом не нужно, число уже здесь.
        ledger.record(
            "checko", endpoint,
            "ok" if meta.get("status") == "ok" and body.get("data") else
            "empty" if meta.get("status") == "ok" else "failed",
            None if meta.get("status") == "ok" else meta.get("message"),
            daily_count=meta.get("today_request_count"),
        )
        return body

    async def _fetch(
        self, endpoint: str, inn: str, source: str, **extra: Any
    ) -> tuple[dict | None, SourceResult | None]:
        """Вернуть данные либо готовый SourceResult с описанием отказа."""
        data, _, failure = await self._fetch_full(endpoint, inn, source, **extra)
        return data, failure

    async def _fetch_full(
        self, endpoint: str, inn: str, source: str, **extra: Any
    ) -> tuple[dict | None, dict | None, SourceResult | None]:
        """То же, но с телом ответа целиком.

        Часть сведений лежит рядом с data, а не внутри неё: ссылки на
        отчётности ФНС приходят в блоке 'bo.nalog.ru' на верхнем уровне.
        """
        try:
            body = await self._get(endpoint, {"inn": inn, **extra})
        except httpx.HTTPStatusError as e:
            return None, None, SourceResult(source=source, status="unavailable",
                                            reason=_why(e))
        except QuotaExhausted as e:
            # Причина различает два случая, которые агент обязан читать
            # по-разному. Квота кончилась — источник отвечает, стоит
            # вернуться позже. Ключ не принят (401) — источник не ответит
            # и завтра: ключ неверен и нужна замена, ждать бессмысленно.
            # Живой прогон поймал: неверный ключ читался как «исчерпан»,
            # и отказ выглядел временной помехой.
            text = str(e)
            if text.startswith("Не задан ключ"):
                # Ключей нет вовсе — это не «исчерпаны», и звук должен
                # быть про настройку, а не про квоту
                kind = text
            elif "401" in text:
                kind = ("Ключ Checko не принят сервисом (неверный или "
                        "отозванный) — проверьте CHECKO_API_KEYS, "
                        f"ожидать восстановления не стоит: {e}")
            else:
                kind = f"Ключи Checko исчерпаны: {e}"
            return None, None, SourceResult(source=source, status="unavailable",
                                            reason=kind)
        except (httpx.TransportError, httpx.TimeoutException) as e:
            return None, None, SourceResult(source=source, status="unavailable",
                                            reason=f"Сеть недоступна: {type(e).__name__}")

        meta = body.get("meta") or {}
        if meta.get("status") != "ok":
            return None, None, SourceResult(source=source, status="unavailable",
                                            reason=meta.get("message") or "Источник вернул ошибку")
        return body.get("data") or {}, body, None

    async def _fetch_pages(
        self, endpoint: str, inn: str, source: str, **extra: Any
    ) -> tuple[dict | None, list[dict], SourceResult | None]:
        """Собрать записи с нескольких страниц.

        Списочные методы отдают по 100 записей. У крупных организаций страниц
        бывают тысячи — выгрузить всё невозможно и не нужно. Берём первые
        settings.max_pages и возвращаем данные первой страницы (там агрегаты)
        вместе с накопленными записями, чтобы вызывающий код мог честно
        сообщить, по какой доле посчитана разбивка.
        """
        first, failure = await self._fetch(endpoint, inn, source, **extra)
        if failure:
            return None, [], failure

        records = list(first.get("Записи") or [])
        pages_total = int(first.get("СтрВсего") or 1)

        for page in range(2, min(pages_total, settings.max_pages) + 1):
            data, failure = await self._fetch(endpoint, inn, source, page=page, **extra)
            if failure:
                break            # частичный сбор лучше, чем полный отказ
            records.extend(data.get("Записи") or [])

        return first, records, None

    # ─────────────────────────  арбитраж  ─────────────────────────

    async def check_arbitration(self, inn: str) -> SourceResult:
        data, records, failure = await self._fetch_pages(
            "legal-cases", inn, "checko.arbitration"
        )
        if failure:
            return failure

        now = datetime.now(UTC)

        defendant = RoleCounts()
        plaintiff = RoleCounts()
        plaintiff_active = RoleCounts()
        both = RoleCounts()
        other = 0
        active = 0
        dates: list[date] = []
        scored: list[tuple[float, dict, str]] = []

        for rec in records:
            amount = float(rec.get("СуммИск") or 0.0)
            is_defendant = any(p.get("ИНН") == inn for p in (rec.get("Ответ") or []))
            is_plaintiff = any(p.get("ИНН") == inn for p in (rec.get("Ист") or []))

            # Компания может числиться одновременно и в истцах, и в ответчиках:
            # встречный иск, либо в деле участвует её же обособленное
            # подразделение. Относить такое дело молча к ответчикам нельзя —
            # это скрытое допущение. Считаем отдельно.
            if is_defendant and is_plaintiff:
                both.count += 1
                both.total_amount += amount
                role = "и истец, и ответчик"
            elif is_defendant:
                defendant.count += 1
                defendant.total_amount += amount
                role = "ответчик"
            elif is_plaintiff:
                plaintiff.count += 1
                plaintiff.total_amount += amount
                role = "истец"
                # Активный иск о взыскании — компания сама ждёт деньги.
                # Единичный случай нормален, поток новых исков значит,
                # что ей систематически не платят её заказчики: кассовый
                # разрыв у контрагента начинается с его дебиторов
                if rec.get("ПрАктив"):
                    plaintiff_active.count += 1
                    plaintiff_active.total_amount += amount
            else:
                # ИНН не встретился ни в одной стороне: компания проходит
                # третьим лицом либо участвует под другим идентификатором
                other += 1
                role = "иное участие"

            if rec.get("ПрАктив"):
                active += 1
            case_date = _parse_date(rec.get("Дата"))
            if case_date:
                dates.append(case_date)

            # Дела, где к компании предъявлены требования, важнее дел,
            # где она взыскивает сама — поэтому идут в отбор с приоритетом
            weight = amount * (10 if is_defendant else 1)
            scored.append((weight, rec, role))

        scored.sort(key=lambda x: x[0], reverse=True)

        facts: list[Fact] = []
        for i, (_, rec, role) in enumerate(scored[:MAX_CASES_IN_FACTS], 1):
            amount = float(rec.get("СуммИск") or 0.0)
            number = rec.get("Номер") or "б/н"
            amount_text = f", цена иска {amount:,.0f} ₽".replace(",", " ") if amount else ""
            facts.append(Fact(
                fact_id=f"ARB-{i}",
                kind="arbitration",
                statement=(f"Арбитражное дело {number} от {rec.get('Дата')}: "
                           f"компания — {role}{amount_text}. Суд: {rec.get('Суд')}"),
                source_url=rec.get("СтрКАД") or "https://kad.arbitr.ru/",
                source_type="court",
                retrieved_at=now,
                event_date=_parse_date(rec.get("Дата")),
                payload={"number": number, "role": role, "amount": amount,
                         "court": rec.get("Суд"), "active": bool(rec.get("ПрАктив"))},
            ))

        total = int(data.get("ЗапВсего") or len(records))
        complete = len(records) >= total

        log.info("checko.arbitration", inn=inn, total=total, seen=len(records),
                 defendant=defendant.count, plaintiff=plaintiff.count,
                 complete=complete)

        # Данные поступают не напрямую из картотеки, а с задержкой в одну-две
        # недели. Недавно поданные иски физически отсутствуют в источнике,
        # поэтому вывод «дел нет» без этой оговорки недостоверен.
        lag = ("Сведения о судебных делах поступают с задержкой 1–2 недели: "
               "иски, поданные за последние две недели, в источнике "
               "отсутствуют. Оговори это в выводах.")

        return SourceResult(
            source="checko.arbitration",
            status="ok" if complete else "partial",
            reason=(lag if complete else
                    f"Дел в базе {total}, разбивка по ролям посчитана по {len(records)}. "
                    f"Выгрузить все дела невозможно — у крупных организаций их тысячи. "
                    f"{lag}"),
            facts=facts,
            arbitration=ArbitrationSummary(
                total=total,
                total_claim_amount=float(data.get("ОбщСуммИск") or 0.0),
                as_defendant=defendant,
                as_plaintiff=plaintiff,
                as_plaintiff_active=plaintiff_active,
                as_both=both,
                other_participation=other,
                roles_counted_from=len(records),
                roles_complete=complete,
                active_cases=active,
                last_case_date=max(dates) if dates else None,
            ),
        )

    # ─────────────────────────  проверки надзорных органов  ─────────────────

    async def check_inspections(self, inn: str) -> SourceResult:
        data, records, failure = await self._fetch_pages(
            "inspections", inn, "checko.inspections"
        )
        if failure:
            return failure

        now = datetime.now(UTC)
        total = int(data.get("ЗапВсего") or len(records))
        complete = len(records) >= total

        violations = [r for r in records if r.get("Наруш")]

        facts = []
        for i, rec in enumerate(violations[:MAX_CASES_IN_FACTS], 1):
            facts.append(Fact(
                fact_id=f"INSP-{i}",
                kind="registry_flag",
                statement=(f"Проверка {rec.get('ТипРасп') or 'надзорного органа'} "
                           f"от {rec.get('ДатаНач')}: выявлены нарушения. "
                           f"Цель: {str(rec.get('Цель') or 'не указана')[:120]}"),
                source_url="https://proverki.gov.ru/",
                source_type="registry_api",
                retrieved_at=now,
                event_date=_parse_date(rec.get("ДатаНач")),
                payload={"number": rec.get("Номер"), "type": rec.get("ТипРасп"),
                         "violations": True},
            ))

        # Предстоящие и плановые проверки (ЕРКНМ) — B2B-триггеры для аудита и безопасности
        planned_inspections: list[PlannedInspection] = []
        today_date = now.date()
        for rec in records:
            is_finished = rec.get("Заверш")
            date_start = _parse_date(rec.get("ДатаНач"))
            status_text = (rec.get("Статус") or "").lower()
            insp_type = rec.get("ТипПров") or rec.get("ТипРасп") or ""

            is_upcoming = (
                is_finished is False
                or (date_start is not None and date_start >= today_date)
                or any(w in status_text for w in ("план", "назнач", "процесс", "запланирован"))
            )
            if is_upcoming:
                org = rec.get("ОргКонтр") or {}
                authority = org.get("Наим") if isinstance(org, dict) else str(org)
                authority = authority or "Надзорный орган"
                num = rec.get("Номер")
                pi = PlannedInspection(
                    number=num,
                    authority=authority,
                    date_start=date_start,
                    inspection_type=insp_type or None,
                    purpose=rec.get("Цель"),
                )
                planned_inspections.append(pi)
                facts.append(Fact(
                    fact_id=f"INSP-P-{len(planned_inspections)}",
                    kind="planned_inspection",
                    statement=(
                        f"Плановая/предстоящая проверка {authority} "
                        f"(начало: {rec.get('ДатаНач') or 'уточняется'}"
                        + (f", тип: {insp_type}" if insp_type else "")
                        + f"): {str(rec.get('Цель') or 'плановый надзор ЕРКНМ')[:120]}"
                    ),
                    source_url="https://proverki.gov.ru/",
                    source_type="registry_api",
                    retrieved_at=now,
                    event_date=date_start,
                    payload={
                        "number": num,
                        "authority": authority,
                        "date_start": date_start.isoformat() if date_start else None,
                        "type": insp_type,
                        "status": rec.get("Статус"),
                        "purpose": rec.get("Цель"),
                    },
                ))

        log.info("checko.inspections", inn=inn, total=total,
                 seen=len(records), violations=len(violations),
                 planned=len(planned_inspections))

        return SourceResult(
            source="checko.inspections",
            status="ok" if complete else "partial",
            reason=None if complete else
                   f"Проверок в базе {total}, просмотрено {len(records)}",
            facts=facts,
            inspections=InspectionSummary(
                total=total, with_violations=len(violations),
                planned_inspections=planned_inspections,
                counted_from=len(records), complete=complete,
            ),
        )

    # ─────────────────────────  госзакупки  ─────────────────────────

    async def check_procurement(self, inn: str) -> SourceResult:
        """Контракты по 44-ФЗ и 223-ФЗ.

        Опыт исполнения госзаказа. Сам по себе риском не является — скорее
        наоборот; значимо в сочетании с реестром недобросовестных поставщиков.
        """
        now = datetime.now(UTC)
        counts: dict[str, int] = {}
        amount = 0.0
        seen = 0
        totals = 0
        complete = True
        facts: list[Fact] = []
        n = 0
        supplier = RoleCounts()
        customer = RoleCounts()
        other = 0

        answered = 0
        last_failure: SourceResult | None = None

        for law in ("44", "223"):
            data, records, failure = await self._fetch_pages(
                "contracts", inn, "checko.procurement", law=law
            )
            if failure:
                # Один закон не ответил — второй всё равно опрашиваем
                counts[law] = 0
                complete = False
                last_failure = failure
                continue
            answered += 1

            total = int(data.get("ЗапВсего") or len(records))
            counts[law] = total
            totals += total
            seen += len(records)
            complete = complete and len(records) >= total
            amount += sum(float(r.get("Цена") or 0.0) for r in records)

            # Роль в контракте меняет смысл на противоположный, ровно как
            # процессуальная роль в суде. Поставщик выиграл заказ — это опыт.
            # Заказчик закупал сам: у организации это признак госучастия,
            # а вовсе не портфель выигранных подрядов.
            roles: dict[int, str] = {}
            for i, rec in enumerate(records):
                price = float(rec.get("Цена") or 0.0)
                is_supplier = any(p.get("ИНН") == inn
                                  for p in (rec.get("Постав") or []))
                is_customer = (rec.get("Заказ") or {}).get("ИНН") == inn
                if is_supplier:
                    supplier.count += 1
                    supplier.total_amount += price
                    roles[i] = "исполнитель"
                elif is_customer:
                    customer.count += 1
                    customer.total_amount += price
                    roles[i] = "заказчик"
                else:
                    # Организация могла участвовать под прежним ИНН либо
                    # входить в состав объединения участников
                    other += 1
                    roles[i] = "иное участие"

            ranked = sorted(enumerate(records),
                            key=lambda pair: float(pair[1].get("Цена") or 0),
                            reverse=True)[:3]
            for i, rec in ranked:
                n += 1
                price = float(rec.get("Цена") or 0.0)
                facts.append(Fact(
                    fact_id=f"GOZ-{n}",
                    kind="procurement",
                    statement=(f"Контракт по {law}-ФЗ от {rec.get('Дата')} "
                               f"на {price:,.0f} ₽: организация — {roles[i]}"
                               .replace(",", " ")),
                    source_url=rec.get("СтрЕИС") or "https://zakupki.gov.ru/",
                    source_type="registry_api",
                    retrieved_at=now,
                    event_date=_parse_date(rec.get("Дата")),
                    payload={"law": law, "number": rec.get("РегНомер"),
                             "price": price, "role": roles[i]},
                ))

        # Ни один закон не ответил — это отказ источника, а не «контрактов нет».
        # Нули здесь читались бы как отсутствие госзаказа, что неверно.
        if answered == 0:
            return last_failure or SourceResult(
                source="checko.procurement", status="unavailable",
                reason="Ни один из реестров закупок не ответил",
            )

        log.info("checko.procurement", inn=inn, law44=counts.get("44"),
                 law223=counts.get("223"), answered=answered)

        return SourceResult(
            source="checko.procurement",
            status="ok" if complete else "partial",
            reason=None if complete else
                   f"Контрактов в базе {totals}, просмотрено {seen}",
            facts=facts,
            procurement=ProcurementSummary(
                contracts_44=counts.get("44", 0),
                contracts_223=counts.get("223", 0),
                as_supplier=supplier,
                as_customer=customer,
                other_participation=other,
                roles_counted_from=seen,
                roles_complete=complete,
                total_amount=amount, counted_from=seen, complete=complete,
            ),
        )

    # ─────────────────────────  ФССП  ─────────────────────────

    async def check_enforcement(self, inn: str) -> SourceResult:
        data, failure = await self._fetch("enforcements", inn, "checko.enforcement")
        if failure:
            return failure

        records = data.get("Записи") or []
        now = datetime.now(UTC)

        facts = []
        for i, rec in enumerate(records[:MAX_CASES_IN_FACTS], 1):
            amount = float(rec.get("Сумма") or 0.0)
            facts.append(Fact(
                fact_id=f"ENF-{i}",
                kind="enforcement",
                statement=(f"Исполнительное производство {rec.get('Номер', 'б/н')}: "
                           f"{rec.get('ПредмИсп') or 'предмет не указан'}, "
                           f"сумма {amount:,.0f} ₽".replace(",", " ")),
                source_url="https://fssp.gov.ru/iss/ip",
                source_type="registry_api",
                retrieved_at=now,
                event_date=_parse_date(rec.get("Дата")),
                payload={"number": rec.get("Номер"), "amount": amount,
                         "subject": rec.get("ПредмИсп")},
            ))

        total = int(data.get("ОбщКолич") or 0)
        log.info("checko.enforcement", inn=inn, total=total)

        # Служба приставов не всегда указывает реквизиты организаций, поэтому
        # сопоставление ведётся по наименованию и адресу приблизительными
        # алгоритмами — это признано в документации поставщика. Значит пустой
        # результат означает «не найдено», а НЕ «задолженности отсутствуют».
        # Помечать его как полную проверку нельзя: именно так «не смогли
        # проверить» превращается в «нарушений нет».
        return SourceResult(
            source="checko.enforcement",
            status="ok" if total else "partial",
            reason=None if total else (
                "Производств не найдено. ВНИМАНИЕ: поиск по базе приставов "
                "приблизительный — реквизиты организаций указываются не всегда, "
                "сопоставление идёт по наименованию и адресу. Пустой результат "
                "означает «не найдено», а НЕ «задолженности отсутствуют». "
                "Не сообщай пользователю об отсутствии долгов как об "
                "установленном факте."
            ),
            facts=facts,
            enforcement=EnforcementSummary(
                total=total,
                total_amount=float(data.get("ОбщСум") or 0.0),
                outstanding=float(data.get("ОстЗадолж") or 0.0),
            ),
        )

    # ─────────────────────────  реестровые отметки  ─────────────────────────

    async def check_registry_flags(self, inn: str) -> SourceResult:
        """Отметки ФНС и банкротство.

        Приходят той же карточкой организации, отдельного обращения не требуют.
        """
        data, failure = await self._fetch(_card_endpoint(inn), inn, "checko.registry_flags")
        if failure:
            return failure

        now = datetime.now(UTC)
        card_url = f"https://focus.kontur.ru/entity?query={inn}"
        flags: dict[str, bool] = {}
        facts: list[Fact] = []
        n = 0

        for field, description in RISK_FLAGS.items():
            raised = bool(data.get(field))
            flags[field] = raised
            if raised:
                n += 1
                facts.append(Fact(
                    fact_id=f"FLAG-{n}", kind="registry_flag",
                    statement=description, source_url=card_url,
                    source_type="registry_api", retrieved_at=now,
                    payload={"flag": field},
                ))

        # Банкротство приходит тем же ответом
        for entry in (data.get("ЕФРСБ") or []):
            n += 1
            facts.append(Fact(
                fact_id=f"FLAG-{n}", kind="bankruptcy",
                statement=(f"Сообщение реестра банкротств: "
                           f"{entry.get('Тип') or entry.get('Наим') or 'без описания'}"),
                source_url="https://bankrot.fedresurs.ru/",
                source_type="registry_api", retrieved_at=now,
                event_date=_parse_date(entry.get("Дата")),
                payload=entry,
            ))
        flags["Банкротство"] = bool(data.get("ЕФРСБ"))

        # Ликвидация и реорганизация — тоже существенные признаки
        status = (data.get("Статус") or {}).get("Наим")
        if status and status != "Действует":
            n += 1
            facts.append(Fact(
                fact_id=f"FLAG-{n}", kind="registry_flag",
                statement=f"Статус организации: {status}",
                source_url=card_url, source_type="registry_api",
                retrieved_at=now, payload={"status": status},
            ))

        # Товарные знаки (Роспатент / ФИПС) — нематериальные активы и реальный оборот
        for tm in self._trademarks(data):
            n += 1
            facts.append(Fact(
                fact_id=f"TM-{n}", kind="trademark",
                statement=f"Зарегистрирован товарный знак: {tm}",
                source_url=card_url, source_type="registry_api",
                retrieved_at=now, payload={"name": tm},
            ))

        log.info("checko.registry_flags", inn=inn,
                 raised=[k for k, v in flags.items() if v])

        return SourceResult(source="checko.registry_flags", status="ok",
                            facts=facts, flags=flags)

    # ─────────────────────────  финансы  ─────────────────────────

    # Коды строк бухгалтерской отчётности
    _REVENUE, _PROFIT, _ASSETS = "2110", "2400", "1600"

    # Границы категорий по критериям МСП: (выручка, численность)
    _SIZE_LIMITS = (
        ("micro", 120_000_000, 15),
        ("small", 800_000_000, 100),
        ("medium", 2_000_000_000, 250),
    )

    @classmethod
    def _size_category(cls, revenue: float | None, employees: int | None) -> str:
        """Категория организации. Определяет, какие признаки риска применимы.

        Массовый адрес у крупной компании невозможен, а у однодневки решает.
        Поэтому оценка риска должна знать масштаб.
        """
        if revenue is None and employees is None:
            return "unknown"
        for name, rev_limit, emp_limit in cls._SIZE_LIMITS:
            if (revenue or 0) <= rev_limit and (employees or 0) <= emp_limit:
                return name
        return "large"

    async def get_finances(self, inn: str) -> tuple[FinancialSummary | None, str | None]:
        """Финансовые показатели по годам. Возвращает (данные, причина отказа)."""
        data, full_body, failure = await self._fetch_full("finances", inn, "checko.finances")
        if failure:
            return None, failure.reason

        years: list[FinancialYear] = []
        for key in sorted((k for k in data if str(k).isdigit()), reverse=True)[:5]:
            block = data[key] or {}
            years.append(FinancialYear(
                year=int(key),
                revenue=block.get(self._REVENUE),
                profit=block.get(self._PROFIT),
                assets=block.get(self._ASSETS),
                balance=block.get("1700"),
                equity=block.get("1300"),
                # Долговая нагрузка и оборотный капитал: строки баланса.
                # 0 в отчётности означает «не привлекали» — это данные,
                # а не отсутствие сведений
                loans=block.get("1410"),
                short_debt=block.get("1500"),
                receivables=block.get("1230"),
                payables=block.get("1520"),
                cash=block.get("1250"),
            ))

        # Ссылки на официальные отчётности ФНС: проверяемый первоисточник
        # любого финансового утверждения. Блок живёт рядом с data —
        # на верхнем уровне тела ответа.
        report_urls: dict[int, str] = {}
        bo = (full_body or {}).get("bo.nalog.ru")
        if isinstance(bo, dict):
            for year_key, url in (bo.get("Отчет") or {}).items():
                if str(year_key).isdigit() and isinstance(url, str) and url:
                    report_urls[int(year_key)] = url
        for fy in years:
            fy.report_url = report_urls.get(fy.year)

        # Численность лежит в карточке организации
        employees = capital = None
        branches = representatives = None
        card, card_failure = await self._fetch(_card_endpoint(inn), inn, "checko.finances")
        if not card_failure:
            employees = card.get("СЧР")
            # Обособленные подразделения. Считаем по этому источнику,
            # а не по справочнику: тот отдаёт не больше десяти записей,
            # и у Сбербанка вместо 87 филиалов вышло бы 9.
            units = card.get("Подразд") or {}
            branches = len(units.get("Филиал") or [])
            representatives = len(units.get("Представ") or [])
            # Уставный капитал бесплатный тариф справочника не отдаёт, а здесь он
            # есть. Для микробизнеса минимальный капитал — заметный признак.
            capital = (card.get("УстКап") or {}).get("Сумма")

        latest_revenue = years[0].revenue if years else None
        summary = FinancialSummary(
            years=years,
            employees=employees,
            capital=capital,
            branches=branches,
            representative_offices=representatives,
            size_category=self._size_category(latest_revenue, employees),
            extras=self._card_extras(card),
        )
        log.info("checko.finances", inn=inn, years=len(years),
                 employees=employees, size=summary.size_category)
        return summary, None

    @staticmethod
    def _extra_okved(data: dict) -> list[str]:
        """Дополнительные ОКВЭДы строкой «код — название».

        Основной код говорит, чем компания зарегистрирована, дополнительные
        — чем занимается фактически: появление нового кода часто означает
        запуск нового направления. Приходят в карточке даром.
        """
        result: list[str] = []
        for item in (data.get("ОКВЭДДоп") or []):
            if not isinstance(item, dict):
                continue
            code, name = item.get("Код"), item.get("Наим")
            if code and name:
                result.append(f"{code} — {name}")
        return result

    @staticmethod
    def _trademarks(data: dict) -> list[str]:
        """Товарные знаки компании.

        Зарегистрированный знак — подтверждение, что рыночное имя
        используется в обороте; название знака — готовая строка для
        коммерческого профиля. Список бывает пуст — поле опциональное.
        """
        result: list[str] = []
        for item in (data.get("ТоварЗнак") or []):
            if isinstance(item, dict):
                mark = item.get("Наим") or item.get("Номер")
                if mark:
                    result.append(str(mark))
            elif item:
                result.append(str(item))
        return result

    def _card_extras(self, card: dict | None) -> CardExtras | None:
        """Налоги, лицензии, контакты, массовость адреса — из той же карточки.

        Всё это приходит в ответе компании и раньше отбрасывалось.
        Card — при отказе карточки None: поля останутся «не установленными»,
        а не нулями; говорить «недоимки нет» на молчании источника нельзя.
        """
        if not card:
            return None

        taxes = card.get("Налоги") or {}
        licenses: list[LicenseInfo] = []
        for lic in card.get("Лиценз") or []:
            activities = lic.get("ВидДеят") or []
            licenses.append(LicenseInfo(
                number=lic.get("Номер") or "",
                issuer=lic.get("ЛицОрг"),
                issued_at=_parse_date(lic.get("ДатаНач") or lic.get("Дата")),
                activity=activities[0] if activities else None,
            ))

        addr = card.get("ЮрАдрес") or {}
        contacts_raw = card.get("Контакты") or {}
        website = contacts_raw.get("ВебСайт")

        return CardExtras(
            tax_debt=taxes.get("СумНедоим"),
            tax_paid_total=taxes.get("СумУпл"),
            tax_year=int(taxes["СведУплГод"]) if taxes.get("СведУплГод") else None,
            tax_mode=list(taxes.get("ОсобРежим") or []),
            okved_extra=self._extra_okved(card),
            trademarks=self._trademarks(card),
            mass_address_orgs=list(addr.get("МассАдрес") or []),
            address_unreliable=bool(addr.get("Недост")),
            licenses=licenses,
            contacts=ContactInfo(
                phones=list(contacts_raw.get("Тел") or []),
                emails=list(contacts_raw.get("Емэйл") or []),
                website=website,
            ),
        )

    # ─────────────────────────  люди и связи  ─────────────────────────

    async def get_person(
        self, person_inn: str, role: str | None = None
    ) -> tuple[PersonProfile | None, list[RelatedCompany]]:
        """Сведения о физическом лице: его организации и личные риски.

        Возвращает профиль и список его организаций. Организации приходят
        не голыми номерами, а полными записями — с наименованием, статусом
        и датой регистрации. Раньше всё это отбрасывалось, и в отчёт попадали
        числа, по которым читатель не мог понять, что перед ним.
        """
        data, failure = await self._fetch("person", person_inn, "checko.person")
        if failure or not data:
            return None, []

        companies: list[RelatedCompany] = []
        for block, link in (("Руковод", "через руководителя"),
                            ("Учред", "через учредителя")):
            for item in (data.get(block) or []):
                companies.append(_brief(item, link=link,
                                        via=data.get("ФИО") or person_inn))

        return PersonProfile(
            inn=person_inn,
            fio=data.get("ФИО"),
            role_in_company=role,
            manages_count=len(data.get("Руковод") or []),
            owns_count=len(data.get("Учред") or []),
            checked=True,
            sole_proprietor=bool(data.get("ИП")),
            personal_bankruptcy=bool(data.get("ЕФРСБ")),
            mass_manager=bool(data.get("МассРуковод")),
            mass_founder=bool(data.get("МассУчред")),
            unfair_supplier=bool(data.get("НедобПост")),
            sanctioned=bool(data.get("Санкции")),
        ), companies

    async def get_company_brief(
        self, ident: str, by: str = "inn"
    ) -> tuple[dict | None, str | None]:
        """Карточка организации для поверхностной проверки.

        Нужна ради отметок риска: наименование и статус приходят и в кратких
        записях, а вот банкротство, санкции, реестр недобросовестных
        поставщиков и массовость лежат только в карточке.

        Часть связей известна лишь по ОГРН — источник принимает и его.
        """
        # У предпринимателя карточки юридического лица не существует:
        # обращение к методу организаций вернёт пустоту, неотличимую
        # от «проверено, ничего не найдено».
        endpoint = "entrepreneur" if by == "inn" and len(ident.strip()) == 12 else "company"
        try:
            body = await self._get(endpoint, {by: ident})
        except httpx.HTTPStatusError as e:
            return None, _why(e)
        except (httpx.HTTPError, httpx.TimeoutException) as e:
            return None, f"{type(e).__name__}"
        if (body.get("meta") or {}).get("status") != "ok":
            return None, (body.get("meta") or {}).get("message") or "источник вернул ошибку"
        data = body.get("data") or {}
        if not data:
            return None, "источник вернул пустую карточку"
        return data, None

    async def _deep_checks(
        self, inn: str
    ) -> tuple[list[str], list[str], list[str]]:
        """Три направления полной проверки, разобранные по значению.

        Возвращает (тревожное, нейтральное, непроверенное). Тревожное —
        то, что делает организацию проблемной: иски ПРОТИВ неё, долги
        приставам, нарушения надзора. Нейтральное — активность, которая
        риском не является: организация сама взыскивает долги, судебных
        дел нет вовсе. Разделение нужно, потому что владельца-организацию
        без реестровых отметок мы тоже проверяем глубоко, и «сам судится
        с должниками» не должно превращать её в подозрительную.
        """
        arb, enf, insp = await asyncio.gather(
            self.check_arbitration(inn),
            self.check_enforcement(inn),
            self.check_inspections(inn),
            return_exceptions=True,
        )

        findings: list[str] = []
        neutral: list[str] = []
        unchecked: list[str] = []

        if isinstance(arb, SourceResult) and arb.arbitration:
            a = arb.arbitration
            if a.as_defendant.count:
                amount = f" на {a.as_defendant.total_amount:,.0f} ₽".replace(",", " ")
                findings.append(f"ответчик по {a.as_defendant.count} делам{amount}")
            if a.as_plaintiff.count:
                neutral.append(f"истец по {a.as_plaintiff.count} делам")
            if not a.total:
                neutral.append("судебных дел нет")
        else:
            unchecked.append("суды")

        if isinstance(enf, SourceResult) and enf.enforcement:
            e = enf.enforcement
            if e.total:
                debt = f"{e.outstanding:,.0f} ₽".replace(",", " ")
                findings.append(
                    f"исполнительных производств {e.total}, остаток долга {debt}")
        else:
            unchecked.append("приставы")

        if isinstance(insp, SourceResult) and insp.inspections:
            if insp.inspections.with_violations:
                findings.append(
                    f"проверок с нарушениями {insp.inspections.with_violations}")
        else:
            unchecked.append("надзорные проверки")

        return findings, neutral, unchecked

    async def _deep_summary(self, inn: str) -> str | None:
        """Полная проверка подозрительной организации, сжатая в одну строку.

        Возвращать сюда полные списки фактов нельзя: пять организаций
        по десять дел каждая вытеснят из окна модели само досье.
        Поэтому здесь только итоговые числа и ссылка на первоисточник.
        """
        findings, neutral, unchecked = await self._deep_checks(inn)
        parts = findings + neutral
        if unchecked:
            parts.append(f"НЕ ПРОВЕРЕНО: {', '.join(unchecked)}")

        return "; ".join(parts) if parts else None

    async def check_affiliations(
        self, inn: str, deep: bool = True
    ) -> tuple[AffiliationGraph | None, SourceResult]:
        """Связи организации через людей, владельцев и реорганизацию.

        Обход идёт в четыре слоя, глубина ровно два шага: проверяемая
        организация -> её люди и владельцы -> организации этих людей.
        Третий шаг не делается сознательно: у массового учредителя бывают
        десятки компаний, и граф разрастается быстрее, чем растёт смысл.

          слой 0  разбор карточки: руководители, учредители, владельцы-
                  организации, управляющая организация, правопреемство;
          слой 1  опрос физических лиц — их организации и личные отметки;
          слой 2  сведение всего в один список без повторов;
          слой 3  поверхностная проверка каждой связанной организации;
          слой 4  полная проверка только тех, что вызвали подозрение.

        Смысл всей конструкции: организация может быть безупречной, а её
        владелец — держать рядом проблемное юрлицо. Общего идентификатора
        у них нет, и проверка одной компании этого не покажет никогда.
        """
        # Казахский идентификатор тоже двенадцатизначный и без этой проверки
        # уходил в метод предпринимателей: запрос тратился впустую, а отказ
        # выглядел невнятно. Источников по этим странам не существует.
        guess = detect_country(inn)
        if guess.country != "RU":
            return None, SourceResult(
                source="checko.affiliations", status="unavailable",
                reason=(f"{guess.note} Проверка связей по этой стране "
                        f"НЕ ПРОВОДИЛАСЬ — источников не существует."
                        if guess.note else
                        "Идентификатор не опознан, проверка не выполнялась."),
            )

        card, failure = await self._fetch(_card_endpoint(inn), inn, "checko.affiliations")
        if failure:
            return None, failure

        now = datetime.now(UTC)
        notes: list[str] = []
        seeds: dict[str, RelatedCompany] = {}

        def add(rc: RelatedCompany) -> None:
            """Положить организацию в набор, отбросив саму проверяемую."""
            key = rc.inn or rc.ogrn
            if not key or rc.inn == inn:
                return
            seeds.setdefault(key, rc)

        # ── слой 0: люди из карточки ────────────────────────────────────
        # Человек может быть и директором, и учредителем одновременно —
        # держим его одной записью, накапливая роли и признаки.
        refs: dict[str, dict[str, Any]] = {}
        anonymous: list[PersonProfile] = []

        def note_person(item: dict, role: str) -> None:
            fio = item.get("ФИО")
            person_inn = item.get("ИНН")
            share = (item.get("Доля") or {}).get("Процент")

            if not person_inn:
                # Без ИНН опросить человека невозможно. Раньше он молча
                # исчезал — и отчёт выглядел так, будто его не существует.
                # Одно лицо бывает и директором, и учредителем сразу.
                # Именованных мы объединяем по ИНН — этих объединяем по имени,
                # иначе один человек появится в отчёте дважды.
                key = fio or "лицо без ИНН"
                same = next((x for x in anonymous
                             if (x.fio or "лицо без ИНН") == key), None)
                if same is not None:
                    same.role_in_company = f"{same.role_in_company}, {role}"
                    if share is not None:
                        same.share_percent = share
                else:
                    anonymous.append(PersonProfile(
                        fio=fio, role_in_company=role, share_percent=share,
                        checked=False,
                        not_checked_reason="ИНН в реестре не указан, личные риски проверить нельзя",
                        unreliable=bool(item.get("Недост")),
                        disqualified=bool(item.get("ДисквЛицо")),
                        mass_manager=bool(item.get("МассРуковод")),
                        mass_founder=bool(item.get("МассУчред")),
                    ))
                # Связи известны только по ОГРН. Руководство и учредительство —
                # разные вещи, подписывать их одинаково значит врать в отчёте.
                for block, link in (("СвязРуковод", "через руководителя"),
                                    ("СвязУчред", "через учредителя")):
                    for ogrn in (item.get(block) or []):
                        add(RelatedCompany(ogrn=ogrn, link=link, via=key))
                return

            slot = refs.setdefault(person_inn, {
                "fio": fio, "roles": [], "share": None,
                "unreliable": False, "disqualified": False,
                "mass_manager": False, "mass_founder": False,
            })
            slot["roles"].append(role)
            if share is not None:
                slot["share"] = share
            slot["unreliable"] |= bool(item.get("Недост"))
            slot["disqualified"] |= bool(item.get("ДисквЛицо"))
            slot["mass_manager"] |= bool(item.get("МассРуковод"))
            slot["mass_founder"] |= bool(item.get("МассУчред"))

        for item in (card.get("Руковод") or []):
            note_person(item, item.get("НаимДолжн") or "руководитель")
        founders = card.get("Учред") or {}
        for item in (founders.get("ФЛ") or []):
            note_person(item, "учредитель")

        # У индивидуального предпринимателя нет ни руководителей, ни
        # учредителей: он сам и есть это лицо. Без такой оговорки граф
        # выходил пустым и читался как «связей нет», хотя у человека
        # за спиной могут стоять другие организации.
        if _card_endpoint(inn) == "entrepreneur" and not refs and not anonymous:
            refs[inn] = {
                "fio": card.get("ФИО"),
                "roles": ["индивидуальный предприниматель"],
                "share": None,
                "unreliable": bool(card.get("Недост")),
                "disqualified": False,
                "mass_manager": bool(card.get("МассРуковод")),
                "mass_founder": bool(card.get("МассУчред")),
            }

        # ── слой 0: владельцы-организации и управление ──────────────────
        owners: list[RelatedCompany] = []
        for block, link in (("РосОрг", "владелец-организация"),
                            ("ИнОрг", "иностранный владелец")):
            for item in (founders.get(block) or []):
                rc = _brief(item, link=link)
                share = (item.get("Доля") or {}).get("Процент")
                rc.via = f"доля {share}%" if share is not None else None
                owners.append(rc)
                add(rc)
                # У владельца-организации свои связи — они уже в карточке
                for ogrn in (item.get("СвязУчред") or []):
                    add(RelatedCompany(ogrn=ogrn, link="через владельца-организацию",
                                       via=item.get("НаимСокр")))

        manager_org = card.get("УпрОрг") or {}
        if manager_org.get("ИНН") or manager_org.get("ОГРН"):
            rc = _brief(manager_org, link="управляющая организация")
            owners.append(rc)
            add(rc)

        # ── слой 0: реорганизация ───────────────────────────────────────
        # Это ответ на самый неудобный обход: сменить не название, а юрлицо.
        # У нового юрлица другой ИНН, и связь видна только здесь.
        predecessors = [_brief(x, link="правопредшественник")
                        for x in (card.get("Правопредш") or [])]
        successors = [_brief(x, link="правопреемник")
                      for x in (card.get("Правопреем") or [])]
        for rc in predecessors + successors:
            add(rc)

        # Связи, посчитанные самим источником, — приходят даром в карточке
        for item in (card.get("СвязУчред") or []):
            add(_brief(item, link="общий учредитель"))
        for ogrn in (card.get("СвязУпрОрг") or []):
            add(RelatedCompany(ogrn=ogrn, link="общая управляющая организация"))

        # ── акционерное общество: владельцы не раскрыты ─────────────────
        undisclosed = bool(card.get("ДержРеестрАО"))
        if undisclosed:
            notes.append(
                "Это акционерное общество: состав владельцев в реестре "
                "НЕ РАСКРЫВАЕТСЯ, он ведётся у держателя реестра акционеров. "
                "Пустой список собственников здесь означает невозможность "
                "проверки, а НЕ отсутствие собственников. Скажи об этом прямо."
            )

        # ── слой 1: опрос физических лиц ────────────────────────────────
        limit = settings.affiliation_max_people

        def person_weight(item: tuple[str, dict[str, Any]]) -> tuple[int, float]:
            """Кого проверять первыми, если всех не осилим.

            Порядок лиц в реестре произволен, и обрезание по нему однажды
            выбросит владельца контрольного пакета ради десятого
            номинального директора.
            """
            meta = item[1]
            flagged = any((meta["unreliable"], meta["disqualified"],
                           meta["mass_manager"], meta["mass_founder"]))
            return (1 if flagged else 0, meta["share"] or 0.0)

        chosen = sorted(refs.items(), key=person_weight, reverse=True)[:limit]
        if len(refs) > limit:
            notes.append(
                f"Физических лиц у организации {len(refs)}, опрошено {limit} — "
                f"упор в лимит. Остальные НЕ ПРОВЕРЕНЫ."
            )

        gathered = await asyncio.gather(
            *(self.get_person(p_inn, ", ".join(meta["roles"]))
              for p_inn, meta in chosen),
            return_exceptions=True,
        )

        people: list[PersonProfile] = []
        for (p_inn, meta), got in zip(chosen, gathered):
            if isinstance(got, BaseException) or got[0] is None:
                people.append(PersonProfile(
                    inn=p_inn, fio=meta["fio"],
                    role_in_company=", ".join(meta["roles"]),
                    share_percent=meta["share"], checked=False,
                    not_checked_reason="Источник не ответил по этому лицу",
                    unreliable=meta["unreliable"], disqualified=meta["disqualified"],
                    mass_manager=meta["mass_manager"], mass_founder=meta["mass_founder"],
                ))
                continue
            profile, companies = got
            # Отметки из карточки объединяем с отметками из профиля:
            # недостоверность и дисквалификация есть только в карточке
            # Если профиль пришёл без имени, берём его из карточки:
            # безымянная запись в отчёте бесполезна
            profile.fio = profile.fio or meta["fio"]
            profile.share_percent = meta["share"]
            profile.unreliable = profile.unreliable or meta["unreliable"]
            profile.disqualified = profile.disqualified or meta["disqualified"]
            profile.mass_manager = profile.mass_manager or meta["mass_manager"]
            profile.mass_founder = profile.mass_founder or meta["mass_founder"]
            people.append(profile)
            for rc in companies:
                add(rc)

        people.extend(anonymous)
        if anonymous:
            notes.append(
                f"У {len(anonymous)} лиц ИНН в реестре не указан — их личные "
                f"риски проверить невозможно. Это не значит, что рисков нет."
            )

        # ── слой 3: поверхностная проверка связанных организаций ────────
        # Значимость связи зависит от её вида: правопреемство — прямая
        # ниточка к прежнему юрлицу, владение — контроль, связь через
        # рядового учредителя слабее. При упоре в лимит отсекать надо
        # с хвоста, а не по случайному порядку обнаружения.
        related = sorted(seeds.values(), key=lambda rc: _LINK_RANK.get(rc.link, 4))
        cap = settings.affiliation_max_related
        to_check, skipped = related[:cap], related[cap:]

        triaged = await asyncio.gather(
            *(self.get_company_brief(rc.inn or rc.ogrn,
                                     by="inn" if rc.inn else "ogrn")
              for rc in to_check),
            return_exceptions=True,
        )

        for rc, got in zip(to_check, triaged):
            if isinstance(got, BaseException):
                rc.triage_status = "unavailable"
                continue
            data, reason = got
            if reason or data is None:
                rc.triage_status = "unavailable"
                continue

            rc.triage_status = "checked"
            rc.inn = rc.inn or data.get("ИНН")
            rc.ogrn = rc.ogrn or data.get("ОГРН")
            rc.name = rc.name or data.get("НаимСокр") or data.get("НаимПолн")
            rc.status = _text(data.get("Статус")) or rc.status
            rc.registered_at = rc.registered_at or _parse_date(data.get("ДатаРег"))
            rc.okved_text = rc.okved_text or _text(data.get("ОКВЭД"))
            if rc.inn and not rc.source_url:
                rc.source_url = f"https://focus.kontur.ru/entity?query={rc.ogrn or rc.inn}"

            for field, description in RISK_FLAGS.items():
                if data.get(field):
                    rc.flags.append(description)
            if data.get("ЕФРСБ"):
                rc.flags.append("Есть сообщения реестра банкротств")
            if data.get("ДисквЛица"):
                rc.flags.append("Среди руководителей есть дисквалифицированные лица")

            # Недействующая организация — сильнейший признак: брошенное
            # юрлицо и есть обычный способ уйти от прошлого
            dead = bool(rc.status) and rc.status != "Действует"
            rc.suspicious = bool(rc.flags) or dead

        # Часть связей приходит одним ОГРН, без ИНН. Проверяемая организация
        # в таком виде не отсеивалась при добавлении и попадала в список
        # связанных сама с собой. ИНН становится известен только после
        # триажа — значит и отсев с объединением повторов делаются здесь.
        kept: dict[str, RelatedCompany] = {}
        for rc in related:
            if rc.inn == inn:
                continue
            key = rc.inn or rc.ogrn
            if key not in kept:
                kept[key] = rc
        related = list(kept.values())
        alive = {id(rc) for rc in related}
        to_check = [rc for rc in to_check if id(rc) in alive]

        # Пометку о лимите пишем здесь, а не в момент обрезания: до слияния
        # повторов число связанных организаций завышено, и в отчёт попадала
        # цифра, которая не сходилась со списком.
        if skipped:
            notes.append(
                f"Связанных организаций {len(related)}, проверено {len(to_check)} — "
                f"упор в лимит. Остальные НЕ ПРОВЕРЕНЫ."
            )

        unavailable = [rc for rc in to_check if rc.triage_status == "unavailable"]
        if unavailable:
            notes.append(
                f"По {len(unavailable)} связанным организациям источник "
                f"не ответил — их риски НЕ ПРОВЕРЕНЫ."
            )

        # ── слой 4: полная проверка подозрительных ──────────────────────
        suspicious = [rc for rc in to_check if rc.suspicious and rc.inn]
        if deep and suspicious:
            deep_cap = settings.affiliation_max_deep
            picked = suspicious[:deep_cap]
            if len(suspicious) > deep_cap:
                notes.append(
                    f"Подозрительных организаций {len(suspicious)}, полностью "
                    f"проверено {deep_cap} — упор в лимит."
                )
            summaries = await asyncio.gather(
                *(self._deep_summary(rc.inn) for rc in picked),
                return_exceptions=True,
            )
            for rc, summary in zip(picked, summaries):
                if isinstance(summary, str):
                    rc.deep_summary = summary

        # ── слой 4б: владельцы без отметок — прямая проверка ────────────
        # Отметки и мёртвый статус ловят брошенные юрлица, но слепы к
        # «чистой витрине»: действующая организация без единой отметки,
        # утопленная в исках. Для рядового связанного юрлица такой риск
        # слабо относится к проверяемой компании, а вот трудности
        # владельца — это её трудности: пакетный владелец отвечает по
        # обязательствам, вводит организацию в недоверие, выводит активы.
        # Поэтому глубокой проверки ради себя требуют владельцы-
        # организации и управляющая организация, отметки ли у них есть.
        # НЕ ПРОВЕРЕНО в сводке честно называет направление, которое
        # не ответило — иначе refusal приставов прочитается как «долгов нет».
        if deep and owners:
            no_inn = [rc for rc in owners if not rc.inn]
            if no_inn:
                notes.append(
                    f"У {len(no_inn)} владельцев нет ИНН в реестре — "
                    f"глубоко не проверены."
                )
            owner_cap = settings.affiliation_max_deep
            # Уже проверенный слоем 4 владелец (по отметкам) не проверяется
            # второй раз — это двойной расход квоты за те же данные.
            picked_owners = [rc for rc in owners
                             if rc.inn and not rc.deep_summary][:owner_cap]
            if len(owners) > owner_cap:
                notes.append(
                    f"Владельцев-организаций {len(owners)}, проверено глубоко "
                    f"{len(picked_owners)} — упор в лимит."
                )
            owner_checks = await asyncio.gather(
                *(self._deep_checks(rc.inn) for rc in picked_owners),
                return_exceptions=True,
            )
            for rc, got in zip(picked_owners, owner_checks):
                if isinstance(got, BaseException):
                    rc.deep_summary = "НЕ ПРОВЕРЕНО: суды, приставы, надзор"
                    continue
                findings, neutral, unchecked = got
                rc.deep_summary = "; ".join(findings + neutral + [
                    f"НЕ ПРОВЕРЕНО: {', '.join(unchecked)}"] if unchecked
                    else findings + neutral) or None
                if findings:
                    rc.suspicious = True
                    rc.triage_status = "checked"

        # ── факты для ссылок из текста отчёта ───────────────────────────
        facts: list[Fact] = []
        n = 0
        for p in people:
            for raised, text in (
                (p.personal_bankruptcy, "имеет сведения о личном банкротстве"),
                (p.mass_manager, "признан массовым руководителем"),
                (p.mass_founder, "признан массовым учредителем"),
                (p.unfair_supplier, "числится в реестре недобросовестных поставщиков"),
                (p.sanctioned, "находится в санкционных списках"),
                (p.unreliable, "сведения о нём признаны ФНС недостоверными"),
                (p.disqualified, "дисквалифицирован"),
            ):
                if raised:
                    n += 1
                    facts.append(Fact(
                        fact_id=f"PERS-{n}", kind="registry_flag",
                        statement=f"{p.fio or p.inn} ({p.role_in_company}) {text}",
                        source_url=(f"https://checko.ru/person/{p.inn}" if p.inn
                                    else f"https://focus.kontur.ru/entity?query={inn}"),
                        source_type="registry_api", retrieved_at=now,
                        payload={"person_inn": p.inn, "role": p.role_in_company},
                    ))

        for rc in to_check:
            if not rc.suspicious:
                continue
            n += 1
            tail = f"; {rc.deep_summary}" if rc.deep_summary else ""
            flags = "; ".join(rc.flags) if rc.flags else f"статус «{rc.status}»"
            facts.append(Fact(
                fact_id=f"PERS-{n}", kind="registry_flag",
                statement=(f"Связанная организация {rc.name or rc.inn or rc.ogrn} "
                           f"({rc.link}{', ' + rc.via if rc.via else ''}): {flags}{tail}"),
                source_url=rc.source_url or f"https://focus.kontur.ru/entity?query={inn}",
                source_type="registry_api", retrieved_at=now,
                payload={"inn": rc.inn, "link": rc.link, "flags": rc.flags},
            ))

        suspicious_count = sum(1 for rc in to_check if rc.suspicious)
        log.info("checko.affiliations", inn=inn, people=len(people),
                 related=len(related), suspicious=suspicious_count,
                 undisclosed=undisclosed)

        graph = AffiliationGraph(
            inn=inn,
            people=people,
            owner_organizations=owners,
            predecessors=predecessors,
            successors=successors,
            related_companies=related,
            suspicious_count=suspicious_count,
            shareholders_undisclosed=undisclosed,
            coverage_note=" ".join(notes) or None,
        )
        return graph, SourceResult(source="checko.affiliations", status="ok", facts=facts)

    # ─────────────────────────  история изменений  ─────────────────────────

    # События, существенные для проверки контрагента
    _RENAME = re.compile(r"аименование изменено с\s+[\"«](?P<old>.+?)[\"»]\s+на\s+[\"«](?P<new>.+?)[\"»]")
    _NOTABLE = ("аименование изменено", "становится генеральным директором",
                "больше не является генеральным директором", "дрес изменен",
                "еорганизац", "иквидац", "удалена запись об учредителе",
                "становится новым учредителем", "становится учредителем")

    async def get_name_history(self, inn: str) -> tuple[list[str], list[dict], str | None]:
        """Прошлые наименования организации и существенные события.

        Зачем: организация может сменить название — в том числе чтобы
        отделиться от прежней репутации. Поиск публикаций только по текущему
        наименованию пропустит всё, что писали о ней раньше, и система
        сообщит об отсутствии негатива, ничего о прошлом не узнав.

        Возвращает (прошлые наименования, существенные события, причина отказа).
        """
        try:
            body = await self._get("timeline", {"inn": inn})
        except (httpx.HTTPError, httpx.TimeoutException) as e:
            return [], [], f"История изменений недоступна: {type(e).__name__}"

        if (body.get("meta") or {}).get("status") != "ok":
            return [], [], "Источник не вернул историю изменений"

        data = body.get("data")
        records = data if isinstance(data, list) else (data or {}).get("Записи") or []

        former: list[str] = []
        notable: list[dict] = []
        for rec in records:
            event = rec.get("Событие") or ""
            if not any(k in event for k in self._NOTABLE):
                continue
            notable.append({"date": rec.get("Дата"), "event": event})

            m = self._RENAME.search(event)
            if m:
                old = m.group("old").strip()
                if old and old not in former:
                    former.append(old)

        log.info("checko.timeline", inn=inn, former_names=len(former),
                 notable=len(notable))
        return former, notable, None

    # ───────────────  резервная карточка и resolve (без DaData)  ───────────────

    async def get_context(self, inn: str) -> "ContextResult":
        """Резервная карточка организации из Checko.

        Нужна, когда DaData недоступна (нет ключа, лимит, сбой): без неё
        система отказывалась работать целиком, хотя Checko отдаёт все
        реестровые сведения — наименование, статус, адрес, руководителя,
        учредителей, капитал. Источник помечается 'checko', чтобы досье
        честно показывало, откуда пришли данные.
        """
        from osint_mcp.context.okved import industry_terms
        from osint_mcp.models import CompanyContext, ContextResult
        from osint_mcp.tools.names import name_variants

        endpoint = "entrepreneur" if len(inn.strip()) == 12 else "company"
        data, failure = await self._fetch(endpoint, inn, "checko.context")
        if failure:
            return ContextResult(status="unavailable",
                                 reason=failure.reason)
        if not data or not data.get("ИНН"):
            return ContextResult(status="ok",
                                 reason="Организация не найдена в реестре")

        legal = data.get("НаимПолн") or data.get("НаимСокр") or ""
        short = data.get("НаимСокр")
        okved = data.get("ОКВЭД") or {}
        okved_code = okved.get("Код")
        addr = data.get("ЮрАдрес") or {}
        director = next(
            (r for r in (data.get("Руковод") or [])
             if (r.get("ВидДолжн") or "").find("РУКОВОДИТЕЛЬ") >= 0),
            None,
        ) if data.get("Руковод") else (
            (data.get("Руковод") or [None])[0]
        )

        founders: list[str] = []
        founder_blocks = data.get("Учред") or {}
        for f in (founder_blocks.get("ФЛ") or []):
            if f.get("ФИО"):
                founders.append(f["ФИО"])
        for f in (founder_blocks.get("РосОрг") or []) + (founder_blocks.get("ИнОрг") or []):
            if f.get("НаимПолн") or f.get("НаимСокр"):
                founders.append(f.get("НаимПолн") or f.get("НаимСокр"))

        registered = _parse_date(data.get("ДатаРег"))
        capital = (data.get("УстКап") or {}).get("Сумма")

        is_ip = endpoint == "entrepreneur" or len(inn.strip()) == 12
        ip_fio = (director or {}).get("ФИО") or (legal if is_ip else None)
        ip_post = (director or {}).get("НаимДолжн") or ("Индивидуальный предприниматель" if is_ip else None)

        ctx = CompanyContext(
            inn=data.get("ИНН") or inn,
            ogrn=data.get("ОГРН"),
            kpp=data.get("КПП"),
            name_legal=legal,
            name_short=short,
            status=(data.get("Статус") or {}).get("Наим"),
            registered_at=registered,
            address_full=addr.get("АдресРФ"),
            city=addr.get("НасПункт"),
            region=(data.get("Регион") or {}).get("Наим"),
            director_fio=ip_fio,
            director_post=ip_post,
            founders=founders,
            okved_code=okved_code,
            okved_text=okved.get("Наим"),
            capital=capital,
            entity_type="individual_entrepreneur" if is_ip else "legal_entity",
            name_variants=name_variants(legal, short, data.get("НаимАнгл")),
            industry_terms=industry_terms(okved_code),
            brand_resolved=False,
            source="checko",
            retrieved_at=datetime.now(UTC),
        )
        log.info("context_checko_fallback", inn=ctx.inn, name=ctx.name_legal,
                 variants=len(ctx.name_variants))
        return ContextResult(status="ok", context=ctx)
