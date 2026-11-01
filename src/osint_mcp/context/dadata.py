"""Источник реестровых данных: DaData.

Бесплатный тариф — 10 000 запросов в сутки. Даёт наименование, адрес,
статус, дату регистрации, ОКВЭД, руководителя, учредителей. Не даёт
численность, выручку, лицензии, телефоны.

Используются два эндпоинта:
  findById/party — точный поиск по ИНН или ОГРН;
  suggest/party  — поиск с частичным совпадением, для запроса по названию.
"""

from datetime import date, datetime, timezone
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
from osint_mcp.context.okved import industry_terms
from osint_mcp.keys import ROTATE_STATUS_CODES, QuotaExhausted
from osint_mcp.keys import dadata as dadata_pool
from osint_mcp.models import (
    BrandInfo,
    Candidate,
    CompanyContext,
    ContextResult,
    ResolveResult,
)
from osint_mcp.tools.country import detect_country
from osint_mcp.tools.inn import validate_inn
from osint_mcp.tools.names import name_variants

log = structlog.get_logger()

# Коды состояния DaData -> человекочитаемый статус
_STATUS = {
    "ACTIVE": "действующая",
    "LIQUIDATING": "в стадии ликвидации",
    "LIQUIDATED": "ликвидирована",
    "BANKRUPT": "банкротство",
    "REORGANIZING": "в стадии реорганизации",
}


def _ms_to_date(value: Any) -> date | None:
    """DaData отдаёт даты меткой времени в миллисекундах."""
    if not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc).date()
    except (ValueError, OSError, OverflowError):
        return None


def _parse_iso(value: Any) -> date | None:
    """Разобрать дату из любого формата, встречающегося в справочниках.

    Российский справочник отдаёт метку времени числом, справочники Беларуси
    и Казахстана — ту же метку СТРОКОЙ. Встречается и запись по ISO.
    """
    if isinstance(value, (int, float)):
        return _ms_to_date(value)
    if not isinstance(value, str) or not value:
        return None
    if value.isdigit():                      # метка времени строкой
        return _ms_to_date(int(value))
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _looks_like_id(query: str) -> bool:
    """Похож ли запрос на идентификатор, а не на название."""
    cleaned = query.strip().replace(" ", "").replace("-", "")
    return cleaned.isdigit() and len(cleaned) in (10, 12, 13, 15)


def _head_offices(items: list[dict]) -> list[dict]:
    """Оставить головные организации, отбросив филиалы.

    Поиск по ИНН возвращает и головную организацию, и её филиалы — у всех
    один ИНН, различаются КПП. У Сбербанка это более десятка записей.
    Без отбора карточка могла бы собраться на филиал вместо головной
    организации, причём незаметно.
    """
    heads = [i for i in items if ((i.get("data") or {}).get("branch_type") == "MAIN")]
    return heads or items


class DaDataSource:
    """Реализация ContextSource поверх DaData."""

    name = "dadata"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    def _headers(self, key: str | None = None) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Token {key or dadata_pool.current()}",
        }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, max=6),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    async def _post(self, endpoint: str, payload: dict[str, Any]) -> list[dict]:
        url = f"{settings.dadata_base_url}/{endpoint}"
        try:
            resp = await self._post_raw(url, payload)
        except QuotaExhausted as e:
            # Факт отказа должен остаться в журнале: coverage обязан
            # отличать «источник молчал» от «сведений нет».
            ledger.record("dadata", endpoint, "failed", str(e))
            raise
        except httpx.HTTPStatusError as e:
            ledger.record("dadata", endpoint, "failed",
                          f"служба ответила {e.response.status_code}")
            raise
        except (httpx.TransportError, httpx.TimeoutException) as e:
            ledger.record("dadata", endpoint, "failed", f"сеть: {type(e).__name__}")
            raise

        items = resp.json().get("suggestions", [])
        ledger.record("dadata", endpoint, "ok" if items else "empty")
        return items

    async def _post_raw(self, url: str, payload: dict[str, Any]) -> httpx.Response:
        """Запрос с ротацией ключей при 401/403/429 — см. keys.KeyPool."""
        key = dadata_pool.current()
        headers = self._headers(key)
        keys_count = len(dadata_pool.keys())
        for attempt in range(keys_count + 1):
            if self._client is not None:
                resp = await self._client.post(url, json=payload, headers=headers)
            else:
                async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
                    resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code in ROTATE_STATUS_CODES and attempt < keys_count:
                if not dadata_pool.rotate(f"HTTP {resp.status_code}"):
                    break
                key = dadata_pool.current()
                headers = self._headers(key)
                continue
            break
        if resp.status_code in ROTATE_STATUS_CODES:
            reason = f"DaData ответила {resp.status_code}"
            dadata_pool.mark_exhausted(key, reason)
            raise QuotaExhausted(reason)
        resp.raise_for_status()
        return resp

    # ─────────────────────────  разбор ответа  ─────────────────────────

    @staticmethod
    def _to_candidate(item: dict) -> Candidate:
        data = item.get("data") or {}
        names = data.get("name") or {}
        address = data.get("address") or {}
        addr_data = address.get("data") or {}
        state = data.get("state") or {}
        management = data.get("management") or {}
        okved = data.get("okved")

        return Candidate(
            inn=data.get("inn") or "",
            kpp=data.get("kpp"),
            ogrn=data.get("ogrn"),
            name=names.get("full_with_opf") or item.get("value") or "",
            short_name=names.get("short_with_opf"),
            city=addr_data.get("city") or addr_data.get("region_with_type"),
            status=_STATUS.get(state.get("status"), state.get("status")),
            registered_at=_ms_to_date(state.get("registration_date")),
            director=management.get("name"),
            okved=okved,
        )

    @staticmethod
    def _to_context(item: dict) -> CompanyContext:
        data = item.get("data") or {}
        names = data.get("name") or {}
        address = data.get("address") or {}
        addr_data = address.get("data") or {}
        state = data.get("state") or {}
        management = data.get("management") or {}

        legal = names.get("full_with_opf") or item.get("value") or ""
        short = names.get("short_with_opf")
        okved_code = data.get("okved")

        # Учредители и капитал на бесплатном тарифе не отдаются — придут из Checko
        founders = []
        for f in (data.get("founders") or []):
            fio = (f.get("fio") or {}).get("source") or f.get("name")
            if fio:
                founders.append(fio)

        capital = None
        if isinstance(data.get("capital"), dict):
            capital = (data["capital"] or {}).get("value")

        # Расшифровка ОКВЭД есть только в платном okveds.
        # Внимание: okved_type — это версия классификатора («2014»), НЕ описание.
        okved_text = None
        for entry in (data.get("okveds") or []):
            if entry.get("main"):
                okved_text = entry.get("name")
                break

        is_individual = (data.get("type") == "INDIVIDUAL") or (len(str(data.get("inn") or "")) == 12)
        fio_dict = data.get("fio") or {}
        fio_str = " ".join(filter(None, [fio_dict.get("surname"), fio_dict.get("name"), fio_dict.get("patronymic")]))
        director_fio = management.get("name") or (fio_str if fio_str else None) or (names.get("full") if is_individual else None)
        director_post = management.get("post") or ("Индивидуальный предприниматель" if is_individual else None)
        ent_type = "individual_entrepreneur" if is_individual else "legal_entity"

        return CompanyContext(
            inn=data.get("inn") or "",
            kpp=data.get("kpp"),
            ogrn=data.get("ogrn"),
            name_legal=legal,
            name_short=short,
            status=_STATUS.get(state.get("status"), state.get("status")),
            registered_at=_ms_to_date(state.get("registration_date")),
            address_full=address.get("value"),
            city=addr_data.get("city"),
            region=addr_data.get("region_with_type"),
            director_fio=director_fio,
            director_post=director_post,
            director_inn=management.get("inn"),
            founders=founders,
            okved_code=okved_code,
            okved_text=okved_text,
            capital=capital,
            entity_type=ent_type,
            # Готовые чистые имена от источника надёжнее выведенных отсечением,
            # поэтому передаём их все, включая латиницу
            name_variants=name_variants(
                legal, short, names.get("full"), names.get("short"),
                names.get("latin"),
            ),
            industry_terms=industry_terms(okved_code),
            brand_resolved=False,   # рыночное имя устанавливается позже, по вебу
            source="dadata",
            retrieved_at=datetime.now(timezone.utc),
        )

    # ─────────────────────────  публичные методы  ─────────────────────────

    async def resolve(self, query: str, limit: int = 10) -> ResolveResult:
        query = query.strip()

        # Страну определяем ДО проверки контрольной суммы: казахский БИН
        # тоже двенадцатизначный, и российский алгоритм объявит его
        # опечаткой. Сказать пользователю «ваш номер неверен» про
        # совершенно правильный номер — худшее, что здесь можно сделать.
        guess = detect_country(query)
        if guess.country in ("BY", "KZ"):
            return await self._resolve_foreign(guess)

        # Идентификатор проверяем локально, до обращения к API
        if _looks_like_id(query):
            check = validate_inn(query)
            if check.kind != "unknown" and not check.valid:
                return ResolveResult(
                    query=query, status="ok", confidence="none", total_found=0,
                    hint=f"ИНН некорректен: {check.reason}. "
                         f"Запроси у пользователя правильный номер.",
                )

        endpoint = "findById/party" if _looks_like_id(query) else "suggest/party"
        payload: dict[str, Any] = {"query": query, "count": limit}

        if not settings.dadata_api_key:
            return ResolveResult(
                query=query, status="unavailable", confidence="none",
                reason="Не задан DADATA_API_KEY",
                hint=("Источник недоступен. Это НЕ означает, что компания не найдена. "
                      "Если запрос — ИНН/ОГРН, попробуй ещё раз: сработает резервный "
                      "определитель через Checko."),
            )

        try:
            items = await self._post(endpoint, payload)
        except RuntimeError as e:
            return ResolveResult(
                query=query, status="unavailable", confidence="none",
                reason=str(e),
                hint="Источник недоступен. Это НЕ означает, что компания не найдена.",
            )
        except httpx.HTTPStatusError as e:
            return ResolveResult(
                query=query, status="unavailable", confidence="none",
                reason=f"DaData ответила {e.response.status_code}",
                hint="Источник недоступен. Это НЕ означает, что компания не найдена.",
            )
        except (httpx.TransportError, httpx.TimeoutException) as e:
            return ResolveResult(
                query=query, status="unavailable", confidence="none",
                reason=f"Сеть недоступна: {type(e).__name__}",
                hint="Источник недоступен. Это НЕ означает, что компания не найдена.",
            )

        branches_hidden = 0
        if _looks_like_id(query):
            heads = _head_offices(items)
            branches_hidden = len(items) - len(heads)
            items = heads

        candidates = [self._to_candidate(i) for i in items]
        active = [c for c in candidates if c.status == "действующая"]

        # Подсказка заполняется во ВСЕХ ветках. В описании инструмента
        # агенту велено её прочесть, и пустое поле на самом частом,
        # успешном пути оставляет его без указаний.
        if _looks_like_id(query) and candidates:
            confidence = "high"
            found = candidates[0]
            branches = (f" Филиалов с тем же ИНН: {branches_hidden}, они скрыты — "
                        f"показана головная организация." if branches_hidden else "")
            hint = (f"Организация определена однозначно: {found.name}, "
                    f"ИНН {found.inn}. Вызывай get_company_context с этим ИНН.{branches}")
        elif len(candidates) == 1:
            confidence = "high"
            found = candidates[0]
            hint = (f"Найдена единственная организация: {found.name}, "
                    f"ИНН {found.inn}. Вызывай get_company_context с этим ИНН.")
        elif len(active) == 1:
            confidence = "medium"
            hint = ("Действующая организация одна, остальные ликвидированы. "
                    "Можешь продолжить, но упомяни выбор пользователю.")
        elif not candidates:
            # Это НЕ неоднозначность: выбирать не из чего, и отправлять
            # агента показывать пустой перечень нельзя.
            confidence = "none"
            hint = ("Организация не найдена. Скажи это пользователю и попроси "
                    "уточнить написание либо дать ИНН. НЕ утверждай, что такой "
                    "компании не существует: возможна опечатка или организация "
                    "записана в реестре под другим наименованием.")
        else:
            confidence = "low"
            hint = (f"Найдено {len(candidates)} организаций. НЕ выбирай сам: "
                    f"покажи список пользователю и попроси уточнить город или ИНН. "
                    f"Досье не на ту компанию выглядит достоверно и вводит в заблуждение.")

        log.info("resolve", query=query, found=len(candidates), confidence=confidence)
        return ResolveResult(
            query=query, status="ok", confidence=confidence,
            total_found=len(candidates), candidates=candidates, hint=hint,
        )

    @staticmethod
    def _to_candidate_foreign(item: dict, country: str) -> Candidate:
        """Кандидат из белорусского или казахского справочника.

        Поля там названы иначе, чем в российском, поэтому разбор отдельный.
        """
        d = item.get("data") or {}
        if country == "BY":
            name = d.get("full_name_ru") or item.get("value") or ""
            short = d.get("short_name_ru")
            city = None
        else:
            name = d.get("name_ru") or item.get("value") or ""
            short = None
            city = d.get("address_settlement_ru")
        return Candidate(
            inn=d.get("unp") or d.get("bin") or "",
            name=name,
            short_name=short,
            city=city,
            status=_STATUS.get(d.get("status"), d.get("status")),
            registered_at=_parse_iso(d.get("registration_date")),
            director=d.get("fio_ru") or d.get("fio"),
            okved=d.get("oked"),
        )

    async def _resolve_foreign(self, guess) -> ResolveResult:
        """Поиск по идентификатору Беларуси или Казахстана.

        Отдельная ветка нужна не ради вежливости: российский метод такую
        организацию не найдёт, и ответ «не найдена» будет неправдой.
        """
        endpoint = {"BY": "findById/party_by", "KZ": "findById/party_kz"}[guess.country]
        try:
            items = await self._post(endpoint, {"query": guess.identifier})
        except (httpx.HTTPError, httpx.TimeoutException) as e:
            return ResolveResult(
                query=guess.identifier, status="unavailable", confidence="none",
                reason=f"Справочник не ответил: {type(e).__name__}",
                hint="Источник недоступен. Это НЕ означает, что компания не найдена.",
            )

        if not items:
            return ResolveResult(
                query=guess.identifier, status="ok", confidence="none",
                hint=(f"Организация с таким {guess.id_type} в справочнике не найдена. "
                      f"Проверьте написание номера. НЕ утверждай, что компании "
                      f"не существует."),
            )

        candidates = [self._to_candidate_foreign(i, guess.country) for i in items]
        found = candidates[0]
        log.info("resolve.foreign", country=guess.country,
                 ident=guess.identifier, name=found.name)
        return ResolveResult(
            query=guess.identifier, status="ok", confidence="high",
            total_found=len(candidates), candidates=candidates,
            hint=(f"Организация определена однозначно: {found.name}, "
                  f"{guess.id_type} {found.inn}. {guess.note} "
                  f"Вызывай get_company_context с этим номером."),
        )

    async def get_context(self, inn: str) -> ContextResult:
        check = validate_inn(inn)
        if not check.valid:
            return ContextResult(status="skipped",
                                 reason=f"ИНН не прошёл проверку: {check.reason}")

        if not settings.dadata_api_key:
            return ContextResult(status="unavailable",
                                 reason="Не задан DADATA_API_KEY")

        try:
            items = await self._post("findById/party", {"query": check.inn})
        except RuntimeError as e:
            return ContextResult(status="unavailable", reason=str(e))
        except httpx.HTTPStatusError as e:
            return ContextResult(status="unavailable",
                                 reason=f"DaData ответила {e.response.status_code}")
        except (httpx.TransportError, httpx.TimeoutException) as e:
            return ContextResult(status="unavailable",
                                 reason=f"Сеть недоступна: {type(e).__name__}")

        if not items:
            return ContextResult(status="ok", reason="Организация не найдена в реестре")

        # Головная организация, а не филиал — см. _head_offices
        ctx = self._to_context(_head_offices(items)[0])
        log.info("context", inn=ctx.inn, name=ctx.name_legal,
                 variants=len(ctx.name_variants))
        return ContextResult(status="ok", context=ctx)

    # ─────────────────────────  рыночное наименование  ─────────────────────

    async def get_brand(self, inn: str) -> BrandInfo:
        """Установить рыночное наименование компании.

        Ключевое для веб-поиска: в реестре организация записана как
        'ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "БПМСОФТ"', а в публикациях
        её называют «BPMSoft». Поиск по юридическому наименованию не найдёт
        ничего, и система честно, но ошибочно сообщит об отсутствии негатива.

        Метод платный (тарифицируется отдельно от подписки) и требует
        секретного ключа. При его отсутствии возвращается resolved=False —
        это не ошибка, а честное «не установлено».
        """
        if not settings.dadata_secret_key:
            return BrandInfo(resolved=False,
                             reason="Не задан секретный ключ DaData, метод недоступен")
        if not settings.dadata_api_key:
            return BrandInfo(resolved=False,
                             reason="Не задан DADATA_API_KEY, метод недоступен")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Token {dadata_pool.current()}",
            "X-Secret": settings.dadata_secret_key,
        }
        try:
            if self._client is not None:
                resp = await self._client.post(settings.dadata_brand_url,
                                               json={"query": inn}, headers=headers)
            else:
                async with httpx.AsyncClient(timeout=settings.request_timeout) as c:
                    resp = await c.post(settings.dadata_brand_url,
                                        json={"query": inn}, headers=headers)
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            ledger.record("dadata", "findById/brand", "failed",
                          f"служба ответила {e.response.status_code}")
            return BrandInfo(resolved=False,
                             reason=f"Сервис ответил {e.response.status_code}")
        except (httpx.TransportError, httpx.TimeoutException) as e:
            ledger.record("dadata", "findById/brand", "failed",
                          f"сеть: {type(e).__name__}")
            return BrandInfo(resolved=False,
                             reason=f"Сеть недоступна: {type(e).__name__}")

        items = resp.json().get("suggestions") or []
        ledger.record("dadata", "findById/brand", "ok" if items else "empty")
        if not items:
            return BrandInfo(resolved=False,
                             reason="Рыночное наименование не найдено")

        data = items[0].get("data") or {}
        social = {
            key: data[field]
            for key, field in (("telegram", "telegram_url"), ("vk", "vk_url"),
                               ("youtube", "youtube_url"),
                               ("yandex_maps", "yandex_maps_url"))
            if data.get(field)
        }
        brand = data.get("name")
        log.info("dadata.brand", inn=inn, brand=brand, domain=data.get("domain"))

        return BrandInfo(
            resolved=bool(brand),
            brand=brand,
            domain=data.get("domain"),
            summary=data.get("summary"),
            social_links=social,
            reason=None if brand else "В ответе нет наименования",
        )

    # ─────────────────────────  справочники и квоты  ─────────────────────────

    async def resolve_okved_text(self, code: str) -> str | None:
        """Расшифровка кода ОКВЭД по официальному классификатору.

        На бесплатном тарифе карточка организации расшифровку не содержит:
        поле okved_type хранит версию классификатора («2014»), а не описание.
        Пробел закрывается обращением к справочнику ОКВЭД 2.
        """
        if not code:
            return None
        try:
            items = await self._post("suggest/okved2", {"query": code, "count": 1})
        except (httpx.HTTPError, httpx.TimeoutException):
            return None

        for item in items:
            data = item.get("data") or {}
            if (data.get("code") or "").startswith(code):
                return data.get("name") or item.get("value")
        return items[0].get("value") if items else None

    async def get_quota(self) -> dict[str, dict[str, int]]:
        """Израсходованные и оставшиеся запросы по каждому сервису за сутки.

        Лимиты сильно различаются: подсказки — тысячи в день, метод
        рыночного наименования — десятки. Знать остаток нужно, чтобы
        не упереться в него посреди работы.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Token {dadata_pool.current()}",
        }
        if settings.dadata_secret_key:
            headers["X-Secret"] = settings.dadata_secret_key

        async with httpx.AsyncClient(timeout=settings.request_timeout) as c:
            resp = await c.get(settings.dadata_stat_url, headers=headers)
        resp.raise_for_status()
        body = resp.json()
        used, left = body.get("services") or {}, body.get("remaining") or {}
        return {k: {"used": used.get(k, 0), "remaining": left.get(k, 0)}
                for k in sorted(set(used) | set(left))}

    # ─────────────────────  Беларусь и Казахстан  ─────────────────────
    #
    # Поля в этих справочниках названы иначе, чем в российском:
    #   Беларусь  — unp, full_name_ru, short_name_ru, fio_ru
    #   Казахстан — bin, name_ru, fio, address_ru, oked
    # Поэтому нужны отдельные разборщики.

    @staticmethod
    def _to_context_by(item: dict) -> CompanyContext:
        d = item.get("data") or {}
        legal = d.get("full_name_ru") or item.get("value") or ""
        short = d.get("short_name_ru")
        trade = d.get("trade_name_ru")
        return CompanyContext(
            inn=d.get("unp") or "",
            name_legal=legal,
            name_short=short,
            status=_STATUS.get(d.get("status"), d.get("status")),
            registered_at=_parse_iso(d.get("registration_date")),
            director_fio=d.get("fio_ru"),
            country="BY",
            name_variants=name_variants(legal, short, trade),
            source="dadata.by",
            retrieved_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _to_context_kz(item: dict) -> CompanyContext:
        d = item.get("data") or {}
        legal = d.get("name_ru") or item.get("value") or ""
        return CompanyContext(
            inn=d.get("bin") or "",
            name_legal=legal,
            status=_STATUS.get(d.get("status"), d.get("status")),
            registered_at=_parse_iso(d.get("registration_date")),
            address_full=d.get("address_ru"),
            city=d.get("address_settlement_ru"),
            director_fio=d.get("fio"),
            okved_code=d.get("oked"),
            country="KZ",
            name_variants=name_variants(legal, d.get("name_kz")),
            source="dadata.kz",
            retrieved_at=datetime.now(timezone.utc),
        )

    async def get_context_foreign(self, guess) -> ContextResult:
        """Карточка организации Беларуси или Казахстана.

        Проверки рисков по этим странам недоступны — предупреждение
        передаётся дальше, чтобы отсутствие находок не приняли за их отсутствие.
        """
        endpoint = {"BY": "findById/party_by", "KZ": "findById/party_kz"}[guess.country]
        try:
            items = await self._post(endpoint, {"query": guess.identifier})
        except httpx.HTTPStatusError as e:
            return ContextResult(status="unavailable",
                                 reason=f"Источник ответил {e.response.status_code}")
        except (httpx.TransportError, httpx.TimeoutException) as e:
            return ContextResult(status="unavailable",
                                 reason=f"Сеть недоступна: {type(e).__name__}")

        if not items:
            return ContextResult(status="ok",
                                 reason=f"Организация не найдена в реестре "
                                        f"({guess.id_type} {guess.identifier})")

        build = self._to_context_by if guess.country == "BY" else self._to_context_kz
        ctx = build(items[0])
        log.info("context.foreign", country=guess.country, ident=guess.identifier,
                 name=ctx.name_legal)
        return ContextResult(status="partial", reason=guess.note, context=ctx)
