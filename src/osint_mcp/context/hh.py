"""HeadHunter — найм компании: вакансии как окно в её планы.

Вакансии — самый быстрый сигнал направления: что компания ищет, какие
технологии использует, куда растёт. Поиск по тексту имени работодателя
не требует авторизации. НО: API отдаёт открытые методы только запросам
с зарегистрированным приложением (токен бесплатный, выдаётся на
dev.hh.ru); без него служба отвечает 403 — и это честно докладывается
в reason, а не превращается в «вакансий нет».

Совпадение по тексту имени не гарантирует, что вакансии той самой
организации: названия компаний повторяются. found_by_name предупреждает
об этом читателя отчёта.
"""

import re

import httpx
import structlog

from osint_mcp import ledger
from osint_mcp.config import settings
from osint_mcp.models import HiringInfo

log = structlog.get_logger()

# Отправляем заголовки по документации hh: без HH-User-Agent служба
# режет запросы даже с токеном.
_HEADERS = {
    "HH-User-Agent": "osint-mcp (company research)",
    "Accept": "application/json",
}


# Правовая форма и кавычки в поисковом запросе только мешают: hh ищет
# по подстроке имени работодателя, а работодатели зарегистрированы как
# «БПМСОФТ», а не «ООО "БПМСОФТ"» — полный вид даёт пустой результат.
_LEGAL_FORM = re.compile(
    r"^(ООО|ОАО|ЗАО|ПАО|АО|НКО|АНО|ИП|ФГУП|ГУП|МУП)\s*", re.IGNORECASE)


def _search_query(name: str) -> str:
    """Имя для поиска: из «ООО "БПМСОФТ"» получается «БПМСОФТ».

    Сначала пробуем содержимое кавычек — там рыночное имя; без кавычек
    срезаем правовую форму. Внешние кавычки и ё/ё-регистрацию hh
    приводит сам, их трогать не нужно.
    """
    cleaned = (name or "").strip()
    m = re.search(r"[«\"](.+?)[»\"]", cleaned)
    if m and m.group(1).strip():
        return m.group(1).strip()
    return _LEGAL_FORM.sub("", cleaned).replace('"', "").strip()


class HhSource:
    """Открытый поиск вакансий HeadHunter по имени работодателя."""

    name = "hh"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def get_hiring(self, name: str) -> HiringInfo:
        """Вакансии по тексту имени компании.

        Не бросает исключений наружу: любой отказ — HiringInfo с reason.
        «Ноль вакансий» и «источник не ответил» различаются полем reason:
        первый может означать и тишину найма, второй — ничего не значит.
        """
        service, method = self.name, "vacancies"
        query = _search_query(name)
        if not query:
            return HiringInfo(reason="имя компании не установлено, найм не искался")

        url = f"{settings.hh_base_url}/vacancies"
        params = {
            "text": query,
            # Поиск строго по имени работодателя: по любому тексту нашлись
            # бы вакансии, где название компании лишь упомянуто
            "search_field": "company_name",
            "per_page": 20,
        }
        headers = dict(_HEADERS)
        # Токен приложения необязателен для анонимного доступа, но hh
        # отдаёт его только зарегистрированным приложениям — с токеном
        # запрос проходит гарантированно, без — по настроению антибота.
        if settings.hh_app_token:
            headers["Authorization"] = f"Bearer {settings.hh_app_token}"
        try:
            if self._client is not None:
                resp = await self._client.get(url, params=params, headers=headers)
            else:
                async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
                    # headers, а не _HEADERS: здесь лежит и Authorization —
                    # раньше токен терялся, и служба отвечала 403 даже
                    # с настроенным HH_APP_TOKEN
                    resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            reason = f"сервис ответил {e.response.status_code}"
            if e.response.status_code == 403:
                reason = ("требуется бесплатный токен приложения (dev.hh.ru) — "
                          "задайте HH_APP_TOKEN, без него найм не проверяется")
            ledger.record(service, method, "failed", reason)
            return HiringInfo(reason=reason)
        except (httpx.TransportError, httpx.TimeoutException) as e:
            ledger.record(service, method, "failed", f"сеть: {type(e).__name__}")
            return HiringInfo(reason=f"сеть: {type(e).__name__}")
        except ValueError:
            ledger.record(service, method, "failed", "ответ не JSON")
            return HiringInfo(reason="сервис вернул не JSON")

        items = data.get("items") or []
        roles = [str(v.get("name")) for v in items if v.get("name")]
        ledger.record(service, method, "ok" if items else "empty")
        log.info("hh.vacancies", name=query, found=len(items))
        return HiringInfo(
            open_vacancies=data.get("found", len(items)),
            roles=roles,
            found_by_name=True,
        )
