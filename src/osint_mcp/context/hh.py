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


_LEADERSHIP_PATTERNS = (
    r"руководител", r"директор", r"начальник", r"head of", r"\blead\b",
    r"тимлид", r"\bроп\b", r"управляющ",
)

_TECH_KEYWORDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("1с", "1c", "1с:ут", "1с:erp", "1c:erp", "1с:бухгалтер", "1с:зуп"), "1С"),
    (("bitrix24", "битрикс24"), "Битрикс24"),
    (("amocrm", "амосрм"), "amoCRM"),
    (("sap", "oracle erp", "navision", "axapta"), "ERP (SAP/Oracle)"),
    (("python", "django", "fastapi"), "Python"),
    (("java", "spring"), "Java"),
    (("c#", ".net"), "C# / .NET"),
    (("golang", "go"), "Go"),
    (("react", "vue", "angular"), "Frontend (React/Vue/Angular)"),
    (("docker", "kubernetes", "k8s"), "DevOps (Docker/K8s)"),
    (("postgresql", "postgres", "sql"), "SQL / PostgreSQL"),
)

_IT_ROLE_KEYWORDS = (
    "разработчик", "developer", "программист", "инженер", "devops",
    "qa", "тестировщик", "архитектор", "data scientist", "data engineer",
)


def _find_best_employer(query: str, items: list[dict]) -> dict | None:
    """Выбирает наиболее точный профиль работодателя из выдачи /employers."""
    if not items:
        return None
    q_clean = query.strip().lower()

    # 1. Полное совпадение наименования
    for it in items:
        name = (it.get("name") or "").strip().lower()
        if name == q_clean:
            return it

    # 2. Имя работодателя содержит точное слово запроса как отдельное слово
    exact_word_matches = []
    for it in items:
        name = (it.get("name") or "").strip().lower()
        if re.search(r'\b' + re.escape(q_clean) + r'\b', name):
            exact_word_matches.append(it)
    if exact_word_matches:
        # Приоритет профилю с открытыми вакансиями и наиболее близкой длиной имени
        return max(
            exact_word_matches,
            key=lambda x: (x.get("open_vacancies") or 0, -len(x.get("name") or "")),
        )

    # 3. Если кандидат ровно один и в нем содержится подстрока запроса
    if len(items) == 1:
        name = (items[0].get("name") or "").strip().lower()
        if q_clean in name or name in q_clean:
            return items[0]

    return None


class HhSource:
    """Открытый поиск вакансий HeadHunter по имени работодателя."""

    name = "hh"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def get_hiring(self, name: str) -> HiringInfo:
        """Вакансии по тексту имени компании.
        
        Сначала пытается однозначно определить работодателя через /employers,
        чтобы не собирать вакансии чужих организаций с похожими названиями.
        Вакансии сортируются строго по времени публикации (order_by=publication_time).
        """
        service, method = self.name, "vacancies"
        query = _search_query(name)
        if not query:
            return HiringInfo(reason="имя компании не установлено, найм не искался")

        headers = dict(_HEADERS)
        if settings.hh_app_token:
            headers["Authorization"] = f"Bearer {settings.hh_app_token}"

        matched_employer = None
        # Шаг 1: попытка однозначного разрешения профиля работодателя через /employers
        try:
            emp_url = f"{settings.hh_base_url}/employers"
            emp_params = {"text": query, "per_page": 10}
            if self._client is not None:
                emp_resp = await self._client.get(emp_url, params=emp_params, headers=headers)
            else:
                async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
                    emp_resp = await client.get(emp_url, params=emp_params, headers=headers)
            if emp_resp.status_code == 200:
                emp_data = emp_resp.json()
                matched_employer = _find_best_employer(query, emp_data.get("items") or [])
        except Exception as exc:  # noqa: BLE001
            log.debug("hh.employer_resolve_skipped", query=query, error=str(exc))
            matched_employer = None

        # Шаг 2: запрос вакансий — строго по employer_id либо текстовый fallback
        url = f"{settings.hh_base_url}/vacancies"
        if matched_employer and matched_employer.get("id"):
            emp_id = str(matched_employer["id"])
            emp_name = matched_employer.get("name")
            params = {
                "employer_id": emp_id,
                "order_by": "publication_time",
                "per_page": 20,
            }
            found_by_name = False
        else:
            emp_id = None
            emp_name = None
            params = {
                "text": query,
                "search_field": "company_name",
                "order_by": "publication_time",
                "per_page": 20,
            }
            found_by_name = True

        try:
            if self._client is not None:
                resp = await self._client.get(url, params=params, headers=headers)
            else:
                async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
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
        roles: list[str] = []
        leadership_roles: list[str] = []
        tech_stack: list[str] = []
        it_count = 0

        for v in items:
            name_val = str(v.get("name") or "").strip()
            if not name_val:
                continue
            roles.append(name_val)
            name_lower = name_val.lower()

            if any(re.search(pat, name_lower) for pat in _LEADERSHIP_PATTERNS):
                if name_val not in leadership_roles:
                    leadership_roles.append(name_val)

            if any(k in name_lower for k in _IT_ROLE_KEYWORDS):
                it_count += 1

            snippet = v.get("snippet") or {}
            full_text = f"{name_lower} {str(snippet.get('requirement') or '')} {str(snippet.get('responsibility') or '')}".lower()
            for needles, label in _TECH_KEYWORDS:
                if any(re.search(r"\b" + re.escape(n) + r"\b" if len(n) <= 3 else re.escape(n), full_text) for n in needles):
                    if label not in tech_stack:
                        tech_stack.append(label)

        it_investing = (it_count >= 2) or (it_count >= 1 and len(items) <= 3)
        ledger.record(service, method, "ok" if items else "empty")
        log.info("hh.vacancies", name=query, employer_id=emp_id, found=len(items),
                 leadership=len(leadership_roles), tech_count=len(tech_stack))

        return HiringInfo(
            open_vacancies=data.get("found", len(items)),
            roles=roles,
            leadership_roles=leadership_roles,
            tech_stack=tech_stack,
            it_investing=it_investing,
            found_by_name=found_by_name,
            employer_id=emp_id,
            employer_name=emp_name,
        )
