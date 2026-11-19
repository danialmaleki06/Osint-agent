"""Каталог подключаемых источников и реестр сигналов.

Позволяет декларативно регистрировать внешние и подключаемые источники данных
(санкции, проверки офиса/культуры, кадровые требования, отзывы).

Поддерживает два режима (scope):
1. 'global' — централизованные датасеты/реестры.
   При проверке 100 компаний такой источник не делает 100 запросов в интернет,
   а выполняет 1 быстрый пакетный поиск по локальной базе или единому реестру.
2. 'company_asset' — точечные проверки индивидуальных ресурсов компании
   (официальный сайт, корпоративные правила, вакансии).
"""

import sqlite3
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.names import core_name
from osint_mcp.tools.web_search_source import SearchUnavailable, search_web

_SOURCES_CATALOG_PATH = Path(__file__).parent.parent / "config_data" / "sources.yaml"
_GLOBAL_DATASET_DB = Path(__file__).parent.parent / "config_data" / "global_datasets.db"

_DATASET_SCHEMA = """
CREATE TABLE IF NOT EXISTS global_registry_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT NOT NULL,
    subject_inn TEXT NOT NULL,
    statement   TEXT NOT NULL,
    source_url  TEXT NOT NULL,
    payload_json TEXT,
    created_at  TEXT NOT NULL,
    UNIQUE(source_name, subject_inn, source_url)
);
CREATE INDEX IF NOT EXISTS idx_registry_lookup ON global_registry_entries(source_name, subject_inn);
"""


class GlobalDatasetStore:
    """Хранилище снимков глобальных датасетов и реестров.

    Позволяет мгновенно проверять пачки из 100+ ИНН по единой базе
    за несколько миллисекунд без повторных веб-запросов.
    """

    def __init__(self, path: Path | str = _GLOBAL_DATASET_DB) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DATASET_SCHEMA)

    def add_entries(
        self,
        source_name: str,
        entries: list[dict],
    ) -> int:
        now = datetime.now(UTC).isoformat()
        rows = [
            (
                source_name,
                e.get("inn", ""),
                e.get("statement", ""),
                e.get("source_url", ""),
                e.get("payload_json", "{}"),
                now,
            )
            for e in entries
            if e.get("inn")
        ]
        cur = self._conn.executemany(
            "INSERT OR IGNORE INTO global_registry_entries "
            "(source_name, subject_inn, statement, source_url, payload_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()
        return cur.rowcount

    def match_inns(
        self,
        source_name: str,
        inns: list[str],
        produces_kind: str,
        trust: str = "reference",
    ) -> dict[str, list[PendingFact]]:
        """Пакетный поиск по единому глобальному реестру для списка ИНН."""
        if not inns:
            return {}
        placeholders = ",".join("?" for _ in inns)
        cur = self._conn.execute(
            f"SELECT subject_inn, statement, source_url, created_at "
            f"FROM global_registry_entries "
            f"WHERE source_name=? AND subject_inn IN ({placeholders})",
            [source_name, *inns],
        )
        grouped: dict[str, list[PendingFact]] = {inn: [] for inn in inns}
        for r in cur.fetchall():
            inn = r["subject_inn"]
            fact_id = f"GLB-{produces_kind[:4].upper()}-{len(grouped[inn]) + 1}"
            grouped[inn].append(
                PendingFact(
                    fact_id=fact_id,
                    kind=produces_kind,
                    statement=r["statement"],
                    source_url=r["source_url"],
                    found_by=f"global_dataset:{source_name}",
                    trust=trust if trust in ("reference", "mention") else "mention",
                    found_at=datetime.fromisoformat(r["created_at"]),
                )
            )
        return grouped

    def has_entries(self, source_name: str) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM global_registry_entries WHERE source_name=? LIMIT 1",
            (source_name,),
        ).fetchone() is not None


_dataset_store = GlobalDatasetStore()


def dataset_has_entries(source_name: str) -> bool:
    return _dataset_store.has_entries(source_name)


class SourceSpec(BaseModel):
    """Спецификация подключаемого источника в каталоге."""

    scope: Literal["global", "company_asset"] = Field(
        default="company_asset",
        description="global — единый реестр на все компании; company_asset — сайт/активы конкретного юрлица",
    )
    topic: str = Field(description="Тематическая категория (sanctions, company_culture, hr_stack, etc.)")
    type: Literal["dataset_table", "official_sanctions", "official_erknm_plan", "official_erknm_month",
                  "curated_domains", "site_inspection", "vacancy_api", "custom"] = Field(
        default="curated_domains",
        description="Тип адаптера источника",
    )
    trust: Literal["registry", "reference", "mention"] = Field(
        default="mention",
        description="Уровень доверия к полученным фактам",
    )
    description: str = Field(default="", description="Описание источника")
    produces_kind: str = Field(description="Вид факта ExtFact.kind (например, international_sanction)")
    domains: list[str] = Field(default_factory=list, description="Целевые домены для точечного поиска")
    search_template: str = Field(default="", description="Шаблон целевого поискового запроса")
    keywords: list[str] = Field(default_factory=list, description="Ключевые слова для фильтрации")


class SourceCatalog(BaseModel):
    """Каталог источников."""

    sources: dict[str, SourceSpec] = Field(default_factory=dict)


def load_source_catalog(path: Path | None = None) -> SourceCatalog:
    """Загрузить каталог источников из YAML."""
    p = path or _SOURCES_CATALOG_PATH
    if not p.exists():
        return SourceCatalog()
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return SourceCatalog(**data)


def save_source_to_catalog(
    name: str,
    spec: SourceSpec,
    path: Path | None = None,
) -> None:
    """Сохранить новый источник в YAML каталога."""
    p = path or _SOURCES_CATALOG_PATH
    cat = load_source_catalog(p)
    current = cat.sources.get(name)
    if current and current.type.startswith("official_"):
        raise ValueError("Встроенный официальный источник нельзя заменить пользовательским")
    cat.sources[name] = spec
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        yaml.safe_dump(cat.model_dump(), f, allow_unicode=True, sort_keys=False)


@dataclass
class CatalogScan:
    hits: list[PendingFact]
    succeeded: int = 0
    failed: int = 0
    config_error: str | None = None

    @property
    def status(self) -> Literal["unavailable", "partial", "ok"]:
        if self.config_error:
            return "unavailable"
        if self.failed:
            return "partial" if self.succeeded else "unavailable"
        return "ok"

    @property
    def failure_note(self) -> str | None:
        if self.config_error:
            return self.config_error
        if self.failed:
            return f"Выполнено веб-запросов: {self.succeeded}, не ответили: {self.failed}."
        return None


def execute_catalog_batch(
    source_name: str,
    inns: list[str],
    catalog: SourceCatalog | None = None,
) -> dict[str, CatalogScan]:
    """Пакетное выполнение для глобального источника на список ИНН.

    Не делает 100 запросов в поисковик! Опрашивает центральную базу за 1 вызов.
    """
    cat = catalog or load_source_catalog()
    spec = cat.sources.get(source_name)
    if spec is None:
        return {inn: CatalogScan([], config_error="Источник отсутствует в каталоге.") for inn in inns}

    if spec.scope == "global" and spec.type == "dataset_table":
        # Мгновенный запрос к локальному срезу глобального реестра
        matches = _dataset_store.match_inns(
            source_name=source_name,
            inns=inns,
            produces_kind=spec.produces_kind,
            trust=spec.trust,
        )
        return {inn: CatalogScan(hits) for inn, hits in matches.items()}

    # Если это внешний поиск по доменам, пакетные запросы объединяются в пачки
    return {
        inn: execute_catalog_source(
            source_name=source_name,
            spec=spec,
            inn=inn,
        )
        for inn in dict.fromkeys(inns)
    }


def execute_catalog_source(
    source_name: str,
    spec: SourceSpec,
    inn: str,
    name: str | None = None,
    brand_domain: str | None = None,
    limit: int = 5,
) -> CatalogScan:
    """Выполнить целенаправленный сбор по источнику из каталога."""
    if spec.type.startswith("official_"):
        raise ValueError("Для официального реестра требуется асинхронная загрузка выгрузки")
    # Если источник глобальный и лежит в локальном снимке датасетов
    if spec.scope == "global" and spec.type == "dataset_table":
        matches = _dataset_store.match_inns(
            source_name=source_name,
            inns=[inn],
            produces_kind=spec.produces_kind,
            trust=spec.trust,
        )
        return CatalogScan(matches.get(inn, []))

    company_name = name or inn
    company_token = core_name(name)
    queries = []

    if spec.type == "site_inspection" and brand_domain:
        # Инспекция конкретного домена компании
        url = brand_domain if "://" in brand_domain else f"//{brand_domain}"
        clean_domain = (urlparse(url).hostname or "").removeprefix("www.")
        if clean_domain:
            queries.extend(f'site:{clean_domain} "{kw}"' for kw in spec.keywords[:3])
    elif spec.domains:
        # Поиск по целевым доверенным доменам
        for domain in spec.domains:
            if spec.search_template:
                q = spec.search_template.replace("{domain}", domain).replace("{inn}", inn).replace("{name}", company_name)
                if "{domain}" not in spec.search_template:
                    q = f"site:{domain} {q}"
            else:
                q = f'site:{domain} "{inn}"'
            queries.append(q)
    elif spec.search_template:
        queries.append(spec.search_template.replace("{inn}", inn).replace("{name}", company_name))

    if not queries:
        return CatalogScan([], config_error="Для источника не настроены поисковые запросы.")

    hits: list[PendingFact] = []
    seen_urls: set[str] = set()
    scan = CatalogScan(hits)

    for q in dict.fromkeys(queries):
        try:
            raw_results = search_web(q, limit=limit, retries=1, raise_on_unavailable=True)
        except SearchUnavailable:
            scan.failed += 1
            continue
        scan.succeeded += 1
        for res in raw_results:
            url = res.get("url") or ""
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            title = res.get("title") or ""
            snippet = res.get("snippet") or ""
            text = f"{title}. {snippet}".strip()
            host = (urlparse(url).hostname or "").removeprefix("www.").lower()
            if spec.domains and not any(
                host == domain.lower() or host.endswith("." + domain.lower()) for domain in spec.domains
            ):
                continue
            if spec.topic == "hr_stack":
                path = urlparse(url).path
                if ("/resume/" in path or (host == "career.habr.com" and not path.startswith("/vacancies/"))):
                    continue
            # Search engines may relax exact queries and return a generic
            # registry page. A keyword alone never ties that page to the company.
            brand_host = urlparse(brand_domain if brand_domain and "://" in brand_domain
                                  else f"//{brand_domain or ''}").hostname or ""
            own_site = bool(brand_host and (host == brand_host or host.endswith("." + brand_host)))
            tokens = [inn]
            if company_token:
                tokens.append(company_token)
            if brand_host:
                tokens.append(brand_host.removeprefix("www.").split(".")[0])
            evidence = f"{title} {snippet} {url}".casefold()
            if not own_site and not any(
                re.search(rf"(?<!\w){re.escape(token.casefold())}(?!\w)", evidence) for token in tokens if token
            ):
                continue

            if spec.keywords:
                matched_kw = [kw for kw in spec.keywords if kw.lower() in text.lower()]
                if not matched_kw:
                    continue

            fact_id = f"SRC-{spec.produces_kind[:4].upper()}-{len(hits) + 1}"
            hits.append(
                PendingFact(
                    fact_id=fact_id,
                    kind=spec.produces_kind,
                    statement=text or f"Найдено совпадение в {url}",
                    source_url=url,
                    found_by=f"catalog:{source_name}",
                    trust=spec.trust if spec.trust in ("reference", "mention") else "mention",
                    found_at=datetime.now(UTC),
                )
            )

    return scan
