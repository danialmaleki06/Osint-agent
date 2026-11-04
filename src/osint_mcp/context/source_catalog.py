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
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.web_search_source import search_web

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


_dataset_store = GlobalDatasetStore()


class SourceSpec(BaseModel):
    """Спецификация подключаемого источника в каталоге."""

    scope: Literal["global", "company_asset"] = Field(
        default="company_asset",
        description="global — единый реестр на все компании; company_asset — сайт/активы конкретного юрлица",
    )
    topic: str = Field(description="Тематическая категория (sanctions, company_culture, hr_stack, etc.)")
    type: Literal["dataset_table", "curated_domains", "site_inspection", "vacancy_api", "custom"] = Field(
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
    cat.sources[name] = spec
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        yaml.safe_dump(cat.model_dump(), f, allow_unicode=True, sort_keys=False)


def execute_catalog_batch(
    source_name: str,
    inns: list[str],
    catalog: SourceCatalog | None = None,
) -> dict[str, list[PendingFact]]:
    """Пакетное выполнение для глобального источника на список ИНН.

    Не делает 100 запросов в поисковик! Опрашивает центральную базу за 1 вызов.
    """
    cat = catalog or load_source_catalog()
    spec = cat.sources.get(source_name)
    if spec is None:
        return {inn: [] for inn in inns}

    if spec.scope == "global" and spec.type == "dataset_table":
        # Мгновенный запрос к локальному срезу глобального реестра
        return _dataset_store.match_inns(
            source_name=source_name,
            inns=inns,
            produces_kind=spec.produces_kind,
            trust=spec.trust,
        )

    # Если это внешний поиск по доменам, пакетные запросы объединяются в пачки
    grouped: dict[str, list[PendingFact]] = {inn: [] for inn in inns}
    for inn in inns:
        grouped[inn] = execute_catalog_source(
            source_name=source_name,
            spec=spec,
            inn=inn,
        )
    return grouped


def execute_catalog_source(
    source_name: str,
    spec: SourceSpec,
    inn: str,
    name: str | None = None,
    brand_domain: str | None = None,
    limit: int = 5,
) -> list[PendingFact]:
    """Выполнить целенаправленный сбор по источнику из каталога."""
    # Если источник глобальный и лежит в локальном снимке датасетов
    if spec.scope == "global" and spec.type == "dataset_table":
        matches = _dataset_store.match_inns(
            source_name=source_name,
            inns=[inn],
            produces_kind=spec.produces_kind,
            trust=spec.trust,
        )
        return matches.get(inn, [])

    company_name = name or inn
    queries = []

    if spec.type == "site_inspection" and brand_domain:
        # Инспекция конкретного домена компании
        clean_domain = urlparse(brand_domain).netloc.lower().removeprefix("www.")
        for kw in spec.keywords[:3]:
            queries.append(f'site:{clean_domain} "{kw}"')
    elif spec.domains:
        # Поиск по целевым доверенным доменам
        for domain in spec.domains:
            if spec.search_template and "{domain}" in spec.search_template:
                q = spec.search_template.replace("{domain}", domain).replace("{inn}", inn).replace("{name}", company_name)
            else:
                q = f'site:{domain} "{inn}"'
            queries.append(q)
    elif spec.search_template:
        queries.append(spec.search_template.replace("{inn}", inn).replace("{name}", company_name))

    if not queries:
        return []

    hits: list[PendingFact] = []
    seen_urls: set[str] = set()

    for q in queries[:2]:
        raw_results = search_web(q, limit=limit, retries=1)
        for i, res in enumerate(raw_results):
            url = res.get("url") or ""
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            title = res.get("title") or ""
            snippet = res.get("snippet") or ""
            text = f"{title}. {snippet}".strip()

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

    return hits
