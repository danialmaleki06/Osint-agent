"""Каталог подключаемых источников и реестр сигналов.

Позволяет декларативно регистрировать внешние и подключаемые источники данных
(санкции, проверки офиса/культуры, кадровые требования, отзывы).
Вместо свободного поиска в поисковике запросы выполняются адресно и структурированно,
генерируя стандартизированные ExtFact или PendingFact.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

from osint_mcp.models import ExtFact
from osint_mcp.scoring.models import PendingFact
from osint_mcp.tools.web_search_source import search_web

_SOURCES_CATALOG_PATH = Path(__file__).parent.parent / "config_data" / "sources.yaml"


class SourceSpec(BaseModel):
    """Спецификация подключаемого источника в каталоге."""

    topic: str = Field(description="Тематическая категория (sanctions, company_culture, hr_stack, etc.)")
    type: Literal["curated_domains", "site_inspection", "vacancy_api", "custom"] = Field(
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


def execute_catalog_source(
    source_name: str,
    spec: SourceSpec,
    inn: str,
    name: str | None = None,
    brand_domain: str | None = None,
    limit: int = 5,
) -> list[PendingFact]:
    """Выполнить целенаправленный сбор по источнику из каталога.

    Вместо слепого поиска по всему интернету формирует точечный запрос:
    - по целевым доверенным доменам (site:domain)
    - либо по официальному сайту компании (если проверяется сайт/офис)
    Возвращает стандартизированные находки (PendingFact) с указанием source_url и kind.
    """
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

    # Запускаем целевые запросы
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

            # Фильтрация по ключевым словам, если они заданы
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
                    found_at=datetime.now(timezone.utc),
                )
            )

    return hits
