"""Тесты для каталога подключаемых источников и динамических критериев."""

from datetime import datetime, timezone
import pytest

from osint_mcp.context.source_catalog import (
    SourceCatalog,
    SourceSpec,
    load_source_catalog,
    execute_catalog_source,
)
from osint_mcp.scoring import score_company
from osint_mcp.scoring.engine import CriterionSpec, Match
from osint_mcp.models import ExtFact, Fact


def test_load_source_catalog():
    catalog = load_source_catalog()
    assert "international_sanctions" in catalog.sources
    assert "office_environment" in catalog.sources
    assert catalog.sources["office_environment"].topic == "company_culture"
    assert catalog.sources["office_environment"].produces_kind == "office_environment_signal"


def test_custom_criterion_office_dog_kill_switch():
    """Тест критического стоп-фактора: обнаружение собаки в офисе срезает вердикт на -100."""
    now = datetime.now(timezone.utc)
    dog_fact = ExtFact(
        fact_id="DOG-1",
        kind="office_environment_signal",
        statement="В офисе компании постоянно находится офисный пес и разрешены собаки",
        source_url="https://company.ru/about",
        source_type="custom",
        trust="mention",
        retrieved_at=now,
        payload={"text": "офисный пес"},
    )

    # Запускаем скоринг только с этим фактом
    res = score_company(facts=[dog_fact])

    # Проверяем, что сработал критерий office_environment_risk из scoring.yaml
    matched_names = [m.criterion for m in res.matched]
    assert "office_environment_risk" in matched_names
    assert res.verdict.label == "не рекомендуется"
    assert res.verdict.floored is True
    assert res.verdict.floor_criterion == "office_environment_risk"
    assert any("Критический стоп-фактор офисной политики" in w for w in res.warnings)


def test_dynamic_extra_criteria():
    """Тест динамического добавления правила на лету через extra_criteria."""
    now = datetime.now(timezone.utc)
    special_fact = ExtFact(
        fact_id="CUSTOM-99",
        kind="custom_audit_finding",
        statement="Обнаружено критическое несоответствие регламенту безопасности",
        source_url="https://audit.internal/report",
        source_type="custom",
        trust="reference",
        retrieved_at=now,
        payload={"severity": "critical"},
    )

    extra_rules = {
        "critical_audit_fail": CriterionSpec(
            group="registry_risk",
            description="Критический провал внутреннего аудита",
            match=Match(kind="custom_audit_finding", op="exists"),
            score=-100.0,
            warn_always=True,
            verdict_floor="не рекомендуется",
            reason="Провал аудита безопасности: {statement}",
        )
    }

    res = score_company(facts=[special_fact], extra_criteria=extra_rules)
    assert any(m.criterion == "critical_audit_fail" for m in res.matched)
    assert res.verdict.label == "не рекомендуется"
    assert res.verdict.floored is True
