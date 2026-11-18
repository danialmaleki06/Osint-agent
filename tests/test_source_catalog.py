"""Тесты для каталога подключаемых источников и динамических критериев."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock
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
    assert catalog.sources["international_sanctions"].type == "official_sanctions"
    assert "office_environment" in catalog.sources
    assert catalog.sources["office_environment"].topic == "company_culture"
    assert catalog.sources["office_environment"].produces_kind == "office_environment_signal"


@pytest.mark.asyncio
async def test_empty_dataset_is_reported_as_unavailable(monkeypatch):
    from osint_mcp import server

    def unexpected_registry_request(*args):
        pytest.fail("Локальный снимок не требует вызова реестров")

    monkeypatch.setattr(server, "_build_context", unexpected_registry_request)
    monkeypatch.setattr(server, "_dataset_has_entries", lambda source_name: False)

    inn = "7707083893"
    source = "local_dataset"
    monkeypatch.setattr(server, "_load_source_catalog", lambda: SourceCatalog(sources={source: SourceSpec(
        scope="global", type="dataset_table", topic="test", produces_kind="test",
    )}))
    single = await server.scan_catalog_source(inn, source)
    batch = await server.scan_catalog_batch(source, [inn])

    assert "Проверка недоступна" in single.note
    assert batch["details"][inn]["status"] == "unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize(("successful", "status"), [(False, "unavailable"), (True, "partial")])
async def test_catalog_reports_web_failures(monkeypatch, successful, status):
    from osint_mcp import server
    from osint_mcp.context import source_catalog
    from osint_mcp.models import ContextResult
    from osint_mcp.tools.web_search_source import SearchUnavailable

    inn = "7707083893"
    source = "test_search"
    spec = SourceSpec(topic="test", produces_kind="test", domains=["one.example", "two.example"])
    monkeypatch.setattr(server, "_build_context", AsyncMock(return_value=ContextResult(status="unavailable")))
    monkeypatch.setattr(server, "_load_source_catalog", lambda: SourceCatalog(sources={source: spec}))

    def search(query, *, limit, retries, raise_on_unavailable):
        assert raise_on_unavailable is True
        if successful and "one.example" in query:
            return []
        raise SearchUnavailable("веб-поиск отказал")

    monkeypatch.setattr(source_catalog, "search_web", search)
    single = await server.scan_catalog_source(inn, source)
    batch = await server.scan_catalog_batch(source, [inn])

    assert single.status == status and single.found == 0
    assert batch["status"] == batch["details"][inn]["status"] == status


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


def test_global_dataset_batch_matching(tmp_path):
    """Тест пакетного сопоставления 100 компаний по единому глобальному реестру без повторного веб-поиска."""
    from osint_mcp.context.source_catalog import GlobalDatasetStore

    store = GlobalDatasetStore(tmp_path / "test_global.db")
    store.add_entries(
        source_name="intl_sanctions",
        entries=[
            {
                "inn": "7701000001",
                "statement": "Субъект включён в санкционный список SDN",
                "source_url": "https://sanctions.org/entry/1",
            },
            {
                "inn": "7701000050",
                "statement": "Субъект под блокирующими санкциями ЕС",
                "source_url": "https://sanctions.org/entry/50",
            },
        ],
    )

    # Проверяем пачку из 100 ИНН
    inns_batch = [f"7701{i:06d}" for i in range(1, 101)]
    matches = store.match_inns(
        source_name="intl_sanctions",
        inns=inns_batch,
        produces_kind="international_sanction",
    )

    # Должны мгновенно найтись совпадения по двум ИНН
    assert len(matches["7701000001"]) == 1
    assert matches["7701000001"][0].kind == "international_sanction"
    assert "SDN" in matches["7701000001"][0].statement

    assert len(matches["7701000050"]) == 1
    assert "ЕС" in matches["7701000050"][0].statement

    # По остальным 98 компаниям результат чистый
    assert len(matches["7701000002"]) == 0
    assert len(matches["7701000100"]) == 0


def test_real_life_batch_quarantine_and_scoring_workflow(tmp_path):
    """Реальный кейс: пакетная проверка 10 компаний на международные санкции.
    
    1. Глобальный датасет санкций хранит записи.
    2. Пакетная проверка за 1 шаг находит подсанкционную компанию.
    3. Факт попадает в карантин.
    4. Факт подтверждается и обнуляет скоринг компании со стоп-фактором 'не рекомендуется'.
    5. Чистая компания проходит скоринг без штрафов.
    """
    from osint_mcp.context.source_catalog import GlobalDatasetStore
    from osint_mcp.tools.quarantine import QuarantineStore
    from osint_mcp.models import CompanyContext

    db_path = tmp_path / "case_global.db"
    store = GlobalDatasetStore(db_path)
    store.add_entries(
        source_name="international_sanctions",
        entries=[
            {
                "inn": "7703807270",
                "statement": "ООО Новые Облачные Технологии включено в санкционный список SDN OFAC",
                "source_url": "https://sanctionssearch.ofac.treas.gov/Details.aspx?id=45120",
            }
        ],
    )

    q_store = QuarantineStore(tmp_path / "case_quarantine.db")

    # 10 компаний в пакете
    batch_inns = ["7703807270"] + [f"770200000{i}" for i in range(1, 10)]
    
    # 1 пакетный вызов к реестру
    matches = store.match_inns(
        source_name="international_sanctions",
        inns=batch_inns,
        produces_kind="international_sanction",
        trust="reference",
    )

    # Чистые компании не получают находок
    assert len(matches["7702000001"]) == 0
    clean_score = score_company(
        facts=[],
        context=CompanyContext(inn="7702000001", name_legal="ООО Чистая Компания"),
    )
    assert clean_score.verdict.label in ("удовлетворительно", "хорошо")
    assert clean_score.verdict.floored is False

    # Подсанкционная компания найдена
    sanctioned_hits = matches["7703807270"]
    assert len(sanctioned_hits) == 1
    
    # Изолируем в карантин
    added = q_store.add("7703807270", sanctioned_hits)
    assert added == 1

    # Подтверждаем находку в карантине
    confirmed = q_store.confirm(
        "7703807270",
        sanctioned_hits[0].fact_id,
        weight=-90.0,
        confirmed_by="agent",
        rationale="Подтверждено по карточке OFAC",
    )
    assert confirmed is not None

    # Пересчитываем скоринг с подтверждёнными фактами
    confirmed_facts = q_store.confirmed_facts("7703807270")
    bad_score = score_company(
        facts=confirmed_facts,
        context=CompanyContext(inn="7703807270", name_legal="ООО Новые Облачные Технологии"),
    )

    # Проверяем срабатывание жесткого стоп-фактора
    assert bad_score.verdict.label == "не рекомендуется"
    assert bad_score.verdict.floored is True
    assert bad_score.verdict.floor_criterion == "international_sanctions_hit"
    assert any("Международные санкции" in w for w in bad_score.warnings)


def test_real_life_on_the_fly_source_and_dog_criterion(tmp_path):
    """Реальный кейс: подключение на лету источника корпоративной политики и критерия 'собака в офисе'.
    
    1. Пользователь/агент на лету регистрирует источник по корпоративной культуре.
    2. При обнаружении собаки в офисе срабатывает критерий -100 баллов.
    3. Вердикт срезается до 'не рекомендуется', факт попадает в warnings.
    """
    from osint_mcp.context.source_catalog import (
        SourceSpec,
        save_source_to_catalog,
        load_source_catalog,
    )
    from osint_mcp.models import CompanyContext

    catalog_file = tmp_path / "custom_sources.yaml"

    # 1. Регистрация источника на лету
    spec = SourceSpec(
        scope="company_asset",
        topic="pet_policy",
        type="site_inspection",
        trust="mention",
        description="Проверка политики компании в отношении животных в офисе",
        produces_kind="office_environment_signal",
        keywords=["собака в офисе", "pet friendly"],
    )
    save_source_to_catalog("office_pets_rule", spec, path=catalog_file)

    loaded = load_source_catalog(catalog_file)
    assert "office_pets_rule" in loaded.sources

    # 2. Имитация обнаружения сигнала на сайте компании
    detected_fact = ExtFact(
        fact_id="PET-01",
        kind="office_environment_signal",
        statement="На странице 'О нас' компания заявляет: Мы dog-friendly офис, у нас живет офисный лабрадор",
        source_url="https://cool-startup.ru/team",
        source_type="company_asset",
        trust="mention",
        retrieved_at=datetime.now(timezone.utc),
        payload={"keywords": ["dog-friendly", "офисный"]},
    )

    # 3. Скоринг компании
    ctx = CompanyContext(inn="7701234567", name_legal="ООО Стартап", brand_domain="https://cool-startup.ru")
    score_res = score_company(facts=[detected_fact], context=ctx)

    # Должен сработать критерий office_environment_risk со счетом -100 и полом 'не рекомендуется'
    assert score_res.verdict.label == "не рекомендуется"
    assert score_res.verdict.floored is True
    assert score_res.verdict.floor_criterion == "office_environment_risk"
    assert any("Критический стоп-фактор офисной политики" in w for w in score_res.warnings)


