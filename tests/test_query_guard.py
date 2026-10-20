from osint_mcp.models import CompanyContext
from osint_mcp.tools.query_guard import (
    extract_inn_and_name,
    calculate_name_similarity,
    check_query_inn_consistency,
    build_discrepancy_fact,
)


def test_extract_inn_and_name():
    inn, name = extract_inn_and_name("ООО «ПСО «Казань» (ИНН 1655065057)")
    assert inn == "1655065057"
    assert name == "ООО «ПСО «Казань»"

    inn2, name2 = extract_inn_and_name("7724744134")
    assert inn2 == "7724744134"
    assert name2 is None

    inn3, name3 = extract_inn_and_name("Яндекс")
    assert inn3 is None
    assert name3 == "Яндекс"


def test_calculate_name_similarity_match():
    ctx = CompanyContext(
        inn="7724744134",
        name_legal='ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ "БПМСОФТ"',
        name_short='ООО "БПМСОФТ"',
        brand="BPMSOFT",
    )
    sim, _, _ = calculate_name_similarity("ООО БПМСофт", ctx)
    assert sim >= 0.8


def test_check_query_inn_consistency_detects_mismatch():
    ctx = CompanyContext(
        inn="1655065057",
        name_legal='УПРАВЛЕНИЕ ФЕДЕРАЛЬНОЙ СЛУЖБЫ ПО НАДЗОРУ В СФЕРЕ ЗАЩИТЫ ПРАВ ПОТРЕБИТЕЛЕЙ ПО РТ',
        name_short='УПРАВЛЕНИЕ РОСПОТРЕБНАДЗОРА ПО РЕСПУБЛИКЕ ТАТАРСТАН',
    )
    res = check_query_inn_consistency("ООО «ПСО «Казань» (ИНН 1655065057)", ctx)
    assert res is not None
    assert res["критичность"] == "high"
    assert "КРИТИЧЕСКОЕ РАСХОЖДЕНИЕ" in res["предупреждение"]
    assert res["коэффициент_сходства"] < 0.2

    fact = build_discrepancy_fact(res)
    assert fact.fact_id == "RISK-QUERY-NAME-MISMATCH"
    assert fact.kind == "registry"
    assert fact.payload["критичность"] == "high"
    assert fact.retrieved_at is not None
