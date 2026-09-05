"""Тесты проверки ИНН.

Чистая функция без сети — тесты идут офлайн, мгновенно и всегда одинаково.
Тот же принцип позже распространим на реальные источники через respx.
"""

import pytest

from osint_mcp.tools.inn import validate_inn

# Реальные действующие ИНН
SBERBANK = "7707083893"   # ПАО Сбербанк, 10 знаков
BPMSOFT = "7724744134"    # БПМСофт, 10 знаков
INDIVIDUAL = "500100732259"  # 12 знаков, физлицо


@pytest.mark.parametrize("inn", [SBERBANK, BPMSOFT])
def test_valid_legal_entity(inn):
    r = validate_inn(inn)
    assert r.valid is True
    assert r.kind == "legal_entity"
    assert r.reason is None


def test_valid_individual():
    r = validate_inn(INDIVIDUAL)
    assert r.valid is True
    assert r.kind == "individual"


def test_typo_is_rejected():
    """Одна изменённая цифра должна ломать контрольную сумму."""
    broken = SBERBANK[:-1] + ("4" if SBERBANK[-1] != "4" else "5")
    r = validate_inn(broken)
    assert r.valid is False
    assert r.reason is not None


def test_wrong_length():
    r = validate_inn("12345")
    assert r.valid is False
    assert r.kind == "unknown"
    assert "10" in r.reason and "12" in r.reason


def test_non_digits():
    r = validate_inn("77О7083893")  # русская О вместо нуля
    assert r.valid is False
    assert r.kind == "unknown"


def test_empty():
    assert validate_inn("   ").valid is False


def test_whitespace_and_dashes_are_tolerated():
    r = validate_inn(" 7707-0838-93 ")
    assert r.valid is True
    assert r.inn == SBERBANK   # нормализованный вид


def test_invalid_result_is_data_not_exception():
    """Некорректный ИНН — обычный результат. Агент должен уметь его прочитать."""
    r = validate_inn("7707083899")   # верная длина, битая контрольная сумма
    assert r.valid is False
    assert isinstance(r.reason, str) and r.reason


def test_checksum_does_not_prove_existence():
    """Граница возможностей инструмента, зафиксированная намеренно.

    Строка из нулей проходит контрольную сумму: взвешенная сумма равна нулю,
    и контрольный разряд тоже ноль. Это не дефект алгоритма — проверка
    математическая, она отсекает опечатки, но не подтверждает, что
    организация с таким ИНН существует.

    Существование проверяется обращением к реестру на следующем этапе.
    """
    assert validate_inn("0000000000").valid is True
