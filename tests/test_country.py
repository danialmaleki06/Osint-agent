"""Тесты определения страны по идентификатору организации.

Смысл проверки: справочные сервисы покрывают разные страны. Реестровые
сведения доступны по России, Беларуси и Казахстану, а проверки рисков —
только по России. Без определения страны контрагент из Казахстана дал бы
пустой результат, неотличимый от «нарушений не найдено».
"""

import pytest

from osint_mcp.tools.country import detect_country, is_valid_bin, is_valid_unp
from osint_mcp.tools.risk import collect_risk_facts

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


# Идентификаторы взяты из справочников сервиса, не выдуманы
RU = ["7724744134", "7707083893"]                 # БПМСОФТ, Сбербанк
BY = ["100041649", "807000028", "191309167"]      # АББ, Белинвестбанк, БАНКАР
KZ = ["931040001411", "930440000156", "971040000210"]   # банки Казахстана


@pytest.mark.parametrize("ident", RU)
def test_russian_inn(ident):
    g = detect_country(ident)
    assert g.country == "RU"
    assert g.registry_supported and g.risk_checks_supported


@pytest.mark.parametrize("ident", BY)
def test_belarus_unp(ident):
    g = detect_country(ident)
    assert g.country == "BY"
    assert g.id_type == "УНП"
    assert g.registry_supported
    assert not g.risk_checks_supported          # проверок рисков нет
    assert "не проверялись" in g.note


@pytest.mark.parametrize("ident", KZ)
def test_kazakhstan_bin(ident):
    g = detect_country(ident)
    assert g.country == "KZ"
    assert g.id_type == "БИН"
    assert g.registry_supported
    assert not g.risk_checks_supported
    assert "не проверялись" in g.note


def test_twelve_digit_ambiguity_resolves_to_russia():
    """ИНН физлица РФ и БИН Казахстана — оба 12-значные.

    Различаются контрольными суммами. Российская проверка идёт первой,
    поскольку это основной случай.
    """
    g = detect_country("500100732259")            # действующий ИНН физлица
    assert g.country == "RU"


def test_broken_checksum_names_the_reason():
    """Сообщение должно называть причину, а не отделываться «формат не опознан»."""
    g = detect_country("7707083899")
    assert g.country == "unknown"
    assert "контрольная сумма" in g.note.lower()


def test_unknown_length_lists_expected_formats():
    g = detect_country("12345")
    assert g.country == "unknown"
    assert "9" in g.note and "10" in g.note      # перечислены допустимые длины


def test_non_digits_rejected():
    assert detect_country("АБВ123").country == "unknown"


def test_separators_are_tolerated():
    assert detect_country(" 7724-744-134 ").country == "RU"


# ───────────────────  контрольные суммы по отдельности  ───────────────────

def test_unp_checksum_rejects_corruption():
    assert is_valid_unp("100041649")
    assert not is_valid_unp("100041640")          # изменён контрольный разряд


def test_bin_checksum_rejects_corruption():
    assert is_valid_bin("931040001411")
    assert not is_valid_bin("931040001412")


# ───────────────────  главное: защита от ложного «чисто»  ───────────────────

@pytest.mark.parametrize("ident,country", [(BY[0], "Беларуси"), (KZ[0], "Казахстана")])
async def test_risk_check_refuses_foreign_instead_of_returning_empty(ident, country):
    """Пустой результат по иностранной организации недопустим.

    Источников проверки рисков по Беларуси и Казахстану нет. Вернуть
    пустой список означало бы сообщить «нарушений не найдено» — это
    ложноположительное заключение, самая опасная ошибка в системе.
    """
    r = await collect_risk_facts(ident)

    assert r.facts == []
    assert r.coverage_note is not None
    assert country in r.coverage_note
    assert "НЕ ПРОВОДИЛАСЬ" in r.coverage_note
    assert "Не сообщай пользователю об отсутствии рисков" in r.coverage_note
