"""Определение страны по идентификатору организации.

Справочные сервисы, которыми мы пользуемся, покрывают разные страны:
реестровые сведения доступны по России, Беларуси и Казахстану, а проверки
рисков — только по России.

Без определения страны контрагент из Казахстана дал бы пустой результат,
неотличимый от «нарушений нет». Это тот же класс ошибки, что и молчащий
источник, поэтому страна определяется явно, а неподдерживаемая —
сообщается прямо.

Идентификаторы:
  Россия     ИНН  10 знаков (организация) либо 12 (ИП, физлицо)
  Беларусь   УНП   9 знаков
  Казахстан  БИН  12 знаков (организация), ИИН 12 (физлицо)

Сложность в том, что российский ИНН физлица и казахстанский БИН —
оба двенадцатизначные. Различаются контрольными суммами, поэтому
проверяются обе.
"""

import re
from typing import Literal

from pydantic import BaseModel, Field

from osint_mcp.tools.inn import validate_inn

Country = Literal["RU", "BY", "KZ", "unknown"]

# Весовые коэффициенты контрольных разрядов
_BY_WEIGHTS = (29, 23, 19, 17, 13, 7, 5, 3)
_KZ_WEIGHTS_1 = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
_KZ_WEIGHTS_2 = (3, 4, 5, 6, 7, 8, 9, 10, 11, 1, 2)


class CountryGuess(BaseModel):
    """Какой стране принадлежит идентификатор."""

    identifier: str = Field(description="Идентификатор в нормализованном виде")
    country: Country = Field(
        description=(
            "RU — Россия, ИНН; BY — Беларусь, УНП; KZ — Казахстан, БИН или ИИН; "
            "unknown — формат не опознан"
        )
    )
    id_type: str | None = Field(default=None, description="Название идентификатора")
    registry_supported: bool = Field(
        description="Доступны ли реестровые сведения по этой стране"
    )
    risk_checks_supported: bool = Field(
        description=(
            "Доступны ли проверки рисков: суды, банкротство, приставы, закупки. "
            "Только по России"
        )
    )
    note: str | None = Field(
        default=None, description="Пояснение для агента, если поддержка неполная"
    )


def _normalize(value: str) -> str:
    return re.sub(r"[\s\-]", "", value.strip())


def is_valid_unp(value: str) -> bool:
    """Проверить белорусский УНП по контрольному разряду."""
    if len(value) != 9 or not value.isdigit():
        return False
    digits = [int(c) for c in value]
    control = sum(d * w for d, w in zip(digits[:8], _BY_WEIGHTS)) % 11
    return control != 10 and control == digits[8]


def is_valid_bin(value: str) -> bool:
    """Проверить казахстанский БИН или ИИН по контрольному разряду."""
    if len(value) != 12 or not value.isdigit():
        return False
    digits = [int(c) for c in value]

    control = sum(d * w for d, w in zip(digits[:11], _KZ_WEIGHTS_1)) % 11
    if control == 10:
        control = sum(d * w for d, w in zip(digits[:11], _KZ_WEIGHTS_2)) % 11
        if control == 10:
            return False
    return control == digits[11]


def detect_country(identifier: str) -> CountryGuess:
    """Определить страну по идентификатору организации.

    Сначала проверяется российский ИНН: он для нас основной, и его
    контрольная сумма отличается от казахстанской. Двенадцатизначный
    номер, не прошедший российскую проверку, проверяется как БИН.
    """
    value = _normalize(identifier)

    if not value.isdigit():
        return CountryGuess(
            identifier=value, country="unknown",
            registry_supported=False, risk_checks_supported=False,
            note="Идентификатор должен состоять из цифр.",
        )

    inn = validate_inn(value)
    if inn.valid:
        return CountryGuess(
            identifier=value, country="RU", id_type="ИНН",
            registry_supported=True, risk_checks_supported=True,
        )

    if len(value) == 9 and is_valid_unp(value):
        return CountryGuess(
            identifier=value, country="BY", id_type="УНП",
            registry_supported=True, risk_checks_supported=False,
            note=("Организация из Беларуси. Реестровые сведения доступны, "
                  "проверки судов, банкротства, приставов и закупок — НЕТ. "
                  "Не сообщай об отсутствии рисков: они просто не проверялись."),
        )

    if len(value) == 12 and is_valid_bin(value):
        return CountryGuess(
            identifier=value, country="KZ", id_type="БИН",
            registry_supported=True, risk_checks_supported=False,
            note=("Организация из Казахстана. Реестровые сведения доступны, "
                  "проверки судов, банкротства, приставов и закупок — НЕТ. "
                  "Не сообщай об отсутствии рисков: они просто не проверялись."),
        )

    # Длина подходит под российский ИНН, но проверка не прошла — назвать
    # конкретную причину полезнее, чем общее «формат не опознан»
    if len(value) in (10, 12) and inn.reason:
        note = (f"Номер не прошёл проверку: {inn.reason}. "
                f"Проверено также как УНП Беларуси и БИН Казахстана — "
                f"не подошло. Запроси у пользователя правильный номер.")
    else:
        note = (f"Формат идентификатора ({len(value)} знаков) не соответствует "
                f"ни ИНН России (10 или 12), ни УНП Беларуси (9), "
                f"ни БИН Казахстана (12). Запроси уточнение.")

    return CountryGuess(
        identifier=value, country="unknown",
        registry_supported=False, risk_checks_supported=False,
        note=note,
    )
