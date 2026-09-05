"""Проверка ИНН по контрольной сумме.

Чистая функция: без сети, без ключей, без внешних зависимостей.
Нужна в проде — отсекает опечатки до обращения к платным API
и тем самым экономит квоту (у Checko на бесплатном тарифе 100 запросов в сутки).

Алгоритм: последняя цифра 10-значного ИНН и две последние цифры
12-значного вычисляются из предыдущих по фиксированным весам.
"""

from osint_mcp.models import InnCheck

# Веса контрольных разрядов, закреплённые порядком ФНС
_W10 = (2, 4, 10, 3, 5, 9, 4, 6, 8)
_W11 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
_W12 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)


def _control_digit(digits: list[int], weights: tuple[int, ...]) -> int:
    """Контрольная цифра: взвешенная сумма по модулю 11, затем по модулю 10."""
    return sum(d * w for d, w in zip(digits, weights)) % 11 % 10


def validate_inn(inn: str) -> InnCheck:
    """Проверить ИНН по контрольной сумме."""
    raw = inn.strip()
    normalized = raw.replace(" ", "").replace("-", "")

    if not normalized:
        return InnCheck(inn=raw, valid=False, kind="unknown",
                        reason="Пустая строка")

    if not normalized.isdigit():
        return InnCheck(inn=raw, valid=False, kind="unknown",
                        reason="ИНН должен состоять только из цифр")

    digits = [int(c) for c in normalized]

    if len(digits) == 10:
        expected = _control_digit(digits[:9], _W10)
        if digits[9] != expected:
            return InnCheck(inn=raw, valid=False, kind="legal_entity",
                            reason="Не сходится контрольная сумма — вероятна опечатка")
        return InnCheck(inn=normalized, valid=True, kind="legal_entity")

    if len(digits) == 12:
        if digits[10] != _control_digit(digits[:10], _W11):
            return InnCheck(inn=raw, valid=False, kind="individual",
                            reason="Не сходится 11-й контрольный разряд")
        if digits[11] != _control_digit(digits[:11], _W12):
            return InnCheck(inn=raw, valid=False, kind="individual",
                            reason="Не сходится 12-й контрольный разряд")
        return InnCheck(inn=normalized, valid=True, kind="individual")

    return InnCheck(
        inn=raw,
        valid=False,
        kind="unknown",
        reason=(
            f"Длина {len(digits)} знаков. Допустимо 10 (организация) "
            f"или 12 (ИП либо физлицо)"
        ),
    )
