"""Отраслевая лексика по коду ОКВЭД.

Обычный словарь из YAML: бесплатно, мгновенно, воспроизводимо, правится
руками. Модель для такого преобразования не нужна.
"""

from functools import lru_cache
from pathlib import Path

import yaml

_TABLE_PATH = Path(__file__).parent.parent / "config_data" / "okved_terms.yaml"


@lru_cache(maxsize=1)
def _table() -> dict[str, list[str]]:
    with _TABLE_PATH.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def industry_terms(okved_code: str | None) -> list[str]:
    """Слова, которыми отрасль называют в прессе.

    >>> industry_terms("41.20")
    ['застройщик', 'строительная компания', 'девелопер', 'подрядчик']
    """
    if not okved_code:
        return []
    group = okved_code.strip()[:2]
    return list(_table().get(group, []))
