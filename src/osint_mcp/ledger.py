"""Учёт обращений к источникам.

Зачем отдельный учёт, если агент и так видит статусы в каждом ответе:
сложить их за четыре вызова и ничего не потерять — работа, которую
модель выполняет ненадёжно. Ровно по этой причине мы не поручаем ей
считать процессуальные роли. Здесь то же самое: считает код.

Записи привязаны к проверяемой организации, а не к пользователю или
сеансу. Так вопрос «насколько полно проверена вот эта компания»
получает ответ и при удалённой работе, когда один сервер обслуживает
многих агентов сразу.

Текущая организация передаётся через contextvars: низкоуровневый слой
запросов не знает, ради кого его вызвали, а тащить идентификатор через
все сигнатуры — значит переписать половину источников ради учёта.
Задачи, порождённые asyncio.gather, наследуют контекст, поэтому
параллельные проверки записываются правильно.
"""

from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections.abc import Iterator
from typing import Literal

Outcome = Literal["ok", "empty", "failed"]

# Сколько организаций держать в памяти. Записи нужны в пределах разговора;
# накапливать их бесконечно в долгоживущем процессе незачем.
MAX_SUBJECTS = 64

_subject: ContextVar[str | None] = ContextVar("osint_subject", default=None)


@dataclass
class Call:
    """Одно обращение к внешнему источнику."""

    service: str
    method: str
    outcome: Outcome
    reason: str | None = None
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Обращения по организациям и общий счётчик за время жизни процесса.
_calls: dict[str, list[Call]] = {}
_session: dict[str, int] = {}

# Сколько запросов израсходовано по ключу за сутки — по данным самой
# службы. Это не то же самое, что потрачено нами на одну организацию:
# счётчик общий на ключ и включает чужие обращения тем же ключом.
_daily_seen: dict[str, int] = {}


def set_subject(inn: str | None) -> Token[str | None]:
    """Установить организацию и вернуть токен для последующего сброса.

    Предпочтительно использовать ``subject_scope``: он гарантирует сброс
    контекста даже при исключении. Возвращаемый токен оставлен для кода,
    которому нужен ручной контроль жизненного цикла.
    """
    return _subject.set(inn)


@contextmanager
def subject_scope(inn: str | None) -> Iterator[None]:
    """Временно привязать обращения к организации в текущем async-контексте."""
    token = _subject.set(inn)
    try:
        yield
    finally:
        _subject.reset(token)


def record(
    service: str,
    method: str,
    outcome: Outcome,
    reason: str | None = None,
    daily_count: int | None = None,
) -> None:
    """Записать обращение. Вызывается из слоя запросов, не из инструментов."""
    _session[service] = _session.get(service, 0) + 1

    if daily_count is not None:
        _daily_seen[service] = daily_count

    inn = _subject.get()
    if not inn:
        # Обращение вне проверки конкретной организации — например,
        # поиск по названию, когда идентификатор ещё неизвестен.
        return

    bucket = _calls.setdefault(inn, [])
    bucket.append(Call(service=service, method=method, outcome=outcome, reason=reason))

    if len(_calls) > MAX_SUBJECTS:
        # Вытесняем самую старую организацию: dict хранит порядок вставки
        oldest = next(iter(_calls))
        if oldest != inn:
            _calls.pop(oldest, None)


def calls_for(inn: str) -> list[Call]:
    return list(_calls.get(inn, []))


def session_totals() -> dict[str, int]:
    """Сколько запросов сделано с момента запуска сервера, по службам."""
    return dict(_session)


def daily_totals() -> dict[str, int]:
    """Сколько израсходовано по ключу за сутки, по данным самой службы."""
    return dict(_daily_seen)


def reset() -> None:
    """Только для тестов: очистить накопленное."""
    _calls.clear()
    _session.clear()
    _daily_seen.clear()
    _subject.set(None)
