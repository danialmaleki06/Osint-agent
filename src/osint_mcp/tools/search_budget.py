"""A shared, thread-safe upper bound on paid search attempts per dossier."""

from contextlib import contextmanager
from contextvars import ContextVar
from decimal import Decimal
from threading import Lock


class SearchBudgetExceeded(RuntimeError):
    pass


class SearchBudget:
    def __init__(self, rubles: float):
        self.limit = Decimal(str(rubles))
        self.reserved = Decimal(0)
        self.attempts = 0
        self.blocked = 0
        self._protected: dict[str, int] = {}
        self._lock = Lock()

    def reserve(self, rubles: float) -> None:
        price = Decimal(str(rubles))
        with self._lock:
            stage = _stage.get()
            held = sum(count for name, count in self._protected.items() if name != stage)
            if self.reserved + price + Decimal(held) * Decimal("0.488") > self.limit:
                self.blocked += 1
                raise SearchBudgetExceeded("Достигнут лимит расходов на платный поиск")
            self.reserved += price
            self.attempts += 1
            if self._protected.get(stage, 0):
                self._protected[stage] -= 1

    def protect(self, stage: str, attempts: int) -> None:
        with self._lock:
            available = max(0, int((self.limit - self.reserved) / Decimal("0.488")))
            self._protected[stage] = min(attempts, available)

    def release(self, stage: str) -> None:
        with self._lock:
            self._protected.pop(stage, None)

    def snapshot(self) -> dict:
        with self._lock:
            return {"лимит_руб": float(self.limit), "верхняя_оценка_расхода_руб": float(self.reserved),
                    "http_попыток": self.attempts, "отклонено_по_бюджету": self.blocked}


_current: ContextVar[SearchBudget | None] = ContextVar("paid_search_budget", default=None)
_stage: ContextVar[str | None] = ContextVar("paid_search_stage", default=None)
_attempt_limit: ContextVar[int | None] = ContextVar("paid_search_attempt_limit", default=None)


@contextmanager
def protect_yandex_attempts(stage: str, attempts: int):
    budget = _current.get()
    if budget is not None:
        budget.protect(stage, attempts)
    try:
        yield
    finally:
        if budget is not None:
            budget.release(stage)


@contextmanager
def yandex_search_stage(stage: str):
    token = _stage.set(stage)
    try:
        yield
    finally:
        _stage.reset(token)
        budget = _current.get()
        if budget is not None:
            budget.release(stage)


@contextmanager
def yandex_attempt_limit(attempts: int):
    """One worker's first attempt must precede retries of another query."""
    token = _attempt_limit.set(attempts)
    try:
        yield
    finally:
        _attempt_limit.reset(token)


@contextmanager
def search_budget(rubles: float):
    existing = _current.get()
    if existing is not None:
        yield existing
        return
    budget = SearchBudget(rubles)
    token = _current.set(budget)
    try:
        yield budget
    finally:
        _current.reset(token)


def reserve_yandex_attempt() -> None:
    remaining = _attempt_limit.get()
    if remaining is not None:
        if remaining <= 0:
            raise SearchBudgetExceeded("Повтор отложен до первой попытки остальных репутационных проверок")
        _attempt_limit.set(remaining - 1)
    budget = _current.get()
    if budget is not None:
        # Reserve the larger public synchronous RU price, VAT included.
        # Failed, malformed and timed-out responses also consume a slot:
        # billing cannot be inferred safely from a lost response.
        budget.reserve(0.488)
