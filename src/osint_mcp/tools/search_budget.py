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
        self._lock = Lock()

    def reserve(self, rubles: float) -> None:
        price = Decimal(str(rubles))
        with self._lock:
            if self.reserved + price > self.limit:
                self.blocked += 1
                raise SearchBudgetExceeded("Достигнут лимит расходов на платный поиск")
            self.reserved += price
            self.attempts += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {"лимит_руб": float(self.limit), "верхняя_оценка_расхода_руб": float(self.reserved),
                    "http_попыток": self.attempts, "отклонено_по_бюджету": self.blocked}


_current: ContextVar[SearchBudget | None] = ContextVar("paid_search_budget", default=None)


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
    budget = _current.get()
    if budget is not None:
        # Reserve the larger public synchronous RU price, VAT included.
        # Failed, malformed and timed-out responses also consume a slot:
        # billing cannot be inferred safely from a lost response.
        budget.reserve(0.488)
