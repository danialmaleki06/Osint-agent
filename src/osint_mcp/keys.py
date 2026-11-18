"""Пул API-ключей одного справочника.

Суточные лимиты бесплатных тарифов малы, а полная проверка одной
организации расходует десятки обращений. Несколько ключей снимают
потолок: сервис ответил, что лимит исчерпан, — запрос повторяется
со следующим ключом пула, без участия человека и без ложного
«источник недоступен» в досье.

Ключи задаются в .env по одному (DADATA_API_KEY, CHECKO_API_KEY)
или списком через запятую (DADATA_API_KEYS, CHECKO_API_KEYS).
Список перечитывается при каждом обращении: тесты подменяют ключи
через monkeypatch, и пул это видит без пересоздания.

Пометка об исчерпании — не приговор навсегда. Лимит суточный, поэтому
пометка живёт EXHAUST_TTL, после чего ключ снова становится кандидатом:
сервер, пережившей полночь, возвращает ключ в оборот сам. Когда
помечены все, пул пробует первый — пусть сервис ещё раз откажет,
это дешевле, чем пропустить работоспособный ключ.
"""

import time
from collections.abc import Callable, Iterable
from functools import wraps
from threading import RLock
from typing import Any

import structlog

from osint_mcp.config import settings

# Ответы, после которых ключ не годится для следующего запроса:
# 401 — не опознан, 403 — лимит или права, 429 — слишком часто.
ROTATE_STATUS_CODES = {401, 403, 429}


class QuotaExhausted(RuntimeError):
    """Все ключи пула отвергнуты сервисом (401/403/429).

    Наследует RuntimeError: часть кода уже ловит его как «источник
    не смог ответить», и это семантически верно.
    """

# Лимит суточный: пометка живёт меньше суток, потом ключ пробуют снова.
EXHAUST_TTL = 20 * 3600


def _synchronized(method: Callable[..., Any]) -> Callable[..., Any]:
    """Сериализовать операции над состоянием одного пула ключей."""
    @wraps(method)
    def wrapper(self: "KeyPool", *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


class KeyPool:
    """Ключи одного сервиса с автоматической ротацией."""

    def __init__(
        self,
        service: str,
        getter: Callable[[], Iterable[str | None]],
        ttl: float = EXHAUST_TTL,
    ) -> None:
        self._service = service
        self._getter = getter
        self._ttl = ttl
        self._cursor: str | None = None
        self._exhausted_until: dict[str, float] = {}
        self._log = structlog.get_logger()
        self._lock = RLock()

    # ─────────────────────────  чтение ключей  ─────────────────────────

    def keys(self) -> list[str]:
        """Список ключей сейчас: без пустых, повторов и заглушек.

        Заглушки отсекаются потому, что иначе они проходят весь путь
        боевого ключа: кириллический плейсхолдер из примера конфига
        ронял DaData на кодировании заголовка (UnicodeEncodeError),
        латинский — доходил до сервиса и возвращал 401, который пул
        честно докладывал как «ключи исчерпаны». Живой прогон через
        agента поймал оба варианта.
        """
        seen: set[str] = set()
        result: list[str] = []
        for raw in self._getter():
            key = (raw or "").strip()
            if not key or key in seen:
                continue
            # Заглушка: не-ASCII символы (пример «<впиши ключ>») либо
            # очевидный шаблон из примера конфигурации.
            if not key.isascii() or key.startswith(("<", "{")) or "..." in key:
                self._log.warning("key_placeholder_dropped", service=self._service,
                                  key=f"{key[:6]}…")
                continue
            seen.add(key)
            result.append(key)
        return result

    def has_keys(self) -> bool:
        return bool(self.keys())

    @_synchronized
    def current(self) -> str:
        """Ключ для следующего запроса. Без ключей — внятная ошибка.

        Исключение — QuotaExhausted, а не голый RuntimeError: его ловят
        обработчики источников как штатное молчание (status=unavailable
        с причиной), и инструмент остаётся жив вместо падения целиком.
        Живой прогон поймал обратное: при не заданных ключах агенты
        получали «Error executing tool» без объяснения.
        """
        keys = self.keys()
        if not keys:
            name = self._service.upper()
            raise QuotaExhausted(
                f"Не задан ключ {name}: заполните {name}_API_KEY "
                f"или {name}_API_KEYS в .env."
            )
        now = time.monotonic()
        usable = [k for k in keys if self._exhausted_until.get(k, 0) <= now]
        if usable:
            candidates = usable
        else:
            # Помечены все — суточное окно кончилось у каждого. Пробуем
            # заново с первого: пусть сервис ещё раз откажет, это
            # дешевле, чем пропустить работоспособный ключ.
            candidates = keys
            self._cursor = None
        if self._cursor not in candidates:
            self._cursor = candidates[0]
        return self._cursor

    # ─────────────────────────  ротация  ───────────────────────────────

    @_synchronized
    def mark_exhausted(self, key: str, reason: str | None = None) -> None:
        """Считать ключ израсходованным до конца суточного окна."""
        self._exhausted_until[key] = time.monotonic() + self._ttl
        self._log.info("key_exhausted", service=self._service,
                       key=f"…{key[-4:]}", reason=reason)

    @_synchronized
    def rotate(self, reason: str | None = None, *, failed_key: str | None = None) -> bool:
        """Пометить отвергнутый ключ негодным и выбрать рабочий.

        Передавайте ключ из запроса: пока провайдер отвечал, другой
        запрос мог уже передвинуть общий курсор.
        False — запасных ключей нет.
        """
        keys = self.keys()
        if not keys:
            return False
        if failed_key is None:
            failed_key = self._cursor if self._cursor in keys else keys[0]
        if failed_key in keys:
            self.mark_exhausted(failed_key, reason)

        now = time.monotonic()
        usable = [k for k in keys if k != failed_key and self._exhausted_until.get(k, 0) <= now]
        if self._cursor in usable:
            return True
        if not usable:
            self._log.warning("keys_depleted", service=self._service,
                              size=len(keys), reason=reason)
            return False
        nxt = usable[0]
        self._cursor = nxt
        self._log.info("key_rotated", service=self._service, key=f"…{nxt[-4:]}")
        return True

    # ─────────────────────────  диагностика  ───────────────────────────

    @_synchronized
    def status(self) -> list[dict[str, str]]:
        """Состав пула для логов и отчёта: без самих ключей, только хвосты."""
        now = time.monotonic()
        return [
            {"key": f"…{k[-4:]}",
             "state": "exhausted" if self._exhausted_until.get(k, 0) > now else "ok"}
            for k in self.keys()
        ]

    @_synchronized
    def reset(self) -> None:
        """Только для тестов: забыть курсор и пометки об исчерпании."""
        self._cursor = None
        self._exhausted_until.clear()


def _dadata_keys() -> list[str]:
    return settings.dadata_key_pool()


def _checko_keys() -> list[str]:
    return settings.checko_key_pool()


dadata = KeyPool("dadata", _dadata_keys)
checko = KeyPool("checko", _checko_keys)
