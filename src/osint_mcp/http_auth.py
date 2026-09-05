"""Проверка доступа для сетевого режима.

Локально сервер защищён тем, что его порождает само приложение и общение
идёт через каналы ввода-вывода — снаружи туда не попасть. Как только
сервер выставлен в сеть, это перестаёт быть верным: ключи к платным
справочникам лежат у него, и любой, кто узнает адрес, сможет расходовать
нашу суточную квоту.

Случайный адрес не является секретом: он попадает в журналы, в историю
переписки, в закладки. Поэтому проверка обязательна.
"""

import hmac

import structlog
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

log = structlog.get_logger()


class TokenAuth:
    """Пропускает только запросы с верным токеном в заголовке.

    Сравнение постоянного времени: обычное сравнение строк завершается
    на первом несовпавшем знаке, и по времени ответа токен подбирается
    посимвольно.
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        self._app = app
        # Сравниваем в байтах: compare_digest на строках требует, чтобы обе
        # состояли только из знаков ASCII, и падает с ошибкой на кириллице.
        # Присланный токен приходит от кого угодно и содержать может что
        # угодно — падение здесь означало бы 500 вместо честного отказа,
        # а разница в ответах подсказывает подбирающему, что он на верном пути.
        self._token = token.encode("utf-8")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request = Request(scope, receive)
        # Принимаем обе записи: со словом Bearer и без него. Разные
        # клиенты заполняют это поле по-разному — часть добавляет слово
        # сама, часть ждёт его от пользователя. Отказ из-за формата
        # выглядел бы как неверный токен и уводил бы поиск не туда.
        header = request.headers.get("authorization", "").strip()
        supplied = header[7:].strip() if header.lower().startswith("bearer ") else header

        if not hmac.compare_digest(supplied.encode("utf-8"), self._token):
            log.warning("auth_rejected", path=request.url.path,
                        client=request.client.host if request.client else None,
                        had_header=bool(header))
            response = JSONResponse(
                {"error": "Требуется заголовок Authorization: Bearer <токен>"},
                status_code=401,
            )
            await response(scope, receive, send)
            return

        await self._app(scope, receive, send)
