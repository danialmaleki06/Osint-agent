"""Проверка ключей доступа. Запускать после правки .env.

    uv run python scripts/check_keys.py

Делает по одному реальному запросу в каждый сервис и печатает вердикт.
"""

import asyncio

import httpx

from osint_mcp.config import settings

SBER = "7707083893"


async def check_dadata() -> bool:
    if not settings.dadata_api_key:
        print("[--] DaData: ключ не задан в .env")
        return False
    url = f"{settings.dadata_base_url}/findById/party"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Token {settings.dadata_api_key}",
    }
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(url, json={"query": SBER}, headers=headers)

    if r.status_code == 200:
        items = r.json().get("suggestions", [])
        if items:
            print(f"[OK] DaData: работает, нашла «{items[0]['value']}»")
            await _show_quota()
            return True
        print("[??] DaData: ответила 200, но ничего не нашла")
        return False

    if r.status_code == 403 and "SUGGESTIONS" in r.text:
        print("[XX] DaData: функция подсказок отключена для ключа.")
        print("     Причины по документации сервиса, по убыванию вероятности:")
        print("       1) не подтверждён email — проверь почту и папку «Спам»;")
        print("       2) взят не тот ключ — нужен API-ключ из личного кабинета;")
        print("       3) исчерпан суточный лимит.")
        return False

    print(f"[XX] DaData: HTTP {r.status_code} — {r.text[:200]}")
    return False


async def _show_quota() -> None:
    """Остаток суточной квоты по каждому сервису.

    Лимиты сильно различаются: подсказки — тысячи в день, метод рыночного
    наименования — десятки. Упереться в лимит посреди работы неприятно.
    """
    from osint_mcp.context.dadata import DaDataSource
    try:
        quota = await DaDataSource().get_quota()
    except Exception as e:
        print(f"     (остаток квоты узнать не удалось: {type(e).__name__})")
        return
    print("     остаток квоты на сегодня:")
    for name, v in quota.items():
        if v["used"] or v["remaining"]:
            mark = "  <-- мало" if 0 < v["remaining"] <= 10 else ""
            print(f"       {name:12} израсходовано {v['used']:>5}, "
                  f"осталось {v['remaining']:>6}{mark}")


async def check_checko() -> bool:
    if not settings.checko_api_key:
        print("[--] Checko: ключ не задан в .env")
        return False
    url = f"{settings.checko_base_url}/company"
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(url, params={"key": settings.checko_api_key, "inn": SBER})

    body = r.text[:200]
    if r.status_code == 200 and '"status":"ok"' in r.text.replace(" ", ""):
        print("[OK] Checko: работает")
        return True

    if r.status_code == 401:
        print("[XX] Checko: ключ не опознан сервисом.")
        print("     Тот же ответ приходит на заведомо неверный ключ, значит дело")
        print("     не в правах, а в самом ключе: проверь, скопирован ли он")
        print("     целиком и активирована ли подписка в личном кабинете.")
        return False

    print(f"[XX] Checko: HTTP {r.status_code} — {body}")
    return False


async def main() -> int:
    print("Проверяю ключи из .env\n")
    ok = all(await asyncio.gather(check_dadata(), check_checko()))
    print("\n" + ("Оба ключа рабочие — можно продолжать."
                  if ok else "Есть неисправные ключи, см. выше."))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
