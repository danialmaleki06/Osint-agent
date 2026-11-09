"""Smoke-тест MCP по stdio: initialize → tools/list → вызов инструмента.

Проверяет ровно то, что делает хост при подключении: хэндшейк, список
инструментов и реальный вызов. Крупный лимит чтения обязателен:
tools/list с полными описаниями инструментов превышает дефолтные 64 КБ.
"""

import asyncio
import json

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "smoke", "version": "0"}}}


async def main() -> None:
    proc = await asyncio.create_subprocess_exec(
        "uv", "run", "python", "-m", "osint_mcp.server",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, limit=8 * 1024 * 1024)

    async def rpc(obj: dict) -> dict:
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        await proc.stdin.drain()
        while True:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=90)
            if not line:
                raise RuntimeError("сервер закрыл stdout")
            msg = json.loads(line)
            if msg.get("id") == obj.get("id"):
                return msg

    init = await rpc(INIT)
    info = init["result"]["serverInfo"]
    print("initialize ok:", info["name"], info["version"])

    tools = await rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                       "params": {}})
    names = [t["name"] for t in tools["result"]["tools"]]
    print(f"tools/list ok: {len(names)} инструментов")
    assert "generate_full_dossier" in names
    assert "check_companies_batch" in names

    call = await rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                      "params": {
                          "name": "generate_full_dossier",
                          "arguments": {"inn": "7724744134",
                                        "detail": "brief"}}})
    data = json.loads(call["result"]["content"][0]["text"])
    print("generate_full_dossier ok. Ключи ответа:", list(data.keys()))
    print("  вердикт:", json.dumps(data.get("вердикт"), ensure_ascii=False)[:200])
    card = data.get("карточка") or {}
    if isinstance(card, dict):
        print("  карточка:",
              {k: str(v)[:60] for k, v in list(card.items())[:6]})
    assert any(k in data for k in ("светофор", "score", "вердикт")), data.keys()

    proc.stdin.close()
    await proc.wait()
    print("SMOKE OK")


if __name__ == "__main__":
    asyncio.run(main())
