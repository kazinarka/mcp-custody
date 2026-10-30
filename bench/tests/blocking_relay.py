"""Stand-in gateway for tests: relays MCP stdio, refusing tools/call for the named tools.

    python blocking_relay.py send_money,update_password -- <server command...>
"""

import asyncio
import json
import sys


async def main() -> None:
    sep = sys.argv.index("--")
    denied = set(sys.argv[1].split(","))
    child = await asyncio.create_subprocess_exec(
        *sys.argv[sep + 1 :], stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE
    )
    assert child.stdin and child.stdout
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=64 * 1024 * 1024)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    out = sys.stdout.buffer

    async def upstream() -> None:
        while line := await reader.readline():
            msg = json.loads(line)
            if msg.get("method") == "tools/call" and msg["params"]["name"] in denied:
                reply = {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "content": [{"type": "text", "text": "blocked"}],
                        "isError": True,
                        "resultType": "complete",  # required since MCP 2026-07-28
                    },
                }
                out.write(json.dumps(reply).encode() + b"\n")
                out.flush()
                continue
            child.stdin.write(line)
            await child.stdin.drain()
        child.stdin.close()

    async def downstream() -> None:
        while line := await child.stdout.readline():
            out.write(line)
            out.flush()

    await asyncio.gather(upstream(), downstream())
    await child.wait()


if __name__ == "__main__":
    asyncio.run(main())
