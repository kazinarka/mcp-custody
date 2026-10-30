"""How the scripted agent reaches the tools: in-process, or over MCP through any command."""

import asyncio
import json
import shlex
import sys
import tempfile
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any, Protocol

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime, TaskEnvironment
from agentdojo.task_suite.task_suite import TaskSuite
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client

from .suite import call_from_json, env_from_wire, env_to_wire


class Transport(Protocol):
    async def seed(self, env: TaskEnvironment) -> None: ...

    async def call(self, name: str, args: dict[str, Any]) -> tuple[str, bool]:
        """Returns (text, is_error)."""
        ...

    async def finish(self) -> tuple[TaskEnvironment, list[FunctionCall]]:
        """Environment after the episode and the calls that actually executed."""
        ...


class DirectTransport:
    """Reference path: AgentDojo's own runtime, no MCP."""

    def __init__(self, suite: TaskSuite) -> None:
        self.runtime = FunctionsRuntime(suite.tools)
        self.env: TaskEnvironment | None = None
        self.trace: list[FunctionCall] = []

    async def seed(self, env: TaskEnvironment) -> None:
        self.env = env.model_copy(deep=True)
        self.trace = []

    async def call(self, name: str, args: dict[str, Any]) -> tuple[str, bool]:
        assert self.env is not None
        self.trace.append(FunctionCall(function=name, args=args))
        result, error = self.runtime.run_function(self.env, name, args)
        if error is not None:
            return error, True
        return tool_result_to_str(result), False

    async def finish(self) -> tuple[TaskEnvironment, list[FunctionCall]]:
        assert self.env is not None
        return self.env, self.trace


class McpTransport:
    """Tools over MCP stdio. `{server}` in the command expands to the bench server invocation,
    so a gateway can wrap it, e.g. `custody -- {server}`."""

    def __init__(self, suite: TaskSuite, version: str, command: str) -> None:
        self.suite = suite
        self._tmp = tempfile.TemporaryDirectory(prefix="custody-bench-")
        self.control_path = str(Path(self._tmp.name) / "control.sock")
        server = shlex.join(
            [sys.executable, "-m", "custody_bench.server", "--suite", suite.name,
             "--version", version, "--control", self.control_path]
        )
        argv = shlex.split(command.replace("{server}", server))
        self.params = StdioServerParameters(command=argv[0], args=argv[1:])
        self._stack = AsyncExitStack()
        self.client: Client | None = None
        self._ctl: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None

    async def __aenter__(self) -> "McpTransport":
        self.client = await self._stack.enter_async_context(
            Client(stdio_client(self.params, errlog=sys.stderr))
        )
        # The control socket appears once the server has started.
        for _ in range(100):
            if Path(self.control_path).exists():
                break
            await asyncio.sleep(0.05)
        self._ctl = await asyncio.open_unix_connection(self.control_path, limit=64 * 1024 * 1024)
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._ctl is not None:
            self._ctl[1].close()
        await self._stack.aclose()
        self._tmp.cleanup()

    async def _control(self, req: dict[str, Any]) -> dict[str, Any]:
        assert self._ctl is not None
        reader, writer = self._ctl
        writer.write(json.dumps(req).encode() + b"\n")
        await writer.drain()
        resp = json.loads(await reader.readline())
        if not resp.get("ok"):
            raise RuntimeError(f"control {req['op']}: {resp.get('error')}")
        return resp

    async def seed(self, env: TaskEnvironment) -> None:
        await self._control({"op": "seed", "env": env_to_wire(env)})

    async def call(self, name: str, args: dict[str, Any]) -> tuple[str, bool]:
        assert self.client is not None
        result = await self.client.call_tool(name, args)
        text = "\n".join(c.text for c in result.content if getattr(c, "type", None) == "text")
        return text, bool(result.is_error)

    async def finish(self) -> tuple[TaskEnvironment, list[FunctionCall]]:
        resp = await self._control({"op": "dump"})
        return env_from_wire(resp["env"]), [call_from_json(c) for c in resp["trace"]]
