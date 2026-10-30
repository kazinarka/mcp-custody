"""MCP server that exposes one AgentDojo suite over stdio.

The environment is owned here. The harness seeds it and reads it back through a separate
Unix socket that the agent (and any gateway in between) never sees. Only calls that reach
this process are recorded in the trace used for scoring.
"""

import argparse
import asyncio
import json
import sys
from typing import Any

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import FunctionsRuntime, TaskEnvironment
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

from .suite import DEFAULT_VERSION, env_from_wire, env_to_wire, load_suite, tool_schemas


class SuiteState:
    def __init__(self, suite_name: str, version: str) -> None:
        self.suite = load_suite(suite_name, version)
        self.runtime = FunctionsRuntime(self.suite.tools)
        self.env: TaskEnvironment | None = None
        self.trace: list[dict[str, Any]] = []

    def seed(self, env: str) -> None:
        self.env = env_from_wire(env)
        self.trace = []

    def dump(self) -> dict[str, Any]:
        if self.env is None:
            raise RuntimeError("environment not seeded")
        return {"env": env_to_wire(self.env), "trace": self.trace}

    def call(self, name: str, args: dict[str, Any]) -> tuple[str, str | None]:
        if self.env is None:
            return "", "RuntimeError: environment not seeded"
        self.trace.append({"function": name, "args": args})
        result, error = self.runtime.run_function(self.env, name, args)
        return tool_result_to_str(result), error


def build_server(state: SuiteState) -> Server:
    tools = [
        Tool(name=t["name"], description=t["description"], input_schema=t["input_schema"])
        for t in tool_schemas(state.suite)
    ]

    async def list_tools(
        ctx: ServerRequestContext, params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        return ListToolsResult(tools=tools)

    async def call_tool(ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
        text, error = state.call(params.name, dict(params.arguments or {}))
        if error is not None:
            return CallToolResult(content=[TextContent(type="text", text=error)], is_error=True)
        return CallToolResult(content=[TextContent(type="text", text=text)])

    return Server(
        f"agentdojo-{state.suite.name}", on_list_tools=list_tools, on_call_tool=call_tool
    )


async def serve_control(state: SuiteState, path: str) -> asyncio.Server:
    # One JSON request per line, one JSON response per line.
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while line := await reader.readline():
            try:
                req = json.loads(line)
                match req["op"]:
                    case "seed":
                        state.seed(req["env"])
                        resp: dict[str, Any] = {"ok": True}
                    case "dump":
                        resp = {"ok": True, **state.dump()}
                    case op:
                        resp = {"ok": False, "error": f"unknown op {op!r}"}
            except Exception as e:
                resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            writer.write(json.dumps(resp).encode() + b"\n")
            await writer.drain()
        writer.close()

    return await asyncio.start_unix_server(handle, path=path, limit=64 * 1024 * 1024)


async def main_async(args: argparse.Namespace) -> None:
    state = SuiteState(args.suite, args.version)
    control = await serve_control(state, args.control)
    server = build_server(state)
    async with control, stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--control", required=True, help="Unix socket path for seed/dump")
    args = parser.parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
