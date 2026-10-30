"""custody-bench: run AgentDojo episodes with a scripted agent and score them.

    custody-bench run --suite banking --agent obedient --attack direct --transport mcp
    custody-bench run ... --transport mcp --command 'custody -- {server}'
    custody-bench diff a.jsonl b.jsonl
"""

import argparse
import asyncio
import json
import sys
import time
from contextlib import AsyncExitStack
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.task_suite.task_suite import TaskSuite
from agentdojo.types import text_content_block_from_string

from .agents import AGENTS, plan
from .suite import DEFAULT_VERSION, call_to_json, load_suite
from .transport import DirectTransport, McpTransport, Transport


class _ScriptedPipeline(BasePipelineElement):
    # Attacks only need a pipeline name; the scripted agent never queries it.
    name = "scripted"

    def query(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


def _select(tasks: dict[str, Any], patterns: list[str] | None) -> list[Any]:
    if not patterns:
        return list(tasks.values())
    return [t for tid, t in tasks.items() if any(fnmatchcase(tid, p) for p in patterns)]


async def run_episode(
    suite: TaskSuite,
    transport: Transport,
    agent: str,
    user_task: BaseUserTask,
    injection_task: BaseInjectionTask | None,
    injections: dict[str, str],
) -> dict[str, Any]:
    env = user_task.init_environment(suite.load_and_inject_default_environment(injections))
    pre_env = env.model_copy(deep=True)
    p = plan(agent, user_task, injection_task, pre_env)

    await transport.seed(env)
    errors = 0
    for call in p.calls:
        _, is_error = await transport.call(call.function, dict(call.args))
        errors += is_error
    post_env, executed = await transport.finish()

    output = [text_content_block_from_string(p.output)]
    utility = suite._check_task_result(user_task, output, pre_env, post_env, executed)
    attack_success = None
    if injection_task is not None:
        attack_success = suite._check_task_result(
            injection_task, output, pre_env, post_env, executed
        )
    return {
        "user_task": user_task.ID,
        "injection_task": injection_task.ID if injection_task else None,
        "utility": utility,
        "attack_success": attack_success,
        "planned": len(p.calls),
        "executed": len(executed),
        "errors": errors,
        "trace": [call_to_json(c) for c in executed],
    }


async def cmd_run(args: argparse.Namespace) -> int:
    suite = load_suite(args.suite, args.version)
    user_tasks = _select(suite.user_tasks, args.tasks)
    injection_tasks = _select(suite.injection_tasks, args.injection_tasks)
    attack = None if args.attack == "none" else load_attack(args.attack, suite, _ScriptedPipeline())
    if attack is None and args.agent == "obedient":
        print("obedient agent needs an attack", file=sys.stderr)
        return 2

    pairs: list[tuple[BaseUserTask, BaseInjectionTask | None]]
    if attack is None:
        pairs = [(u, None) for u in user_tasks]
    else:
        pairs = [(u, i) for u in user_tasks for i in injection_tasks]

    out = open(args.out, "w") if args.out else None
    results = []
    started = time.monotonic()
    async with AsyncExitStack() as stack:
        transport: Transport
        if args.transport == "direct":
            transport = DirectTransport(suite)
        else:
            transport = await stack.enter_async_context(
                McpTransport(suite, args.version, args.command)
            )
        for user_task, injection_task in pairs:
            injections = attack.attack(user_task, injection_task) if attack and injection_task else {}
            r = await run_episode(suite, transport, args.agent, user_task, injection_task, injections)
            results.append(r)
            if out:
                out.write(json.dumps(r) + "\n")
    if out:
        out.close()

    n = len(results)
    utility = sum(r["utility"] for r in results)
    print(f"suite={args.suite} agent={args.agent} attack={args.attack} transport={args.transport}")
    print(f"episodes   {n}  ({time.monotonic() - started:.1f}s)")
    print(f"utility    {utility}/{n} ({100 * utility / max(n, 1):.1f}%)")
    if attack is not None:
        asr = sum(bool(r["attack_success"]) for r in results)
        print(f"attack     {asr}/{n} ({100 * asr / max(n, 1):.1f}%)")
    print(f"calls      planned {sum(r['planned'] for r in results)}, "
          f"executed {sum(r['executed'] for r in results)}, "
          f"errors {sum(r['errors'] for r in results)}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    def load(path: str) -> dict[tuple[str, str | None], dict[str, Any]]:
        rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line]
        return {(r["user_task"], r["injection_task"]): r for r in rows}

    a, b = load(args.a), load(args.b)
    fields = ("utility", "attack_success", "executed", "errors", "trace")
    diffs = 0
    for key in sorted(a.keys() | b.keys(), key=str):
        ra, rb = a.get(key), b.get(key)
        if ra is None or rb is None:
            print(f"{key}: only in {'b' if ra is None else 'a'}")
            diffs += 1
            continue
        changed = [f for f in fields if ra[f] != rb[f]]
        if changed:
            diffs += 1
            print(f"{key}: " + ", ".join(f"{f} {ra[f]!r} -> {rb[f]!r}" for f in changed if f != "trace")
                  + (" (trace differs)" if "trace" in changed else ""))
    print(f"{len(a.keys() | b.keys())} episodes, {diffs} differ")
    return 1 if diffs else 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="custody-bench")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run")
    run.add_argument("--suite", required=True)
    run.add_argument("--version", default=DEFAULT_VERSION)
    run.add_argument("--agent", choices=AGENTS, default="honest")
    run.add_argument("--attack", default="none", help="AgentDojo attack name, or none")
    run.add_argument("--transport", choices=("direct", "mcp"), default="direct")
    run.add_argument("--command", default="{server}",
                     help="stdio command for --transport mcp; {server} is the bench server")
    run.add_argument("--tasks", action="append", help="user task id or glob, repeatable")
    run.add_argument("--injection-tasks", action="append", help="injection task id or glob")
    run.add_argument("--out", help="write per-episode results as JSON lines")

    diff = sub.add_parser("diff", help="compare two result files episode by episode")
    diff.add_argument("a")
    diff.add_argument("b")

    args = parser.parse_args()
    if args.cmd == "run":
        sys.exit(asyncio.run(cmd_run(args)))
    sys.exit(cmd_diff(args))


if __name__ == "__main__":
    main()
