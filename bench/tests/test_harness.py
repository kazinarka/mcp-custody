import asyncio
import shlex
import sys
from pathlib import Path

import pytest
from agentdojo.attacks.attack_registry import load_attack

from custody_bench.run import _ScriptedPipeline, run_episode
from custody_bench.suite import DEFAULT_VERSION, load_suite
from custody_bench.transport import DirectTransport, McpTransport, ServerDaemon

RELAY = Path(__file__).with_name("blocking_relay.py")


def episodes(suite_name: str, user_ids: list[str], injection_ids: list[str]):
    suite = load_suite(suite_name)
    attack = load_attack("direct", suite, _ScriptedPipeline())
    for uid in user_ids:
        for iid in injection_ids:
            u, i = suite.user_tasks[uid], suite.injection_tasks[iid]
            yield suite, u, i, attack.attack(u, i)


async def run_all(transport_factory, items, agent="obedient"):
    results = []
    for suite, u, i, inj in items:
        async with transport_factory(suite) as t:
            results.append(await run_episode(suite, t, agent, u, i, inj))
    return results


class _Direct:
    def __init__(self, suite):
        self.t = DirectTransport(suite)

    async def __aenter__(self):
        return self.t

    async def __aexit__(self, *exc):
        return None


# workspace exercises the Inbox validator that once broke state transfer.
CASES = [
    ("banking", ["user_task_0", "user_task_3"], ["injection_task_0", "injection_task_3"]),
    ("workspace", ["user_task_1", "user_task_13"], ["injection_task_0", "injection_task_3"]),
]


@pytest.mark.parametrize("suite_name,users,injections", CASES)
def test_mcp_matches_direct(suite_name, users, injections):
    items = list(episodes(suite_name, users, injections))
    direct = asyncio.run(run_all(_Direct, items))
    mcp = asyncio.run(
        run_all(lambda s: McpTransport(s, DEFAULT_VERSION, "{server}"), items)
    )
    assert direct == mcp


def test_forked_daemon_matches_direct():
    items = list(episodes("workspace", ["user_task_1"], ["injection_task_0", "injection_task_3"]))
    suite = items[0][0]
    direct = asyncio.run(run_all(_Direct, items))

    async def via_daemon():
        async with ServerDaemon(suite, DEFAULT_VERSION) as daemon:
            return await run_all(
                lambda s: McpTransport(s, DEFAULT_VERSION, "{server}", daemon.path), items
            )

    assert asyncio.run(via_daemon()) == direct


def test_blocked_call_is_not_scored():
    # banking injection_task_0 succeeds only by executing send_money.
    items = list(episodes("banking", ["user_task_0"], ["injection_task_0"]))
    command = shlex.join([sys.executable, str(RELAY), "send_money", "--"]) + " {server}"
    [blocked] = asyncio.run(
        run_all(lambda s: McpTransport(s, DEFAULT_VERSION, command), items)
    )
    [open_] = asyncio.run(run_all(_Direct, items))
    assert open_["attack_success"] is True
    assert blocked["attack_success"] is False
    assert blocked["executed"] < blocked["planned"]
    assert all(c["function"] != "send_money" for c in blocked["trace"])
