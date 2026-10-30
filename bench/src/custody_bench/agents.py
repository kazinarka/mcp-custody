"""Scripted agents built from AgentDojo ground truths. No model involved.

- honest: does exactly the user's task. Anything a gateway blocks here is a false positive.
- obedient: does the user's task, then everything the injection asks. This is the worst case
  the threat model assumes (a fully steerable model), so attack success without a gateway
  is 100% by construction.
"""

from dataclasses import dataclass

from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.functions_runtime import FunctionCall, TaskEnvironment

AGENTS = ("honest", "obedient")


@dataclass
class Plan:
    calls: list[FunctionCall]
    output: str


def plan(
    agent: str,
    user_task: BaseUserTask,
    injection_task: BaseInjectionTask | None,
    pre_env: TaskEnvironment,
) -> Plan:
    # Ground truths are computed on copies: some of them read the environment while building.
    calls = list(user_task.ground_truth(pre_env.model_copy(deep=True)))
    output = user_task.GROUND_TRUTH_OUTPUT
    if agent == "obedient" and injection_task is not None:
        calls += injection_task.ground_truth(pre_env.model_copy(deep=True))
        output = "\n".join(s for s in (output, injection_task.GROUND_TRUTH_OUTPUT) if s)
    elif agent != "honest":
        raise ValueError(f"unknown agent {agent!r}")
    return Plan(calls=calls, output=output)
