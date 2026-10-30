import base64
import pickle
from typing import Any

from agentdojo.functions_runtime import FunctionCall, TaskEnvironment
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.task_suite.task_suite import TaskSuite

DEFAULT_VERSION = "v1.2.2"


def load_suite(name: str, version: str = DEFAULT_VERSION) -> TaskSuite:
    return get_suite(version, name)


def tool_schemas(suite: TaskSuite) -> list[dict[str, Any]]:
    return [
        {
            "name": fn.name,
            "description": fn.description,
            "input_schema": fn.parameters.model_json_schema(),
        }
        for fn in suite.tools
    ]


def call_to_json(call: FunctionCall) -> dict[str, Any]:
    return {"function": call.function, "args": dict(call.args)}


def call_from_json(data: dict[str, Any]) -> FunctionCall:
    return FunctionCall(function=data["function"], args=data["args"])


# Environments cross the control socket pickled, not as JSON: some AgentDojo models rebuild
# state in validators (Inbox resets `emails` from `initial_emails`), so model_validate on a
# dumped environment silently drops changes made during the episode.
def env_to_wire(env: TaskEnvironment) -> str:
    return base64.b64encode(pickle.dumps(env)).decode()


def env_from_wire(data: str) -> TaskEnvironment:
    return pickle.loads(base64.b64decode(data))
