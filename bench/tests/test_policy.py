import tomllib

import pytest

from custody_bench.policy import EXTRA_SINKS, LEVELS, SINKS, TRUSTED_SOURCES, generate
from custody_bench.suite import load_suite


@pytest.mark.parametrize("suite_name", sorted(SINKS))
@pytest.mark.parametrize("level", LEVELS)
def test_generated_policy_is_valid_toml(suite_name, level):
    policy = tomllib.loads(generate(load_suite(suite_name), level))
    assert policy["default"] == "deny"
    assert policy["tools"]


def test_sink_annotations_name_real_parameters():
    for suite_name, tools in SINKS.items():
        suite = load_suite(suite_name)
        schemas = {t.name: t.parameters.model_json_schema()["properties"] for t in suite.tools}
        for tool, args in tools.items():
            assert set(args) <= set(schemas[tool]), (suite_name, tool)
        for tool in TRUSTED_SOURCES[suite_name] | EXTRA_SINKS[suite_name]:
            assert tool in schemas, (suite_name, tool)
