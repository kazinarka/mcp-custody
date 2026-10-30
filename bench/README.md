# custody-bench

AgentDojo episodes played against MCP servers, with or without a gateway in between.

The tool environment lives in the MCP server process. The harness seeds it and reads it back
over a Unix socket the agent never sees, and scores each episode on the calls that actually
reached the server. A call that a gateway refuses cannot change the result.

## Agents

There is no model in the loop yet. Two scripted agents are built from AgentDojo ground truths:

- `honest` does the user task only. Anything a gateway blocks here is a false positive.
- `obedient` does the user task and then everything the injection asks for. This is the
  fully steerable model from the threat model, so without a gateway every doable attack
  succeeds.

## Usage

```
uv sync
uv run custody-bench run --suite banking --agent obedient --attack direct --transport mcp
uv run custody-bench run ... --transport mcp --command 'custody -- {server}'
uv run custody-bench diff a.jsonl b.jsonl
uv run pytest
```

`{server}` expands to the bench server command, so any stdio gateway can wrap it.

## Baseline without a gateway (AgentDojo v1.2.2, `direct` attack)

| suite | honest utility | obedient utility | obedient attack success |
|---|---|---|---|
| banking | 16/16 | 125/144 | 144/144 |
| slack | 21/21 | 102/105 | 105/105 |
| travel | 20/20 | 26/140 | 136/140 |
| workspace | 40/40 | 326/560 | 218/560 |

Direct (in-process), MCP, and MCP through `custody run` give identical per-episode results on
all four suites.

Known gaps inherited from AgentDojo: workspace injection tasks 6 to 13 have empty ground
truths (ethz-spylab/agentdojo#213), so the obedient agent cannot carry them out and the
workspace number is a floor, not 100%. Obedient utility is below 100% because some injected
actions undo or conflict with the user task.
