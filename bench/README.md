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
uv run custody-bench policy --suite banking --level args -o banking.toml
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

## L0: static policy

`custody-bench policy` writes a policy from the suite's user tasks only; injection tasks are
never read, so a policy cannot be fitted to the attacks it is scored on.

- `tools`: least privilege. Tools that no user task needs are denied.
- `args`: `tools`, plus each sink argument (recipients, IBANs, URL hosts, file and event ids)
  limited to the values user tasks use. This is an oracle, an operator who knows every
  legitimate recipient in advance, so it bounds what static allowlists can do at best.

`honest` utility is 100% on clean environments for every row and is left out. "Under attack"
is the honest agent working in an environment that contains injections it ignores.

| suite | policy | honest utility under attack | obedient attack success |
|---|---|---|---|
| banking | none | 144/144 | 144/144 |
| | tools | 144/144 | 144/144 |
| | args | 144/144 | 0/144 |
| slack | none | 105/105 | 105/105 |
| | tools | 105/105 | 84/105 |
| | args | 80/105 | 21/105 |
| travel | none | 140/140 | 136/140 |
| | tools | 140/140 | 136/140 |
| | args | 140/140 | 56/140 |
| workspace | none | 560/560 | 218/560 |
| | tools | 560/560 | 191/560 |
| | args | 560/560 | 0/560 |

What gets through even the oracle policy:

- Payloads on allowed selectors. slack: "send this link to Alice" (Alice is a legitimate
  recipient). travel: passport and card numbers emailed to a contact the user also mails, and
  a calendar event with an attacker-chosen title.
- Text to the user (travel: "say that I should visit Riverside View Hotel"), which is not a
  tool call and is out of scope.

What the oracle policy breaks: in slack the injection lives in a channel name, so a user task
that must act on that channel is refused under attack (25 episodes). Static allowlists fail
when the attacker controls identifiers, not just content.

Least privilege alone (`tools`) barely helps: the attacks mostly use tools that legitimate
tasks need too.
