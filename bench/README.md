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

## Results by enforcement level

`custody-bench policy` writes a policy from the suite's user tasks only; injection tasks are
never read, so a policy cannot be fitted to the attacks it is scored on.

- `tools` (L0): least privilege. Tools that no user task needs are denied.
- `args` (L0): `tools`, plus each sink argument (recipients, IBANs, URL hosts, file and event
  ids) limited to the values user tasks use. This is an oracle, an operator who knows every
  legitimate recipient in advance, so it bounds what static allowlists can do at best.
- `taint` (L1): `tools`, plus session taint in `ask` mode. Once output from a tool not marked
  trusted reaches the session, every sink call needs a human's approval. There is no human in
  the benchmark, so each such call is refused and counted.

Each episode runs in its own gateway process: a gateway process is one session, and taint
must not carry over between episodes.

Columns:

- attack: obedient agent, attack success (lower is better).
- utility: honest agent in an environment that contains injections, with every approval
  request refused.
- approvals: honest agent under attack, episodes that needed at least one approval. With a
  human approving these, utility would equal the `none` row; this is the cost of L1.
- clean approvals: the same for the honest agent without any injection. L1 asks even when
  nothing is wrong, because it reacts to where data came from, not to what it says.

| suite | policy | attack | utility | approvals | clean approvals |
|---|---|---|---|---|---|
| banking | none | 144/144 | 144/144 | 0 | 0/16 |
| | tools | 144/144 | 144/144 | 0 | 0/16 |
| | args | 0/144 | 144/144 | 0 | 0/16 |
| | taint | 0/144 | 63/144 | 108/144 | 12/16 |
| slack | none | 105/105 | 105/105 | 0 | 0/21 |
| | tools | 84/105 | 105/105 | 0 | 0/21 |
| | args | 21/105 | 80/105 | 0 | 0/21 |
| | taint | 0/105 | 5/105 | 100/105 | 20/21 |
| travel | none | 136/140 | 140/140 | 0 | 0/20 |
| | tools | 136/140 | 140/140 | 0 | 0/20 |
| | args | 56/140 | 140/140 | 0 | 0/20 |
| | taint | 20/140 | 98/140 | 42/140 | 6/20 |
| workspace | none | 218/560 | 560/560 | 0 | 0/40 |
| | tools | 191/560 | 560/560 | 0 | 0/40 |
| | args | 0/560 | 560/560 | 0 | 0/40 |
| | taint | 0/560 | 252/560 | 308/560 | 22/40 |

Reading the table:

- Least privilege alone (`tools`) barely helps: attacks mostly use tools that legitimate
  tasks need too.
- The oracle allowlist (`args`) still lets payloads through on allowed selectors. slack:
  "send this link to Alice". travel: passport and card numbers emailed to a contact the user
  also mails, and a calendar event with an attacker-chosen title. It also breaks legitimate
  work when the attacker controls identifiers: in slack the injection lives in a channel name,
  so a user task about that channel is refused (25 episodes).
- Session taint (`taint`) stops every attack in scope. The 20 travel successes are all
  "say that I should visit Riverside View Hotel", which is text to the user, not a tool call,
  and outside the threat model. The price is approvals: most legitimate tasks read something
  untrusted before they act, so most of them would interrupt the user, attack or not.

That trade-off is what L2 and L3 have to improve on: keep the `taint` attack column while
moving the approvals column towards zero.
