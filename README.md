# mcp-custody

An MCP gateway that tracks where data came from and decides where it is allowed to go.

Agents read untrusted content all the time: web pages, email, issues, documents. Any of it can
carry instructions, and the model has no reliable way to tell data from commands. Filtering the
text for "injections" does not hold up against an attacker who adapts. mcp-custody takes the
other route and controls the flow instead: every tool result gets a label, and labeled data is
not allowed to choose where a sensitive action goes or what leaves the machine, unless policy or
the user says so.

It sits between an MCP client and the MCP servers it uses. The agent does not need to be
modified.

## Status

Early. The gateway relays MCP stdio traffic, enforces a static (L0) policy on tool calls, pins
tool definitions on first sight, and writes a hash-chained audit log. The threat model is in
[docs/threat-model.md](docs/threat-model.md), the evaluation harness in [bench/](bench/).

```
custody run --policy policy.toml --pins pins.json --log audit.jsonl -- <mcp server command...>
custody verify-log audit.jsonl
```

Frames that are not valid JSON are dropped, and a frame larger than `--max-message-bytes`
stops the gateway: traffic that cannot be inspected does not pass. A refused call gets a tool
error with a fixed text; the reason is written to the audit log only. A tool whose definition
changed after it was pinned cannot be called until the pin is removed.

Policy format:

```toml
default = "deny"                  # tools not listed

[tools.get_balance]               # allowed, no argument rules

[tools.update_password]
action = "deny"

[tools.send_money.args.recipient]
one_of = ["GB29NWBK60161331926819"]

[tools.get_webpage.args.url]
hosts = ["www.informations.com", "*.example.org"]
```

Results per enforcement level are in [bench/README.md](bench/README.md).

## Planned levels of enforcement

- L0, static policy: which tools and arguments are allowed, egress allowlists, pinned tool
  definitions.
- L1, session taint: once untrusted data enters a session, sensitive calls need approval.
- L2, heuristic provenance: match call arguments against earlier tool output. Kept mainly as a
  baseline to measure how it fails.
- L3, handles: untrusted values reach the agent as opaque references that the gateway resolves
  itself at the sink, so their origin is known exactly.

Each level is evaluated for attack success rate and for how many legitimate tasks it breaks.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
