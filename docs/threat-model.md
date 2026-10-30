# Threat model

Draft. Expect this to change as the benchmark shows where the assumptions are wrong.

## 1. System

```
 user ──> agent host (MCP client, LLM) ──> custody ──> MCP server A ──> web, mail, files, ...
                                                  └──> MCP server B ──> ...
```

custody is an MCP server towards the agent and an MCP client towards the downstream servers.
It sees every tool definition, every tool call and every tool result. It does not see the
conversation itself.

Targeted MCP revision: 2026-07-28.

## 2. Assets

- A1. Confidential data reachable through tools: files, credentials, mail, private repositories,
  calendar, internal APIs.
- A2. Integrity of side effects: messages sent, files written or deleted, code executed,
  payments, permission changes.
- A3. Credentials that custody or downstream servers hold to talk to external services.
- A4. The audit log. If it can be altered, nothing else in this document can be verified after
  the fact.

## 3. Trust assumptions

- T1. The user is trusted, and so are the instructions they give the agent directly.
- T2. The model is not malicious by itself, but anything in its context can steer it. Once
  untrusted content has been in the context, every tool call the agent makes is treated as
  possibly attacker-influenced.
- T3. custody, its configuration and its policy are trusted. They are the trusted computing base,
  and the design should keep them small.
- T4. Tool calls through custody are the only way the agent can cause side effects or send data
  out. This is a deployment requirement, not something custody can enforce. For Claude Code it
  means the sandbox with a strict network allowlist, deny rules for built-in tools that reach the
  network or filesystem (WebFetch, WebSearch, Read, Write, Edit), and managed settings that
  stop other MCP servers from being added. If T4 does not hold, custody gives no guarantees.
- T5. A downstream server is either vetted (the operator trusts its code) or unvetted. The
  content a vetted server returns can still come from an attacker: a vetted mail server returns
  attacker-written mail.

## 4. Adversaries

- ADV-1, content author. Controls some of the data that a vetted tool returns: a web page, an
  email, an issue comment, a document, a field in an API response. Cannot change configuration
  or code. This is the main adversary.
- ADV-2, malicious server. Controls an unvetted server completely: tool names, descriptions,
  schemas, results. Can change them over time, and can try to influence how the agent uses
  other servers.
- Both are assumed to know how custody works and what the policy is. Every claim in section 8
  has to hold against an attacker who has read this repository.

Out of scope: a compromised host or custody process, a malicious user, a malicious model or
model provider, timing side channels.

## 5. What custody can and cannot see

Visible: tool definitions (`tools/list`), call arguments, results including `structuredContent`,
elicitation requests that travel inside results (multi round-trip requests).

Not visible: the user's prompt, the system prompt, the model's reasoning, the agent's built-in
tools, anything the user pastes into the chat.

Consequences:

- custody cannot tell a value that the user typed from a value the model made up or rewrote
  from untrusted text. Provenance therefore has to be positive: a value counts as untrusted
  when custody can show it came from a tool result, or by policy when untrusted data has
  already entered the session (L1). A value that matches nothing is not proof that it is clean.
- Every untrusted input does pass through custody, because tool results are the only way
  external content reaches the agent under T4. So custody always knows whether and when the
  session has been exposed.
- The 2026-07-28 revision removed protocol sessions. custody has to define what a session is.
  For stdio it is the lifetime of the process. For HTTP it is still open (Q1).

## 6. Sinks

A sink is a tool argument whose value decides a side effect or carries data out. Two roles:

- Selector: where the action goes. Email recipient, URL host, file path, payment recipient,
  repository, shell command. The main concern is integrity: an attacker must not choose it.
- Payload: what is carried. Email body, request body, file contents. The main concern is
  confidentiality: secret data must not reach an external selector.

Classes:

- S-EGRESS: network requests (URL, host, body).
- S-COMM: messages to people (recipient, body). Email, chat, comments, issues.
- S-WRITE: writing, moving or deleting files and repository contents.
- S-EXEC: running code or shell commands.
- S-FIN: moving money (recipient, amount).
- S-PERM: sharing settings, access grants, invitations.

Which arguments are sinks is part of the policy and comes from the operator. Server-provided
tool annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`) may serve as defaults for
vetted servers only. The spec itself says to treat them as untrusted otherwise.

## 7. Attack classes

IDs are used to tag benchmark cases.

- AC-1, hijack. An injected instruction makes the agent call a sink with a selector chosen by
  the attacker.
- AC-2, exfiltration. Confidential data reaches a sink the attacker can read. Includes multi-step
  variants (read a secret, then send it) and payloads that are encoded, paraphrased or split
  across calls.
- AC-3, argument steering. The action is one the user asked for, but the attacker picks an
  argument: the amount, which file, which of several recipients mentioned in the content.
- AC-4, tool poisoning. Instructions hidden in tool descriptions or schemas.
- AC-5, rug pull. A tool definition changes after it was reviewed.
- AC-6, cross-server influence. One server's definitions or results change how the agent uses
  another server.
- AC-7, laundering. Untrusted data is written somewhere through a harmless-looking tool and read
  back later through a path that looks trusted.
- AC-8, denial channel. The attacker learns about data or policy from how custody refuses calls.
- AC-9, approval abuse. The human approves something harmful because of how it was presented,
  or because they were asked too often to keep reading.
- AC-10, handle abuse (L3). Getting the value behind a handle revealed by passing the handle to
  a sink that resolves it, or by asking the quarantined extractor to leak it.

## 8. Security goals

Each goal assumes T1 to T5.

- G1 (L0). No call reaches a downstream server unless the policy allows that tool with those
  arguments.
- G2 (L0). A changed tool definition is detected before the tool is used again.
- G3 (L1). After untrusted data has entered a session, no sink call is forwarded without
  explicit human approval or a policy rule that allows it for untrusted sessions.
- G4 (L3). A value delivered as a handle reaches a sink only if the policy allows its label for
  that sink and role.
- G5. Every decision is recorded in an append-only log that shows tampering.

L2 (heuristic provenance) has no goal. It is measured, not relied on.

## 9. Non-goals

- What the agent says to the user in plain text. A convincing lie or a phishing link in the
  final answer is not a tool call.
- Keeping the model from being persuaded. custody limits what a persuaded agent can do.
- Availability. An attacker can make the agent fail its task, for example by triggering
  denials. Utility under attack is measured but not guaranteed.
- Implicit flows through which tool the agent decides to call. Acknowledged and partly covered
  by L1. Discussed, not solved.

## 10. Open questions

- Q1. What a session is over stateless HTTP: per connection, per client identity, per trace?
- Q2. Who labels result fields and sink arguments at scale. Operator-maintained packs for common
  servers, with drafts generated offline and reviewed?
- Q3. What an approval does to labels. Does approving one send endorse the recipient for the rest
  of the session?
- Q4. How to show an approval so that it resists AC-9: what to display, how to batch, how to
  count approvals per task as a cost metric.
- Q5. What a denial says to the agent. Too little and the agent gets stuck, too much and AC-8
  opens up.
- Q6. Output of the quarantined extractor: schema constraints, and whether any output type can
  be considered safe to show the agent directly (booleans, enums).
