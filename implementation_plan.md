# Assessment: Classified-Data Tooling in citron

## Objective

Inventory every tool/binding that currently exists for handling classified
data (Go `caps` layer, Starlark sandbox, MCP server surface), identify the
gaps, and propose concrete changes to close them.

---

## Phase 1 — What exists today

### MCP tool surface (`cmd/citron/main.go`)

| Tool | Classified relevance |
|---|---|
| `execute_starlark` | Runs code under `SafeExecute`; analyzer rejects classified leaks pre-execution |
| `analyze_starlark` | Reports `CLASSIFIED_WRITE_MISMATCH`, impure-map-callback, `DYNAMIC_GETATTR` issues |
| `harness_guide` | Documents classified rules |
| `list_capabilities` | Describes `fs.read_classified`, `write_classified`, `Classified.map/flat_map`, IO masking |
| resource `citron://harness-guide.md` | Same guide |

### Starlark bindings (`starlark_bindings.go`)

- `fs.access(p)` → `read`, `write`, `read_classified`, `write_classified`
- `Classified.map(pure)` / `Classified.flat_map(pure)` (panic-safe, error-message sanitized)
- `io.println` masks `Classified(****)` agent-side; unmasked copy goes to the secure sink
- Taint tracking in `analysis/analyzer.go`: sticky per-variable taint through
  assignment, binary ops, containers, slices, conditionals; capability refs
  forbidden inside callbacks

### Go `caps` layer

- `Classified[T]` (masked `String/GoString/Format`, JSON mask, unmarshal refused)
- FS: path-pattern classification (root + nested `**` globs), plain read/write
  rejected on classified paths, classified ops restricted to classified paths,
  `0o600` on classified writes
- `Chat`/`ChatClassified` (LLM), `Network` (allowlist, DNS-rebinding defense,
  port pinning, 10 MiB cap), `Proc` allowlist, `IOCapability` dual sink, VFS mirror

---

## Phase 2 — Gaps (what is missing for classified data)

### G1. No agent-facing LLM binding
`caps.Chat`/`ChatClassified` exist but are **not exposed to Starlark** and not
listed in `list_capabilities`. Agents cannot do classified-preserving LLM
calls inside the sandbox.

### G2. `proc.exec` stdout is always plain
Command output (e.g. `printenv`, `kubectl get secret`) enters the agent
context as an unclassified string. No `exec_classified` / per-execution
"classified output" flag, and the analyzer has no `CLASSIFIED_ARG` check for
proc arguments.

### G3. Network responses cannot be classified; no POST
`net.get` returns a plain string. A response body containing secrets
(e.g. a metadata endpoint) is unprotected. There is also no way to send
data anywhere (no POST), classified or not.

### G4. Taint analysis only guards `write`
`exprProducesClassified` is checked only for `entry.write(...)`. Calls like
`net.get(url=...)`, `proc.exec(cmd, args)` are blocked from receiving
`Classified` **only by runtime type mismatch** (UnpackArgs into string), not
statically — no `CLASSIFIED_ARG` issue code, so a future signature change
(regression) or a Go-side caller could silently accept it.

### G5. Classified only supports `string` in the sandbox
Starlark wrapper is `starlarkClassified{c caps.Classified[string]}`. No
Classified lists/dicts/bytes, no `combine`/`zip` for two classified values
(`flat_map` + `map` workaround is awkward), no pure predicates
(`contains`, `len`) that return non-classified booleans safely.

### G6. Secure output sink is unguarded
`SecureOutputPath` receives plaintext. Nothing verifies the sink path is
**outside** `WorkingDir` — if it is inside, the agent can `fs.read()` the
plaintext back, defeating the whole gate. No 0600 perms check, no rotation,
no audit log of unmask events.

### G7. No content-based classification
Classification is purely path-pattern based. Secrets printed to stdout by a
command or embedded in an HTTP response are invisible to the system
(no optional secret-scanning heuristics on proc/net output).

### G8. No classified audit trail surfaced
`telemetry.go` records spans/ops, but there is no MCP tool or log stream
answering "which classified reads/unmasks happened in run X".

### G9. MCP result labeling
`execute_starlark` output is a plain string; tool results carry no
classification metadata, so downstream MCP consumers can't distinguish
masked from unmasked content.

---

## Phase 3 — Proposed file-by-file changes (priority order)

1. **`analysis/analyzer.go`** — add `CLASSIFIED_ARG`: reject
   `exprProducesClassified` in args of `net.get`/`proc.exec`/`write`-style
   capability calls (defense-in-depth, closes G4). Tests in
   `analysis/analyzer_test.go`, `bypass_test.go`.

2. **`caps/proc.go`** — add `ExecClassified(opts...)` returning
   `Classified[ProcessResult]`; Starlark binding `proc.exec_classified`.
   Closes G2. Tests `proc_test.go`, new binding test.

3. **`caps/net.go`** — add `HTTPGetClassified` (response wrapped) and
   `HTTPPost`; Starlark `net.get_classified`, `net.post`. Closes G3.
   Analyzer: forbid classified in POST body unless it is a Classified arg
   rule interplay (decide: require Classified body?).

4. **`cmd/citron/main.go` + `citron.go`** — expose `llm.chat` /
   `llm.chat_classified` bindings behind `Options.LLMConfig`; add to
   `list_capabilities`. Closes G1.

5. **`citron.go` (Options validation)** — reject `SecureOutputPath` inside
   `WorkingDir`; chmod 0600 on sink creation. Closes G6.

6. **`caps/telemetry.go` + new MCP tool `classified_audit`** — emit
   structured events (read/unmask/write-classified with paths, no values)
   and expose them. Closes G8.

7. **Optional/later**: `Classified` combinators (`combine`, `contains`),
   content-based secret scanning on proc/net output (G5, G7), MCP result
   labels (G9).

## Open questions

- Should `net.post` exist at all, or only `post_classified` (body must be
  Classified, response Classified)?
- Is runtime type-mismatch blocking of classified→`net.get(url)` sufficient,
  or should the static check also cover interpolated map-results (those are
  Classified by design, so `net.get` on them stays a runtime error)?
- Should `proc.exec_classified` classify stdout+stderr, stdout only, or take
  a flag?

## Resolution (decided during implementation)

- `net.post` exists in both forms: plain `post` (plain body only, static
  `CLASSIFIED_ARG` rejects Classified) and `post_classified` (body must be
  Classified, response Classified).
- The static `CLASSIFIED_ARG` check covers all Classified taint, including
  map-derived results; combined with runtime type checks this is
  defense-in-depth.
- `proc.exec_classified` classifies both stdout and stderr; `.exit_code`
  stays plain. No flag.
- Audit (G8) is implemented as an always-on in-process event log
  (`caps/audit.go`); `Result.Audit` carries the per-run events and the MCP
  server exposes them via the new `classified_audit` tool and the `audit`
  field of `execute_starlark` results. Events carry paths/URLs/commands
  only, never values.
- Optional items from the plan (Classified combinators, content-based
  scanning, MCP result labels) remain future work.

## Implementation status: complete (all tests pass)
