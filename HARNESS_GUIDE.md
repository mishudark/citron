# citron — Agent Skill: Safe Starlark Code Generation

You are an AI agent generating Python (Starlark) code to be executed inside the **citron** safety harness.
Every program you write must follow the rules below. The harness will reject unsafe code.

---

## 1. Execution Environment

You write **Starlark** code (a Python dialect). It is executed top-to-bottom.
Capabilities are provided as global variables: `fs`, `io`, `net`, `proc`.

Depending on server configuration, additional **remote MCP tools** may also be
available as top-level globals (e.g. `get_weather`, `search`).  These proxy to
an external MCP server and behave like regular functions — call them with keyword
arguments and they return results as Starlark values.

```python
# Remote MCP tools (if configured — call list_capabilities to discover)
result = get_weather(location="New York", units="celsius")
io.println(result)
```

The filesystem is an **in-memory virtual filesystem** — there is no access to the host disk.
Files are seeded before execution via `SeedDir` (if configured); all agent-created files exist
only within the virtual sandbox and are discarded when execution ends.

```python
# ✅ CORRECT
f = fs.access("OUTPUT.md")
f.write("Hello from citron!")
io.println("Done.")
```

---

## 2. Capability API (Globals)

### 2a. File System (`fs`)

The file system capability is provided via the global `fs` object.
All paths are resolved relative to the virtual root (default `/work`).

```python
entry = fs.access("README.md")
content = entry.read()
io.println(content)
```

`FileEntry` methods:

| Method | Returns | Notes |
|--------|---------|-------|
| `read()` | `string` | Plain file. Rejects classified paths. |
| `write(content)` | `None` | Content must be a plain `string` — passing `Classified` data is rejected by the static analyzer before execution. |
| `read_classified()` | `Classified` | Only on classified paths. Returns an error if called on a non-classified path. |
| `write_classified(c)`| `None` | Only writes `Classified` data to classified paths. |

### 2b. Command Execution (`proc`)

```python
result = proc.exec("echo", ["hello world"])
io.println(result)
```

| Method | Returns | Notes |
|--------|---------|-------|
| `exec(cmd, args)` | `string` | Returns stdout. Commands are restricted to the configured allowlist. Passing `Classified` values produces a type error at runtime. |
| `exec_classified(cmd, args)` | `ClassifiedProcess` | stdout and stderr are wrapped in `Classified`; use when the command output may contain secrets (environment dumps, cloud CLIs). `.exit_code` is a plain int. |

```python
out = proc.exec_classified("printenv", [])
io.println(out.stdout)          # Classified(****)
def find_path(s):
    for line in s.split("\n"):
        if line.startswith("PATH="):
            return line
    return ""
path_line = out.stdout.map(find_path)
io.println(path_line)           # still masked
```

### 2c. Network Access (`net`)

```python
body = net.get("https://api.example.com/v1/status")
io.println(body)
```

| Method | Returns | Notes |
|--------|---------|-------|
| `get(url)` | `string` | Host validated against allowlist. Redirect targets are re-checked. Passing a `Classified` value produces a type error at runtime. |
| `get_classified(url)` | `Classified` | Same validation; the response body is wrapped in `Classified` (token endpoints, metadata services, ...). |
| `post(url, body, content_type?)` | `string` | Plain POST. The body must be plain text; passing `Classified` data is rejected. |
| `post_classified(url, body=Classified, content_type?)` | `Classified` | The only way to send classified data over the network: the body must be `Classified` and the response is wrapped in `Classified`. |

---

## 2d. LLM (`llm`)

Available when the server has an LLM backend configured.

| Method | Returns | Notes |
|--------|---------|-------|
| `chat(message)` | `string` | Plain chat. |
| `chat_classified(message=Classified)` | `Classified` | Prompt and response stay inside the classified boundary. |

---

## 3. Classified Data

`Classified` wraps sensitive values. The harness prevents exfiltration.

### Pure transformations only

```python
secret = fs.access("key.txt").read_classified()

def to_upper(s):
    return s.upper()

upper = secret.map(to_upper)      # ✅ pure function

# flat_map is for transformations that return another Classified value.
# You can chain map/flat_map: callbacks may themselves call .map() or .flat_map()
# on other classified values (these methods are treated as pure).
```

### What is forbidden inside `map`/`flat_map` callbacks

The callback MUST be a **pure function** — no side effects.
The static analyzer prevents:
1. Re-assigning external variables (`a[0] = 1`, `a.b = 2`).
2. Calling mutative methods on lists/dicts (`.append()`, `.pop()`).
3. Calling global impure functions (`io.println`, `fs.access`, `net.get`, `proc.exec`).
4. Referencing the capability globals `fs`, `io`, `net`, `proc` — directly, via an alias (`n = net`), or via any value that holds them (e.g. `d = {"n": net}`).

`map`/`flat_map` must also be invoked **directly** — `secret.map(cb)`, not through a saved method value (`m = secret.map; m(cb)`) or `getattr(secret, "map")(cb)`.

**Allowed inside callbacks:** string methods (`upper()`, `replace()`, `split()`, etc.), pure builtins (`len`, `max`, `str`), control flow (`if`, `for`), and chained `map`/`flat_map` calls on other classified values (these methods are treated as pure). Nested functions (defined inside other functions) are also valid callbacks.

### Output is masked

```python
io.println(secret)   # prints: "Classified(****)"
```

The real value goes to a secure output channel (if configured) — never to the agent's context.

### Common mistakes caught by the analyzer

| Mistake | Error code |
|---------|-----------|
| Passing `Classified` to `write()` | `CLASSIFIED_WRITE_MISMATCH` — use `write_classified()` instead |
| Passing `Classified` to `net.get`/`net.post`/`proc.exec` arguments (URLs, command lines, args) | `CLASSIFIED_ARG` — secrets must never appear in URLs or process arguments |
| `io.println` inside a map callback | `IMPURE_METHOD_CALL` |
| `fs.access` inside a map callback | `IMPURE_METHOD_CALL` |

### How to export processed classified data

```python
# Write the pure mapped result back via write_classified
out_f = fs.access("summary_output.txt")
out_f.write_classified(upper)
```

> **Note:** The destination path must match a classified pattern in the configuration.

---

## 4. Output via `io`

Both `io.println` and `print()` are routed through the IO capability:

```python
io.println("hello", 42)    # agent sees: "hello 42"
print("hello", 42)         # same — routed through io gate
io.println(secret)          # agent sees: Classified(****)
```

---

## 5. Error Handling

Errors come in two forms, distinguished by their format:

### Analysis errors (caught before execution)

The static analyzer rejects unsafe code **before running it**.  These errors
include the error code in parentheses:

```
agent.star:4:32: call to potentially impure method 'println' inside
pure callback is forbidden (IMPURE_METHOD_CALL)
```

These always point to the exact line and column of the violation.  Fix the
offending code and retry.

### Runtime errors (pass analysis, crash during execution)

Code that passes static analysis can still fail at runtime (division by zero,
type errors, network timeouts, etc.).  These return a **traceback** showing
the call stack:

```
agent.star: floating-point division by zero
Traceback (most recent call last):
  agent.star:1:7: in <toplevel>
Error: floating-point division by zero
```

The first line repeats the error message. The traceback shows the file, line,
and column of the failing expression and every enclosing function call.
If your code uses remote MCP tools, errors from the remote server are
wrapped in `"mcp tool <name>: <error>"`.

### Common runtime mistakes

| Mistake | Error message |
|---------|--------------|
| Passing `Classified` to `net.get()` | `"for parameter url: got Classified, want string"` |
| Passing `Classified` to `proc.exec()` | `"for parameter command: got Classified, want string"` |
| Division by zero | `"floored division by zero"` |
| Type mismatch (`"hello" + 42`) | `"unknown binary op: string + int"` |
| Calling an undefined variable | `"undefined: <name>"` |

