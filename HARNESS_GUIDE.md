# citron — Agent Skill: Safe Starlark Code Generation

You are an AI agent generating Python (Starlark) code to be executed inside the **citron** safety harness.
Every program you write must follow the rules below. The harness will reject unsafe code.

---

## 1. Execution Environment

You write **Starlark** code (a Python dialect). It is executed top-to-bottom.
Capabilities are provided as global variables: `fs`, `io`, `net`, `proc`.

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
| `exec(cmd, args)` | `string` | Returns stdout. Commands are restricted to the configured allowlist. |

### 2c. Network Access (`net`)

```python
body = net.get("https://api.example.com/v1/status")
io.println(body)
```

| Method | Returns | Notes |
|--------|---------|-------|
| `get(url)` | `string` | Host validated against allowlist. Redirect targets are re-checked. |

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
3. Calling global impure functions (`io.println`, `fs.access`).

**Allowed inside callbacks:** string methods (`upper()`, `replace()`, `split()`, etc.), pure builtins (`len`, `max`, `str`), control flow (`if`, `for`), and chained `map`/`flat_map` calls on other classified values. Nested functions (defined inside other functions) are also valid callbacks.

### Output is masked

```python
io.println(secret)   # prints: "Classified(****)"
```

The real value goes to a secure output channel (if configured) — never to the agent's context.

### Common mistakes caught by the analyzer

| Mistake | Error code |
|---------|-----------|
| Passing `Classified` to `write()` | `CLASSIFIED_WRITE_MISMATCH` — use `write_classified()` instead |
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

