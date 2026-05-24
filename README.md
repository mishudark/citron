# citron Tracked Capabilities for Safer Agents

A Go implementation of the capability-safe agent framework from *[Tracking Capabilities for Safer Agents](https://arxiv.org/abs/2603.00991)* (CAIS '26), adapted to use **Starlark** as the agent execution language.

> **citron** is a safety harness for AI agents.
> Instead of calling tools directly, agents express their intentions as Starlark scripts
> using **tracked capabilities** global objects that regulate access to files, processes,
> network, and I/O. The harness validates safety via AST analysis and evaluates the script
> in an isolated sandbox.

## Quick Start

```go
import "github.com/mishudark/citron"

code := `
f = fs.access("output.txt")
f.write("safe agent output")
io.println("Wrote to file")
`

result, err := citron.SafeExecute(code, citron.Options{
    WorkingDir: "/tmp",
})
```

## Architecture

citron provides a pipeline that validates and executes agent-generated Starlark scripts:

1. **Analyze** parses the Starlark AST and checks:
   - `Classified.map`/`flat_map` callback purity (forbids side-effects, global mutation, impure function calls)
   - `write()` with `Classified` data (rejected; use `write_classified` instead)
2. **Execute** runs the script in an isolated `go.starlark.net` thread within an in-memory virtual filesystem
3. **Capabilities** injects `fs`, `io`, `net`, `proc` as globals with scoped lifetimes (invalidated after execution completes)

Capabilities follow a **scope-based access pattern**: each capability is created, passed to a callback, and automatically invalidated when the callback returns, preventing smuggling of capabilities outside their intended scope.

## Capabilities

### FileSystem (`fs`)

All paths are resolved relative to a virtual root (default `/work`). The in-memory virtual filesystem can be seeded from a real directory via `SeedDir`.

```python
entry = fs.access("README.md")
content = entry.read()
io.println(content)

# Write to the virtual filesystem
f = fs.access("output.txt")
f.write("agent output")
```

`FileEntry` methods:

| Method | Returns | Notes |
|--------|---------|-------|
| `read()` | `string` | Plain read; rejects classified paths |
| `write(content)` | `None` | String content only |
| `append(content)` | `None` | Append to existing content |
| `read_classified()` | `Classified` | Only on classified paths |
| `write_classified(c)` | `None` | Writes `Classified` data to classified paths |
| `exists()` | `bool` | Whether the file exists |
| `is_dir()` | `bool` | Whether the entry is a directory |
| `delete()` | `None` | Remove the file |
| `mkdir_all()` | `None` | Create directory and parents |
| `children()` | `list[DirEntry]` | List directory contents |
| `walk()` | `list[DirEntry]` | Recursive directory listing |

### Classified Data

`Classified` wraps sensitive values. The harness prevents exfiltration through pure-function enforcement and output masking.

```python
secret = fs.access("key.txt").read_classified()
io.println(secret)  # prints "Classified(****)"

def to_upper(s):
    return s.upper()

upper = secret.map(to_upper)
# secret content never revealed to the agent context
```

The static analyzer prevents:
- Calling impure functions (`io.println`, `fs.access`, `proc.exec`, `net.get`) inside `map`/`flat_map` callbacks
- Writing `Classified` data via `write()` (use `write_classified` instead)
- Reassignment of external variables or mutable method calls inside callbacks

### Process Execution (`proc`)

```python
out = proc.exec("echo", ["hello"])
io.println(out)  # "hello"
```

Commands are restricted to a configured allowlist. The Starlark binding returns stdout as a string.

### Network (`net`)

```python
body = net.get("https://api.example.com/v1/status")
io.println(body)
```

Hosts are validated against a configured allowlist. Redirect targets are re-checked.

The Go API also exposes `caps.HTTPPost` for POST requests with body and content-type, though the Starlark binding currently exposes only `get`.

### IO Capability (`io`)

```python
io.println("agent-visible output", 42)
```

`io` gates all I/O. When a secure output sink is configured via `SecureOutputPath`, `io.println` writes the **unmasked** classified content to that sink and `"Classified(****)"` to the agent-visible output. Both `io.println()` and Starlark's `print()` are routed through the IO gate.

### LLM (`llm`) Go API only

Configure an LLM backend for `Chat` and `ChatClassified` operations:

```go
caps.ConfigureLLM(&caps.LLMConfig{
    Model:    "gpt-4",
    APIKey:   os.Getenv("OPENAI_API_KEY"),
    Endpoint: "https://api.openai.com/v1/chat/completions",
})
```

`ChatClassified` accepts a `Classified[string]` and returns `Classified[string]`, keeping sensitive prompts and responses within the classified boundary.

## API

### SafeExecute (one-shot)

```go
result, err := citron.SafeExecute(code, citron.Options{
    WorkingDir:         "/work",
    SeedDir:            "./seed-data",
    CommandAllowlist:   []string{"echo", "cat"},
    NetworkAllowlist:   []string{"api.example.com"},
    ClassifiedPatterns: []string{".env", ".ssh/**"},
    SecureOutputPath:   "/var/log/classified.log",
    TimeoutMs:          30000,
    Extras:             myMCPBuiltins,  // additional Starlark globals
})
```

### Session (stateful)

```go
s := citron.NewSession(citron.Options{
    WorkingDir: "/work",
    SeedDir:    "./contracts",
    Extras:     myMCPBuiltins,
})
defer s.Close()

// Each Execute call preserves filesystem state from previous calls.
result1, _ := s.Execute(`f = fs.access("draft.md"); f.write("v1")`)
result2, _ := s.Execute(`f = fs.access("draft.md"); io.println(f.read())`)
```

### Analyze (static check only)

```go
err := citron.Analyze(code)
```

## Options

| Option | Type | Description |
|--------|------|-------------|
| `WorkingDir` | `string` | Virtual root for filesystem operations (default `/work`) |
| `SeedDir` | `string` | Real directory to copy into the virtual filesystem before execution |
| `CommandAllowlist` | `[]string` | Allowed commands for `proc.exec` |
| `NetworkAllowlist` | `[]string` | Allowed hosts for `net.get` |
| `ClassifiedPatterns` | `[]string` | Glob patterns for classified file paths |
| `SecureOutputPath` | `string` | File path for unmasked classified output |
| `TimeoutMs` | `int64` | Execution timeout in milliseconds |
| `Extras` | `starlark.StringDict` | Additional Starlark globals (e.g. MCP tool bindings) |
| `DoNotTrack` | `bool` | Disable all OpenTelemetry collection |
| `TracerProvider` | `trace.TracerProvider` | Custom OTel tracer provider |
| `MeterProvider` | `metric.MeterProvider` | Custom OTel meter provider |
| `MetricsOutputPath` | `string` | Write JSON metrics to file after execution |

## Examples

```bash
go run examples/01_basic_capability.go    # Basic capability pattern
go run examples/02_classified_data.go     # Classified data with pure map
go run examples/03_scoped_lifetime.go     # Scoped lifetime and invalidation
go run examples/04_scenario_contracts.go  # Full scenario: contract comparison
go run examples/05_safety_guarantees.go   # Safety guarantees leak prevention
go run examples/06_citron_harness.go      # citron SafeExecute harness
```

## Packages

| Package | Purpose |
|---------|---------|
| [`caps/`](caps/) | Capability library `FileSystem`, `VirtualFileSystem`, `Classified[T]`, `ProcessPermission`, `Network`, `IOCapability`, `LLMConfig` |
| [`analysis/`](analysis/) | Starlark AST-based static analyzer `Classified.map` purity checks, `CLASSIFIED_WRITE_MISMATCH` detection |
| [`mcpclient/`](mcpclient/) | Remote MCP client connect, list tools/resources/prompts, generate Starlark bindings or server proxy registrations |
| `citron.go` | Top-level API `SafeExecute`, `Analyze`, `Session` |
| `starlark_bindings.go` | Wraps capabilities into Starlark builtins |
| [`examples/`](examples/) | Runnable examples from the paper |

## Remote MCP Tools as Capabilities

The [`mcpclient`](mcpclient/) package connects to a remote MCP server, lists its tools (including JSON Schema inputs and outputs), and **generates Go code** that wraps each tool as a Starlark builtin turning remote MCP tools into first-class citron capabilities.

### mcpgen CLI

```bash
# Streamable HTTP transport
go run ./cmd/mcpgen --url http://localhost:9090/mcp --package mytools

# Dry-run to inspect generated code
go run ./cmd/mcpgen --url http://localhost:9090/mcp --dry-run

# Stdio transport (spawn a subprocess)
go run ./cmd/mcpgen --command "npx @modelcontextprotocol/server-everything" --output tools.go

# SSE transport
go run ./cmd/mcpgen --sse http://localhost:8080/sse --package mytools

# Include resources and prompts alongside tools
go run ./cmd/mcpgen --all-caps --url http://localhost:9090/mcp --package mytools

# Generate MCP server proxy registration code (--server mode)
go run ./cmd/mcpgen --server --url http://remote:9090/mcp --package main --output gen_remote.go
```

The generated file exports `RegisterMCPSession(*mcp.ClientSession) starlark.StringDict`.

### Using generated builtins

Pass the generated dict through `Options.Extras`:

```go
session, _ := mcpclient.Connect(ctx, &mcpclient.Config{
    Transport: mcpclient.TransportStreamableHTTP,
    ServerURL: "http://localhost:9090/mcp",
})
dict := mytools.RegisterMCPSession(session)

result, _ := citron.SafeExecute(code, citron.Options{
    Extras: dict,
})
```

In Starlark each MCP tool becomes a callable:

```python
result = get_weather(location="New York", units="celsius")
io.println(result)
```

Generated code includes input and output schema property names as documentation comments, and `StructuredContent` is automatically converted to native Starlark types (`dict`, `list`, `string`, `int`, `float`, `bool`).

### Usage via go:generate

```go
//go:generate go run github.com/mishudark/citron/cmd/mcpgen --url http://localhost:9090/mcp --package mytools --output gen_mcp.go
```

## Telemetry

citron integrates OpenTelemetry tracing and metrics. Nothing is exported by default unless a provider or output path is configured.

### Traces

| Span | Emitted at |
|------|-----------|
| `citron.SafeExecute` | Top-level script execution |
| `citron.Session.Execute` | Session-based execution |
| `caps.FileSystem.Request` / `caps.VirtualFileSystem.Request` | Capability grant |
| `caps.Network.Request` | Capability grant |
| `caps.Process.Request` | Capability grant |
| `caps.Network.HTTPGet` / `caps.Network.HTTPPost` | Network operation |
| `caps.Process.Exec` | Process execution |
| `caps.LLM.Chat` / `caps.LLM.ChatClassified` | LLM call |

### Metrics

| Metric | Tags | Description |
|--------|------|-------------|
| `caps.requests` | `type` | Capability grants by type (filesystem, network, process, virtual_filesystem) |
| `caps.operations` | `operation`, `status`, `error_kind` | Capability operations by name and outcome |
| `caps.operation_duration_ms` | `operation`, `status` | Histogram of operation duration in milliseconds |

### Configuration

```go
// File export (simplest no SDK setup needed)
result, err := citron.SafeExecute(code, citron.Options{
    MetricsOutputPath: "metrics.json",
})

// Custom MeterProvider (OTLP, Prometheus, etc.)
result, err := citron.SafeExecute(code, citron.Options{
    MeterProvider: myOTLPProvider,
})

// Opt out entirely
result, err := citron.SafeExecute(code, citron.Options{
    DoNotTrack: true,
})
```

## MCP Server citron as a Service

The [`cmd/citron/`](cmd/citron/) package runs an MCP server that exposes the entire citron safety harness as MCP tools. This follows the [code-execution-with-MCP](https://modelcontextprotocol.io) pattern: instead of loading dozens of tool definitions into context, the agent learns the harness API via `harness_guide` and writes Starlark code that citron safely executes.

```bash
# Stdio transport (default pipe into your MCP client)
go run ./cmd/citron

# Streamable HTTP transport
PORT=9090 go run ./cmd/citron
```

### Available tools

| Tool | Description |
|------|-------------|
| `harness_guide` | Returns the full HARNESS_GUIDE.md. Call this first. |
| `execute_starlark` | Executes Starlark code through `citron.SafeExecute` with full safety guarantees. |
| `analyze_starlark` | Static analysis without execution returns structured issues. |
| `list_capabilities` | Lists every capability built-in (`fs`, `net`, `proc`, `io`, `Classified`) and any remote MCP tools registered via `mcpgen --server`. |

### Resource

The harness guide is also available as a readable resource at `citron://harness-guide.md`.

### Environment variables

| Variable | Purpose |
|----------|---------|
| `PORT` | HTTP port (default `8080`; set empty for stdio) |
| `CITRON_COMMAND_ALLOWLIST` | Comma-separated allowed commands for `proc.exec` |
| `CITRON_NETWORK_ALLOWLIST` | Comma-separated allowed hosts for `net.get` |
| `CITRON_CLASSIFIED_PATTERNS` | Comma-separated glob patterns for classified files |
| `CITRON_SECURE_OUTPUT_PATH` | Path for unmasked classified output |
| `CITRON_TIMEOUT_MS` | Execution timeout (default `30000`) |

### Programmatic usage

```go
import (
    "github.com/mishudark/citron"
    "github.com/mishudark/citron/cmd/citron"
    "github.com/mishudark/citron/mcpclient"
)

server := citroncmd.NewServer(citron.Options{
    CommandAllowlist:   []string{"echo", "cat"},
    NetworkAllowlist:   []string{"api.example.com"},
    ClassifiedPatterns: []string{".env"},
}, remoteCaps...)
```

Remote MCP tools (generated via `mcpgen --server`) are registered by passing their `CapabilityInfo` entries as variadic arguments to `NewServer`. They appear in `list_capabilities` alongside the built-in capabilities.

## Harness Guide

The embedded `HARNESS_GUIDE.md` documents the full capability API for agents. Access it programmatically:

```go
import "github.com/mishudark/citron"
fmt.Println(citron.HarnessGuide)
```

## License

MIT see [LICENSE](LICENSE).
