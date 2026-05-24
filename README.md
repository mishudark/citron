# citron  Tracked Capabilities for Safer Agents

A Go implementation of the capability-safe agent framework from *[Tracking Capabilities for Safer Agents](paper.md)* (CAIS '26), adapted to use **Starlark (Python)** as the agent execution language.

> **citron** (pronounced /ˈsɪtrən/) is a safety harness for AI agents.
> Instead of calling tools directly, agents express their intentions as Starlark (Python) scripts
> using **tracked capabilities**  global objects that regulate access to files, processes,
> network, and I/O. The harness validates safety via AST analysis and evaluates the script natively.

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

1. **Analyze**  [`analysis`](analysis/) package parses the Starlark AST and checks:
   - `Classified.map`/`flat_map` callback purity (forbids side-effects, global mutation, impure function calls).
2. **Execute**  runs the script in an isolated `go.starlark.net` thread.
3. **Capabilities**  injects `fs`, `io`, `net`, `proc` as Pythonic globals.

## Capabilities

### FileSystem (`fs`)

```python
entry = fs.access("README.md")
content = entry.read()       # plain read (fails on classified paths)
io.println(content)

secret = fs.access("key.txt").read_classified() # Classified  safe wrapper
io.println(secret)           # prints "Classified(****)"
```

### Classified Data

```python
secret = fs.access("key.txt").read_classified()
io.println(secret) # "Classified(****)"

def to_upper(s):
    return s.upper()

upper = secret.map(to_upper)
# secret content never revealed to the agent context!
```

### Process Execution (`proc`)

```python
out = proc.exec("echo", ["hello"])
io.println(out) # "hello\n"
```

### Network (`net`)

```python
body = net.get("https://api.example.com/v1/status")
io.println(body)
```

### IO Capability (`io`)

```python
io.println("agent-visible output", 42)
```

`io` gates all I/O. When a secure output sink is configured, `io.println` writes the
**unmasked** classified content to that sink and `"Classified(****)"` to the
agent-visible output.

## Examples

Runnable examples are in the [`examples/`](examples/) directory.

```bash
# Basic capability pattern
go run examples/01_basic_capability.go

# Classified data with pure map
go run examples/02_classified_data.go

# Scoped lifetime and invalidation
go run examples/03_scoped_lifetime.go

# Full scenario: contract comparison
go run examples/04_scenario_contracts.go

# Safety guarantees  leak prevention
go run examples/05_safety_guarantees.go

# citron SafeExecute harness
go run examples/06_citron_harness.go
```

## Packages

| Package | Purpose |
|---------|---------|
| [`caps/`](caps/) | Capability library  `FileSystem`, `Classified[T]`, `ProcessPermission`, `Network`, `IOCapability` |
| [`analysis/`](analysis/) | Starlark AST-based static analyzer  `Classified.map` purity checks |
| [`mcpclient/`](mcpclient/) | Remote MCP client  connect, list tools/resources/prompts, generate Starlark bindings or server proxy registrations |
| `citron.go` | Top-level API  `SafeExecute`, `Session` |
| `starlark_bindings.go` | Wraps capabilities into Starlark Builtins |
| [`examples/`](examples/) | Runnable examples from the paper |

## Telemetry

citron integrates OpenTelemetry tracing and metrics around every capability operation. All telemetry flows through the standard OTel export pipeline — nothing is exported by default unless a `MeterProvider` or `MetricsOutputPath` is configured.

### Traces (Spans)

| Span name | Emitted at |
|---|---|
| `citron.SafeExecute` | Top-level script execution |
| `citron.Session.Execute` | Session-based script execution |
| `caps.FileSystem.Request` / `caps.VirtualFileSystem.Request` | Capability grant |
| `caps.Network.Request` | Capability grant |
| `caps.Process.Request` | Capability grant |
| `caps.Network.HTTPGet` / `caps.Network.HTTPPost` | Network operation |
| `caps.Process.Exec` | Process execution |
| `caps.LLM.Chat` / `caps.LLM.ChatClassified` | LLM call |

Each span carries relevant attributes (root path, hosts, command, args) and records error status when the operation fails.

### Metrics (Counters)

| Metric | Tags | Description |
|---|---|---|
| `caps.requests` | `type` | Number of capability grants by type (filesystem, network, process, virtual_filesystem) |
| `caps.operations` | `operation`, `status` | Number of capability operations by name and outcome (ok / error) |

### Configuration

Telemetry is configured through `citron.Options`:

```go
type Options struct {
    // ...

    // TracerProvider for OpenTelemetry spans.
    TracerProvider trace.TracerProvider

    // MeterProvider for OpenTelemetry metrics.
    MeterProvider metric.MeterProvider

    // DoNotTrack disables all telemetry collection.
    DoNotTrack bool

    // MetricsOutputPath writes JSON metrics to a file after execution.
    MetricsOutputPath string
}
```

### Usage patterns

**File export (simplest — no SDK setup needed):**
```go
result, err := citron.SafeExecute(code, citron.Options{
    MetricsOutputPath: "metrics.json",
})
```

**Custom MeterProvider (OTLP, Prometheus, etc.):**
```go
import (
    "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
    sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

exporter, _ := otlpmetrichttp.New(ctx)
reader := sdkmetric.NewPeriodicReader(exporter)
provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

result, err := citron.SafeExecute(code, citron.Options{
    MeterProvider: provider,
})
```

**Opt out entirely:**
```go
result, err := citron.SafeExecute(code, citron.Options{
    DoNotTrack: true,
})
```

## Remote MCP Tools as Capabilities  [`mcpclient`](mcpclient/)

The [`mcpclient`](mcpclient/) package connects to a remote MCP server, lists its tools
(including their JSON Schema inputs and outputs), and **generates Go code** that wraps
each tool as a Starlark builtin  turning remote MCP tools into first-class citron
capabilities.

### Quick start  `mcpgen`

The easiest way is the `mcpgen` CLI tool.  It connects, lists, generates, and writes
all in one step:

```bash
# Connect via streamable HTTP, write gen_mcp.go
go run ./cmd/mcpgen --url http://localhost:9090/mcp --package mytools

# Dry-run to inspect generated code
go run ./cmd/mcpgen --url http://localhost:9090/mcp --dry-run | head -40

# Stdio transport (spawn a subprocess)
go run ./cmd/mcpgen --command "npx @modelcontextprotocol/server-everything" --output tools.go

# SSE transport
go run ./cmd/mcpgen --sse http://localhost:8080/sse --package mytools
```

The generated file exports `RegisterMCPSession(*mcp.ClientSession) starlark.StringDict`.

### Library usage

For programmatic use (e.g. in `go:generate` or tests):

```go
session, err := mcpclient.Connect(ctx, &mcpclient.Config{
    Transport: mcpclient.TransportStreamableHTTP,
    ServerURL: "http://localhost:9090/mcp",
})
tools, err := mcpclient.ListTools(ctx, session)
code, err := mcpclient.GenerateTools(tools, mcpclient.GenOptions{
    PackageName: "mytools",
})
os.WriteFile("mcp_tools.go", code, 0644)
```

### Using the generated builtins

Merge the returned `starlark.StringDict` into the citron execution context alongside
`fs`, `net`, `proc`, and `io`:

```go
dict := mytools.RegisterMCPSession(session)
// merge into citron's dict before starlark.ExecFile
```

In Starlark each MCP tool becomes a callable:

```python
result = get_weather(location="New York", units="celsius")
io.println(result)
```

Generated code includes both **input** and **output** schema property names as
documentation comments, and `StructuredContent` that conforms to the tool's
`OutputSchema` is automatically converted to native Starlark types (`dict`, `list`,
`string`, `int`, `float`, `bool`) rather than raw JSON strings.

### Proxying remote tools through the citron MCP server  `--server`

The `--server` flag generates MCP **server registration** code instead of Starlark
bindings.  Each remote tool is registered as a local `mcp.Tool` that proxies all
calls to the remote MCP session, and the generated function returns
`[]mcpclient.CapabilityInfo` entries that feed into the `list_capabilities` tool.

```bash
# Generate server registration code from a remote MCP server
go run ./cmd/mcpgen --server --url http://remote:9090/mcp --package main --output gen_remote.go

# Stdio transport
go run ./cmd/mcpgen --server --command "npx @modelcontextprotocol/server-everything" --output gen_remote.go
```

Integration in the citron server:

```go
import (
    "github.com/mishudark/citron/cmd/citron"
    "github.com/mishudark/citron/mcpclient"
    "path/to/gen_remote"
)

func main() {
    // Connect to the remote MCP server
    session, _ := mcpclient.Connect(ctx, &mcpclient.Config{
        Transport: mcpclient.TransportStreamableHTTP,
        ServerURL: "http://remote:9090/mcp",
    })

    // Create the citron server and register remote tools as proxy tools
    server := citron.NewServer(opts,
        gen_remote.RegisterRemoteTools(server, session)...,
    )
}
```

The registered tools appear in `list_capabilities` alongside the built-in `fs`,
`net`, `proc`, `io`, and `Classified` capabilities.

### All capabilities  `--all-caps`

The `--all-caps` flag (combined with the default Starlark mode) also lists
**resources** and **prompts** from the remote MCP server, generating Starlark
builtins for reading resources (`get_<name>`) and retrieving prompts
(`<prompt_name>`) alongside the tool builtins.

```bash
go run ./cmd/mcpgen --all-caps --url http://localhost:9090/mcp --package mytools
```

## MCP Server — citron as a Service

The [`cmd/citron/`](cmd/citron/) package runs an MCP server that exposes the
entire citron safety harness as MCP tools.  This follows the
[code-execution-with-MCP](https://modelcontextprotocol.io) pattern described by
Anthropic: instead of loading dozens of tool definitions into context, the
agent learns the harness API via `harness_guide` and writes Starlark code that
citron safely executes.

### Quick start

```bash
# Stdio transport (default — pipe into your MCP client)
go run ./cmd/citron

# Streamable HTTP transport
PORT=9090 go run ./cmd/citron
```

### Available tools

| Tool | Description |
|------|-------------|
| `harness_guide` | Returns the full HARNESS_GUIDE.md. Call this first. |
| `execute_starlark` | Executes Starlark code through `citron.SafeExecute` with full safety guarantees. |
| `analyze_starlark` | Static analysis without execution — returns structured issues. |
| `list_capabilities` | Lists every capability — built-in (`fs`, `net`, `proc`, `io`, `Classified`) and any remote MCP tools registered via `mcpgen --server`. |

Remote MCP tools are registered as proxy tools alongside the built-in ones.
See the [`--server` flag](#proxying-remote-tools-through-the-citron-mcp-server---server)
section above.

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

### Usage with MCP clients

The server works with any MCP client.  An agent connects, calls
`harness_guide` or reads the `citron://harness-guide.md` resource, and then
writes Starlark code that uses `fs`, `net`, `proc`, `io`, and `Classified`.

```python
# Example Starlark code the agent might write:
f = fs.access("output.txt")
f.write("safe agent output")
io.println("Wrote to file")

# With classified data:
secret = fs.access("key.txt").read_classified()
def to_upper(s):
    return s.upper()
upper = secret.map(to_upper)
io.println(upper)  # prints "Classified(****)"
```
