# citron: Tracked Capabilities for Safer Agents

A Go implementation of the capability-safe agent framework from *[Tracking Capabilities for Safer Agents](https://arxiv.org/abs/2603.00991)* (CAIS '26), adapted to use **Starlark** as the agent execution language.

> **citron** is a safety harness for AI agents.
> Instead of calling tools directly, agents express their intentions as Starlark scripts
> using **tracked capabilities**: global objects that regulate access to files, processes,
> network, and I/O. The harness validates safety via AST analysis and evaluates the script
> in an isolated sandbox.

**What citron guarantees**

- **Scoped capabilities**: `fs`, `net`, `proc`, `io` are granted per execution, restricted by allowlists, and invalidated when the run completes. Nothing escapes the sandbox.
- **No classified disclosure**: sensitive values wrapped in `Classified` print as `Classified(****)`, are JSON-masked, and can only flow through statically verified **pure functions**.
- **Static rejection before execution**: the analyzer blocks impure callbacks, classified-to-plain writes, and capability aliases *before any code runs*.

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

Capabilities follow a **scope-based access pattern**: each capability is created, passed to a callback, and automatically invalidated when the callback returns, preventing smuggling of capabilities outside their intended scope. In citron the *scope is the script run itself*, and the allowlists in `Options` define what each capability may do.

## Capabilities

### FileSystem (`fs`)

All paths are resolved relative to the virtual root (default `/work`). A filesystem capability is scoped to a single execution: Starlark scripts receive it as the `fs` global, and Go code receives a `FileSystem` inside a `RequestFileSystem` callback. The in-memory virtual filesystem can be seeded from a real directory via `SeedDir`.

```python
# The script run is the capability scope; the root is fixed by Options.WorkingDir.
content = fs.access("README.md").read()
io.println(content)

fs.access("out/result.txt").write("done")

# Directory listing and recursive walk are available
# through the Go API (FileEntry.Children / FileEntry.Walk).
```

```go
// Go-side scoped execution: the capability is passed
// to the callback and invalidated when it returns.
_, err := caps.RequestFileSystem("/home/user/project", nil, func(fsys caps.FileSystem) (string, error) {
    content, err := fsys.Access("README.md")
    if err != nil {
        return "", err
    }
    txt, _ := content.Read()

    fsAccess, _ := fsys.Access("out/result.txt")
    fsAccess.Write("done")

    // Directory listing:
    src, _ := fsys.Access("src")
    kids, _ := src.Children()
    for _, k := range kids {
        fmt.Println(k.Name)
    }
    return txt, nil
})
```

Outside the callback the `FileSystem` capability is dead: any `Access` call returns `cap: FileSystem used outside its scope`, so capabilities cannot leak beyond their scope.

`FileEntry` methods (Go API):

| Method | Returns | Notes |
|--------|---------|-------|
| `Read()` | `string` | Plain read; rejects classified paths |
| `Write(content)` | `error` | String content only |
| `Append(content)` | `error` | Append to existing content |
| `ReadLines()` | `[]string` | Split content into lines |
| `ReadClassified()` | `Classified[string]` | Only on classified paths |
| `WriteClassified(c)` | `error` | Writes `Classified` data to classified paths |
| `Exists()` | `bool` | Whether the file exists |
| `IsDir()` | `bool` | Whether the entry is a directory |
| `Size()` | `int64` | File size in bytes |
| `Delete()` | `error` | Remove the file |
| `MkdirAll()` | `error` | Create directory and parents |
| `Children()` | `[]DirEntry` | List directory contents |
| `Walk()` | `[]DirEntry` | Recursive directory listing |

Starlark scripts see a subset: `read`, `write`, `append`, `read_classified`, `write_classified`, `exists`, `is_dir`, `delete`, `mkdir_all`, `children`, `walk`, `read_lines`.

#### Searching files (grep and find)

citron does not ship a `grep` builtin; compose it from `ReadLines` and `Walk`:

```go
// grep: match the lines of a file against a regex,
// collecting caps.GrepMatch values (file, line number, line).
re := regexp.MustCompile(`TODO`)
caps.RequestFileSystem("/project", nil, func(fsys caps.FileSystem) ([]caps.GrepMatch, error) {
    entry, err := fsys.Access("Main.star")
    if err != nil {
        return nil, err
    }
    lines, err := entry.ReadLines()
    if err != nil {
        return nil, err
    }
    var matches []caps.GrepMatch
    for i, line := range lines {
        if re.MatchString(line) {
            matches = append(matches, caps.GrepMatch{
                File: entry.Path(), LineNumber: i + 1, Line: line,
            })
        }
    }
    return matches, nil
})
```

```go
// grepRecursive / find: walk a directory tree, filter by glob,
// and match each file's lines.
re := regexp.MustCompile(`deprecated`)
caps.RequestFileSystem("/project", nil, func(fsys caps.FileSystem) (bool, error) {
    src, _ := fsys.Access("src")
    entries, _ := src.Walk() // recursive descendants
    for _, e := range entries {
        matched, _ := filepath.Match("*.star", e.Name)
        if !matched || e.IsDirectory {
            continue
        }
        f, err := fsys.Access(e.Path)
        if err != nil {
            continue
        }
        lines, _ := f.ReadLines()
        for i, line := range lines {
            if re.MatchString(line) {
                fmt.Printf("%s:%d: %s\n", e.Path, i+1, line)
            }
        }
    }
    return false, nil
})
```

### Classified Data

Classified values are read and written with `read_classified` and `write_classified`. `Classified` wraps sensitive values; the harness prevents exfiltration through pure-function enforcement and output masking.

```python
# Assumes the files exist in the virtual filesystem, e.g.
# seeded from disk via Options.SeedDir.
secret = fs.access("key.txt").read_classified()
io.println(secret)  # prints "Classified(****)"

def to_upper(s):
    return s.strip().upper()

processed = secret.map(to_upper)   # pure transform OK
io.println(processed)              # still "Classified(****)"

# Write the transformed value back to a classified path:
out = fs.access("secrets/upper.txt")
out.write_classified(processed)
```

Pure transformations can also chain. A `flat_map` callback must itself return a `Classified` value, so it is typically composed from `map` on another classified value:

```python
salt = fs.access("salt.txt").read_classified()

def combine(s):
    return salt.map(lambda p: s + ":" + p)

combined = secret.flat_map(combine)   # returns another Classified
```

The static analyzer prevents:
- Calling impure functions (`io.println`, `fs.access`, `proc.exec`, `net.get`) inside `map`/`flat_map` callbacks
- Referencing the capability globals (`fs`, `io`, `net`, `proc`) inside callbacks, including through aliases or containers (`n = net`, `d = {"n": net}`)
- Invoking `map`/`flat_map` indirectly (method-value aliases like `m = secret.map`, or `getattr` indirection): callbacks are only verified on direct calls
- Writing `Classified` data via `write()` (use `write_classified` instead), including taint propagated through concatenation (`"x" + secret`) and containers
- Reassignment of external variables or mutable method calls inside callbacks

Additionally, `SafeExecute` and `Session` reject injected globals (`Options.Extras`, e.g. remote MCP tool bindings) whose names shadow pure builtins like `str` or `list`, since such a shadow would silently defeat callback purity verification.

On the Go side, `caps.Classify` wraps any value, and `caps.Map` / `caps.FlatMap` transform it with a callback. `String()`, `GoString()`, `fmt.Format`, and `MarshalJSON` all emit masked output, so the value never leaks through logs or serialization:

```go
secret := caps.Classify("s3cret")
fmt.Println(secret) // "Classified(****)", never the raw value

upper := caps.Map(secret, strings.ToUpper)
fmt.Printf("%v\n", upper) // "Classified(****)"

// Unwrapping is impossible outside the caps package:
// the value field is unexported.
```

### Process Execution (`proc`)

The commands available to `proc.exec` are set with `Options.CommandAllowlist`:

```python
out = proc.exec("echo", ["hello"])
io.println(out)  # "hello"
```

```go
result, err := citron.SafeExecute(code, citron.Options{
    CommandAllowlist: []string{"pip", "python"},
})
```

Commands outside the allowlist are rejected. The Starlark binding returns stdout as a string. Passing a `Classified` value to `proc.exec` is a type error at runtime, so secrets cannot be smuggled into a command line.

The Go API exposes the full `Exec`/`ExecOutput` signatures, including working directory and timeout, inside the scoped `RequestExecPermission` callback:

```go
caps.RequestExecPermission([]string{"pip", "python"}, func(p caps.ProcessPermission) (string, error) {
    res, err := caps.Exec(p, "pip", []string{"install", "."}, caps.ExecOptions{
        WorkingDir: "/project",
        TimeoutMs:  30000, // error on timeout
    })
    // res.ExitCode, res.Stdout, res.Stderr
    if err != nil {
        return "", err
    }
    return caps.ExecOutput(p, "python", []string{"script.py"})
})
```

### Network (`net`)

The hosts reachable by `net.get` are set with `Options.NetworkAllowlist`:

```python
body = net.get("https://api.example.com/v1/status")
io.println(body)
```

```go
result, err := citron.SafeExecute(code, citron.Options{
    NetworkAllowlist: []string{"api.example.com"},
})

// Go API: scoped capability callback with HTTPGet / HTTPPost
caps.RequestNetwork([]string{"api.example.com"}, func(n caps.Network) (string, error) {
    body, err := caps.HTTPGet(n, "https://api.example.com/v1/status")
    if err != nil {
        return "", err
    }
    resp, err := caps.HTTPPost(n, "https://api.example.com/v1/data",
        `{"key": "value"}`, "application/json")
    return body, err
})
```

Hosts are validated against the configured allowlist, and redirect targets are re-checked, so a redirect cannot be used to escape the grant.

### IO Capability (`io`)

The `io` capability gates all output. Both `io.println` and Starlark's `print` are routed through the same gate:

```python
io.println("agent-visible output", 42)
print("same gate", 42)
```

When a secure output sink is configured via `SecureOutputPath`, `io.println` writes the **unmasked** classified content to that sink and `"Classified(****)"` to the agent-visible output.

### LLM (`llm`): Go API only

`caps.Chat` sends a message to the configured LLM, and `caps.ChatClassified` accepts and returns `Classified[string]`. Configure a backend first:

```go
caps.ConfigureLLM(&caps.LLMConfig{
    Model:    "gpt-4",
    APIKey:   os.Getenv("OPENAI_API_KEY"),
    Endpoint: "https://api.openai.com/v1/chat/completions",
})
```

```go
// Send a plain message:
answer, err := caps.Chat("What is the capital of Switzerland?")
```

`ChatClassified` keeps sensitive prompts and responses within the classified boundary:

```go
// Read a classified file, build the prompt with a pure map,
// and send it: the response stays Classified.
caps.RequestFileSystem("/data/secrets", nil, func(fsys caps.FileSystem) (string, error) {
    entry, _ := fsys.Access("question.txt")
    secret, _ := entry.ReadClassified()

    prompt := caps.Map(secret, func(q string) string {
        return "Summarize the following: " + q
    })
    summary, err := caps.ChatClassified(prompt)
    fmt.Println(summary) // "Classified(****)": response stays protected
    return "", err
})
```

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

## Runnable Examples

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
| [`examples/`](examples/) | Runnable examples |

## Remote MCP Tools as Capabilities

The [`mcpclient`](mcpclient/) package connects to a remote MCP server, lists its tools (including JSON Schema inputs and outputs), and **generates Go code** that wraps each tool as a Starlark builtin, turning remote MCP tools into first-class citron capabilities.

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
go run ./cmd/mcpgen --server --url http://localhost:9090/mcp --package main --output gen_remote.go
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

## Domain Facades (τ²-bench and AgentDojo)

A domain facade is a set of domain-specific Starlark tools exposed to agents, as in the **τ²-bench** (airline, retail) and **AgentDojo** (banking, slack, travel, workspace) scenarios. In citron, a domain facade combines the mechanisms shown above:

- Each domain's tools are **Starlark globals** injected through `Options.Extras` (the same mechanism used for remote MCP tool bindings), so every call is mediated by the harness.
- Reads that touch sensitive data return **`Classified`**, and flow through the pure-`map`/`flat_map` and masking guarantees, with no special-casing per domain.
- LLM calls go through `caps.Chat`, and unmasked classified output goes through the `SecureOutputPath` IO gate, never through the agent context.
- Structured results (users, orders, transactions) arrive as native Starlark `dict`/`list` values, exactly like MCP `StructuredContent` conversion.

### Airline (τ²-bench)

```python
# Query tools
airports = list_all_airports()
user = get_user_details(user_id="u_1")
res = get_reservation_details(reservation_id="r_1")
status = get_flight_status(flight_number="HA101", date="2026-05-01")
direct = search_direct_flight(origin="SFO", destination="ORD", date="2026-05-01")
onestop = search_onestop_flight(origin="SFO", destination="ORD", date="2026-05-01")
total = calculate(expression="1200 * 2 + 45")

# Booking tools
booked = book_reservation(
    user_id="u_1", origin="SFO", destination="ORD",
    flight_type="round_trip", cabin="economy",
    flights=[{"flight_number": "HA101", "date": "2026-05-01"}],
    payment_methods=[{"payment_id": "credit_card_1", "amount": 1245}],
    total_baggages=2, nonfree_baggages=0, insurance="no",
)

# Update tools
updated = update_reservation_flights(
    reservation_id="r_1", cabin="business",
    flights=[{"flight_number": "HA102", "date": "2026-05-02"}],
    payment_id="credit_card_1",
)
update_reservation_passengers(reservation_id="r_1", passengers=[...])
update_reservation_baggages(reservation_id="r_1",
    total_baggages=3, nonfree_baggages=1, payment_id="credit_card_1")

# Other tools
send_certificate(user_id="u_1", amount=50)
transfer_to_human_agents(summary="Complex itinerary change")
```

### Retail (τ²-bench)

```python
# User lookup tools
user_id = find_user_id_by_email(email="amy@example.com")
user_id = find_user_id_by_name_zip(first_name="Amy", last_name="Dean", zip="54321")

# Query tools
user = get_user_details(user_id=user_id)
order = get_order_details(order_id="#W0001")
product = get_product_details(product_id="1234567890")
types = list_all_product_types()

# Order modification tools (pending orders)
cancel_pending_order(order_id="#W0001", reason="no longer needed")
modify_pending_order_address(order_id="#W0001", address1="123 Main",
    address2="", city="Springfield", state="IL", country="US", zip="62701")
modify_pending_order_items(order_id="#W0001", item_ids=["1"],
    new_item_ids=["2"], payment_method_id="credit_card_1")
modify_pending_order_payment(order_id="#W0001", payment_method_id="gift_card_1")

# Delivered order tools
return_delivered_order_items(order_id="#W0002", item_ids=["1"],
    payment_method_id="credit_card_1")
exchange_delivered_order_items(order_id="#W0002", item_ids=["1"],
    new_item_ids=["3"], payment_method_id="credit_card_1")

# User modification tools
modify_user_address(user_id=user_id, address1="10 Elm", address2="",
    city="Austin", state="TX", country="US", zip="78701")
```

### Banking (AgentDojo)

All transaction reads return `Classified`, so account data cannot leak into the agent's context:

```python
# Account info
iban = get_iban()
balance = get_balance()
info = get_user_info()

# Transactions (Classified)
txns = get_most_recent_transactions(n=50)      # Classified
sched = get_scheduled_transactions()           # Classified
doc = read_file(path="statement.txt")          # Classified

# Pure transform on classified data, verified by the analyzer
def total_by_recipient(txn_list):
    return txn_list.map(lambda t: t["recipient"])

recipients = txns.map(total_by_recipient)
io.println(recipients)                         # Classified(****)

# Mutations
send_money(recipient="IBAN123", amount=250.0, subject="Rent", date="2026-05-01")
schedule_transaction(recipient="IBAN123", amount=250.0,
    subject="Rent", date="2026-06-01", recurring=True)
update_scheduled_transaction(id=7, amount=300.0)
update_password(password="correct-horse-battery-staple")
update_user_info(street="New Street 1")
```

### Slack (AgentDojo)

Message history is classified; outbound posts are plain mutations:

```python
# Reads (Classified)
channels = get_channels()                       # Classified
msgs = read_channel_messages(channel="general") # Classified
inbox = read_inbox(user="amy")                  # Classified
members = get_users_in_channel(channel="general")
page = get_webpage(url="https://example.com")   # Classified

# Mutations
add_user_to_channel(user="bob", channel="general")
send_direct_message(recipient="bob", body="FYI")
send_channel_message(channel="general", body="Standup at 10")
invite_user_to_slack(user="carol", user_email="carol@example.com")
remove_user_from_slack(user="dave")
post_webpage(url="https://example.com/report", content="...")
```

### Travel (AgentDojo)

```python
# User info
me = get_user_information()   # passport and card numbers are personal data;
                              # wrap as Classified on the Go side before
                              # injecting, so masking rules apply

# Hotels
hotels = get_all_hotels_in_city(city="Paris")
prices = get_hotels_prices(hotel_names=hotels)
reviews = get_rating_reviews_for_hotels(hotel_names=hotels)  # Classified
addr = get_hotels_address(hotel_name="Hotel Lumiere")

# Restaurants
restaurants = get_all_restaurants_in_city(city="Paris")
cuisines = get_cuisine_type_for_restaurants(restaurant_names=restaurants)
hours = check_restaurant_opening_hours(restaurant_names=restaurants)

# Car rental
companies = get_all_car_rental_companies_in_city(city="Paris")
per_day = get_car_price_per_day(company_names=companies)

# Calendar (Classified reads, plain mutations)
event = create_calendar_event(title="Dinner", start_time="2026-05-01T19:00",
    end_time="2026-05-01T21:00", participants=["amy@example.com"])
events = search_calendar_events(query="dinner")  # Classified
cancel_calendar_event(event_id=event["id"])

# Reservations
reserve_hotel(hotel="Hotel Lumiere", start_day="2026-05-01", end_day="2026-05-03")
reserve_car_rental(company="Hertz", start_time="2026-05-01T10:00")
reserve_restaurant(restaurant="Le Petit", start_time="2026-05-01T19:30")

# Flights & email
flights = get_flight_information(departure_city="Paris", arrival_city="Rome")
send_email(recipients=["amy@example.com"], subject="Trip", body="Booked!")
```

### Workspace (AgentDojo)

Email, contacts, calendar, and drive reads are all classified; only creation and deletion of plain content are unclassified:

```python
# Email reads (Classified)
unread = get_unread_emails()             # Classified
sent = get_sent_emails()                 # Classified
hits = search_emails(query="invoice")    # Classified
contacts = search_contacts_by_name(query="Amy")  # Classified

# Email mutations
send_email(recipients=["bob@example.com"], subject="Report",
    body="Attached", attachments=["file_ref_1"], cc=[], bcc=[])
delete_email(email_id="e_42")

# Calendar
day = get_current_day()
events = get_day_calendar_events(day="2026-05-01")  # Classified
event = create_calendar_event(title="1:1", start_time="2026-05-02T09:00",
    end_time="2026-05-02T09:30")
rescheduled = reschedule_calendar_event(event_id=event["id"],
    new_start_time="2026-05-02T10:00")              # Classified
add_calendar_event_participants(event_id=event["id"], participants=["bob@x.com"])

# Drive (Classified reads, plain create)
files = list_files()                        # Classified
by_name = search_files_by_filename(filename="report.pdf")  # Classified
doc = get_file_by_id(file_id="f_1")         # Classified
new = create_file(filename="notes.md", content="...")
delete_file(file_id="f_2")
append_to_file(file_id=new["id"], content="more")
shared = share_file(file_id=new["id"], email="bob@example.com",
    permission="read_write")                # Classified
```

### Registering a domain facade

Facades are plain `starlark.StringDict` globals. Generate them from a remote MCP server with `mcpgen` (recommended: schemas and `Classified` wrapping come for free), or hand-write them:

```go
session, _ := mcpclient.Connect(ctx, &mcpclient.Config{
    Transport: mcpclient.TransportStreamableHTTP,
    ServerURL: "http://localhost:9090/mcp",
})
airlineTools := myairline.RegisterMCPSession(session)

_, err := citron.SafeExecute(agentScript, citron.Options{
    Extras: airlineTools,
    // Unmasked classified output goes here instead
    // of the agent-visible stream.
    SecureOutputPath:   "/var/log/citron-secure.log",
    ClassifiedPatterns: []string{"secrets/**"},
})
```

Anything a facade returns that the agent must not see verbatim should be wrapped as `Classified` before it reaches Starlark; from that point on, the analyzer enforces the same pure-callback and masking rules as the built-in capabilities.

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
// File export (simplest: no SDK setup needed)
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

## MCP Server: citron as a Service

The [`cmd/citron/`](cmd/citron/) package runs an MCP server that exposes the entire citron safety harness as MCP tools. This follows the [code-execution-with-MCP](https://modelcontextprotocol.io) pattern: instead of loading dozens of tool definitions into context, the agent learns the harness API via `harness_guide` and writes Starlark code that citron safely executes.

```bash
# Stdio transport (default: pipe into your MCP client)
go run ./cmd/citron

# Streamable HTTP transport
PORT=9090 go run ./cmd/citron
```

### Available tools

| Tool | Description |
|------|-------------|
| `harness_guide` | Returns the full HARNESS_GUIDE.md. Call this first. |
| `execute_starlark` | Executes Starlark code through `citron.SafeExecute` with full safety guarantees. |
| `analyze_starlark` | Static analysis without execution; returns structured issues. |
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

MIT: see [LICENSE](LICENSE).
