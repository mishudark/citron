package mcpclient

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"
)

// -- FromStarlark tests -- //

func TestFromStarlark_String(t *testing.T) {
	got := FromStarlark(starlark.String("hello"))
	want := "hello"
	if got != want {
		t.Fatalf("FromStarlark(String) = %v (%T), want %v", got, got, want)
	}
}

func TestFromStarlark_Int(t *testing.T) {
	got := FromStarlark(starlark.MakeInt(42))
	want := int64(42)
	if got != want {
		t.Fatalf("FromStarlark(Int) = %v (%T), want %v", got, got, want)
	}
}

func TestFromStarlark_Float(t *testing.T) {
	got := FromStarlark(starlark.Float(3.14))
	want := 3.14
	if got != want {
		t.Fatalf("FromStarlark(Float) = %v (%T), want %v", got, got, want)
	}
}

func TestFromStarlark_Bool(t *testing.T) {
	if got := FromStarlark(starlark.Bool(true)); got != true {
		t.Fatalf("FromStarlark(Bool(true)) = %v, want true", got)
	}
	if got := FromStarlark(starlark.Bool(false)); got != false {
		t.Fatalf("FromStarlark(Bool(false)) = %v, want false", got)
	}
}

func TestFromStarlark_None(t *testing.T) {
	got := FromStarlark(starlark.None)
	if got != nil {
		t.Fatalf("FromStarlark(None) = %v, want nil", got)
	}
}

func TestFromStarlark_List(t *testing.T) {
	sl := starlark.NewList([]starlark.Value{
		starlark.String("a"),
		starlark.MakeInt(1),
		starlark.Float(2.5),
	})
	got := FromStarlark(sl)
	want := []any{"a", int64(1), 2.5}
	if !deepEqual(got, want) {
		t.Fatalf("FromStarlark(List) = %v, want %v", got, want)
	}
}

func TestFromStarlark_Dict(t *testing.T) {
	sd := starlark.NewDict(2)
	_ = sd.SetKey(starlark.String("name"), starlark.String("test"))
	_ = sd.SetKey(starlark.String("count"), starlark.MakeInt(10))
	got := FromStarlark(sd)
	want := map[string]any{"name": "test", "count": int64(10)}
	if !deepEqual(got, want) {
		t.Fatalf("FromStarlark(Dict) = %v, want %v", got, want)
	}
}

func TestFromStarlark_Nested(t *testing.T) {
	// nested dict with list
	inner := starlark.NewDict(1)
	_ = inner.SetKey(starlark.String("items"), starlark.NewList([]starlark.Value{starlark.MakeInt(1), starlark.MakeInt(2)}))
	outer := starlark.NewDict(1)
	_ = outer.SetKey(starlark.String("data"), inner)
	got := FromStarlark(outer)
	want := map[string]any{"data": map[string]any{"items": []any{int64(1), int64(2)}}}
	if !deepEqual(got, want) {
		t.Fatalf("FromStarlark(Nested) = %v, want %v", got, want)
	}
}

func TestFromStarlark_Tuple(t *testing.T) {
	tup := starlark.Tuple{starlark.String("x"), starlark.MakeInt(2)}
	got := FromStarlark(tup)
	want := []any{"x", int64(2)}
	if !deepEqual(got, want) {
		t.Fatalf("FromStarlark(Tuple) = %v, want %v", got, want)
	}
}

// -- MCPResultToStarlark tests -- //

func TestMCPResultToStarlark_SingleText(t *testing.T) {
	result := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "hello world"}},
	}
	got, err := MCPResultToStarlark(result)
	if err != nil {
		t.Fatalf("MCPResultToStarlark returned error: %v", err)
	}
	s, ok := starlark.AsString(got)
	if !ok || s != "hello world" {
		t.Fatalf("MCPResultToStarlark = %v, want 'hello world'", got)
	}
}

func TestMCPResultToStarlark_Nil(t *testing.T) {
	got, err := MCPResultToStarlark(nil)
	if err != nil {
		t.Fatalf("MCPResultToStarlark(nil) returned error: %v", err)
	}
	if got != starlark.None {
		t.Fatalf("MCPResultToStarlark(nil) = %v, want None", got)
	}
}

func TestMCPResultToStarlark_EmptyContent(t *testing.T) {
	result := &mcp.CallToolResult{}
	got, err := MCPResultToStarlark(result)
	if err != nil {
		t.Fatalf("MCPResultToStarlark returned error: %v", err)
	}
	if got != starlark.None {
		t.Fatalf("MCPResultToStarlark(empty) = %v, want None", got)
	}
}

func TestMCPResultToStarlark_IsError(t *testing.T) {
	result := &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: "something went wrong"}},
	}
	_, err := MCPResultToStarlark(result)
	if err == nil {
		t.Fatal("MCPResultToStarlark should return error for IsError result")
	}
	if !strings.Contains(err.Error(), "something went wrong") {
		t.Fatalf("error message = %v, want 'something went wrong'", err)
	}
}

func TestMCPResultToStarlark_MultipleText(t *testing.T) {
	result := &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "first"},
			&mcp.TextContent{Text: "second"},
		},
	}
	got, err := MCPResultToStarlark(result)
	if err != nil {
		t.Fatalf("MCPResultToStarlark returned error: %v", err)
	}
	l, ok := got.(*starlark.List)
	if !ok {
		t.Fatalf("MCPResultToStarlark = %T, want *starlark.List", got)
	}
	if l.Len() != 2 {
		t.Fatalf("list.Len() = %d, want 2", l.Len())
	}
	if s, _ := starlark.AsString(l.Index(0)); s != "first" {
		t.Fatalf("list[0] = %v, want 'first'", l.Index(0))
	}
}

// -- GenerateTools tests -- //

func TestGenerateTools_Basic(t *testing.T) {
	tools := []*ToolInfo{
		{
			Name:        "get_weather",
			Description: "Get current weather for a location",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"location": map[string]any{"type": "string"},
					"units":    map[string]any{"type": "string", "enum": []any{"celsius", "fahrenheit"}},
				},
				"required": []any{"location"},
			},
			OutputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"temp":       map[string]any{"type": "number"},
					"conditions": map[string]any{"type": "string"},
				},
			},
		},
		{
			Name:        "search",
			Description: "Search the web",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string"},
				},
				"required": []any{"query"},
			},
		},
	}
	code, err := GenerateTools(tools, GenOptions{PackageName: "mytools"})
	if err != nil {
		t.Fatalf("GenerateTools: %v", err)
	}

	src := string(code)

	// Check package declaration
	if !strings.Contains(src, "package mytools") {
		t.Fatal("generated code missing package declaration")
	}

	// Check function declaration
	if !strings.Contains(src, "func RegisterMCPSession") {
		t.Fatal("generated code missing RegisterMCPSession function")
	}

	// Check tool names appear
	if !strings.Contains(src, `"get_weather"`) {
		t.Fatal("generated code missing get_weather tool")
	}
	if !strings.Contains(src, `"search"`) {
		t.Fatal("generated code missing search tool")
	}

	// Check descriptions appear as comments
	if !strings.Contains(src, "get_weather") && !strings.Contains(src, "Get current weather") {
		t.Fatal("generated code missing tool description")
	}

	// Check input property names from JSON Schema are referenced
	if !strings.Contains(src, "location") {
		t.Fatal("generated code missing input property 'location'")
	}

	// Check output property names from JSON Schema appear in comments
	if !strings.Contains(src, "Outputs:") {
		t.Fatal("generated code missing Outputs: section")
	}
	if !strings.Contains(src, "temp") || !strings.Contains(src, "conditions") {
		t.Fatal("generated code missing output properties")
	}
}

func TestGenerateTools_Empty(t *testing.T) {
	code, err := GenerateTools(nil, GenOptions{PackageName: "empty"})
	if err != nil {
		t.Fatalf("GenerateTools(nil): %v", err)
	}
	if !strings.Contains(string(code), "package empty") {
		t.Fatal("generated code missing package")
	}
	// Should return empty dict
	if !strings.Contains(string(code), "StringDict{}") {
		t.Fatal("generated code for no tools should return empty StringDict")
	}
}

func TestGenerateTools_MissingPackageName(t *testing.T) {
	_, err := GenerateTools(nil, GenOptions{})
	if err == nil {
		t.Fatal("GenerateTools with empty PackageName should error")
	}
}

func TestGenerateTools_CustomFuncName(t *testing.T) {
	tools := []*ToolInfo{{Name: "ping", Description: "Ping the server"}}
	code, err := GenerateTools(tools, GenOptions{PackageName: "pkg", FuncName: "MyFunc"})
	if err != nil {
		t.Fatalf("GenerateTools: %v", err)
	}
	if !strings.Contains(string(code), "func MyFunc") {
		t.Fatal("generated code should use custom function name")
	}
}

func TestGenerateTools_NoSchema(t *testing.T) {
	tools := []*ToolInfo{{Name: "ping", Description: "Ping the server"}}
	code, err := GenerateTools(tools, GenOptions{PackageName: "test"})
	if err != nil {
		t.Fatalf("GenerateTools: %v", err)
	}
	if !strings.Contains(string(code), `"ping"`) {
		t.Fatal("generated code missing ping tool")
	}
}

// -- End-to-end with in-memory MCP transport -- //

func TestConnectAndListTools_InMemory(t *testing.T) {
	// Build a server with one tool via the low-level AddTool API.
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "test-server",
		Version: "1.0.0",
	}, nil)

	server.AddTool(&mcp.Tool{
		Name:        "greet",
		Description: "Greet someone",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}}}`),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "Hello, " + args.Name + "!"}},
		}, nil
	})

	ctx := context.Background()
	session := connectInMemory(ctx, t, server)
	defer func() {
		if err := session.Close(); err != nil {
			t.Errorf("session close: %v", err)
		}
	}()

	// List tools.
	tools, err := ListTools(ctx, session)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	if len(tools) != 1 {
		t.Fatalf("ListTools returned %d tools, want 1", len(tools))
	}
	if tools[0].Name != "greet" {
		t.Fatalf("tool.Name = %q, want %q", tools[0].Name, "greet")
	}
	if tools[0].Description != "Greet someone" {
		t.Fatalf("tool.Description = %q, want %q", tools[0].Description, "Greet someone")
	}

	// Verify schema was captured.
	if tools[0].InputSchema == nil {
		t.Fatal("InputSchema should not be nil")
	}

	// Generate code from the tools.
	code, err := GenerateTools(tools, GenOptions{PackageName: "generated"})
	if err != nil {
		t.Fatalf("GenerateTools: %v", err)
	}
	if !strings.Contains(string(code), `"greet"`) {
		t.Fatal("generated code missing greet tool")
	}
}

// connectInMemory creates an in-memory MCP transport pair, connects the server
// and a client, and returns the client session.
func connectInMemory(ctx context.Context, t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "1.0.0",
	}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	return session
}

// -- GoToStarlark tests -- //

func TestGoToStarlark_Nil(t *testing.T) {
	got, err := GoToStarlark(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != starlark.None {
		t.Fatalf("GoToStarlark(nil) = %v, want None", got)
	}
}

func TestGoToStarlark_String(t *testing.T) {
	got, err := GoToStarlark("hello")
	if err != nil {
		t.Fatal(err)
	}
	s, ok := starlark.AsString(got)
	if !ok || s != "hello" {
		t.Fatalf("GoToStarlark(string) = %v, want 'hello'", got)
	}
}

func TestGoToStarlark_Bool(t *testing.T) {
	got, err := GoToStarlark(true)
	if err != nil {
		t.Fatal(err)
	}
	if got != starlark.True {
		t.Fatalf("GoToStarlark(true) = %v, want True", got)
	}
}

func TestGoToStarlark_Float64(t *testing.T) {
	got, err := GoToStarlark(float64(3.14))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := got.(starlark.Float)
	if !ok || float64(f) != 3.14 {
		t.Fatalf("GoToStarlark(float64) = %v, want 3.14", got)
	}
}

func TestGoToStarlark_Int64(t *testing.T) {
	got, err := GoToStarlark(int64(42))
	if err != nil {
		t.Fatal(err)
	}
	n, ok := got.(starlark.Int)
	if !ok {
		t.Fatalf("GoToStarlark(int64) = %T, want starlark.Int", got)
	}
	v, _ := n.Int64()
	if v != 42 {
		t.Fatalf("GoToStarlark(int64) = %d, want 42", v)
	}
}

func TestGoToStarlark_List(t *testing.T) {
	got, err := GoToStarlark([]any{"a", int64(1), float64(2.5)})
	if err != nil {
		t.Fatal(err)
	}
	l, ok := got.(*starlark.List)
	if !ok {
		t.Fatalf("GoToStarlark(list) = %T, want *starlark.List", got)
	}
	if l.Len() != 3 {
		t.Fatalf("list.Len() = %d, want 3", l.Len())
	}
}

func TestGoToStarlark_Dict(t *testing.T) {
	got, err := GoToStarlark(map[string]any{
		"name":  "test",
		"count": int64(10),
		"nested": map[string]any{
			"enabled": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	d, ok := got.(*starlark.Dict)
	if !ok {
		t.Fatalf("GoToStarlark(dict) = %T, want *starlark.Dict", got)
	}
	if d.Len() != 3 {
		t.Fatalf("dict.Len() = %d, want 3", d.Len())
	}
	v, _, _ := d.Get(starlark.String("name"))
	s, _ := starlark.AsString(v)
	if s != "test" {
		t.Fatalf("dict['name'] = %v, want 'test'", v)
	}
}

// -- MCPResultToStarlark with StructuredContent tests -- //

func TestMCPResultToStarlark_StructuredContent(t *testing.T) {
	result := &mcp.CallToolResult{
		StructuredContent: map[string]any{
			"temp":       float64(72.5),
			"conditions": "sunny",
		},
	}
	got, err := MCPResultToStarlark(result)
	if err != nil {
		t.Fatalf("MCPResultToStarlark returned error: %v", err)
	}
	d, ok := got.(*starlark.Dict)
	if !ok {
		t.Fatalf("MCPResultToStarlark = %T, want *starlark.Dict", got)
	}
	v, _, _ := d.Get(starlark.String("temp"))
	f, ok := v.(starlark.Float)
	if !ok || float64(f) != 72.5 {
		t.Fatalf("temp = %v, want 72.5", v)
	}
}

func TestMCPResultToStarlark_StructuredContentList(t *testing.T) {
	result := &mcp.CallToolResult{
		StructuredContent: []any{
			map[string]any{"id": int64(1), "label": "item1"},
			map[string]any{"id": int64(2), "label": "item2"},
		},
	}
	got, err := MCPResultToStarlark(result)
	if err != nil {
		t.Fatalf("MCPResultToStarlark returned error: %v", err)
	}
	l, ok := got.(*starlark.List)
	if !ok {
		t.Fatalf("MCPResultToStarlark = %T, want *starlark.List", got)
	}
	if l.Len() != 2 {
		t.Fatalf("list.Len() = %d, want 2", l.Len())
	}
}

func TestMCPResultToStarlark_StructuredContentPrecedesText(t *testing.T) {
	result := &mcp.CallToolResult{
		StructuredContent: map[string]any{"result": "from_structured"},
		Content:           []mcp.Content{&mcp.TextContent{Text: "from_text"}},
	}
	got, err := MCPResultToStarlark(result)
	if err != nil {
		t.Fatalf("MCPResultToStarlark returned error: %v", err)
	}
	d, ok := got.(*starlark.Dict)
	if !ok {
		t.Fatalf("MCPResultToStarlark should return dict for StructuredContent, got %T", got)
	}
	v, _, _ := d.Get(starlark.String("result"))
	s, _ := starlark.AsString(v)
	if s != "from_structured" {
		t.Fatalf("result = %v, want 'from_structured'", v)
	}
}

// -- helper -- //

func deepEqual(a, b any) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}
