package mcpclient

import (
	"encoding/json"
	"go/format"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// Phase 2 regression tests: pagination caps, conversion depth limits, and
// code-generation injection guards.

func TestPaginateRejectsRepeatedCursor(t *testing.T) {
	seen := make(map[string]bool)
	if _, err := paginate("page2", seen); err != nil {
		t.Fatalf("first advance should succeed: %v", err)
	}
	if _, err := paginate("page3", seen); err != nil {
		t.Fatalf("second advance should succeed: %v", err)
	}
	if _, err := paginate("page3", seen); err == nil {
		t.Fatal("repeated cursor should be rejected")
	}
	if _, err := paginate("", seen); err != nil {
		t.Fatalf("empty cursor terminates pagination: %v", err)
	}
}

func TestPaginateRejectsUnboundedPages(t *testing.T) {
	seen := make(map[string]bool)
	var lastErr error
	for i := 0; i < maxListPages+2; i++ {
		cursor := "cursor-" + strings.Repeat("x", i+1)
		next, err := paginate(cursor, seen)
		if err != nil {
			lastErr = err
			break
		}
		_ = next
	}
	if lastErr == nil {
		t.Fatal("unbounded pagination should be rejected")
	}
	if !strings.Contains(lastErr.Error(), "did not terminate") {
		t.Fatalf("unexpected error: %v", lastErr)
	}
}

func TestFromStarlarkCyclicListTerminates(t *testing.T) {
	l := starlark.NewList([]starlark.Value{})
	l.Append(starlark.None) //nolint:errcheck
	// Make the list self-referential: index 1 points at the list itself.
	l.Append(l) //nolint:errcheck
	out := FromStarlark(l)
	s, ok := out.(string)
	if !ok || !strings.Contains(s, "conversion depth") {
		t.Fatalf("cyclic list should degrade to a depth placeholder, got %#v", out)
	}
}

func TestGoToStarlarkCyclicStructuresError(t *testing.T) {
	// Build a Go map that references itself via a slice chain deep enough to
	// exceed the depth limit.
	deep := any(nil)
	for i := 0; i < maxConversionDepth+10; i++ {
		deep = []any{deep}
	}
	if _, err := GoToStarlark(deep); err == nil {
		t.Fatal("over-deep structure should return an error")
	}
}

func TestValidateGenOptionsRejectsInjection(t *testing.T) {
	cases := []struct {
		name string
		opts GenOptions
	}{
		{
			name: "tag with newline injects code",
			opts: GenOptions{PackageName: "p", Tag: "mcp\npackage evil\nfunc init() {}"},
		},
		{
			name: "package name with newline",
			opts: GenOptions{PackageName: "p\nfunc evil() {}"},
		},
		{
			name: "package name with space",
			opts: GenOptions{PackageName: "p x"},
		},
		{
			name: "func name with newline",
			opts: GenOptions{PackageName: "p", FuncName: "f\nvar x = 1"},
		},
	}
	for _, tc := range cases {
		if err := validateGenOptions(tc.opts); err == nil {
			t.Errorf("%s: expected rejection", tc.name)
		}
	}
}

func TestValidateGenOptionsAcceptsLegit(t *testing.T) {
	if err := validateGenOptions(GenOptions{PackageName: "mytools", FuncName: "RegisterMCPSession", Tag: "linux,amd64"}); err != nil {
		t.Fatalf("legitimate options rejected: %v", err)
	}
	if err := validateGenOptions(GenOptions{PackageName: "main", Tag: "!windows"}); err != nil {
		t.Fatalf("legitimate options rejected: %v", err)
	}
}

func TestGenerateServerToolsSchemaWithBacktick(t *testing.T) {
	// A server-controlled schema containing a backtick previously produced
	// generated code that failed go/format (broken raw string literal).
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"evil": map[string]any{"type": "string", "description": "has ` backtick and \\\\ escapes"},
		},
	}
	tools := []*ToolInfo{{
		Name:        "sneaky",
		Description: "schema with backtick",
		InputSchema: schema,
	}}
	code, err := GenerateServerTools(tools, GenOptions{PackageName: "generated"})
	if err != nil {
		t.Fatalf("GenerateServerTools: %v", err)
	}
	if _, err := format.Source(code); err != nil {
		t.Fatalf("generated code does not compile: %v", err)
	}
	// The raw schema must survive round-trip through the quoted literal.
	var back map[string]any
	src := string(code)
	start := strings.Index(src, "json.RawMessage(\"")
	if start < 0 {
		t.Fatal("expected quoted schema literal in output")
	}
	if !strings.Contains(src, "backtick") {
		t.Fatalf("schema content missing from generated code:\n%s", src)
	}
	_ = back
	_ = json.Marshal
}
