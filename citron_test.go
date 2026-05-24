package citron

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestSafeExecuteRejectsImports(t *testing.T) {
	code := `load("os", "getenv")`
	_, err := SafeExecute(code, Options{})
	if err == nil {
		t.Fatal("expected error for code with imports")
	}
}

func TestSafeExecuteRejectsUnsafeCode(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("API_KEY=secret123"), 0o644)

	tests := []struct {
		name string
		code string
	}{
		{
			name: "undefined os module",
			code: `_ = os.Getenv("PATH")`,
		},
		{
			name: "undefined fmt module",
			code: `_ = fmt.Println("hello")`,
		},
		{
			name: "io.println inside map callback",
			code: `
entry = fs.access(".env")
secret = entry.read_classified()
result = secret.map(lambda s: (io.println(s), s.upper())[1])
io.println(result)
`,
		},
		{
			name: "fs.access inside map callback",
			code: `
entry = fs.access(".env")
secret = entry.read_classified()
result = secret.map(lambda s: (fs.access("other.txt").read(), s)[1])
io.println(result)
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SafeExecute(tt.code, Options{
				SeedDir:            dir,
				ClassifiedPatterns: []string{".env"},
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			t.Logf("blocked: %v", err)
		})
	}
}

func TestSessionCreateAndClose(t *testing.T) {
	s := NewSession(Options{})
	if s == nil {
		t.Fatal("expected non-nil session")
	}
	s.Close()
}

func TestSessionRejectsImports(t *testing.T) {
	s := NewSession(Options{})
	defer s.Close()

	_, err := s.Execute(`load("os", "getenv")`)
	if err == nil {
		t.Fatal("expected error for code with imports")
	}
}

func TestSessionRejectsImpureClassifiedCallback(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("secret"), 0o644)

	s := NewSession(Options{
		SeedDir:            dir,
		ClassifiedPatterns: []string{".env"},
	})
	defer s.Close()

	code := `
entry = fs.access(".env")
secret = entry.read_classified()
result = secret.map(lambda s: (io.println(s), s.upper())[1])
io.println(result)
`
	_, err := s.Execute(code)
	if err == nil {
		t.Fatal("expected error for impure Map callback")
	}
	t.Logf("blocked: %v", err)
}

// -- Extras tests -- //

func doubleBuiltin() *starlark.Builtin {
	return starlark.NewBuiltin("double", func(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var x int
		if err := starlark.UnpackPositionalArgs("double", args, kwargs, 1, &x); err != nil {
			return nil, err
		}
		return starlark.MakeInt(x * 2), nil
	})
}

func TestSafeExecuteWithExtras(t *testing.T) {
	extras := starlark.StringDict{"double": doubleBuiltin()}

	result, err := SafeExecute(`io.println(double(21))`, Options{
		Extras: extras,
	})
	if err != nil {
		t.Fatalf("SafeExecute with Extras: %v", err)
	}
	if result.Output != "42\n" {
		t.Fatalf("expected output '42\\n', got %q", result.Output)
	}
}

func TestSafeExecuteExtrasFallback(t *testing.T) {
	_, err := SafeExecute(`io.println(double(21))`, Options{})
	if err == nil {
		t.Fatal("expected error for undefined double without Extras")
	}
}

func TestSafeExecuteExtrasCannotOverrideBuiltins(t *testing.T) {
	extras := starlark.StringDict{
		"io": starlark.MakeInt(99),
	}
	result, err := SafeExecute(`io.println("hello")`, Options{
		Extras: extras,
	})
	if err != nil {
		t.Fatalf("SafeExecute with Extras attempting to override io: %v", err)
	}
	if result.Output != "\"hello\"\n" {
		t.Fatalf("expected output '\"hello\"\\n', got %q; io should be the real capability", result.Output)
	}
}

func TestSessionExecuteWithExtras(t *testing.T) {
	extras := starlark.StringDict{"double": doubleBuiltin()}

	s := NewSession(Options{
		Extras: extras,
	})
	defer s.Close()

	result, err := s.Execute(`io.println(double(21))`)
	if err != nil {
		t.Fatalf("Session.Execute with Extras: %v", err)
	}
	if result.Output != "42\n" {
		t.Fatalf("expected output '42\\n', got %q", result.Output)
	}
}

// -- Runtime error (passes analysis, fails at execution) -- //

func TestSafeExecuteRuntimeError(t *testing.T) {
	_, err := SafeExecute(`x = 1 // 0`, Options{})
	if err == nil {
		t.Fatal("expected runtime error")
	}
	t.Logf("runtime error:\n%v", err)
	if !strings.Contains(err.Error(), "Traceback") {
		t.Fatalf("error should contain traceback, got: %v", err)
	}
	if !strings.Contains(err.Error(), "agent.star:1") {
		t.Fatalf("error should contain source location, got: %v", err)
	}
}

func TestSafeExecuteTypeError(t *testing.T) {
	_, err := SafeExecute(`x = "hello" + 42`, Options{})
	if err == nil {
		t.Fatal("expected runtime error")
	}
	t.Logf("type error:\n%v", err)
	if !strings.Contains(err.Error(), "Traceback") {
		t.Fatalf("error should contain traceback, got: %v", err)
	}
	if !strings.Contains(err.Error(), "agent.star:1") {
		t.Fatalf("error should contain source location, got: %v", err)
	}
}

func TestCompareRuntimeVsAnalysisErrors(t *testing.T) {
	// Code with impure callback — caught by analysis before execution.
	code := `
entry = fs.access(".env")
secret = entry.read_classified()
result = secret.map(lambda s: (io.println(s), s.upper())[1])
`
	_, analysisErr := SafeExecute(code, Options{})
	if analysisErr == nil {
		t.Fatal("expected analysis error")
	}
	t.Logf("ANALYSIS error:  %v", analysisErr)

	// Code that passes analysis but fails at runtime.
	_, runtimeErr := SafeExecute(`x = 1 / 0`, Options{})
	if runtimeErr == nil {
		t.Fatal("expected runtime error")
	}
	t.Logf("RUNTIME error:\n%v", runtimeErr)

	// Analysis: structured with rule code, no traceback.
	if strings.Contains(analysisErr.Error(), "Traceback") {
		t.Fatal("analysis error should NOT contain traceback")
	}
	// Runtime: has traceback with call stack.
	if !strings.Contains(runtimeErr.Error(), "Traceback") {
		t.Fatal("runtime error SHOULD contain traceback")
	}
}
