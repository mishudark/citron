package citron

import (
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

// An injected global (e.g. a remote MCP tool binding) that shadows a pure
// builtin would defeat callback purity verification: `secret.map(str)`
// would call the remote tool with the unwrapped classified value.
func TestSafeExecuteRejectsExtrasShadowingPureBuiltin(t *testing.T) {
	_, err := SafeExecute(`io.println("hi")`, Options{
		Extras: starlark.StringDict{"str": starlark.String("not the builtin")},
	})
	if err == nil {
		t.Fatal("expected error for extras global shadowing a pure builtin")
	}
	if !strings.Contains(err.Error(), "shadows the pure builtin") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// Non-regression: unrelated extras names are still accepted.
func TestSafeExecuteAcceptsUnrelatedExtras(t *testing.T) {
	result, err := SafeExecute(`io.println(get_weather(location="x"))`, Options{
		Extras: starlark.StringDict{
			"get_weather": starlark.NewBuiltin("get_weather", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				return starlark.String("sunny"), nil
			}),
		},
	})
	if err != nil {
		t.Fatalf("expected extras tool to be callable, got: %v", err)
	}
	if !strings.Contains(result.Output, "sunny") {
		t.Fatalf("expected tool output, got: %q", result.Output)
	}
}

func TestSessionExecuteRejectsExtrasShadowingPureBuiltin(t *testing.T) {
	s := NewSession(Options{
		Extras: starlark.StringDict{"list": starlark.NewBuiltin("list", nil)},
	})
	defer s.Close()
	_, err := s.Execute(`io.println("hi")`)
	if err == nil {
		t.Fatal("expected session to reject extras global shadowing a pure builtin")
	}
}
