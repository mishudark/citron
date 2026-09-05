package citron

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// Regression test: the timeout must cancel the running Starlark thread via
// thread.Cancel and wait for the execution goroutine to exit. Previously the
// goroutine kept mutating the virtual filesystem and network after the caller
// was told execution timed out.
func TestSafeExecuteTimeoutCancelsExecution(t *testing.T) {
	before := runtime.NumGoroutine()

	start := time.Now()
	_, err := SafeExecute(`
def spin():
    x = 0
    for i in range(1000000000000):
        x = x + 1

spin()
`, Options{TimeoutMs: 200})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got: %v", err)
	}

	// The exec goroutine must have exited (starlark cancellation takes effect
	// at the next evaluation step, so allow a grace period).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("execution goroutine leaked after timeout: before=%d after=%d", before, after)
	}

	// The call itself must return promptly, not block for the leaked script.
	if elapsed > 5*time.Second {
		t.Fatalf("SafeExecute took %v to return on timeout", elapsed)
	}
}

func TestSessionExecuteTimeoutCancelsExecution(t *testing.T) {
	before := runtime.NumGoroutine()

	s := NewSession(Options{TimeoutMs: 200})
	_, err := s.Execute(`
def spin():
    y = 0
    for i in range(1000000000000):
        y = y + 1

spin()
`)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("session execution goroutine leaked after timeout: before=%d after=%d", before, after)
	}

	// The session must remain usable after a timeout.
	res, err := s.Execute("io.println('still alive')")
	if err != nil {
		t.Fatalf("session unusable after timeout: %v", err)
	}
	if !strings.Contains(res.Output, "still alive") {
		t.Fatalf("unexpected output: %q", res.Output)
	}
}

// Regression test: concurrent Session.Execute calls must not race on the
// shared globals map. Each execution gets its own copy.
func TestSessionConcurrentExecute(t *testing.T) {
	s := NewSession(Options{})
	done := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func(i int) {
			code := "x = io.println('run ' + str("
			code += string(rune('0' + i))
			code += "))"
			_, err := s.Execute(code)
			done <- err
		}(i)
	}
	for i := 0; i < 4; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent Execute failed: %v", err)
		}
	}
}

// Regression: script-defined globals must persist across session executions.
// Note Starlark resolves assigned names to the module's own globals, so
// persisted globals are readable but not re-assignable; the read path is the
// supported session-state pattern.
func TestSessionGlobalsPersist(t *testing.T) {
	s := NewSession(Options{})
	if _, err := s.Execute("counter = 41"); err != nil {
		t.Fatalf("first execute: %v", err)
	}
	res, err := s.Execute("io.println(str(counter + 1))")
	if err != nil {
		t.Fatalf("second execute: %v", err)
	}
	if !strings.Contains(res.Output, "42") {
		t.Fatalf("session globals lost across executes, output: %q", res.Output)
	}
}
