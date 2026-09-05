package caps

import (
	"net"
	"strings"
	"testing"
	"time"
)

// Phase 2 regression tests: process capability timeout and network guards.

func TestExecTimeoutKillsProcess(t *testing.T) {
	_, err := RequestExecPermission([]string{"sleep"}, func(p ProcessPermission) (any, error) {
		start := time.Now()
		_, err := Exec(p, "sleep", []string{"10"}, ExecOptions{TimeoutMs: 150})
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("expected timeout error")
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("expected timeout error, got: %v", err)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("Exec took %v to return on timeout", elapsed)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("RequestExecPermission: %v", err)
	}
}

func TestExecCapturesOutput(t *testing.T) {
	_, err := RequestExecPermission([]string{"echo"}, func(p ProcessPermission) (any, error) {
		result, err := Exec(p, "echo", []string{"hello"}, ExecOptions{})
		if err != nil {
			t.Fatalf("Exec: %v", err)
		}
		if result.ExitCode != 0 {
			t.Fatalf("exit code = %d, want 0", result.ExitCode)
		}
		if got := result.Stdout; got != "hello\n" {
			t.Fatalf("stdout = %q, want %q", got, "hello\n")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("RequestExecPermission: %v", err)
	}
}

func TestValidatePortRejectsNonDefault(t *testing.T) {
	if err := validatePort("", "https"); err != nil {
		t.Fatalf("empty port should be allowed: %v", err)
	}
	if err := validatePort("443", "https"); err != nil {
		t.Fatalf("443/https should be allowed: %v", err)
	}
	if err := validatePort("80", "http"); err != nil {
		t.Fatalf("80/http should be allowed: %v", err)
	}
	if err := validatePort("8080", "https"); err == nil {
		t.Fatal("8080/https should be rejected")
	}
	if err := validatePort("8080", "http"); err == nil {
		t.Fatal("8080/http should be rejected")
	}
}

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.1.1", "0.0.0.0", "::1", "fe80::1", "fd00::1",
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "2606:4700::1111"}
	for _, s := range allowed {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should not be blocked", s)
		}
	}
}

func TestExecClassifiedWrapsOutput(t *testing.T) {
	_, err := RequestExecPermission([]string{"echo"}, func(p ProcessPermission) (any, error) {
		c, err := ExecClassified(p, "echo", []string{"hello"}, ExecOptions{})
		if err != nil {
			t.Fatalf("ExecClassified: %v", err)
		}
		if got := c.String(); got != "Classified(****)" {
			t.Fatalf("String() = %q, want masked", got)
		}
		unmasked, ok := c.unmask().(ProcessResult)
		if !ok {
			t.Fatalf("unmask returned %T", c.unmask())
		}
		if got := unmasked.Stdout; got != "hello\n" {
			t.Fatalf("stdout = %q, want %q", got, "hello\n")
		}
		if unmasked.ExitCode != 0 {
			t.Fatalf("exit code = %d, want 0", unmasked.ExitCode)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("RequestExecPermission: %v", err)
	}
}

func TestExecClassifiedRejectsNonAllowlisted(t *testing.T) {
	_, err := RequestExecPermission([]string{"echo"}, func(p ProcessPermission) (any, error) {
		_, err := ExecClassified(p, "printenv", nil, ExecOptions{})
		return nil, err
	})
	if err == nil {
		t.Fatal("expected allowlist error")
	}
	if !strings.Contains(err.Error(), "not in allowlist") {
		t.Fatalf("unexpected error: %v", err)
	}
}
