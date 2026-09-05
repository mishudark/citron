package citron

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mishudark/citron/caps"
)

// exec_classified must classify command output: the agent-visible stream
// only ever shows masked values, while the secure sink receives the truth.
func TestExecClassifiedMasksOutput(t *testing.T) {
	opts := Options{
		WorkingDir:         "/work",
		CommandAllowlist:   []string{"echo"},
		ClassifiedPatterns: []string{"secret.out"},
	}

	code := `
out = proc.exec_classified("echo", ["hello"])
upper = out.stdout.map(lambda s: s.upper())
io.println(out.stdout)
io.println(upper)
io.println("exit code:", out.exit_code)
`
	res, err := SafeExecute(code, opts)
	if err != nil {
		t.Fatalf("SafeExecute: %v", err)
	}
	out := res.Output
	if !strings.Contains(out, "Classified(****)") {
		t.Fatalf("expected masked stdout, got: %q", out)
	}
	if strings.Contains(out, "hello") || strings.Contains(out, "HELLO") {
		t.Fatalf("classified command output leaked: %q", out)
	}
	if !strings.Contains(out, "exit code: 0") {
		t.Fatalf("exit code should be plain, got: %q", out)
	}
}

func TestExecClassifiedRejectsPlainWriteOfResult(t *testing.T) {
	code := `
out = proc.exec_classified("echo", ["x"])
f = fs.access("out.txt")
f.write(out.stdout)
`
	err := Analyze(code)
	if err == nil {
		t.Fatal("expected analysis rejection of write(exec_classified stdout)")
	}
	if !strings.Contains(err.Error(), "CLASSIFIED_WRITE_MISMATCH") {
		t.Fatalf("expected CLASSIFIED_WRITE_MISMATCH, got: %v", err)
	}
}

func TestLLMChatClassifiedBinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"llm-reply"}}]}`))
	}))
	defer srv.Close()

	seed := t.TempDir()
	if err := os.WriteFile(filepath.Join(seed, ".env"), []byte("my-secret-api-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := Options{
		WorkingDir:         "/work",
		SeedDir:            seed,
		ClassifiedPatterns: []string{".env"},
		LLM:                &caps.LLMConfig{Endpoint: srv.URL, Model: "test"},
	}

	code := `
secret = fs.access(".env").read_classified()
reply = llm.chat_classified(secret)
io.println(reply)
plain = llm.chat("hi")
io.println(plain)
`
	res, err := SafeExecute(code, opts)
	if err != nil {
		t.Fatalf("SafeExecute: %v", err)
	}
	out := res.Output
	if !strings.Contains(out, "Classified(****)") {
		t.Fatalf("classified LLM reply should be masked, got: %q", out)
	}
	if strings.Contains(out, "my-secret-api-key") {
		t.Fatalf("classified prompt leaked: %q", out)
	}
	if !strings.Contains(out, "llm-reply") {
		t.Fatalf("plain chat reply missing: %q", out)
	}
}

func TestLLMChatClassifiedRequiresClassifiedMessage(t *testing.T) {
	opts := Options{LLM: &caps.LLMConfig{Model: "test"}}
	_, err := SafeExecute(`llm.chat_classified("plain string")`, opts)
	if err == nil {
		t.Fatal("expected rejection of plain message to chat_classified")
	}
	if !strings.Contains(err.Error(), "must be Classified") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLLMUnconfiguredErrors(t *testing.T) {
	_, err := SafeExecute(`llm.chat("hi")`, Options{})
	if err == nil {
		t.Fatal("expected error when LLM is not configured")
	}
	if !strings.Contains(err.Error(), "LLM not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPostClassifiedRequiresClassifiedBody(t *testing.T) {
	opts := Options{NetworkAllowlist: []string{"api.example.com"}}
	_, err := SafeExecute(`net.post_classified("https://api.example.com", body="plain")`, opts)
	if err == nil {
		t.Fatal("expected rejection of plain body to post_classified")
	}
	if !strings.Contains(err.Error(), "body must be Classified") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSecureOutputPathInsideWorkingDirRejected(t *testing.T) {
	opts := Options{
		WorkingDir:       "/work",
		SecureOutputPath: "/work/secure.log",
	}
	_, err := SafeExecute(`io.println("hi")`, opts)
	if err == nil {
		t.Fatal("expected rejection of sink inside working dir")
	}
	if !strings.Contains(err.Error(), "inside WorkingDir") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSecureOutputPathOutsideWorkingDirAllowed(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "secure.log")
	seed := t.TempDir()
	if err := os.WriteFile(filepath.Join(seed, ".env"), []byte("secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		WorkingDir:         "/work",
		SeedDir:            seed,
		ClassifiedPatterns: []string{".env"},
		SecureOutputPath:   sink,
	}
	res, err := SafeExecute(`
secret = fs.access(".env").read_classified()
io.println(secret)
`, opts)
	if err != nil {
		t.Fatalf("SafeExecute: %v", err)
	}
	if strings.Contains(res.Output, "secret-value") {
		t.Fatal("agent output must stay masked")
	}
	data, err := os.ReadFile(sink)
	if err != nil {
		t.Fatalf("reading sink: %v", err)
	}
	if !strings.Contains(string(data), "secret-value") {
		t.Fatalf("secure sink should hold the truth, got: %q", data)
	}
	info, err := os.Stat(sink)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("sink perms = %o, want 600", perm)
	}
}

func TestAuditTrailRecordsClassifiedOps(t *testing.T) {
	seed := t.TempDir()
	if err := os.WriteFile(filepath.Join(seed, ".env"), []byte("secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		WorkingDir:         "/work",
		SeedDir:            seed,
		ClassifiedPatterns: []string{".env"},
	}
	res, err := SafeExecute(`
secret = fs.access(".env").read_classified()
io.println(secret)
`, opts)
	if err != nil {
		t.Fatalf("SafeExecute: %v", err)
	}
	if len(res.Audit) == 0 {
		t.Fatal("expected audit events")
	}
	var ops []string
	for _, e := range res.Audit {
		ops = append(ops, e.Op)
		if strings.Contains(e.Detail, "secret-value") {
			t.Fatalf("audit event carries classified value: %+v", e)
		}
	}
	joined := strings.Join(ops, ",")
	if !strings.Contains(joined, "read_classified") {
		t.Fatalf("expected read_classified event, got %v", ops)
	}
	if !strings.Contains(joined, "io.unmask") {
		t.Fatalf("expected io.unmask event, got %v", ops)
	}
}
