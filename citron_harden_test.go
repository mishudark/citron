package citron

import (
	"strings"
	"testing"

	"github.com/mishudark/citron/caps"
	"go.starlark.net/starlark"
)

// Phase 3 regression tests.

// TestFrozenFileEntryRejectsWrite verifies that Freeze() propagates to the
// wrapper and mutating operations are refused after freezing (previously all
// wrappers had empty Freeze() bodies).
func TestFrozenFileEntryRejectsWrite(t *testing.T) {
	err := func() error {
		_, err := caps.RequestVirtualFileSystem("/work", caps.NewVirtualFileSystem(), nil, func(fs caps.FileSystem) (any, error) {
			entry, err := fs.Access("out.txt")
			if err != nil {
				return nil, err
			}
			se := &starlarkFileEntry{f: entry}
			se.Freeze()

			thread := &starlark.Thread{Name: "test"}
			writeBuiltin, err := se.Attr("write")
			if err != nil || writeBuiltin == nil {
				t.Fatalf("Attr(write): %v", err)
			}
			_, werr := starlark.Call(thread, writeBuiltin, starlark.Tuple{starlark.String("data")}, nil)
			if werr == nil || !strings.Contains(werr.Error(), "frozen") {
				t.Fatalf("write on frozen entry should fail with 'frozen', got: %v", werr)
			}
			return nil, nil
		})
		return err
	}()
	if err != nil {
		t.Fatalf("frozen-entry test failed: %v", err)
	}
}

// TestAnalyzeAllIssuesReported verifies that citron.Analyze surfaces every
// issue, not just the first one.
func TestAnalyzeAllIssuesReported(t *testing.T) {
	// One shadowed pure builtin + one classified-write mismatch.
	code := `
len = 1
f = fs.access("x.txt")
secret = f.read_classified()
f.write(secret)
`
	err := Analyze(code)
	if err == nil {
		t.Fatal("expected analysis errors")
	}
	msg := err.Error()
	if !strings.Contains(msg, "SHADOWED_PURE_BUILTIN") || !strings.Contains(msg, "CLASSIFIED_WRITE_MISMATCH") {
		t.Fatalf("expected all issues to be reported, got: %s", msg)
	}
}
