package caps

import (
	"strings"
	"testing"
)

// Regression tests for the virtual filesystem path traversal escape.

func TestVirtualFSAccessRejectsTraversal(t *testing.T) {
	vfs := NewVirtualFileSystem()
	_, err := RequestVirtualFileSystem("/work", vfs, nil, func(fs FileSystem) (any, error) {
		for _, path := range []string{
			"../../etc/passwd",
			"../etc/passwd",
			"sub/../../escape.txt",
			"a/b/../../../escape.txt",
			"..",
		} {
			entry, err := fs.Access(path)
			if err == nil {
				t.Errorf("Access(%q) unexpectedly succeeded, resolved to %q", path, entry.Path())
				continue
			}
			if !strings.Contains(err.Error(), "escapes root") {
				t.Errorf("Access(%q) error should mention escape, got: %v", path, err)
			}
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("RequestVirtualFileSystem failed: %v", err)
	}
}

func TestVirtualFSAccessAllowsLegitimatePaths(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/hello.txt", "hello")
	vfs.Set("/work/sub/nested.txt", "nested")
	_, err := RequestVirtualFileSystem("/work", vfs, nil, func(fs FileSystem) (any, error) {
		for _, tc := range []struct {
			path string
			want string
		}{
			{"hello.txt", "hello"},
			{"./hello.txt", "hello"},
			{"sub/nested.txt", "nested"},
			{"sub/../hello.txt", "hello"},
		} {
			entry, err := fs.Access(tc.path)
			if err != nil {
				t.Errorf("Access(%q) failed: %v", tc.path, err)
				continue
			}
			got, err := entry.Read()
			if err != nil {
				t.Errorf("Read(%q) failed: %v", tc.path, err)
				continue
			}
			if got != tc.want {
				t.Errorf("Read(%q) = %q, want %q", tc.path, got, tc.want)
			}
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("RequestVirtualFileSystem failed: %v", err)
	}
}

func TestVirtualFSClassifiedStillEnforced(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/.env", "SECRET=1")
	_, err := RequestVirtualFileSystem("/work", vfs, nil, func(fs FileSystem) (any, error) {
		entry, err := fs.Access(".env")
		if err != nil {
			t.Fatalf("Access(.env) failed: %v", err)
		}
		if _, err := entry.Read(); err == nil {
			t.Fatal("Read() on classified path should be rejected")
		}
		c, err := entry.ReadClassified()
		if err != nil {
			t.Fatalf("ReadClassified failed: %v", err)
		}
		var gotLen int
		_ = FlatMap(c, func(v string) Classified[string] {
			gotLen = len(v)
			return Classify(v)
		})
		if gotLen != len("SECRET=1") {
			t.Fatalf("classified content length = %d, want %d", gotLen, len("SECRET=1"))
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("RequestVirtualFileSystem failed: %v", err)
	}
}
