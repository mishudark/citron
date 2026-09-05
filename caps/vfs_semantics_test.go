package caps

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
)

// Phase 3 regression tests: glob semantics, directory semantics, quota,
// atomic Append, and Classified JSON handling.

func TestMatchPathGlobSemantics(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{".env", ".env", true},
		{".env", "sub/.env", false},   // wildcard-free: root only
		{".env", ".env/foo", true},    // directory-prefix fallback
		{"**/.env", "sub/.env", true}, // mid-path doublestar
		{"**/.env", ".env", true},     // ** matches zero segments
		{"a/**/b", "a/x/y/b", true},   // mid-path ** no longer degenerates
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/xb", false},
		{".aws/**", ".aws/credentials", true},
		{".aws/**", "other/.aws/credentials", false},
		{"**/.aws/**", "other/.aws/credentials", true},
		{".ssh/*", ".ssh/id_rsa", true},
		{".ssh/*", ".ssh/sub/id_rsa", false},
	}
	for _, tc := range cases {
		if got := matchPath(tc.pattern, tc.path); got != tc.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestVFSNestedClassifiedByDefault(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/sub/.env", "SECRET=1")
	_, err := RequestVirtualFileSystem("/work", vfs, nil, func(fs FileSystem) (any, error) {
		entry, err := fs.Access("sub/.env")
		if err != nil {
			t.Fatalf("Access: %v", err)
		}
		if _, err := entry.Read(); err == nil {
			t.Fatal("Read() on nested classified path should be rejected")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("RequestVirtualFileSystem: %v", err)
	}
}

func TestVFSListExactPrefixMatching(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/data/file.txt", "1")
	vfs.Set("/work/database/file.txt", "2")
	got := vfs.List("/work/data")
	if len(got) != 1 || got[0].Path != "/work/data/file.txt" {
		t.Fatalf("List(/work/data) = %+v, want only data/file.txt (prefix bug regression)", got)
	}
}

func TestVFSDirectorySemantics(t *testing.T) {
	vfs := NewVirtualFileSystem()
	_, err := RequestVirtualFileSystem("/work", vfs, nil, func(fs FileSystem) (any, error) {
		dir, err := fs.Access("a/b/c")
		if err != nil {
			t.Fatalf("Access: %v", err)
		}
		if err := dir.MkdirAll(); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if !dir.IsDir() {
			t.Fatal("mkdir'd path should be a directory")
		}

		f, _ := fs.Access("a/b/c/file.txt")
		if err := f.Write("content"); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if !f.Exists() {
			t.Fatal("written file should exist")
		}

		parent, _ := fs.Access("a/b")
		kids, err := parent.Children()
		if err != nil {
			t.Fatalf("Children: %v", err)
		}
		if len(kids) != 1 || kids[0].Name != "c" || !kids[0].IsDirectory {
			t.Fatalf("Children(a/b) = %+v, want directory c only", kids)
		}

		root, _ := fs.Access(".")
		all, err := root.Walk()
		if err != nil {
			t.Fatalf("Walk: %v", err)
		}
		// Expect dirs a, a/b, a/b/c plus the file.
		found := map[string]bool{}
		for _, d := range all {
			found[d.Path] = d.IsDirectory
		}
		for _, want := range []string{"/work/a", "/work/a/b", "/work/a/b/c", "/work/a/b/c/file.txt"} {
			if _, ok := found[want]; !ok {
				t.Fatalf("Walk missing %q: %+v", want, all)
			}
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("RequestVirtualFileSystem: %v", err)
	}
}

func TestVFSAppendIsAtomic(t *testing.T) {
	vfs := NewVirtualFileSystem()
	_, err := RequestVirtualFileSystem("/work", vfs, nil, func(fs FileSystem) (any, error) {
		entry, err := fs.Access("log.txt")
		if err != nil {
			return nil, err
		}
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = entry.Append("x")
			}()
		}
		wg.Wait()
		got, err := entry.Read()
		if err != nil {
			return nil, err
		}
		if len(got) != 16 {
			t.Fatalf("concurrent appends lost data: got %d chars, want 16", len(got))
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("RequestVirtualFileSystem: %v", err)
	}
}

func TestVFSQuotaRejectsOversizedWrite(t *testing.T) {
	vfs := NewVirtualFileSystem()
	_, err := RequestVirtualFileSystem("/work", vfs, nil, func(fs FileSystem) (any, error) {
		entry, err := fs.Access("big.txt")
		if err != nil {
			return nil, err
		}
		if err := entry.Write(strings.Repeat("a", maxVFSBytes)); err != nil {
			t.Fatalf("filling to the limit should succeed: %v", err)
		}
		other, _ := fs.Access("other.txt")
		if err := other.Write("x"); err == nil {
			t.Fatal("write beyond byte budget should be rejected")
		} else if !strings.Contains(err.Error(), "quota") {
			t.Fatalf("unexpected error: %v", err)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("RequestVirtualFileSystem: %v", err)
	}
}

func TestClassifiedUnmarshalJSONRejected(t *testing.T) {
	var c Classified[string]
	err := json.Unmarshal([]byte(`"secret"`), &c)
	if err == nil {
		t.Fatal("UnmarshalJSON into Classified must be rejected, not silently no-op")
	}
}

func TestWriteClassifiedRealFSPermissions(t *testing.T) {
	dir := t.TempDir()
	cfg := &FileSystemConfig{ClassifiedPatterns: []string{".env"}}
	_, err := RequestFileSystem(dir, cfg, func(fs FileSystem) (any, error) {
		entry, err := fs.Access(".env")
		if err != nil {
			return nil, err
		}
		if err := entry.WriteClassified(Classify("topsecret")); err != nil {
			t.Fatalf("WriteClassified: %v", err)
		}
		info, err := os.Stat(entry.Path())
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("classified file mode = %o, want 600", perm)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("RequestFileSystem: %v", err)
	}
}
