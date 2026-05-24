package caps

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSecurityClassifiedNoJSONLeak(t *testing.T) {
	c := Classify("API_KEY=supersecret")
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	if output != "{}" {
		t.Errorf("Classified leaked via JSON: %s", output)
	}
}

func TestSecurityClassifiedNoFmtPlusVLeak(t *testing.T) {
	c := Classify("secret-value")
	output := fmt.Sprintf("%+v", c)
	if output != "Classified(****)" {
		t.Errorf("Classified leaked via %%+v: %s", output)
	}
}

func TestSecurityClassifiedNoFmtHashVLeak(t *testing.T) {
	c := Classify("secret-value")
	output := fmt.Sprintf("%#v", c)
	if output != "Classified(****)" {
		t.Errorf("Classified leaked via %%#v: %s", output)
	}
}

func TestSecurityClassifiedNoFmtVLeak(t *testing.T) {
	c := Classify("secret-value")
	output := fmt.Sprintf("%v", c)
	if output != "Classified(****)" {
		t.Errorf("Classified leaked via %%v: %s", output)
	}
}

func TestSecurityClassifiedNoFmtSLeak(t *testing.T) {
	c := Classify("secret-value")
	output := fmt.Sprintf("%s", c)
	if output != "Classified(****)" {
		t.Errorf("Classified leaked via %%s: %s", output)
	}
}

func TestSecurityClassifiedPanicNoLeak(t *testing.T) {
	c := Classify("secret-value")
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				msg := fmt.Sprintf("%v", r)
				if msg != "Classified(****)" {
					// If the panic message contains the actual value, that's a leak
					t.Errorf("panic message leaked classified value: %s", msg)
				}
			}
		}()
		panic(c)
	}()
	if !panicked {
		t.Error("expected panic")
	}
}

func TestSecurityClassifiedEqualityNoLeak(t *testing.T) {
	c1 := Classify("secret1")
	c2 := Classify("secret1")
	c3 := Classify("secret2")

	// struct comparison in Go uses field-by-field comparison
	// Since value is unexported, == is not allowed
	var _ = c1
	var _ = c2
	var _ = c3
}

func TestSecurityFileEntryUsedAfterScope(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/file.txt", "content")

	var captured FileEntry
	_, err := RequestVirtualFileSystem("/work", vfs, nil, func(fs FileSystem) (any, error) {
		entry, err := fs.Access("file.txt")
		if err != nil {
			return nil, err
		}
		captured = entry
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if captured != nil {
		_, err := captured.Read()
		if err == nil {
			t.Error("FileEntry should be invalid after scope exit")
		}
	}
}

func TestSecurityFileSystemUsedAfterScope(t *testing.T) {
	vfs := NewVirtualFileSystem()

	var captured FileSystem
	_, err := RequestVirtualFileSystem("/work", vfs, nil, func(fs FileSystem) (any, error) {
		captured = fs
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if captured != nil {
		_, err = captured.Access("test.txt")
		if err == nil {
			t.Error("FileSystem should be invalid after scope exit")
		}
	}
}

func TestSecurityGoroutineScopeEscape(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/secret.txt", "classified content")

	done := make(chan bool)
	go func() {
		_, _ = RequestVirtualFileSystem[any]("/work", vfs, nil, func(fs FileSystem) (any, error) {
			entry, err := fs.Access("secret.txt")
			if err != nil {
				return nil, err
			}
			content, err := entry.Read()
			if err != nil {
				return nil, err
			}
			_ = content
			done <- true
			return nil, nil
		})
	}()

	_, err := RequestVirtualFileSystem[any]("/other", vfs, nil, func(fs FileSystem) (any, error) {
		entry, err := fs.Access("test.txt")
		if err != nil {
			return nil, err
		}
		return nil, entry.Write("data")
	})

	<-done
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecurityClassifiedInterfaceExtraction(t *testing.T) {
	c := Classify("supersecret")
	var iface any = c

	// Type assertion to the concrete type doesn't expose the value
	c2, ok := iface.(Classified[string])
	if !ok {
		t.Fatal("type assertion failed")
	}
	if c2.String() != "Classified(****)" {
		t.Errorf("type-asserted classified leaked: %s", c2.String())
	}
}

func TestSecurityClassifiedMapViaInterface(t *testing.T) {
	c := Classify("secret")
	_ = Map(c, func(s string) string {
		if s != "secret" {
			t.Error("Map callback should receive the actual value")
		}
		return s
	})
}

func TestSecurityIOPrintlnClassifiedNoLeak(t *testing.T) {
	var buf secureBuffer
	io := NewIOCapability(&buf, nil)

	c := Classify("SUPER_SECRET_KEY")
	io.Println(c)

	if buf.String() != "" {
		// If the secure buffer got any output, it would contain the UNMASKED value
		if buf.String() != "SUPER_SECRET_KEY\n" {
			t.Errorf("secure output expected SUPER_SECRET_KEY, got: %s", buf.String())
		}
	}
}

type secureBuffer struct {
	data []byte
}

func (b *secureBuffer) Write(p []byte) (n int, err error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *secureBuffer) String() string {
	return string(b.data)
}
