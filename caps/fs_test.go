package caps

import (
	"testing"
)

func TestVirtualFileSystem(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/test/hello.txt", "Hello, World!")

	content, ok := vfs.Get("/test/hello.txt")
	if !ok {
		t.Fatal("expected file to exist")
	}
	if content != "Hello, World!" {
		t.Errorf("expected Hello, World!, got %s", content)
	}
}

func TestRequestVirtualFileSystemRead(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/data.txt", "file content")

	_, err := RequestVirtualFileSystem[any]("/work", vfs, nil, func(fs FileSystem) (any, error) {
		entry, err := fs.Access("data.txt")
		if err != nil {
			return nil, err
		}
		content, err := entry.Read()
		if err != nil {
			return nil, err
		}
		if content != "file content" {
			t.Errorf("expected file content, got %s", content)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRequestVirtualFileSystemWrite(t *testing.T) {
	vfs := NewVirtualFileSystem()

	_, err := RequestVirtualFileSystem[any]("/work", vfs, nil, func(fs FileSystem) (any, error) {
		entry, err := fs.Access("output.txt")
		if err != nil {
			return nil, err
		}
		return nil, entry.Write("new content")
	})
	if err != nil {
		t.Fatal(err)
	}

	content, ok := vfs.Get("/work/output.txt")
	if !ok {
		t.Fatal("expected file to exist")
	}
	if content != "new content" {
		t.Errorf("expected new content, got %s", content)
	}
}

func TestRequestVirtualFileSystemScope(t *testing.T) {
	vfs := NewVirtualFileSystem()

	var capturedFs FileSystem
	_, err := RequestVirtualFileSystem[any]("/work", vfs, nil, func(fs FileSystem) (any, error) {
		capturedFs = fs
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = capturedFs.Access("test.txt")
	if err == nil {
		t.Error("expected error using FileSystem outside scope")
	}
}

func TestFileEntryBasicMethod(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/readme.txt", "line1\nline2\nline3")

	_, err := RequestVirtualFileSystem[any]("/work", vfs, nil, func(fs FileSystem) (any, error) {
		entry, err := fs.Access("readme.txt")
		if err != nil {
			return nil, err
		}

		if entry.Name() != "readme.txt" {
			t.Errorf("expected readme.txt, got %s", entry.Name())
		}

		lines, err := entry.ReadLines()
		if err != nil {
			return nil, err
		}
		if len(lines) != 3 {
			t.Errorf("expected 3 lines, got %d", len(lines))
		}

		var lineCount int
		if err := entry.ForEachLine(func(line string, lineNum int) {
			lineCount++
		}); err != nil {
			t.Errorf("ForEachLine failed: %v", err)
		}
		if lineCount != 3 {
			t.Errorf("expected 3 lines via ForEachLine, got %d", lineCount)
		}

		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRequestVirtualFileSystemAppend(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/log.txt", "first line")

	_, err := RequestVirtualFileSystem[any]("/work", vfs, nil, func(fs FileSystem) (any, error) {
		entry, err := fs.Access("log.txt")
		if err != nil {
			return nil, err
		}
		return nil, entry.Append("\nsecond line")
	})
	if err != nil {
		t.Fatal(err)
	}

	content, _ := vfs.Get("/work/log.txt")
	if content != "first line\nsecond line" {
		t.Errorf("expected first line\\nsecond line, got %s", content)
	}
}

func TestRequestVirtualFileSystemDelete(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/temp.txt", "temporary")

	_, err := RequestVirtualFileSystem[any]("/work", vfs, nil, func(fs FileSystem) (any, error) {
		entry, err := fs.Access("temp.txt")
		if err != nil {
			return nil, err
		}
		return nil, entry.Delete()
	})
	if err != nil {
		t.Fatal(err)
	}

	_, ok := vfs.Get("/work/temp.txt")
	if ok {
		t.Error("expected file to be deleted")
	}
}

func TestClassifiedPathDetection(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/.env", "API_KEY=secret")
	vfs.Set("/work/readme.txt", "public")

	cfg := &FileSystemConfig{
		ClassifiedPatterns: []string{".env"},
	}

	_, err := RequestVirtualFileSystem[any]("/work", vfs, cfg, func(fs FileSystem) (any, error) {
		envEntry, err := fs.Access(".env")
		if err != nil {
			return nil, err
		}

		classified, err := envEntry.ReadClassified()
		if err != nil {
			return nil, err
		}
		if classified.String() != "Classified(****)" {
			t.Errorf("expected Classified(****), got %s", classified.String())
		}

		u := classified.unmask()
		if u != "API_KEY=secret" {
			t.Errorf("expected API_KEY=secret, got %v", u)
		}

		txtEntry, err := fs.Access("readme.txt")
		if err != nil {
			return nil, err
		}

		if txtEntry.IsClassified() {
			t.Error("readme.txt should not be classified")
		}

		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteClassified(t *testing.T) {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/.secret", "old")

	cfg := &FileSystemConfig{
		ClassifiedPatterns: []string{".secret"},
	}

	_, err := RequestVirtualFileSystem[any]("/work", vfs, cfg, func(fs FileSystem) (any, error) {
		entry, err := fs.Access(".secret")
		if err != nil {
			return nil, err
		}
		return nil, entry.WriteClassified(Classify("new-value"))
	})
	if err != nil {
		t.Fatal(err)
	}

	content, _ := vfs.Get("/work/.secret")
	if content != "new-value" {
		t.Errorf("expected new-value, got %s", content)
	}
}
