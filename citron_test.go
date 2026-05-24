package citron

import (
	"os"
	"path/filepath"
	"testing"
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
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("API_KEY=secret123"), 0644)

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
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("secret"), 0644)

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
