package citron

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPipelinePureMap(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("secret"), 0o644)

	code := `
entry = fs.access(".env")
secret = entry.read_classified()
result = secret.map(lambda s: s.upper())
io.println(result)
`
	result, err := SafeExecute(code, Options{
		WorkingDir:         "/work",
		SeedDir:            dir,
		ClassifiedPatterns: []string{".env"},
	})
	if err != nil {
		t.Fatalf("unexpected error for pure map: %v", err)
	}
	t.Logf("Output: %s", result.Output)
}

func TestPipelineImpureMapBlocked(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("API_KEY=supersecret"), 0o644)

	code := `
entry = fs.access(".env")
secret = entry.read_classified()
result = secret.map(lambda s: (io.println(s), s.upper())[1])
io.println(result)
`
	_, err := SafeExecute(code, Options{
		WorkingDir:         "/work",
		SeedDir:            dir,
		ClassifiedPatterns: []string{".env"},
	})
	if err == nil {
		t.Fatal("expected error for io.println inside Map callback")
	}
	t.Logf("Blocked (expected): %v", err)
}

func TestPipelineImpureFsAccessMapBlocked(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("secret"), 0o644)

	code := `
entry = fs.access(".env")
secret = entry.read_classified()
result = secret.map(lambda s: (fs.access("other.txt").read(), s)[1])
io.println(result)
`
	_, err := SafeExecute(code, Options{
		WorkingDir:         "/work",
		SeedDir:            dir,
		ClassifiedPatterns: []string{".env"},
	})
	if err == nil {
		t.Fatal("expected error for fs.access inside Map callback")
	}
	t.Logf("Blocked (expected): %v", err)
}
