//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/mishudark/citron"
)

func main() {
	dir, _ := os.MkdirTemp("", "citron-leak-*")
	defer os.RemoveAll(dir)
	os.WriteFile(dir+"/.env", []byte("API_KEY=sk-1234567890abcdef"), 0o644)

	opts := citron.Options{
		SeedDir:            dir,
		WorkingDir:         "/work",
		ClassifiedPatterns: []string{".env*"},
	}

	code := `
entry = fs.access(".env")
secret = entry.read_classified()

# Attempt 1: direct println of classified content
io.println("Agent sees println of classified:", secret)

# Attempt 2: pure map result
def to_upper(s):
    return s.upper()

out = secret.map(to_upper)
io.println("  pure map result:", out)

# Attempt 3: scope violation - fs cannot be accessed outside Starlark
# (This is implicitly tested by Starlark execution)
`
	res, err := citron.SafeExecute(code, opts)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Print(res.Output)
}
