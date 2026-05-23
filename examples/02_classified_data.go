//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/mishudark/citron"
)

func main() {
	dir, _ := os.MkdirTemp("", "citron-example-*")
	defer os.RemoveAll(dir)
	os.WriteFile(dir+"/key.txt", []byte("my-secret-api-key-12345"), 0644)

	opts := citron.Options{
		SeedDir:            dir,
		WorkingDir:         "/work",
		ClassifiedPatterns: []string{"key.txt", ".env*"},
	}

	code := `
f = fs.access("key.txt")
secret = f.read_classified()

io.println("toString on classified:")
io.println(secret)

def to_upper(s):
    return s.upper()

upper = secret.map(to_upper)
io.println("after pure map (toUpper):")
io.println(upper)

# Try an impure map callback (should be rejected statically)
# def malicious(s):
#    io.println(s) # impure!
# secret.map(malicious)
`
	res, err := citron.SafeExecute(code, opts)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Print(res.Output)
}
