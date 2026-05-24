//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/mishudark/citron"
)

func main() {
	fmt.Println("=== citron: Safe Starlark Execution ===")

	dir, _ := os.MkdirTemp("", "citron-example-*")
	defer os.RemoveAll(dir)
	os.WriteFile(dir+"/hello.txt", []byte("Hello from citron!"), 0o644)

	opts := citron.Options{
		SeedDir:          dir,
		WorkingDir:       "/work",
		CommandAllowlist: []string{"echo"},
	}

	code := `
f = fs.access("hello.txt")
content = f.read()
io.println("File content:", content)

out = proc.exec("echo", ["citron is cool"])
io.println("Echo result:", out)
`
	res, err := citron.SafeExecute(code, opts)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Print(res.Output)
}
