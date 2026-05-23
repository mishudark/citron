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

	opts := citron.Options{
		SeedDir:    dir,
		WorkingDir: "/work",
	}

	code := `
f = fs.access("OUTPUT.md")
f.write("The answer is 42.")
io.println("wrote: The answer is 42.")

content = f.read()
io.println("read back:", content)
`
	res, err := citron.SafeExecute(code, opts)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Print(res.Output)
}
