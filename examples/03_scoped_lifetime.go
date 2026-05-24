//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/mishudark/citron"
)

func main() {
	dir, _ := os.MkdirTemp("", "citron-scope-*")
	defer os.RemoveAll(dir)
	os.WriteFile(dir+"/secret.txt", []byte("classified-content"), 0o644)

	opts := citron.Options{
		SeedDir:    dir,
		WorkingDir: "/work",
	}

	// Session scopes lifetimes
	sess := citron.NewSession(opts)
	defer sess.Close()

	code := `
f = fs.access("secret.txt")
content = f.read()
io.println("inside scope: read", content)
`
	res, err := sess.Execute(code)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Print(res.Output)
	fmt.Println("scope exited, session is closed")
}
