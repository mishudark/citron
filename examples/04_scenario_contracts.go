//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/mishudark/citron"
)

func main() {
	dir, _ := os.MkdirTemp("", "citron-scenario-*")
	defer os.RemoveAll(dir)

	os.WriteFile(dir+"/contract_v1.txt", []byte("This agreement grants 20% equity vesting over 4 years with a 1-year cliff."), 0o644)
	os.WriteFile(dir+"/contract_v2.txt", []byte("This agreement grants 25% equity vesting over 3 years with a 6-month cliff."), 0o644)
	os.WriteFile(dir+"/summary_output.txt", []byte(""), 0o644)

	opts := citron.Options{
		SeedDir:            dir,
		WorkingDir:         "/work",
		ClassifiedPatterns: []string{"contract_*", "summary_output.txt"},
	}

	code := `
v1 = fs.access("contract_v1.txt").read_classified()
v2 = fs.access("contract_v2.txt").read_classified()

io.println("documents loaded (agent sees masked form):")
io.println("  v1:", v1)
io.println("  v2:", v2)

def compute_diff(s1):
    def inner(s2):
        return s1 + " <diff> " + s2
    return v2.map(inner)

diff = v1.flat_map(compute_diff)

io.println("diff computed (agent sees masked form):")
io.println("  diff:", diff)

def summarize(d):
    return "Contract changes: " + d

summary = diff.map(summarize)

io.println("summary ready (agent sees masked form):")
io.println("  summary:", summary)

out_f = fs.access("summary_output.txt")
out_f.write_classified(summary)
`
	res, err := citron.SafeExecute(code, opts)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Print(res.Output)
	fmt.Println("summary written to virtual filesystem")
}
