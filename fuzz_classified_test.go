package citron

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// classifiedLeaked checks whether classifiedValue appears in output
// as actual leaked data (not as part of legitimate "Classified(****)" masking).
func classifiedLeaked(output, classifiedValue string) bool {
	if classifiedValue == "" {
		return false
	}
	// Strip all legitimate masked representations and structural artifacts
	sanitized := strings.ReplaceAll(output, "Classified(****)", "")
	sanitized = strings.ReplaceAll(sanitized, "\n", "")
	sanitized = strings.TrimSpace(sanitized)
	if sanitized == "" {
		return false
	}
	return strings.Contains(sanitized, classifiedValue)
}

// FuzzClassifiedMapExpression runs random expressions inside a map callback
// and asserts that the classified value never appears in agent output or errors.
//
// The fuzzer mutates Starlark expressions (starting from the seed corpus),
// plugs them into c.map(lambda s: <expr>), and checks all observable outputs.
func FuzzClassifiedMapExpression(f *testing.F) {
	seeds := []string{
		"s",
		"s.upper()",
		"s + " + `"x"`,
		"str(s)",
		"len(s)",
		"repr(s)",
		"int(s)",
		"s[0]",
		"s[0:1]",
		`s.replace("a", "b")`,
		"s.split(\",\")",
		`s.format(s)`,
		"getattr(io, 'println')(s)",
		`getattr(getattr(fs, 'access')('/etc/passwd'), 'read')()`,
		"getattr(io, 'print')(s)",
		"hasattr(s, 'upper')",
		"type(s)",
		"bool(s)",
		"dir(s)",
		"s.count(\"S\")",
		"[x for x in s]",
		`"{}".format(s)`,
		"s > \"A\"",
		"s == s",
		"max(s)",
		"min(s)",
		"sorted(s)",
		"reversed(s)",
		"enumerate(s)",
		"all(s)",
		"any(s)",
		"list(s)",
		"tuple(s)",
		"set(s)",
		"dict(s)",
		"s.find(\"S\")",
		"s.index(\"S\")",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	classifiedValue := "CLASSIFIED_FUZZ_12345_SECRET"

	f.Fuzz(func(t *testing.T, expr string) {
		dir := t.TempDir()
		classifiedPath := "classified.txt"
		if err := os.WriteFile(filepath.Join(dir, classifiedPath), []byte(classifiedValue), 0o644); err != nil {
			t.Skip(err)
		}

		code := "entry = fs.access(\"" + classifiedPath + "\")\n" +
			"secret = entry.read_classified()\n" +
			"result = secret.map(lambda s: " + expr + ")\n" +
			"io.println(result)"

		result, err := SafeExecute(code, Options{
			WorkingDir:         "/work",
			SeedDir:            dir,
			ClassifiedPatterns: []string{"classified.txt"},
		})
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, classifiedValue) {
				t.Fatalf("LEAK: classified value in error for expr=%q: %s", expr, errMsg)
			}
		}

		if result != nil && classifiedLeaked(result.Output, classifiedValue) {
			t.Fatalf("LEAK: classified value in agent output for expr=%q: %s", expr, result.Output)
		}
	})
}

// FuzzClassifiedFlatMapExpression is the flat_map equivalent of the above.
func FuzzClassifiedFlatMapExpression(f *testing.F) {
	seeds := []string{
		"caps.Classify(s)",
		"caps.Classify(s.upper())",
		"caps.Classify(str(len(s)))",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	classifiedValue := "FLAT_FUZZ_SECRET_67890"

	f.Fuzz(func(t *testing.T, expr string) {
		dir := t.TempDir()
		classifiedPath := "secret.txt"
		if err := os.WriteFile(filepath.Join(dir, classifiedPath), []byte(classifiedValue), 0o644); err != nil {
			t.Skip(err)
		}

		code := "entry = fs.access(\"" + classifiedPath + "\")\n" +
			"secret = entry.read_classified()\n" +
			"result = secret.flat_map(lambda s: " + expr + ")\n" +
			"io.println(result)"

		result, err := SafeExecute(code, Options{
			WorkingDir:         "/work",
			SeedDir:            dir,
			ClassifiedPatterns: []string{"secret.txt"},
		})
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, classifiedValue) {
				t.Fatalf("LEAK: classified value in flat_map error: %s", errMsg)
			}
		}

		if result != nil && classifiedLeaked(result.Output, classifiedValue) {
			t.Fatalf("LEAK: classified value in flat_map output: %s", result.Output)
		}
	})
}

// FuzzClassifiedValueFormat varies the classified value format to test
// that masking holds for different payload shapes (secrets, keys, JSON, unicode, etc.)
func FuzzClassifiedValueFormat(f *testing.F) {
	seeds := []string{
		"API_KEY=sk-1234567890abcdef",
		`{"password":"hunter2"}`,
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
		"ghp_xxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyy",
		"AKIAIOSFODNN7EXAMPLE",
		"hello",
		"",
		"a",
		"\x00\x01\x02\xfe\xff",
		"日本語の秘密",
		strings.Repeat("A", 1000),
		"SECRET\nWITH\nNEWLINES",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	expr := "s"

	f.Fuzz(func(t *testing.T, classifiedValue string) {
		if len(classifiedValue) > 2000 {
			t.Skip("value too long")
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "key.txt"), []byte(classifiedValue), 0o644); err != nil {
			t.Skip(err)
		}

		code := "entry = fs.access(\"key.txt\")\n" +
			"secret = entry.read_classified()\n" +
			"io.println(secret)\n" +
			"result = secret.map(lambda s: " + expr + ")\n" +
			"io.println(result)"

		result, err := SafeExecute(code, Options{
			WorkingDir:         "/work",
			SeedDir:            dir,
			ClassifiedPatterns: []string{"key.txt"},
		})
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, classifiedValue) {
				t.Fatalf("LEAK: classified value in error for value=%q: %s", classifiedValue, errMsg)
			}
		}

		if result != nil && classifiedLeaked(result.Output, classifiedValue) {
			t.Fatalf("LEAK: classified value in output for value=%q: %s", classifiedValue, result.Output)
		}
	})
}

// FuzzPathSafety checks that no file path can escape the workspace root.
func FuzzPathSafety(f *testing.F) {
	seeds := []string{
		"classified.txt",
		"../etc/passwd",
		"../classified.txt",
		"./../../etc/shadow",
		"a/b/c/../../../etc/passwd",
		".../.../.../etc/passwd",
		"foo/bar",
		"/etc/passwd",
		"",
		".",
		"..",
		"...",
		"a/../../../b",
		`..\..\..\windows\system32\config`,
		"a/b/../../c/d/../../../etc/passwd",
		"link/somefile",
		"a/b/../../../etc/./passwd/.",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, path string) {
		if strings.Contains(path, "\x00") {
			t.Skip("null bytes not allowed")
		}
		dir := t.TempDir()
		workspace := dir + "/workspace"
		if err := os.MkdirAll(workspace, 0o755); err != nil {
			t.Skip(err)
		}

		// Create a classified file inside workspace
		if err := os.WriteFile(workspace+"/classified.txt", []byte("TOP_SECRET"), 0o644); err != nil {
			t.Skip(err)
		}

		code := "f = fs.access(\"" + strings.ReplaceAll(path, "\"", "\\\"") + "\")\n" +
			"io.println(f.read())"

		result, err := SafeExecute(code, Options{
			WorkingDir:         workspace,
			ClassifiedPatterns: []string{"classified.txt"},
		})

		if err == nil && result != nil {
			// If execution succeeded, the path was resolved inside the workspace.
			// Make sure we can't read the classified file via non-classified read.
			if strings.Contains(result.Output, "TOP_SECRET") {
				t.Fatalf("LEAK: classified file read via non-classified path %q: %s", path, result.Output)
			}
		}
	})
}

// FuzzSessionPersistence checks that classified data doesn't accumulate
// across multiple session turns in an unsafe way.
func FuzzSessionPersistence(f *testing.F) {
	seeds := []string{
		"x = 42",
		"io.println(\"hello\")",
		"s = fs.access(\"classified.txt\").read_classified()",
		"s.map(lambda x: x.upper())",
	}
	turn2Seeds := []string{
		"io.println(x)",
		"io.println(s)",
		"io.println(\"done\")",
	}
	for _, t1 := range seeds {
		for _, t2 := range turn2Seeds {
			f.Add(t1, t2)
		}
	}

	classifiedValue := "SESSION_SECRET_999"

	f.Fuzz(func(t *testing.T, turn1 string, turn2 string) {
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/classified.txt", []byte(classifiedValue), 0o644); err != nil {
			t.Skip(err)
		}

		s := NewSession(Options{
			WorkingDir:         "/work",
			SeedDir:            dir,
			ClassifiedPatterns: []string{"classified.txt"},
		})
		defer s.Close()

		_, err1 := s.Execute(turn1)
		if err1 != nil {
			return
		}

		result2, err2 := s.Execute(turn2)
		if err2 != nil {
			errMsg := err2.Error()
			if strings.Contains(errMsg, classifiedValue) {
				t.Fatalf("LEAK: classified value in session error: %s", errMsg)
			}
		}

		if result2 != nil && classifiedLeaked(result2.Output, classifiedValue) {
			t.Fatalf("LEAK: classified value in session output: %s", result2.Output)
		}
	})
}
