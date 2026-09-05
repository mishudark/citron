package main

import (
	"reflect"
	"testing"
)

func TestSplitCommandQuoting(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"npx @server/everything", []string{"npx", "@server/everything"}},
		{`server --flag "a b"`, []string{"server", "--flag", "a b"}},
		{`sh -c 'echo "hello world"'`, []string{"sh", "-c", `echo "hello world"`}},
		{`path/with\ space --x`, []string{"path/with space", "--x"}},
		{`  spaced   out  `, []string{"spaced", "out"}},
		{`empty "" arg`, []string{"empty", "", "arg"}},
	}
	for _, tc := range cases {
		got, err := splitCommand(tc.in)
		if err != nil {
			t.Errorf("splitCommand(%q) error: %v", tc.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("splitCommand(%q) = %#v, want %#v", tc.in, got, tc.want)
		}
	}
	if _, err := splitCommand(`unterminated "quote`); err == nil {
		t.Error("unterminated quote should error")
	}
}
