package caps

import (
	"bytes"
	"strings"
	"testing"
)

func TestIOCapabilityPrintln(t *testing.T) {
	var buf bytes.Buffer
	io := NewIOCapability(&buf, nil)

	captureOutput(t, func() {
		io.Println("hello")
	})

	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("expected output to contain hello, got %s", buf.String())
	}
}

func TestIOCapabilityPrintlnClassified(t *testing.T) {
	var secureBuf bytes.Buffer
	io := NewIOCapability(&secureBuf, nil)

	classified := Classify("secret-data")

	captureOutput(t, func() {
		io.Println(classified)
	})

	if !strings.Contains(secureBuf.String(), "secret-data") {
		t.Errorf("secure output should contain secret-data, got %s", secureBuf.String())
	}
}

func TestIOCapabilityPrint(t *testing.T) {
	var buf bytes.Buffer
	io := NewIOCapability(&buf, nil)

	captureOutput(t, func() {
		io.Print("hello ")
		io.Print("world")
	})

	if !strings.Contains(buf.String(), "hello world") {
		t.Errorf("expected hello world, got %s", buf.String())
	}
}

func TestIOCapabilityPrintf(t *testing.T) {
	var buf bytes.Buffer
	io := NewIOCapability(&buf, nil)

	captureOutput(t, func() {
		io.Printf("value: %d", 42)
	})

	if !strings.Contains(buf.String(), "value: 42") {
		t.Errorf("expected value: 42, got %s", buf.String())
	}
}

func captureOutput(t *testing.T, fn func()) {
	t.Helper()
	fn()
}
