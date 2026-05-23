package caps

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	c := Classify("secret")
	if c.String() != "Classified(****)" {
		t.Errorf("expected Classified(****), got %s", c.String())
	}
}

func TestClassifyInt(t *testing.T) {
	c := Classify(42)
	if c.String() != "Classified(****)" {
		t.Errorf("expected Classified(****), got %s", c.String())
	}
}

func TestMap(t *testing.T) {
	c := Classify("hello, world")
	result := Map(c, strings.ToUpper)
	if result.String() != "Classified(****)" {
		t.Errorf("expected Classified(****), got %s", result.String())
	}
}

func TestFlatMap(t *testing.T) {
	c := Classify(10)
	result := FlatMap(c, func(v int) Classified[string] {
		return Classify(strings.Repeat("x", v))
	})
	if result.String() != "Classified(****)" {
		t.Errorf("expected Classified(****), got %s", result.String())
	}
}

func TestUnmask(t *testing.T) {
	c := Classify("secret-value")
	u := c.unmask()
	if u != "secret-value" {
		t.Errorf("expected secret-value, got %v", u)
	}
}

func TestClassifyRoundTrip(t *testing.T) {
	original := "sensitive data"
	c := Classify(original)
	result := Map(c, func(s string) string {
		return "processed: " + s
	})
	u := result.unmask()
	if u != "processed: sensitive data" {
		t.Errorf("expected processed: sensitive data, got %v", u)
	}
}
