package caps

import (
	"encoding/json"
	"fmt"
)

type Classified[T any] struct {
	value T
}

func Map[T, U any](c Classified[T], f func(T) U) Classified[U] {
	return Classified[U]{value: f(c.value)}
}

func FlatMap[T, U any](c Classified[T], f func(T) Classified[U]) Classified[U] {
	return f(c.value)
}

func (c Classified[T]) String() string {
	return "Classified(****)"
}

func (c Classified[T]) GoString() string {
	return "Classified(****)"
}

func (c Classified[T]) Format(f fmt.State, verb rune) {
	_, _ = fmt.Fprint(f, "Classified(****)")
}

func (Classified[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct{}{})
}

func (Classified[T]) UnmarshalJSON([]byte) error {
	return fmt.Errorf("cap: cannot unmarshal into Classified; use Classify to construct classified values explicitly")
}

func Classify[T any](v T) Classified[T] {
	return Classified[T]{value: v}
}

// Value returns the unmasked content. It is an escape hatch for trusted
// harness code (Starlark bindings, sinks) that must move the value between
// capability boundaries; the classified guarantees are enforced at the
// sandbox and output layers, not here.
func (c Classified[T]) Value() T {
	return c.value
}

type unmasker interface {
	unmask() any
}

func (c Classified[T]) unmask() any {
	return c.value
}
