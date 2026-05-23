package mcpclient

import (
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"
)

// FromStarlark converts a starlark.Value to a plain Go value suitable for
// passing as an MCP tool argument (i.e. json.Marshal-able).
//
// Mapping:
//
//	starlark.String    → string
//	starlark.Int       → int64
//	starlark.Float     → float64
//	starlark.Bool      → bool
//	starlark.NoneType  → nil
//	*starlark.List     → []any
//	*starlark.Dict     → map[string]any
//	*starlark.Tuple    → []any
//	*starlark.Set      → []any
//	starlark.Callable  → string (.String())
//	other              → string (fallback, .String())
func FromStarlark(v starlark.Value) any {
	switch val := v.(type) {
	case starlark.String:
		return string(val)
	case starlark.Int:
		n, ok := val.Int64()
		if ok {
			return n
		}
		return val.String()
	case starlark.Float:
		return float64(val)
	case starlark.Bool:
		return bool(val)
	case starlark.NoneType:
		return nil
	case *starlark.List:
		elems := make([]any, val.Len())
		for i := 0; i < val.Len(); i++ {
			elems[i] = FromStarlark(val.Index(i))
		}
		return elems
	case starlark.Tuple:
		elems := make([]any, val.Len())
		for i := 0; i < val.Len(); i++ {
			elems[i] = FromStarlark(val.Index(i))
		}
		return elems
	case *starlark.Set:
		elems := make([]any, 0, val.Len())
		it := val.Iterate()
		defer it.Done()
		var elem starlark.Value
		for it.Next(&elem) {
			elems = append(elems, FromStarlark(elem))
		}
		return elems
	case *starlark.Dict:
		out := make(map[string]any, val.Len())
		for _, item := range val.Items() {
			key, ok := starlark.AsString(item[0])
			if !ok {
				continue
			}
			out[key] = FromStarlark(item[1])
		}
		return out
	default:
		return v.String()
	}
}

// MCPResultToStarlark converts an MCP CallToolResult into a starlark.Value.
//
// Rules:
//   - If the result is an error (IsError), it returns a (nil, error) tuple.
//   - StructuredContent (non-nil) → converted via GoToStarlark.
//   - Single TextContent → starlark.String.
//   - Single non-text content → JSON string.
//   - Multiple content items → *starlark.List of strings.
func MCPResultToStarlark(result *mcp.CallToolResult) (starlark.Value, error) {
	if result == nil {
		return starlark.None, nil
	}

	// If the server explicitly signals an error, propagate it.
	if result.IsError {
		text := extractErrorText(result)
		return nil, fmt.Errorf("mcp tool error: %s", text)
	}

	// Prefer structured content when present.  This is the data path that
	// corresponds to the tool's OutputSchema.
	if result.StructuredContent != nil {
		return GoToStarlark(result.StructuredContent)
	}

	n := len(result.Content)
	if n == 0 {
		return starlark.None, nil
	}
	if n == 1 {
		return singleContentToStarlark(result.Content[0])
	}

	items := make([]starlark.Value, n)
	for i, c := range result.Content {
		s, err := singleContentToStarlark(c)
		if err != nil {
			s = starlark.String(fmt.Sprintf("<error: %v>", err))
		}
		items[i] = s
	}
	return starlark.NewList(items), nil
}

// GoToStarlark converts a plain Go value (typically from JSON unmarshaling)
// into the corresponding starlark.Value.
//
// Mapping:
//
//	nil              → starlark.None
//	string           → starlark.String
//	bool             → starlark.Bool
//	float64          → starlark.Float
//	int              → starlark.MakeInt
//	int64            → starlark.MakeInt64
//	json.Number      → starlark.String (preserves original representation)
//	[]any            → *starlark.List (each element recursed)
//	map[string]any   → *starlark.Dict  (keys are strings, values recursed)
//	other            → starlark.String(fmt.Sprint(v))
func GoToStarlark(v any) (starlark.Value, error) {
	switch val := v.(type) {
	case nil:
		return starlark.None, nil
	case string:
		return starlark.String(val), nil
	case bool:
		return starlark.Bool(val), nil
	case float64:
		return starlark.Float(val), nil
	case int:
		return starlark.MakeInt(val), nil
	case int64:
		return starlark.MakeInt64(val), nil
	case uint64:
		return starlark.MakeUint64(val), nil
	case []any:
		elems := make([]starlark.Value, len(val))
		for i, e := range val {
			s, err := GoToStarlark(e)
			if err != nil {
				return nil, err
			}
			elems[i] = s
		}
		return starlark.NewList(elems), nil
	case map[string]any:
		d := starlark.NewDict(len(val))
		for k, vv := range val {
			sv, err := GoToStarlark(vv)
			if err != nil {
				return nil, err
			}
			if err := d.SetKey(starlark.String(k), sv); err != nil {
				return nil, err
			}
		}
		return d, nil
	case json.Number:
		return starlark.String(val.String()), nil
	default:
		return starlark.String(fmt.Sprint(val)), nil
	}
}

// -- internal helpers -- //

func singleContentToStarlark(c mcp.Content) (starlark.Value, error) {
	switch v := c.(type) {
	case *mcp.TextContent:
		return starlark.String(v.Text), nil
	default:
		data, err := json.Marshal(c)
		if err != nil {
			return starlark.String(fmt.Sprintf("%v", c)), nil
		}
		return starlark.String(string(data)), nil
	}
}

func extractErrorText(result *mcp.CallToolResult) string {
	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	return "tool returned an error (no details)"
}
