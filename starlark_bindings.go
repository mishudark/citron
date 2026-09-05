package citron

import (
	"errors"
	"fmt"

	"github.com/mishudark/citron/caps"
	"go.starlark.net/starlark"
)

// --- FileSystem Bindings ---

type starlarkFileSystem struct {
	fs caps.FileSystem
}

func (s *starlarkFileSystem) String() string        { return "<FileSystem>" }
func (s *starlarkFileSystem) Type() string          { return "FileSystem" }
func (s *starlarkFileSystem) Freeze()               {}
func (s *starlarkFileSystem) Truth() starlark.Bool  { return true }
func (s *starlarkFileSystem) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: FileSystem") }

func (s *starlarkFileSystem) Attr(name string) (starlark.Value, error) {
	if name == "access" {
		return starlark.NewBuiltin("access", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var path string
			if err := starlark.UnpackArgs("access", args, kwargs, "path", &path); err != nil {
				return nil, err
			}
			f, err := s.fs.Access(path)
			if err != nil {
				return nil, err
			}
			return &starlarkFileEntry{f: f}, nil
		}), nil
	}
	return nil, nil
}
func (s *starlarkFileSystem) AttrNames() []string { return []string{"access"} }

type starlarkFileEntry struct {
	f      caps.FileEntry
	frozen bool
}

func (s *starlarkFileEntry) String() string        { return fmt.Sprintf("<FileEntry %s>", s.f.Name()) }
func (s *starlarkFileEntry) Type() string          { return "FileEntry" }
func (s *starlarkFileEntry) Freeze()               { s.frozen = true }
func (s *starlarkFileEntry) Truth() starlark.Bool  { return true }
func (s *starlarkFileEntry) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: FileEntry") }

func (s *starlarkFileEntry) Attr(name string) (starlark.Value, error) {
	switch name {
	case "read":
		return starlark.NewBuiltin("read", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			data, err := s.f.Read()
			if err != nil {
				return nil, err
			}
			return starlark.String(data), nil
		}), nil
	case "write":
		return starlark.NewBuiltin("write", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if s.frozen {
				return nil, fmt.Errorf("write: FileEntry is frozen")
			}
			var data string
			if err := starlark.UnpackArgs("write", args, kwargs, "content", &data); err != nil {
				return nil, err
			}
			if err := s.f.Write(data); err != nil {
				return nil, err
			}
			return starlark.None, nil
		}), nil
	case "read_classified":
		return starlark.NewBuiltin("read_classified", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			c, err := s.f.ReadClassified()
			if err != nil {
				return nil, err
			}
			return &starlarkClassified{c: c}, nil
		}), nil
	case "write_classified":
		return starlark.NewBuiltin("write_classified", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if s.frozen {
				return nil, fmt.Errorf("write_classified: FileEntry is frozen")
			}
			var cv starlark.Value
			if err := starlark.UnpackArgs("write_classified", args, kwargs, "data", &cv); err != nil {
				return nil, err
			}
			sc, ok := cv.(*starlarkClassified)
			if !ok {
				return nil, fmt.Errorf("expected Classified data")
			}
			if err := s.f.WriteClassified(sc.c); err != nil {
				return nil, err
			}
			return starlark.None, nil
		}), nil
	}
	return nil, nil
}

func (s *starlarkFileEntry) AttrNames() []string {
	return []string{"read", "write", "read_classified", "write_classified"}
}

// --- Classified Bindings ---

type starlarkClassified struct {
	c caps.Classified[string]
}

func (s *starlarkClassified) String() string        { return s.c.String() }
func (s *starlarkClassified) Type() string          { return "Classified" }
func (s *starlarkClassified) Freeze()               {}
func (s *starlarkClassified) Truth() starlark.Bool  { return true }
func (s *starlarkClassified) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: Classified") }

func (s *starlarkClassified) Attr(name string) (starlark.Value, error) {
	if name == "map" {
		return starlark.NewBuiltin("map", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var fn starlark.Callable
			if err := starlark.UnpackArgs("map", args, kwargs, "callback", &fn); err != nil {
				return nil, err
			}

			var result caps.Classified[string]
			if err := safeClassifiedMap(s.c, fn, thread, &result); err != nil {
				return nil, err
			}
			return &starlarkClassified{c: result}, nil
		}), nil
	}
	if name == "flat_map" {
		return starlark.NewBuiltin("flat_map", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var fn starlark.Callable
			if err := starlark.UnpackArgs("flat_map", args, kwargs, "callback", &fn); err != nil {
				return nil, err
			}

			var result caps.Classified[string]
			if err := safeClassifiedFlatMap(s.c, fn, thread, &result); err != nil {
				return nil, err
			}
			return &starlarkClassified{c: result}, nil
		}), nil
	}
	return nil, nil
}
func (s *starlarkClassified) AttrNames() []string { return []string{"map", "flat_map"} }

// callbackError is a private sentinel used to carry a callback failure out
// of the caps.Map/FlatMap closures without letting an arbitrary panic escape.
type callbackError struct{ err error }

// sanitizeCallbackError strips the error message of a Starlark evaluation
// failure (which may echo classified data) but keeps its source position so
// failures remain debuggable.
func sanitizeCallbackError(err error) error {
	var evalErr *starlark.EvalError
	if errors.As(err, &evalErr) {
		stack := evalErr.CallStack
		if len(stack) > 0 {
			return fmt.Errorf("%s: callback error (message suppressed to avoid leaking classified data)", stack[len(stack)-1].Pos)
		}
		return errors.New("callback error (message suppressed to avoid leaking classified data)")
	}
	return err
}

// safeClassifiedMap calls caps.Map with a panic-recovering wrapper so that
// callback failures are returned as sanitized errors rather than leaking
// classified data through panic messages or error strings.
func safeClassifiedMap(c caps.Classified[string], fn starlark.Callable, thread *starlark.Thread, result *caps.Classified[string]) (cbErr error) {
	defer func() {
		if r := recover(); r != nil {
			if ce, ok := r.(callbackError); ok {
				cbErr = ce.err
				return
			}
			panic(r)
		}
	}()
	*result = caps.Map(c, func(val string) string {
		v, err := starlark.Call(thread, fn, starlark.Tuple{starlark.String(val)}, nil)
		if err != nil {
			panic(callbackError{sanitizeCallbackError(err)})
		}
		str, ok := starlark.AsString(v)
		if !ok {
			panic(callbackError{fmt.Errorf("map callback must return a string, got %s", v.Type())})
		}
		return str
	})
	return nil
}

// safeClassifiedFlatMap is the flat_map equivalent with panic-safe error handling.
func safeClassifiedFlatMap(c caps.Classified[string], fn starlark.Callable, thread *starlark.Thread, result *caps.Classified[string]) (cbErr error) {
	defer func() {
		if r := recover(); r != nil {
			if ce, ok := r.(callbackError); ok {
				cbErr = ce.err
				return
			}
			panic(r)
		}
	}()
	*result = caps.FlatMap(c, func(val string) caps.Classified[string] {
		v, err := starlark.Call(thread, fn, starlark.Tuple{starlark.String(val)}, nil)
		if err != nil {
			panic(callbackError{sanitizeCallbackError(err)})
		}
		if sc, ok := v.(*starlarkClassified); ok {
			return sc.c
		}
		panic(callbackError{fmt.Errorf("flat_map callback must return Classified, got %s", v.Type())})
	})
	return nil
}

// --- IOCapability Bindings ---

type starlarkIO struct {
	io *caps.IOCapability
}

func (s *starlarkIO) String() string        { return "<IOCapability>" }
func (s *starlarkIO) Type() string          { return "IOCapability" }
func (s *starlarkIO) Freeze()               {}
func (s *starlarkIO) Truth() starlark.Bool  { return true }
func (s *starlarkIO) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: IOCapability") }

func (s *starlarkIO) Attr(name string) (starlark.Value, error) {
	if name == "println" {
		return starlark.NewBuiltin("println", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if len(kwargs) > 0 {
				return nil, fmt.Errorf("println: unexpected keyword arguments")
			}
			var vals []any
			for _, arg := range args {
				switch v := arg.(type) {
				case *starlarkClassified:
					vals = append(vals, v.c) // pass caps.Classified to IO so it can unmask
				case starlark.String:
					vals = append(vals, string(v)) // print text, not the quoted repr
				default:
					vals = append(vals, arg.String())
				}
			}
			s.io.Println(vals...)
			return starlark.None, nil
		}), nil
	}
	return nil, nil
}
func (s *starlarkIO) AttrNames() []string { return []string{"println"} }

// --- Network and Proc Bindings ---

// Create starlark wrappers for HTTPGet, HTTPPost and Exec.

type starlarkNetwork struct {
	n caps.Network
}

func (s *starlarkNetwork) String() string        { return "<Network>" }
func (s *starlarkNetwork) Type() string          { return "Network" }
func (s *starlarkNetwork) Freeze()               {}
func (s *starlarkNetwork) Truth() starlark.Bool  { return true }
func (s *starlarkNetwork) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: Network") }

func (s *starlarkNetwork) Attr(name string) (starlark.Value, error) {
	if name == "get" {
		return starlark.NewBuiltin("get", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var url string
			if err := starlark.UnpackArgs("get", args, kwargs, "url", &url); err != nil {
				return nil, err
			}
			body, err := caps.HTTPGet(s.n, url)
			if err != nil {
				return nil, err
			}
			return starlark.String(body), nil
		}), nil
	}
	return nil, nil
}
func (s *starlarkNetwork) AttrNames() []string { return []string{"get"} }

type starlarkProc struct {
	p caps.ProcessPermission
}

func (s *starlarkProc) String() string        { return "<ProcessPermission>" }
func (s *starlarkProc) Type() string          { return "ProcessPermission" }
func (s *starlarkProc) Freeze()               {}
func (s *starlarkProc) Truth() starlark.Bool  { return true }
func (s *starlarkProc) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: ProcessPermission") }

func (s *starlarkProc) Attr(name string) (starlark.Value, error) {
	if name == "exec" {
		return starlark.NewBuiltin("exec", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var command string
			var cmdArgs *starlark.List
			if err := starlark.UnpackArgs("exec", args, kwargs, "command", &command, "args?", &cmdArgs); err != nil {
				return nil, err
			}

			var strArgs []string
			if cmdArgs != nil {
				for i := 0; i < cmdArgs.Len(); i++ {
					str, ok := starlark.AsString(cmdArgs.Index(i))
					if !ok {
						return nil, fmt.Errorf("exec: args[%d] must be a string, got %s", i, cmdArgs.Index(i).Type())
					}
					strArgs = append(strArgs, str)
				}
			}

			out, err := caps.ExecOutput(s.p, command, strArgs)
			if err != nil {
				return nil, err
			}
			return starlark.String(out), nil
		}), nil
	}
	return nil, nil
}
func (s *starlarkProc) AttrNames() []string { return []string{"exec"} }
