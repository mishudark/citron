package citron

import (
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
	f caps.FileEntry
}

func (s *starlarkFileEntry) String() string        { return fmt.Sprintf("<FileEntry %s>", s.f.Name()) }
func (s *starlarkFileEntry) Type() string          { return "FileEntry" }
func (s *starlarkFileEntry) Freeze()               {}
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
			ok := safeClassifiedMap(s.c, fn, thread, &result)
			if !ok {
				return nil, fmt.Errorf("map callback failed")
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
			ok := safeClassifiedFlatMap(s.c, fn, thread, &result)
			if !ok {
				return nil, fmt.Errorf("flat_map callback failed")
			}
			return &starlarkClassified{c: result}, nil
		}), nil
	}
	return nil, nil
}
func (s *starlarkClassified) AttrNames() []string { return []string{"map", "flat_map"} }

// safeClassifiedMap calls caps.Map with a panic-recovering wrapper so that
// any error from the starlark callback is returned as a sanitized error
// rather than leaking classified data through panic messages.
func safeClassifiedMap(c caps.Classified[string], fn starlark.Callable, thread *starlark.Thread, result *caps.Classified[string]) (ok bool) {
	defer func() { _ = recover() }()
	*result = caps.Map(c, func(val string) string {
		v, err := starlark.Call(thread, fn, starlark.Tuple{starlark.String(val)}, nil)
		if err != nil {
			panic("map callback failed")
		}
		if str, ok := starlark.AsString(v); ok {
			return str
		}
		return v.String()
	})
	return true
}

// safeClassifiedFlatMap is the flat_map equivalent with panic-safe error handling.
func safeClassifiedFlatMap(c caps.Classified[string], fn starlark.Callable, thread *starlark.Thread, result *caps.Classified[string]) (ok bool) {
	defer func() { _ = recover() }()
	*result = caps.FlatMap(c, func(val string) caps.Classified[string] {
		v, err := starlark.Call(thread, fn, starlark.Tuple{starlark.String(val)}, nil)
		if err != nil {
			panic("flat_map callback failed")
		}
		if sc, ok := v.(*starlarkClassified); ok {
			return sc.c
		}
		panic("flat_map callback must return Classified")
	})
	return true
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
			var vals []any
			for _, arg := range args {
				if sc, ok := arg.(*starlarkClassified); ok {
					vals = append(vals, sc.c) // pass caps.Classified to IO so it can unmask
				} else {
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
					if str, ok := starlark.AsString(cmdArgs.Index(i)); ok {
						strArgs = append(strArgs, str)
					}
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
