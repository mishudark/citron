package caps

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

type VirtualFileSystem struct {
	files sync.Map
}

func NewVirtualFileSystem() *VirtualFileSystem {
	return &VirtualFileSystem{}
}

func (vfs *VirtualFileSystem) Set(path, content string) {
	vfs.files.Store(path, content)
}

func (vfs *VirtualFileSystem) Get(path string) (string, bool) {
	v, ok := vfs.files.Load(path)
	if !ok {
		return "", false
	}
	return v.(string), true
}

func (vfs *VirtualFileSystem) Delete(path string) {
	vfs.files.Delete(path)
}

func (vfs *VirtualFileSystem) List(dir string) []DirEntry {
	var result []DirEntry
	vfs.files.Range(func(key, value any) bool {
		p := key.(string)
		if strings.HasPrefix(p, dir) {
			result = append(result, DirEntry{
				Path: p,
				Name: filepath.Base(p),
			})
		}
		return true
	})
	return result
}

type virtualFSImpl struct {
	capabilityMarker
	root  string
	vfs   *VirtualFileSystem
	cfg   *FileSystemConfig
	valid bool
}

type virtualEntryImpl struct {
	fs   *virtualFSImpl
	path string
}

func (e *virtualEntryImpl) checkValid() error {
	if e.fs == nil || !e.fs.valid {
		return errCapabilityUsedAfterScope("FileEntry (virtual)")
	}
	return nil
}

func (e *virtualEntryImpl) pathOrError() (string, error) {
	if err := e.checkValid(); err != nil {
		return "", err
	}
	return e.path, nil
}

func RequestVirtualFileSystem[T any](
	root string,
	vfs *VirtualFileSystem,
	cfg *FileSystemConfig,
	op func(FileSystem) (T, error),
) (T, error) {
	if cfg == nil {
		cfg = &FileSystemConfig{}
	}
	if cfg.ClassifiedPatterns == nil {
		cfg.ClassifiedPatterns = DefaultClassifiedPatterns
	}
	fs := &virtualFSImpl{
		root:  root,
		vfs:   vfs,
		cfg:   cfg,
		valid: true,
	}
	defer func() { fs.valid = false }()
	return op(fs)
}

func (fs *virtualFSImpl) Access(path string) (FileEntry, error) {
	if !fs.valid {
		return nil, fmt.Errorf("cap: FileSystem used outside its scope")
	}
	full := filepath.Join(fs.root, path)
	return &virtualEntryImpl{fs: fs, path: full}, nil
}

func (e *virtualEntryImpl) Path() string { return e.path }

func (e *virtualEntryImpl) Name() string { return filepath.Base(e.path) }

func (e *virtualEntryImpl) Read() (string, error) {
	path, err := e.pathOrError()
	if err != nil {
		return "", err
	}
	if e.IsClassified() {
		return "", fmt.Errorf("cap: Read() not allowed on classified path %q; use ReadClassified", e.path)
	}
	v, ok := e.fs.vfs.Get(path)
	if !ok {
		return "", fmt.Errorf("cap: file %q not found", e.path)
	}
	return v, nil
}

func (e *virtualEntryImpl) ReadBytes() ([]byte, error) {
	v, err := e.Read()
	if err != nil {
		return nil, err
	}
	return []byte(v), nil
}

func (e *virtualEntryImpl) Write(content string) error {
	path, err := e.pathOrError()
	if err != nil {
		return err
	}
	if e.IsClassified() {
		return fmt.Errorf("cap: Write() not allowed on classified path %q; use WriteClassified", e.path)
	}
	e.fs.vfs.Set(path, content)
	return nil
}

func (e *virtualEntryImpl) Append(content string) error {
	path, err := e.pathOrError()
	if err != nil {
		return err
	}
	if e.IsClassified() {
		return fmt.Errorf("cap: Append() not allowed on classified path %q", e.path)
	}
	existing, _ := e.fs.vfs.Get(path)
	e.fs.vfs.Set(path, existing+content)
	return nil
}

func (e *virtualEntryImpl) ReadLines() ([]string, error) {
	content, err := e.Read()
	if err != nil {
		return nil, err
	}
	if content == "" {
		return nil, nil
	}
	return strings.Split(strings.TrimSuffix(content, "\n"), "\n"), nil
}

func (e *virtualEntryImpl) ForEachLine(f func(line string, lineNum int)) error {
	content, err := e.Read()
	if err != nil {
		return err
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if i == len(lines)-1 && line == "" {
			continue
		}
		f(line, i+1)
	}
	return nil
}

func (e *virtualEntryImpl) Delete() error {
	path, err := e.pathOrError()
	if err != nil {
		return err
	}
	e.fs.vfs.Delete(path)
	return nil
}

func (e *virtualEntryImpl) MkdirAll() error {
	_, err := e.pathOrError()
	return err
}

func (e *virtualEntryImpl) Children() ([]DirEntry, error) {
	path, err := e.pathOrError()
	if err != nil {
		return nil, err
	}
	return e.fs.vfs.List(path), nil
}

func (e *virtualEntryImpl) Walk() ([]DirEntry, error) {
	path, err := e.pathOrError()
	if err != nil {
		return nil, err
	}
	return e.fs.vfs.List(path), nil
}

func (e *virtualEntryImpl) Exists() bool {
	path, err := e.pathOrError()
	if err != nil {
		return false
	}
	_, ok := e.fs.vfs.Get(path)
	return ok
}

func (e *virtualEntryImpl) IsDir() bool {
	_, err := e.pathOrError()
	if err != nil {
		return false
	}
	return false
}

func (e *virtualEntryImpl) Size() (int64, error) {
	path, err := e.pathOrError()
	if err != nil {
		return 0, err
	}
	v, ok := e.fs.vfs.Get(path)
	if !ok {
		return 0, fmt.Errorf("cap: file %q not found", e.path)
	}
	return int64(len(v)), nil
}

func (e *virtualEntryImpl) IsClassified() bool {
	path, err := e.pathOrError()
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(e.fs.root, path)
	if err != nil {
		return false
	}

	for _, pattern := range e.fs.cfg.ClassifiedPatterns {
		if matchPath(pattern, rel) {
			return true
		}
	}
	return false
}

func (e *virtualEntryImpl) ReadClassified() (Classified[string], error) {
	path, err := e.pathOrError()
	if err != nil {
		return Classified[string]{}, err
	}
	if !e.IsClassified() {
		return Classified[string]{}, fmt.Errorf("cap: ReadClassified() only allowed on classified paths; %q is not classified", path)
	}
	v, ok := e.fs.vfs.Get(path)
	if !ok {
		return Classified[string]{}, fmt.Errorf("cap: file %q not found", path)
	}
	return Classify(v), nil
}

func (e *virtualEntryImpl) WriteClassified(data Classified[string]) error {
	path, err := e.pathOrError()
	if err != nil {
		return err
	}
	if !e.IsClassified() {
		return fmt.Errorf("cap: WriteClassified() only allowed on classified paths")
	}
	e.fs.vfs.Set(path, data.value)
	return nil
}
