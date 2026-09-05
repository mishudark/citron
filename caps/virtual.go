package caps

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/attribute"
)

// Capacity limits for script-driven VFS writes. Seeding via Set is trusted
// host code and not limited; scripts are.
const (
	maxVFSFiles = 100_000
	maxVFSBytes = 64 << 20 // 64 MiB of total content
)

// ErrVFSQuotaExceeded is returned when a script-driven write would exceed
// the VFS file or byte budget.
var ErrVFSQuotaExceeded = errors.New("cap: virtual filesystem quota exceeded")

// VirtualFileSystem is an in-memory store of files. It tracks directories
// explicitly so that directory semantics (mkdir, children, walk, is_dir)
// behave like a real filesystem. It is safe for concurrent use.
type VirtualFileSystem struct {
	files      sync.Map // path -> string
	dirs       sync.Map // path -> struct{}
	appendMu   sync.Mutex
	totalBytes atomic.Int64
	fileCount  atomic.Int64
}

func NewVirtualFileSystem() *VirtualFileSystem {
	return &VirtualFileSystem{}
}

// Set stores a file, creating parent directories implicitly. It is the
// trusted seeding entry point and is not subject to quota limits.
func (vfs *VirtualFileSystem) Set(path, content string) {
	vfs.set(path, content)
}

// set stores a file and maintains directory and accounting metadata.
func (vfs *VirtualFileSystem) set(path, content string) {
	path = filepath.Clean(path)
	vfs.ensureDirs(filepath.Dir(path))
	var oldLen int
	if old, ok := vfs.files.Load(path); ok {
		oldLen = len(old.(string))
	} else {
		vfs.fileCount.Add(1)
	}
	vfs.files.Store(path, content)
	vfs.totalBytes.Add(int64(len(content) - oldLen))
}

// store is the quota-checked write path used by script-facing operations.
func (vfs *VirtualFileSystem) store(path, content string) error {
	path = filepath.Clean(path)
	if _, exists := vfs.files.Load(path); !exists && vfs.fileCount.Load() >= maxVFSFiles {
		return fmt.Errorf("%w: more than %d files", ErrVFSQuotaExceeded, maxVFSFiles)
	}
	var oldLen int
	if old, ok := vfs.files.Load(path); ok {
		oldLen = len(old.(string))
	}
	projected := vfs.totalBytes.Load() - int64(oldLen) + int64(len(content))
	if projected > maxVFSBytes {
		return fmt.Errorf("%w: total content would exceed %d bytes", ErrVFSQuotaExceeded, int64(maxVFSBytes))
	}
	vfs.set(path, content)
	return nil
}

// ensureDirs records dir and all its ancestors as directories.
func (vfs *VirtualFileSystem) ensureDirs(dir string) {
	for d := dir; d != "/" && d != "." && d != ""; d = filepath.Dir(d) {
		if _, existed := vfs.dirs.LoadOrStore(d, struct{}{}); existed {
			return
		}
	}
}

func (vfs *VirtualFileSystem) Get(path string) (string, bool) {
	v, ok := vfs.files.Load(filepath.Clean(path))
	if !ok {
		return "", false
	}
	return v.(string), true
}

func (vfs *VirtualFileSystem) Delete(path string) {
	path = filepath.Clean(path)
	if _, ok := vfs.files.LoadAndDelete(path); ok {
		vfs.fileCount.Add(-1)
	}
}

// List returns the immediate children (files and directories) of dir,
// with exact parent matching so "/data" no longer matches "/database".
func (vfs *VirtualFileSystem) List(dir string) []DirEntry {
	dir = filepath.Clean(dir)
	var result []DirEntry
	vfs.files.Range(func(key, value any) bool {
		p := key.(string)
		if filepath.Dir(p) == dir {
			result = append(result, DirEntry{
				Path:        p,
				Name:        filepath.Base(p),
				IsDirectory: false,
				Size:        int64(len(value.(string))),
			})
		}
		return true
	})
	vfs.dirs.Range(func(key, _ any) bool {
		p := key.(string)
		if p != dir && filepath.Dir(p) == dir {
			result = append(result, DirEntry{
				Path:        p,
				Name:        filepath.Base(p),
				IsDirectory: true,
			})
		}
		return true
	})
	return result
}

// Walk returns dir and every file/directory beneath it, recursively.
func (vfs *VirtualFileSystem) Walk(dir string) []DirEntry {
	dir = filepath.Clean(dir)
	prefix := dir
	if prefix != "/" {
		prefix = dir + "/"
	}
	var result []DirEntry
	vfs.dirs.Range(func(key, _ any) bool {
		p := key.(string)
		if p == dir || strings.HasPrefix(p, prefix) {
			result = append(result, DirEntry{
				Path:        p,
				Name:        filepath.Base(p),
				IsDirectory: true,
			})
		}
		return true
	})
	vfs.files.Range(func(key, value any) bool {
		p := key.(string)
		if strings.HasPrefix(p, prefix) {
			result = append(result, DirEntry{
				Path:        p,
				Name:        filepath.Base(p),
				IsDirectory: false,
				Size:        int64(len(value.(string))),
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
	valid atomic.Bool
}

type virtualEntryImpl struct {
	fs   *virtualFSImpl
	path string
}

func (e *virtualEntryImpl) checkValid() error {
	if e.fs == nil || !e.fs.valid.Load() {
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
	_, span := StartSpan(context.Background(), "caps.VirtualFileSystem.Request",
		attribute.String("root", root),
	)
	defer EndSpan(span, nil)
	RecordRequest(context.Background(), "virtual_filesystem")

	if cfg == nil {
		cfg = &FileSystemConfig{}
	}
	if cfg.ClassifiedPatterns == nil {
		cfg.ClassifiedPatterns = DefaultClassifiedPatterns
	}
	fs := &virtualFSImpl{
		root: root,
		vfs:  vfs,
		cfg:  cfg,
	}
	fs.valid.Store(true)
	defer func() { fs.valid.Store(false) }()
	result, err := op(fs)
	EndSpan(span, err)
	return result, err
}

func (fs *virtualFSImpl) Access(path string) (FileEntry, error) {
	if !fs.valid.Load() {
		return nil, fmt.Errorf("cap: FileSystem used outside its scope")
	}
	full, err := fs.resolve(path)
	if err != nil {
		return nil, err
	}
	return &virtualEntryImpl{fs: fs, path: full}, nil
}

func (fs *virtualFSImpl) resolve(req string) (string, error) {
	full := filepath.Clean(filepath.Join(fs.root, req))
	rel, err := filepath.Rel(fs.root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("cap: path %q escapes root %q", req, fs.root)
	}
	return full, nil
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
	return e.fs.vfs.store(path, content)
}

func (e *virtualEntryImpl) Append(content string) error {
	path, err := e.pathOrError()
	if err != nil {
		return err
	}
	if e.IsClassified() {
		return fmt.Errorf("cap: Append() not allowed on classified path %q", e.path)
	}
	// Serialize the read-modify-write so concurrent appends cannot lose data.
	e.fs.vfs.appendMu.Lock()
	defer e.fs.vfs.appendMu.Unlock()
	existing, _ := e.fs.vfs.Get(path)
	return e.fs.vfs.store(path, existing+content)
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
	path, err := e.pathOrError()
	if err != nil {
		return err
	}
	e.fs.vfs.ensureDirs(path)
	return nil
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
	return e.fs.vfs.Walk(path), nil
}

func (e *virtualEntryImpl) Exists() bool {
	path, err := e.pathOrError()
	if err != nil {
		return false
	}
	if _, ok := e.fs.vfs.Get(path); ok {
		return true
	}
	_, isDir := e.fs.vfs.dirs.Load(path)
	return isDir
}

func (e *virtualEntryImpl) IsDir() bool {
	path, err := e.pathOrError()
	if err != nil {
		return false
	}
	if _, ok := e.fs.vfs.dirs.Load(path); ok {
		return true
	}
	// A directory also exists implicitly when files live beneath it.
	prefix := path
	if prefix != "/" {
		prefix = path + "/"
	}
	found := false
	e.fs.vfs.files.Range(func(key, _ any) bool {
		if strings.HasPrefix(key.(string), prefix) {
			found = true
			return false
		}
		return true
	})
	return found
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
	return e.fs.vfs.store(path, data.value)
}
