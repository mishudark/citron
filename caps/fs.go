package caps

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type FileSystem interface {
	Capability
	Access(path string) (FileEntry, error)
}

type FileEntry interface {
	Path() string
	Name() string
	Read() (string, error)
	ReadBytes() ([]byte, error)
	Write(content string) error
	Append(content string) error
	ReadLines() ([]string, error)
	ForEachLine(f func(line string, lineNum int)) error
	Delete() error
	MkdirAll() error
	Children() ([]DirEntry, error)
	Walk() ([]DirEntry, error)
	Exists() bool
	IsDir() bool
	Size() (int64, error)
	IsClassified() bool
	ReadClassified() (Classified[string], error)
	WriteClassified(data Classified[string]) error
}

type fsImpl struct {
	capabilityMarker
	root    string
	valid   bool
	cfg     *FileSystemConfig
}

type FileSystemConfig struct {
	ClassifiedPatterns []string
}

var DefaultClassifiedPatterns = []string{
	".ssh/**", ".gnupg/**", ".env", ".env.*", ".netrc",
	".npmrc", ".pypirc", ".docker/**", ".kube/**",
	".aws/**", ".azure/**", ".gcloud/**",
}

type fileEntryImpl struct {
	fs   *fsImpl
	path string
}

func RequestFileSystem[T any](
	root string,
	cfg *FileSystemConfig,
	op func(FileSystem) (T, error),
) (T, error) {
	if cfg == nil {
		cfg = &FileSystemConfig{}
	}
	if cfg.ClassifiedPatterns == nil {
		cfg.ClassifiedPatterns = DefaultClassifiedPatterns
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("cap: bad filesystem root %q: %w", root, err)
	}
	fs := &fsImpl{
		root:  absRoot,
		valid: true,
		cfg:   cfg,
	}
	defer func() { fs.valid = false }()
	return op(fs)
}

func (fs *fsImpl) Access(path string) (FileEntry, error) {
	if !fs.valid {
		return nil, errCapabilityUsedAfterScope("FileSystem")
	}
	full, err := fs.resolve(path)
	if err != nil {
		return nil, err
	}
	return &fileEntryImpl{fs: fs, path: full}, nil
}

func (fs *fsImpl) resolve(req string) (string, error) {
	if filepath.IsAbs(req) {
		return fs.resolveAbs(req)
	}
	return fs.resolveRel(req)
}

// resolveSymlinks walks up from path to find the deepest existing ancestor,
// resolves its symlinks, and reconstructs the full resolved path.
// This prevents path traversal via intermediate symlink components.
func resolveSymlinks(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	// Path doesn't exist; resolve parent directory to catch intermediate symlinks.
	parent := filepath.Dir(path)
	if parent == path {
		// Cannot go further up; return as-is.
		return path, nil
	}
	resolvedParent, err := resolveSymlinks(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(path)), nil
}

func (fs *fsImpl) resolveAbs(req string) (string, error) {
	clean := filepath.Clean(req)

	// Resolve all symlinks to prevent path traversal via intermediate symlinks.
	resolved, err := resolveSymlinks(clean)
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(resolved, fs.root) {
		return "", fmt.Errorf("cap: path %q is outside root %q", req, fs.root)
	}
	rel, err := filepath.Rel(fs.root, resolved)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("cap: path %q escapes root %q", req, fs.root)
	}
	return resolved, nil
}

func (fs *fsImpl) resolveRel(req string) (string, error) {
	clean := filepath.Clean(filepath.Join(fs.root, req))
	return fs.resolveAbs(clean)
}

func (e *fileEntryImpl) Path() string { return e.path }

func (e *fileEntryImpl) Name() string { return filepath.Base(e.path) }

func (e *fileEntryImpl) Read() (string, error) {
	if err := e.checkValid(); err != nil {
		return "", err
	}
	if e.IsClassified() {
		return "", fmt.Errorf("cap: Read() not allowed on classified path %q; use ReadClassified", e.path)
	}
	data, err := os.ReadFile(e.path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (e *fileEntryImpl) ReadBytes() ([]byte, error) {
	if err := e.checkValid(); err != nil {
		return nil, err
	}
	if e.IsClassified() {
		return nil, fmt.Errorf("cap: ReadBytes() not allowed on classified path %q; use ReadClassified", e.path)
	}
	return os.ReadFile(e.path)
}

func (e *fileEntryImpl) Write(content string) error {
	if err := e.checkValid(); err != nil {
		return err
	}
	if e.IsClassified() {
		return fmt.Errorf("cap: Write() not allowed on classified path %q; use WriteClassified", e.path)
	}
	return os.WriteFile(e.path, []byte(content), 0644)
}

func (e *fileEntryImpl) Append(content string) error {
	if err := e.checkValid(); err != nil {
		return err
	}
	if e.IsClassified() {
		return fmt.Errorf("cap: Append() not allowed on classified path %q", e.path)
	}
	f, err := os.OpenFile(e.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	_, err = f.WriteString(content)
	_ = f.Close()
	return err
}

func (e *fileEntryImpl) ReadLines() ([]string, error) {
	if err := e.checkValid(); err != nil {
		return nil, err
	}
	if e.IsClassified() {
		return nil, fmt.Errorf("cap: ReadLines() not allowed on classified path %q; use ReadClassified", e.path)
	}
	data, err := os.ReadFile(e.path)
	if err != nil {
		return nil, err
	}
	content := string(data)
	if content == "" {
		return nil, nil
	}
	return strings.Split(strings.TrimSuffix(content, "\n"), "\n"), nil
}

func (e *fileEntryImpl) ForEachLine(f func(line string, lineNum int)) error {
	if err := e.checkValid(); err != nil {
		return err
	}
	if e.IsClassified() {
		return fmt.Errorf("cap: ForEachLine() not allowed on classified path %q; use ReadClassified", e.path)
	}
	data, err := os.ReadFile(e.path)
	if err != nil {
		return err
	}
	content := string(data)
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if i == len(lines)-1 && line == "" {
			continue
		}
		f(line, i+1)
	}
	return nil
}

func (e *fileEntryImpl) Delete() error {
	if err := e.checkValid(); err != nil {
		return err
	}
	return os.RemoveAll(e.path)
}

func (e *fileEntryImpl) MkdirAll() error {
	if err := e.checkValid(); err != nil {
		return err
	}
	return os.MkdirAll(e.path, 0755)
}

func (e *fileEntryImpl) Children() ([]DirEntry, error) {
	if err := e.checkValid(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(e.path)
	if err != nil {
		return nil, err
	}
	var result []DirEntry
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		result = append(result, DirEntry{
			Path:        filepath.Join(e.path, entry.Name()),
			Name:        entry.Name(),
			IsDirectory: entry.IsDir(),
			Size:        info.Size(),
		})
	}
	return result, nil
}

func (e *fileEntryImpl) Walk() ([]DirEntry, error) {
	if err := e.checkValid(); err != nil {
		return nil, err
	}
	var result []DirEntry
	err := filepath.WalkDir(e.path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		result = append(result, DirEntry{
			Path:        path,
			Name:        d.Name(),
			IsDirectory: d.IsDir(),
			Size:        info.Size(),
		})
		return nil
	})
	return result, err
}

func (e *fileEntryImpl) Exists() bool {
	if err := e.checkValid(); err != nil {
		return false
	}
	_, err := os.Stat(e.path)
	return err == nil
}

func (e *fileEntryImpl) IsDir() bool {
	if err := e.checkValid(); err != nil {
		return false
	}
	info, err := os.Stat(e.path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func (e *fileEntryImpl) Size() (int64, error) {
	if err := e.checkValid(); err != nil {
		return 0, err
	}
	info, err := os.Stat(e.path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (e *fileEntryImpl) IsClassified() bool {
	if e.fs == nil {
		return false
	}
	rel, err := filepath.Rel(e.fs.root, e.path)
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

func matchPath(pattern, path string) bool {
	// Simple implementation of ** support
	if strings.Contains(pattern, "**") {
		prefix := strings.Split(pattern, "**")[0]
		return strings.HasPrefix(path, prefix)
	}
	match, _ := filepath.Match(pattern, path)
	if match {
		return true
	}
	// Also check if path is inside a directory matched by pattern
	return strings.HasPrefix(path, strings.TrimRight(pattern, "/")+"/")
}

func (e *fileEntryImpl) ReadClassified() (Classified[string], error) {
	if err := e.checkValid(); err != nil {
		return Classified[string]{}, err
	}
	if !e.IsClassified() {
		return Classified[string]{}, fmt.Errorf("cap: ReadClassified() only allowed on classified paths; %q is not classified", e.path)
	}
	data, err := os.ReadFile(e.path)
	if err != nil {
		return Classified[string]{}, err
	}
	return Classify(string(data)), nil
}

func (e *fileEntryImpl) WriteClassified(data Classified[string]) error {
	if err := e.checkValid(); err != nil {
		return err
	}
	if !e.IsClassified() {
		return fmt.Errorf("cap: WriteClassified() only allowed on classified paths")
	}
	return os.WriteFile(e.path, []byte(data.value), 0644)
}

func (e *fileEntryImpl) checkValid() error {
	if e.fs == nil || !e.fs.valid {
		return errCapabilityUsedAfterScope("FileEntry")
	}
	return nil
}

func errCapabilityUsedAfterScope(name string) error {
	return fmt.Errorf("cap: %s used outside its scope (Request* block has returned)", name)
}
