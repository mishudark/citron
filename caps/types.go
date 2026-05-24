package caps

type GrepMatch struct {
	File       string
	LineNumber int
	Line       string
}

type ProcessResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

type ExecOptions struct {
	WorkingDir string
	TimeoutMs  int64
}

type DirEntry struct {
	Path        string
	Name        string
	IsDirectory bool
	Size        int64
}
