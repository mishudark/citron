//go:build windows

package caps

import "os/exec"

// configureKillGroup is a no-op on Windows; exec.CommandContext already kills
// the direct child process on context cancellation.
func configureKillGroup(cmd *exec.Cmd) {}
