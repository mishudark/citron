//go:build !windows

package caps

import (
	"os/exec"
	"syscall"
)

// configureKillGroup puts the child in its own process group and arranges for
// the whole group (including grandchildren) to be killed when the command's
// context is cancelled.
func configureKillGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return cmd.Process.Kill()
	}
}
