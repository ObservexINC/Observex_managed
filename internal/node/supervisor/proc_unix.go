//go:build !windows

package supervisor

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcAttrs puts the child in its own process group, so a kill reaches
// any processes it started (NGINX workers, for example).
func setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	platformProcAttrs(cmd.SysProcAttr)
}

// signalStop sends the stop signal (SIGTERM by default) to the process.
func signalStop(cmd *exec.Cmd, sig os.Signal) error {
	if sig == nil {
		sig = syscall.SIGTERM
	}
	return cmd.Process.Signal(sig)
}

// killAll kills the child's whole process group.
func killAll(cmd *exec.Cmd) {
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}
