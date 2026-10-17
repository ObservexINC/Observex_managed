//go:build windows

package supervisor

import (
	"os"
	"os/exec"
)

// Managed nodes run on Linux. On Windows the supervisor builds and its
// portable tests run, but a stop is always a kill, so a stop is never
// reported as clean there.

func setProcAttrs(*exec.Cmd) {}

func signalStop(cmd *exec.Cmd, _ os.Signal) error { return cmd.Process.Kill() }

func killAll(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
