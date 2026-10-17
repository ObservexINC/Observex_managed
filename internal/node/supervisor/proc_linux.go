//go:build linux

package supervisor

import "syscall"

// platformProcAttrs asks the kernel to kill the child if the supervisor
// dies, so no component outlives it. Pdeathsig follows the thread that
// started the child; the Go runtime does not end such threads unless a
// goroutine locked to one exits, which this package never does.
func platformProcAttrs(a *syscall.SysProcAttr) {
	a.Pdeathsig = syscall.SIGKILL
}
