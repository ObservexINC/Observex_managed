//go:build !windows && !linux

package supervisor

import "syscall"

func platformProcAttrs(*syscall.SysProcAttr) {}
