//go:build !windows

package selfmon

import (
	"syscall"
	"testing"
)

func pgrpOfSelf(t *testing.T) int {
	t.Helper()
	return syscall.Getpgrp()
}
