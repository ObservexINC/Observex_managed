package tracestore

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

func lockDirectory(path string) (io.Closer, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304,G703: lock in the operator-selected store directory
	if err != nil {
		return nil, err
	}
	// Compare no localized error strings: every failed lock, including
	// ERROR_LOCK_VIOLATION, must reject the second opener.
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
