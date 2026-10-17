//go:build windows

package selfmon

import "errors"

// Managed nodes run on Linux; on Windows disk space is not reported.
func diskSpace(string) (total, avail uint64, err error) {
	return 0, 0, errors.New("disk space is reported on Linux only")
}
