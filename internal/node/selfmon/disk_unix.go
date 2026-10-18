//go:build !windows

package selfmon

import (
	"fmt"
	"syscall"
)

func diskSpace(path string) (total, avail uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	// Bsize is int64 on Linux and uint32 elsewhere; a block size is never
	// negative, but a broken file system must not wrap around.
	if st.Bsize <= 0 {
		return 0, 0, fmt.Errorf("statfs %s: block size %d", path, st.Bsize)
	}
	bs := uint64(st.Bsize) //nolint:unconvert // int64 on Linux, uint32 elsewhere; positive (checked above)
	return st.Blocks * bs, st.Bavail * bs, nil
}
