//go:build !windows

package selfmon

import "syscall"

func diskSpace(path string) (total, avail uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize) //nolint:unconvert // Bsize is int64 on Linux, uint32 elsewhere
	return st.Blocks * bs, st.Bavail * bs, nil
}
