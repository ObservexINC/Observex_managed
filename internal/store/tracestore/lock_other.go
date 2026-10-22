//go:build !windows

package tracestore

import (
	"io"
	"os"

	"go.etcd.io/etcd/client/pkg/v3/fileutil"
)

func lockDirectory(path string) (io.Closer, error) {
	return fileutil.TryLockFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
}
