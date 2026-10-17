//go:build !windows

package node

import "syscall"

// gracefulStop asks NGINX to finish open requests and exit.
var gracefulStop = syscall.SIGQUIT
