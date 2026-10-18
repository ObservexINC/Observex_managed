//go:build !windows

package firewall

import "syscall"

var errnoKinds = map[syscall.Errno]netErrKind{
	syscall.EADDRINUSE:    kindInUse,
	syscall.EACCES:        kindPermission,
	syscall.EPERM:         kindPermission,
	syscall.EADDRNOTAVAIL: kindNoAddress,
	syscall.ECONNREFUSED:  kindRefused,
	syscall.ETIMEDOUT:     kindTimeout,
	syscall.EHOSTUNREACH:  kindUnreachable,
	syscall.ENETUNREACH:   kindUnreachable,
	syscall.ENETDOWN:      kindUnreachable,
	syscall.EHOSTDOWN:     kindUnreachable,
}
