//go:build windows

package firewall

import "syscall"

// Winsock error numbers (winerror.h). The Unix-style names in package
// syscall do not match them on Windows.
const (
	wsaeacces        syscall.Errno = 10013
	wsaeaddrinuse    syscall.Errno = 10048
	wsaeaddrnotavail syscall.Errno = 10049
	wsaenetdown      syscall.Errno = 10050
	wsaenetunreach   syscall.Errno = 10051
	wsaetimedout     syscall.Errno = 10060
	wsaeconnrefused  syscall.Errno = 10061
	wsaehostdown     syscall.Errno = 10064
	wsaehostunreach  syscall.Errno = 10065
)

var errnoKinds = map[syscall.Errno]netErrKind{
	wsaeaddrinuse:    kindInUse,
	wsaeacces:        kindPermission,
	wsaeaddrnotavail: kindNoAddress,
	wsaeconnrefused:  kindRefused,
	wsaetimedout:     kindTimeout,
	wsaehostunreach:  kindUnreachable,
	wsaenetunreach:   kindUnreachable,
	wsaenetdown:      kindUnreachable,
	wsaehostdown:     kindUnreachable,
}
