package firewall

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
)

// netErrKind is what a bind or dial error means, decided from the error's
// type and operating-system error number, never from its English text
// (which differs between Linux and Windows).
type netErrKind int

const (
	kindOther       netErrKind = iota
	kindInUse                  // the address is already bound
	kindPermission             // not allowed to bind (privileged port)
	kindNoAddress              // this host does not have that address
	kindRefused                // the peer answered, nothing listens on the port
	kindTimeout                // no answer before the deadline
	kindUnreachable            // no route to the host or network
	kindUnresolved             // the host name did not resolve
)

func classify(err error) netErrKind {
	if err == nil {
		return kindOther
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if k, ok := errnoKinds[errno]; ok {
			return k
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return kindTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return kindTimeout
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return kindUnresolved
	}
	return kindOther
}

// bindStatus turns a failed bind into a status and a readable detail.
func bindStatus(err error) (status, detail string) {
	switch classify(err) {
	case kindInUse:
		return StatusInUse, "already in use by another process"
	case kindPermission:
		return StatusPermission, "permission denied (ports below 1024 need CAP_NET_BIND_SERVICE)"
	case kindNoAddress:
		return StatusNoAddress, "this host has no such address"
	default:
		return StatusBindError, "cannot bind: " + err.Error()
	}
}

// dialStatus turns a failed peer connection into a status and a detail.
func dialStatus(err error) (status, detail string) {
	switch classify(err) {
	case kindRefused:
		return StatusRefused, "the host answered but nothing listens yet"
	case kindTimeout:
		return StatusTimeout, "no answer; a firewall or the network may drop it"
	case kindUnreachable:
		return StatusUnreachable, "no route to the host; check routing and the network"
	case kindUnresolved:
		return StatusUnreachable, "the host name does not resolve"
	default:
		return StatusUnreachable, "cannot connect: " + err.Error()
	}
}
