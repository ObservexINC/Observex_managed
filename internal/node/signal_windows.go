//go:build windows

package node

import "os"

// Managed nodes run on Linux. On Windows the package builds so that tests
// and tools compile there, and a stop is a kill.
var gracefulStop = os.Kill
