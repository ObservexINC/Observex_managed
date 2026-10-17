//go:build windows

package selfmon

import "testing"

func pgrpOfSelf(t *testing.T) int {
	t.Helper()
	t.Skip("no process groups on Windows")
	return 0
}
