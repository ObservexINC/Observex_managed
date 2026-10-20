package logging

import (
	"strings"
	"testing"
)

func TestSettle(t *testing.T) {
	calls := 0
	// Hides one more "x" per pass: settles once none is left.
	pass := func(s string) string {
		calls++
		return strings.Replace(s, "x", "-", 1)
	}
	for _, c := range []struct {
		in, want string
		calls    int
	}{
		{"abc", "abc", 1},   // nothing to hide: one pass
		{"axc", "a-c", 2},   // a second pass confirms
		{"xxa", "--a", 3},   // two changes, then a confirming pass
		{"xxxa", "---a", 4}, // the last pass allowed confirms
	} {
		calls = 0
		if got := settle(c.in, pass); got != c.want || calls != c.calls {
			t.Errorf("settle(%q) = %q after %d passes, want %q after %d", c.in, got, calls, c.want, c.calls)
		}
	}
	calls = 0
	if got := settle("xxxxa", pass); got != tooAmbiguous(5) || calls != maxPasses {
		t.Errorf("text still changing after %d passes: %q after %d passes, want the whole text replaced", maxPasses, got, calls)
	}
	// What settle returns for unsettled text is itself settled.
	if again := RedactString(tooAmbiguous(5)); again != tooAmbiguous(5) {
		t.Errorf("the whole-text marker redacts to %q", again)
	}
}
