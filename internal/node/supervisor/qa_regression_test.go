package supervisor

import (
	"bytes"
	"strings"
	"testing"
)

func TestQASupervisorRedactsMultilinePrivateKey(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		var out bytes.Buffer
		sink := &lineSink{w: &out}
		writer := sink.prefixed("front-door")
		// Invented marker only. This is not a real key.
		lines := []string{beginPK + "\n", "UUFfUFJJVkFURV9LRVlfTEVBS19NQVJLRVI=\n", endPK + "\n", "ordinary diagnostic\n"}
		if chunked {
			for _, line := range lines {
				if _, err := writer.Write([]byte(line)); err != nil {
					t.Fatal(err)
				}
			}
		} else {
			if _, err := writer.Write([]byte(strings.Join(lines, ""))); err != nil {
				t.Fatal(err)
			}
		}
		sink.flush()
		if strings.Contains(out.String(), "UUFfUFJJVkFURV9LRVlfTEVBS19NQVJLRVI=") {
			t.Errorf("private-key body escaped child-output redaction (chunked=%v): %s", chunked, out.String())
		}
		if !strings.Contains(out.String(), "ordinary diagnostic") {
			t.Error("ordinary log line disappeared")
		}
	}
}
