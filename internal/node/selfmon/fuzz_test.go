package selfmon

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzParseStat checks that any /proc/<pid>/stat line parses without
// panicking, including command names with spaces and parentheses.
func FuzzParseStat(f *testing.F) {
	for _, s := range []string{
		"4100 (nginx) S 1 4100 4100 0 -1 4194560 100 0 0 0 150 120 0 0 20 0 1 0 100 12345678 1736 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0",
		"7000 (a) b) (c) R 1 7000 7000 0 -1 0 0 0 0 0 1 2 0 0 20 0 3 0 1 1 4",
		"1 () S",
		") (",
		"x (y) z",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		ps, ok := parseStat(line)
		if ok && ps.pid == 0 && !strings.HasPrefix(strings.TrimSpace(line), "0") {
			t.Fatalf("pid 0 from %q", line)
		}
	})
}

// FuzzWriteText checks that label values and help text with any bytes keep
// one sample per line: escaping must stop a value from starting a new line
// or closing its label early.
func FuzzWriteText(f *testing.F) {
	f.Add("front-door", "help text")
	f.Add("a\"b\\c\nd", "line1\nline2\\")
	f.Fuzz(func(t *testing.T, value, help string) {
		r := &Registry{}
		r.Register(CollectorFunc{CollectorName: "fuzz", Fn: func(b *Batch) {
			b.Gauge("observex_fuzz", help, 1, L("v", value))
		}})
		var buf bytes.Buffer
		if err := WriteText(&buf, r.Gather()); err != nil {
			t.Fatal(err)
		}
		samples := 0
		for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
			if strings.HasPrefix(line, "observex_fuzz{") {
				samples++
				if !strings.HasSuffix(line, `"} 1`) {
					t.Fatalf("sample line broken: %q", line)
				}
			} else if !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "observex_selfmon_errors") {
				t.Fatalf("unexpected line %q", line)
			}
		}
		if samples != 1 {
			t.Fatalf("%d sample lines for one sample", samples)
		}
	})
}
