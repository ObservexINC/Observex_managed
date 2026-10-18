package supervisor

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// bodyMarker stands in for private-key material. It is invented and must
// never reach output.
const bodyMarker = "QUFBQkJCS0VZQk9EWU1BUktFUg"

// Key markers are assembled from parts, so secret scanners (gitleaks) do not
// take these test files for files holding a key.
const (
	beginPK = "-----BEGIN " + "PRIVATE KEY-----"
	endPK   = "-----END " + "PRIVATE KEY-----"
)

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// pem builds a key block of the given label, ending each line with eol.
func pem(label, eol string, end bool) string {
	var b strings.Builder
	b.WriteString("-----BEGIN " + label + "-----" + eol)
	if strings.HasPrefix(label, "ENCRYPTED") || label == "RSA PRIVATE KEY" {
		b.WriteString("Proc-Type: 4,ENCRYPTED" + eol + "DEK-Info: AES-256-CBC,00FF" + eol + eol)
	}
	for i := 0; i < 3; i++ {
		b.WriteString(bodyMarker + fmt.Sprint(i) + strings.Repeat("A", 30) + eol)
	}
	if end {
		b.WriteString("-----END " + label + "-----" + eol)
	}
	return b.String()
}

// feed writes s to a fresh stream in chunks of n bytes (n <= 0: one write)
// and returns what the sink received after the stream ends.
func feed(t *testing.T, s string, n int) string {
	t.Helper()
	var out bytes.Buffer
	sink := &lineSink{w: &out}
	w := sink.prefixed("c")
	if n <= 0 {
		_, _ = io.WriteString(w, s)
	} else {
		for i := 0; i < len(s); i += n {
			_, _ = io.WriteString(w, s[i:min(i+n, len(s))])
		}
	}
	sink.flush()
	return out.String()
}

func noBody(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, bodyMarker) {
		t.Fatalf("key material reached the output:\n%s", out)
	}
}

func TestPrivateKeyBlocksAreDropped(t *testing.T) {
	labels := []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY", "DSA PRIVATE KEY"}
	for _, label := range labels {
		for _, eol := range []string{"\n", "\r\n"} {
			for _, chunk := range []int{0, 1, 3, 7, 64} {
				name := fmt.Sprintf("%s/crlf=%v/chunk=%d", label, eol == "\r\n", chunk)
				t.Run(name, func(t *testing.T) {
					in := "before" + eol + "note: loading " + pem(label, eol, true) + "after the key" + eol
					out := feed(t, in, chunk)
					noBody(t, out)
					want := "[c] before\n[c] note: loading [REDACTED]\n[c] after the key\n"
					if out != want {
						t.Fatalf("got\n%s\nwant\n%s", out, want)
					}
				})
			}
		}
	}
}

func TestTextAfterTheEndMarkerOnTheSameLineIsKept(t *testing.T) {
	in := beginPK + "\n" + bodyMarker + "\n" + endPK + " then ok\nnext\n"
	out := feed(t, in, 5)
	noBody(t, out)
	if out != "[c] [REDACTED]\n[c]  then ok\n[c] next\n" {
		t.Fatalf("got %q", out)
	}
}

func TestSeveralBlocksAndDiagnosticsBetween(t *testing.T) {
	in := pem("PRIVATE KEY", "\n", true) + "diag one\n" + pem("EC PRIVATE KEY", "\n", true) + "diag two\n" +
		"single line " + beginPK + bodyMarker + endPK + " done\n"
	out := feed(t, in, 11)
	noBody(t, out)
	for _, want := range []string{"[c] diag one\n", "[c] diag two\n", "[c] single line [REDACTED] done\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	if strings.Count(out, "[REDACTED]") != 3 {
		t.Fatalf("want three redacted markers:\n%s", out)
	}
}

func TestUnterminatedKeyFailsClosedUntilTheStreamEnds(t *testing.T) {
	var out bytes.Buffer
	sink := &lineSink{w: &out}
	w := sink.prefixed("c")
	_, _ = io.WriteString(w, "start\n"+pem("PRIVATE KEY", "\n", false)+"looks ordinary "+bodyMarker+"\nmore\npartial "+bodyMarker)
	sink.flush()
	noBody(t, out.String())
	if out.String() != "[c] start\n[c] [REDACTED]\n" {
		t.Fatalf("got %q", out.String())
	}
	// A new stream (the next process) starts clean.
	_, _ = io.WriteString(w, "fresh line\n")
	sink.flush()
	if !strings.HasSuffix(out.String(), "[c] fresh line\n") {
		t.Fatalf("state carried over: %q", out.String())
	}
}

func TestMarkersBeyondTheShownPartOfLongLines(t *testing.T) {
	long := strings.Repeat("x", maxLine+50)
	// BEGIN lies beyond the shown part of a long line; the body follows on
	// the next lines.
	in := long + beginPK + "\n" + bodyMarker + "\n" + endPK + "\nafter\n"
	out := feed(t, in, 4096)
	noBody(t, out)
	if !strings.Contains(out, truncatedMark) || !strings.HasSuffix(out, "[c] after\n") {
		t.Fatalf("got %.200q ... %q", out, out[max(0, len(out)-80):])
	}
	// BEGIN straddles the cut: only its start is shown.
	in = strings.Repeat("y", maxLine-10) + beginPK + "\n" + bodyMarker + "\n" + endPK + "\nafter\n"
	out = feed(t, in, 1000)
	noBody(t, out)
	if !strings.HasSuffix(out, "[c] after\n") {
		t.Fatalf("got tail %q", out[max(0, len(out)-80):])
	}
	// A line that starts inside a key and holds its END beyond the cut is
	// all key material.
	in = beginPK + "\n" + strings.Repeat(bodyMarker, maxLine/len(bodyMarker)+5) + endPK + " tail\nafter\n"
	out = feed(t, in, 512)
	noBody(t, out)
	if out != "[c] [REDACTED]\n[c] after\n" {
		t.Fatalf("got %q", out)
	}
	// A long key line inside a block, then a normal ending.
	in = beginPK + "\n" + strings.Repeat(bodyMarker, maxLine/len(bodyMarker)+5) + "\n" + endPK + "\nafter\n"
	out = feed(t, in, 0)
	noBody(t, out)
	if out != "[c] [REDACTED]\n[c] after\n" {
		t.Fatalf("got %q", out)
	}
}

func TestEndMarkerWithoutBeginIsOrdinaryText(t *testing.T) {
	out := feed(t, endPK+"\nstill shown\n", 0)
	if out != "[c] -----END PRIVATE KEY-----\n[c] still shown\n" {
		t.Fatalf("got %q", out)
	}
}

func TestPublicKeysAndCertificatesAreKept(t *testing.T) {
	in := "-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----\n-----BEGIN PUBLIC KEY-----\nMIIBpub\n-----END PUBLIC KEY-----\n"
	out := feed(t, in, 3)
	if !strings.Contains(out, "[c] MIIBcert\n") || !strings.Contains(out, "[c] MIIBpub\n") {
		t.Fatalf("certificate or public key dropped:\n%s", out)
	}
}

func TestConcurrentStreamsKeepTheirOwnState(t *testing.T) {
	out := &safeBuf{}
	sink := &lineSink{w: out}
	a := sink.prefixed("a")
	b := sink.prefixed("b")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s := "a-start\n" + pem("PRIVATE KEY", "\n", true) + "a-end\n"
		for i := 0; i < len(s); i += 3 {
			_, _ = io.WriteString(a, s[i:min(i+3, len(s))])
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = fmt.Fprintf(b, "b-line %d\n", i)
		}
	}()
	wg.Wait()
	sink.flush()
	got := out.String()
	noBody(t, got)
	if strings.Count(got, "[b] b-line ") != 200 {
		t.Fatalf("stream b lost lines while a was inside a key")
	}
	for _, want := range []string{"[a] a-start\n", "[a] [REDACTED]\n", "[a] a-end\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q", want)
		}
	}
	// Lines never interleave: every line has exactly one prefix at its start.
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if !strings.HasPrefix(line, "[a] ") && !strings.HasPrefix(line, "[b] ") {
			t.Fatalf("broken line %q", line)
		}
	}
}

func TestWriterIsRemovedWhenItsProcessEnds(t *testing.T) {
	var out bytes.Buffer
	sink := &lineSink{w: &out}
	w := sink.prefixed("c")
	_, _ = io.WriteString(w, "partial")
	w.close()
	if out.String() != "[c] partial\n" || len(sink.ps) != 0 {
		t.Fatalf("close: %q, %d writers left", out.String(), len(sink.ps))
	}
}

// validLabel is the PEM private-key label form the writer recognises.
var validLabel = regexp.MustCompile(`^[A-Z0-9 ]{0,40}PRIVATE KEY$`)

// FuzzPrefixWriter checks that key material never reaches output however
// the stream is cut into writes and whatever surrounds the block.
func FuzzPrefixWriter(f *testing.F) {
	f.Add("before ", " after", uint8(1), "PRIVATE KEY")
	f.Add("", "\r", uint8(0), "EC PRIVATE KEY")
	f.Add(strings.Repeat("z", 100), "-----END", uint8(13), "ENCRYPTED PRIVATE KEY")
	f.Fuzz(func(t *testing.T, pre, post string, chunk uint8, label string) {
		if !validLabel.MatchString(label) {
			label = "PRIVATE KEY"
		}
		for _, end := range []bool{true, false} {
			in := pre + "\n" + pem(label, "\n", end) + post + "\nlast\n"
			out := feed(t, in, int(chunk))
			if strings.Contains(out, bodyMarker) {
				t.Fatalf("leak (end=%v, chunk=%d):\n%q", end, chunk, out)
			}
		}
	})
}
