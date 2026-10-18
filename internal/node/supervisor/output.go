package supervisor

import (
	"bytes"
	"io"
	"regexp"
	"sync"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// maxLine is the longest line passed on; longer lines are cut and marked.
const maxLine = 16 << 10

const truncatedMark = " [line truncated]"

// markerWindow is how many trailing bytes of a line are kept to recognise
// a PEM private-key marker that arrives split across writes.
const markerWindow = 128

// pemMarker matches a complete private-key BEGIN or END marker at the end
// of the window: RSA, EC, DSA, OPENSSH, ENCRYPTED and plain PKCS#8 keys.
var pemMarker = regexp.MustCompile(`-----(BEGIN|END) [A-Z0-9 ]{0,40}PRIVATE KEY-----$`)

// lineSink writes component output one whole line at a time, so lines of
// different components never interleave, and redacts each line.
type lineSink struct {
	mu sync.Mutex
	w  io.Writer
	ps []*prefixWriter
}

func (l *lineSink) prefixed(name string) *prefixWriter {
	l.mu.Lock()
	defer l.mu.Unlock()
	p := &prefixWriter{sink: l, prefix: "[" + name + "] ", endAt: -1}
	l.ps = append(l.ps, p)
	return p
}

// flush ends every stream: partial lines are written, and the private-key
// state is reset.
func (l *lineSink) flush() {
	l.mu.Lock()
	ps := append([]*prefixWriter(nil), l.ps...)
	l.mu.Unlock()
	for _, p := range ps {
		p.flush()
	}
}

// remove forgets a writer whose process has exited.
func (l *lineSink) remove(p *prefixWriter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, q := range l.ps {
		if q == p {
			l.ps = append(l.ps[:i], l.ps[i+1:]...)
			return
		}
	}
}

// prefixWriter is one process's output stream (stdout and stderr share it).
//
// Each complete line is redacted with logging.RedactString. A PEM private
// key spans several lines, so the writer also follows the stream: from a
// BEGIN ... PRIVATE KEY marker until its END marker, every line is dropped
// (the BEGIN line itself is shown as [REDACTED]). A key whose END never
// arrives is dropped until the stream ends: the writer fails closed. Markers
// are found byte by byte, so they are recognised even when split across
// writes or lying beyond the part of an over-long line that is shown.
type prefixWriter struct {
	sink   *lineSink
	prefix string
	mu     sync.Mutex

	line []byte // shown part of the current line, at most maxLine bytes
	cut  bool   // the current line is longer than maxLine
	pos  int    // bytes of the current line seen so far
	win  []byte // last bytes of the current line, for marker detection

	inKey    bool // inside a private-key block now
	startKey bool // the current line started inside a private-key block
	endAt    int  // offset just past the first END marker of a line that started inside a key; -1 if none
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range b {
		if c == '\n' {
			p.endLine()
			continue
		}
		p.pos++
		if len(p.line) < maxLine {
			p.line = append(p.line, c)
		} else {
			p.cut = true
		}
		if len(p.win) == markerWindow {
			copy(p.win, p.win[1:])
			p.win = p.win[:markerWindow-1]
		}
		p.win = append(p.win, c)
		if c == '-' && bytes.HasSuffix(p.win, []byte("-----")) {
			p.marker()
		}
	}
	return len(b), nil
}

// marker updates the key state when the window ends with a marker.
func (p *prefixWriter) marker() {
	m := pemMarker.FindSubmatch(p.win)
	if m == nil {
		return
	}
	switch string(m[1]) {
	case "BEGIN":
		p.inKey = true
	case "END":
		if !p.inKey {
			return
		}
		p.inKey = false
		if p.startKey && p.endAt < 0 {
			p.endAt = p.pos
		}
	}
}

// endLine writes the current line, or drops it when it is part of a key.
func (p *prefixWriter) endLine() {
	text := p.line
	show := true
	if p.startKey {
		// The line began inside a key: everything up to the END marker is
		// key material. Show only what follows it, if any.
		switch {
		case p.endAt < 0, p.endAt > len(text):
			show = false
		default:
			text = text[p.endAt:]
			if len(bytes.TrimSpace(text)) == 0 {
				show = false
			}
		}
	}
	if show {
		out := logging.RedactString(string(bytes.TrimSuffix(text, []byte("\r"))))
		if p.cut {
			out += truncatedMark
		}
		p.sink.mu.Lock()
		_, _ = io.WriteString(p.sink.w, p.prefix+out+"\n")
		p.sink.mu.Unlock()
	}
	p.line = p.line[:0]
	p.win = p.win[:0]
	p.cut = false
	p.pos = 0
	p.startKey = p.inKey
	p.endAt = -1
}

// flush ends the stream: a partial last line is written (or dropped when it
// is key material), and the key state is reset for a new stream.
func (p *prefixWriter) flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pos > 0 {
		p.endLine()
	}
	p.inKey, p.startKey, p.endAt = false, false, -1
}

// close flushes the stream and removes the writer from its sink. It is
// called when the process has exited and its output is drained.
func (p *prefixWriter) close() {
	p.flush()
	p.sink.remove(p)
}
