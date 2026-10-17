package supervisor

import (
	"bytes"
	"io"
	"sync"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// maxLine is the longest line passed on; longer lines are cut and marked.
const maxLine = 16 << 10

const truncatedMark = " [line truncated]"

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
	p := &prefixWriter{sink: l, prefix: "[" + name + "] "}
	l.ps = append(l.ps, p)
	return p
}

func (l *lineSink) flush() {
	l.mu.Lock()
	ps := append([]*prefixWriter(nil), l.ps...)
	l.mu.Unlock()
	for _, p := range ps {
		p.flush()
	}
}

type prefixWriter struct {
	sink   *lineSink
	prefix string
	mu     sync.Mutex
	buf    []byte
	// skipping is set after a line was cut, until its end arrives.
	skipping bool
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(b)
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			if !p.skipping {
				p.buf = append(p.buf, b...)
				if len(p.buf) >= maxLine {
					p.emit(p.buf[:maxLine], true)
					p.buf = p.buf[:0]
					p.skipping = true
				}
			}
			break
		}
		if p.skipping {
			p.skipping = false
		} else {
			p.buf = append(p.buf, b[:i]...)
			cut := len(p.buf) > maxLine
			if cut {
				p.buf = p.buf[:maxLine]
			}
			p.emit(p.buf, cut)
		}
		p.buf = p.buf[:0]
		b = b[i+1:]
	}
	return n, nil
}

func (p *prefixWriter) flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.buf) > 0 {
		p.emit(p.buf, false)
		p.buf = p.buf[:0]
	}
	p.skipping = false
}

func (p *prefixWriter) emit(line []byte, cut bool) {
	text := logging.RedactString(string(bytes.TrimSuffix(line, []byte("\r"))))
	if cut {
		text += truncatedMark
	}
	p.sink.mu.Lock()
	defer p.sink.mu.Unlock()
	_, _ = io.WriteString(p.sink.w, p.prefix+text+"\n")
}
