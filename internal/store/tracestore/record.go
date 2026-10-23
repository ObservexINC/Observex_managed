package tracestore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// spanRec is a span with the sequence number of the write that stored it.
// When the same trace and span ID appear more than once, the highest
// sequence wins, which is how a rewrite replaces a span across the
// write-ahead log, the in-memory head and immutable blocks.
type spanRec struct {
	span store.Span
	seq  uint64
}

// errCorrupt reports bytes that do not decode: a torn write at the end of
// the log, or damage on disk.
var errCorrupt = errors.New("tracestore: corrupt data")

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errCorrupt, fmt.Sprintf(format, args...))
}

// Times are stored as Unix nanoseconds, which int64 holds from 1677 to 2262.
var (
	minTime = time.Unix(0, math.MinInt64).UTC()
	maxTime = time.Unix(0, math.MaxInt64).UTC()
)

func storableTime(t time.Time) bool {
	return !t.Before(minTime) && !t.After(maxTime)
}

// validate applies the contract's checks and the store's own limit on
// times.
func validate(s store.Span) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if !storableTime(s.Start) || !storableTime(s.End) {
		return store.Invalid("span %s has a time outside 1678 to 2262, which the TraceStore cannot hold", s.SpanID)
	}
	return nil
}

// minSpanBytes is the smallest encoded span: three IDs (32 bytes), sequence,
// start and duration (a byte each at least), the error flag, and the lengths
// of service, name and attributes (a byte each).
const minSpanBytes = 39

// appendString writes a length-prefixed string.
func appendString(b []byte, s string) []byte {
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

// appendSpan encodes one span. Attributes are written sorted by key, and a
// nil map is told apart from an empty one (count 0 is nil, n+1 is n
// entries), so a span reads back exactly as written.
func appendSpan(b []byte, r spanRec) []byte {
	s := r.span
	b = append(b, s.TraceID[:]...)
	b = append(b, s.SpanID[:]...)
	b = append(b, s.ParentID[:]...)
	b = binary.AppendUvarint(b, r.seq)
	b = binary.AppendVarint(b, s.Start.UnixNano())
	// End is stored as its distance from start; unsigned arithmetic keeps it
	// exact over the whole int64 range, since End is never before Start.
	b = binary.AppendUvarint(b, uint64(s.End.UnixNano())-uint64(s.Start.UnixNano()))
	if s.Error {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = appendString(b, s.Service)
	b = appendString(b, s.Name)
	if s.Attributes == nil {
		return binary.AppendUvarint(b, 0)
	}
	b = binary.AppendUvarint(b, uint64(len(s.Attributes))+1)
	keys := make([]string, 0, len(s.Attributes))
	for k := range s.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b = appendString(b, k)
		b = appendString(b, s.Attributes[k])
	}
	return b
}

// decoder reads the encoding above, refusing anything that would read past
// the end or claim more entries than the bytes left can hold.
type decoder struct {
	b   []byte
	err error
}

func (d *decoder) fail(format string, args ...any) {
	if d.err == nil {
		d.err = corrupt(format, args...)
	}
}

func (d *decoder) bytes(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b) {
		d.fail("need %d bytes, %d left", n, len(d.b))
		return nil
	}
	out := d.b[:n]
	d.b = d.b[n:]
	return out
}

func (d *decoder) uvarint() uint64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.fail("bad unsigned varint")
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) varint() int64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Varint(d.b)
	if n <= 0 {
		d.fail("bad varint")
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) string() string {
	n := d.uvarint()
	if n > uint64(len(d.b)) {
		d.fail("string of %d bytes, %d left", n, len(d.b))
		return ""
	}
	return string(d.bytes(int(n))) //nolint:gosec // G115: n <= len(d.b), checked above
}

func (d *decoder) span() spanRec {
	var r spanRec
	s := &r.span
	copy(s.TraceID[:], d.bytes(16))
	copy(s.SpanID[:], d.bytes(8))
	copy(s.ParentID[:], d.bytes(8))
	r.seq = d.uvarint()
	start := d.varint()
	dur := d.uvarint()
	// start+dur must fit in int64. In modular unsigned arithmetic
	// MaxInt64-start is exact, because the true value lies in [0, 2^64).
	if d.err == nil && dur > uint64(math.MaxInt64)-uint64(start) { //nolint:gosec // G115: modular arithmetic is intended, see above
		d.fail("span end overflows")
	}
	s.Start = time.Unix(0, start).UTC()
	s.End = time.Unix(0, int64(uint64(start)+dur)).UTC() //nolint:gosec // G115: start+dur fits in int64, checked above
	switch flag := d.bytes(1); {
	case flag == nil:
	case flag[0] == 0:
	case flag[0] == 1:
		s.Error = true
	default:
		d.fail("error flag %d", flag[0])
	}
	s.Service = d.string()
	s.Name = d.string()
	n := d.uvarint()
	if n > 0 {
		// Each entry takes at least two bytes, so a count beyond what is left
		// is damage, not a reason to allocate.
		if n-1 > uint64(len(d.b))/2 {
			d.fail("%d attributes in %d bytes", n-1, len(d.b))
			return r
		}
		s.Attributes = make(map[string]string, n-1)
		for i := uint64(0); i < n-1 && d.err == nil; i++ {
			k := d.string()
			s.Attributes[k] = d.string()
		}
	}
	return r
}
