package tracestore

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/parquet-go/parquet-go"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// A block is an immutable directory, blocks/<min seq>-<max seq>/, holding
// the spans of one flushed head sorted by trace ID, start and span ID, in one
// of two formats, plus index.bin. It is written under a temporary name and
// renamed into place, so a crash leaves either a whole block or none.

// Block formats.
const (
	FormatParquet = "parquet" // the TraceStore's format (technology row T7)
	FormatSegment = "segment" // the simpler format it is benchmarked against
)

const (
	formatParquetID byte = 1
	formatSegmentID byte = 2
	// parquetPageBytes keeps Parquet pages small, so reading one trace
	// decodes little beyond it.
	parquetPageBytes = 16 << 10
	// pointLookups is how many traces are looked up one by one before a
	// block's groups are scanned instead.
	pointLookups = 32
)

type blockFormat interface {
	id() byte
	// write stores recs in dir, in groups of about groupSize spans that end
	// at a trace boundary, syncs what it wrote, and returns the groups and
	// one entry per trace.
	write(dir string, recs []spanRec, groupSize int) ([]group, []traceEntry, error)
	open(dir string, idx *blockIndex) (blockReader, error)
}

type blockReader interface {
	// read returns the spans of the given groups whose trace is wanted.
	read(groups []int, want func(store.TraceID) bool) ([]spanRec, error)
	// readTrace returns the spans of one trace entry.
	readTrace(e traceEntry) ([]spanRec, error)
	close() error
}

func formatByName(name string) (blockFormat, error) {
	switch name {
	case "", FormatParquet:
		return parquetFormat{}, nil
	case FormatSegment:
		return segmentFormat{}, nil
	}
	return nil, store.Invalid("unknown block format %q", name)
}

func formatByID(id byte) (blockFormat, error) {
	switch id {
	case formatParquetID:
		return parquetFormat{}, nil
	case formatSegmentID:
		return segmentFormat{}, nil
	}
	return nil, corrupt("unknown block format %d", id)
}

// splitGroups cuts recs, sorted by trace, into groups of size spans or a
// little more: a group ends only where a trace ends, so every trace lies in
// one group.
func splitGroups(recs []spanRec, size int) [][]spanRec {
	var out [][]spanRec
	for len(recs) > 0 {
		n := size
		if n > len(recs) {
			n = len(recs)
		}
		for n < len(recs) && recs[n].span.TraceID == recs[n-1].span.TraceID {
			n++
		}
		out = append(out, recs[:n])
		recs = recs[n:]
	}
	return out
}

// traceRuns calls f for each run of spans of one trace in a group: the
// trace, the index of its first span and the number of spans.
func traceRuns(g []spanRec, f func(id store.TraceID, first, n int)) {
	for i := 0; i < len(g); {
		j := i + 1
		for j < len(g) && g[j].span.TraceID == g[i].span.TraceID {
			j++
		}
		f(g[i].span.TraceID, i, j-i)
		i = j
	}
}

// syncFile writes data to path and syncs it.
func syncFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: a file of the store's own block
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// guard turns a panic in a decoding library into a corruption error: a
// damaged block must fail its query, not the process.
func guard(err *error) {
	if p := recover(); p != nil {
		*err = corrupt("block reader failed: %v", p)
	}
}

// --- Parquet ---------------------------------------------------------------

// parquetSpan is one row of spans.parquet. The file can be read by any
// Parquet tool: IDs are fixed-length byte arrays, times are nanosecond
// timestamps, and attributes are a list of key and value pairs sorted by key.
type parquetSpan struct {
	TraceID       [16]byte      `parquet:"trace_id"`
	SpanID        [8]byte       `parquet:"span_id"`
	ParentID      [8]byte       `parquet:"parent_span_id"`
	Service       string        `parquet:"service_name,dict"`
	Name          string        `parquet:"name,dict"`
	Start         int64         `parquet:"start_time,timestamp(nanosecond)"`
	End           int64         `parquet:"end_time,timestamp(nanosecond)"`
	Error         bool          `parquet:"error"`
	HasAttributes bool          `parquet:"has_attributes"`
	Attributes    []parquetAttr `parquet:"attributes"`
	Seq           int64         `parquet:"write_sequence"`
}

type parquetAttr struct {
	Key   string `parquet:"key,dict"`
	Value string `parquet:"value"`
}

func toParquet(r spanRec) parquetSpan {
	s := r.span
	p := parquetSpan{
		TraceID: s.TraceID, SpanID: s.SpanID, ParentID: s.ParentID,
		Service: s.Service, Name: s.Name,
		Start: s.Start.UnixNano(), End: s.End.UnixNano(),
		Error: s.Error, HasAttributes: s.Attributes != nil,
		Seq: int64(r.seq), //nolint:gosec // G115: sequences stay far below 2^63
	}
	if len(s.Attributes) > 0 {
		keys := make([]string, 0, len(s.Attributes))
		for k := range s.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p.Attributes = append(p.Attributes, parquetAttr{Key: k, Value: s.Attributes[k]})
		}
	}
	return p
}

func fromParquet(p parquetSpan) (spanRec, error) {
	if p.End < p.Start || p.Seq < 0 {
		return spanRec{}, corrupt("row with end before start or a negative sequence")
	}
	s := store.Span{
		TraceID: p.TraceID, SpanID: p.SpanID, ParentID: p.ParentID,
		Service: p.Service, Name: p.Name,
		Start: time.Unix(0, p.Start).UTC(), End: time.Unix(0, p.End).UTC(),
		Error: p.Error,
	}
	if p.HasAttributes {
		s.Attributes = make(map[string]string, len(p.Attributes))
		for _, a := range p.Attributes {
			s.Attributes[a.Key] = a.Value
		}
	}
	return spanRec{span: s, seq: uint64(p.Seq)}, nil
}

type parquetFormat struct{}

func (parquetFormat) id() byte { return formatParquetID }

func (parquetFormat) write(dir string, recs []spanRec, groupSize int) ([]group, []traceEntry, error) {
	path := filepath.Join(dir, "spans.parquet")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: a file of the store's own block
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	w := parquet.NewGenericWriter[parquetSpan](f, parquet.Compression(&parquet.Zstd), parquet.PageBufferSize(parquetPageBytes))
	var groups []group
	var traces []traceEntry
	rows := make([]parquetSpan, 0, groupSize)
	for i, g := range splitGroups(recs, groupSize) {
		rows = rows[:0]
		for _, r := range g {
			rows = append(rows, toParquet(r))
		}
		if _, err := w.Write(rows); err != nil {
			return nil, nil, err
		}
		if err := w.Flush(); err != nil {
			return nil, nil, err
		}
		groups = append(groups, group{first: g[0].span.TraceID, last: g[len(g)-1].span.TraceID, pos: uint64(i), n: uint64(len(g))})
		traceRuns(g, func(id store.TraceID, first, n int) {
			traces = append(traces, traceEntry{id: id, group: uint32(i), off: uint32(first), n: uint32(n)}) //nolint:gosec // G115: groups and rows stay far below 2^32
		})
	}
	if err := w.Close(); err != nil {
		return nil, nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, nil, err
	}
	return groups, traces, f.Close()
}

type parquetReader struct {
	f    *os.File
	file *parquet.File
	idx  *blockIndex
}

func (parquetFormat) open(dir string, idx *blockIndex) (r blockReader, err error) {
	defer guard(&err)
	f, err := os.Open(filepath.Join(dir, "spans.parquet")) //nolint:gosec // G304: a file of the store's own block
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	pf, err := parquet.OpenFile(f, st.Size(), parquet.SkipBloomFilters(true))
	if err != nil {
		_ = f.Close()
		return nil, corrupt("spans.parquet: %v", err)
	}
	if len(pf.RowGroups()) != len(idx.groups) {
		_ = f.Close()
		return nil, corrupt("spans.parquet has %d row groups, the index %d", len(pf.RowGroups()), len(idx.groups))
	}
	for i, rg := range pf.RowGroups() {
		if rg.NumRows() != int64(idx.groups[i].n) { //nolint:gosec // G115: row counts were checked when the index was read
			_ = f.Close()
			return nil, corrupt("row group %d has %d rows, the index %d", i, rg.NumRows(), idx.groups[i].n)
		}
	}
	return &parquetReader{f: f, file: pf, idx: idx}, nil
}

func (p *parquetReader) read(groups []int, want func(store.TraceID) bool) (out []spanRec, err error) {
	defer guard(&err)
	rgs := p.file.RowGroups()
	for _, gi := range groups {
		g := p.idx.groups[gi]
		rows := make([]parquetSpan, g.n)
		rd := parquet.NewGenericRowGroupReader[parquetSpan](rgs[gi])
		n, rerr := rd.Read(rows)
		_ = rd.Close()
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return nil, corrupt("row group %d: %v", gi, rerr)
		}
		if uint64(n) != g.n { //nolint:gosec // G115: n is a count of rows read
			return nil, corrupt("row group %d: read %d of %d rows", gi, n, g.n)
		}
		for _, row := range rows[:n] {
			if !want(row.TraceID) {
				continue
			}
			r, err := fromParquet(row)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
	}
	return out, nil
}

func (p *parquetReader) readTrace(e traceEntry) (out []spanRec, err error) {
	defer guard(&err)
	rgs := p.file.RowGroups()
	g := p.idx.groups[e.group]
	if uint64(e.off)+uint64(e.n) > g.n {
		return nil, corrupt("trace entry outside row group %d", e.group)
	}
	rd := parquet.NewGenericRowGroupReader[parquetSpan](rgs[e.group])
	defer func() { _ = rd.Close() }()
	if err := rd.SeekToRow(int64(e.off)); err != nil {
		return nil, corrupt("row group %d: %v", e.group, err)
	}
	rows := make([]parquetSpan, e.n)
	n, rerr := rd.Read(rows)
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		return nil, corrupt("row group %d: %v", e.group, rerr)
	}
	if n != len(rows) {
		return nil, corrupt("row group %d: read %d of %d rows", e.group, n, len(rows))
	}
	for _, row := range rows {
		if row.TraceID != e.id {
			return nil, corrupt("row group %d: the trace entry points at another trace", e.group)
		}
		r, err := fromParquet(row)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (p *parquetReader) close() error { return p.f.Close() }

// --- Segment ---------------------------------------------------------------

// The segment format is spans.seg: the spans encoded as in the write-ahead
// log, one after another, uncompressed. Each group is a byte range with its
// own CRC-32C.

type segmentFormat struct{}

func (segmentFormat) id() byte { return formatSegmentID }

func (segmentFormat) write(dir string, recs []spanRec, groupSize int) ([]group, []traceEntry, error) {
	var data []byte
	var groups []group
	var traces []traceEntry
	for gi, g := range splitGroups(recs, groupSize) {
		start := len(data)
		traceRuns(g, func(id store.TraceID, first, n int) {
			off := len(data)
			for _, r := range g[first : first+n] {
				data = appendSpan(data, r)
			}
			traces = append(traces, traceEntry{
				id: id, group: uint32(gi), off: uint32(off - start), n: uint32(len(data) - off), //nolint:gosec // G115: groups stay far below 4 GiB
				crc: crc32.Checksum(data[off:], castagnoli),
			})
		})
		groups = append(groups, group{
			first: g[0].span.TraceID, last: g[len(g)-1].span.TraceID,
			pos: uint64(start), n: uint64(len(data) - start), //nolint:gosec // G115: lengths are positive
			crc: crc32.Checksum(data[start:], castagnoli),
		})
	}
	return groups, traces, syncFile(filepath.Join(dir, "spans.seg"), data)
}

type segmentReader struct {
	f   *os.File
	idx *blockIndex
}

func (segmentFormat) open(dir string, idx *blockIndex) (blockReader, error) {
	f, err := os.Open(filepath.Join(dir, "spans.seg")) //nolint:gosec // G304: a file of the store's own block
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	var end uint64
	for i, g := range idx.groups {
		if g.pos != end || g.n > uint64(st.Size()) { //nolint:gosec // G115: file sizes are positive
			_ = f.Close()
			return nil, corrupt("segment group %d is not where the index says", i)
		}
		end += g.n
	}
	if end != uint64(st.Size()) { //nolint:gosec // G115: file sizes are positive
		_ = f.Close()
		return nil, corrupt("segment of %d bytes, the index covers %d", st.Size(), end)
	}
	return &segmentReader{f: f, idx: idx}, nil
}

func (s *segmentReader) read(groups []int, want func(store.TraceID) bool) ([]spanRec, error) {
	var out []spanRec
	for _, gi := range groups {
		g := s.idx.groups[gi]
		buf := make([]byte, g.n)
		if _, err := s.f.ReadAt(buf, int64(g.pos)); err != nil { //nolint:gosec // G115: positions were checked against the file size
			return nil, err
		}
		if crc32.Checksum(buf, castagnoli) != g.crc {
			return nil, corrupt("segment group %d checksum mismatch", gi)
		}
		d := decoder{b: buf}
		for len(d.b) > 0 && d.err == nil {
			// Read the trace ID first, so unwanted spans are decoded but not kept.
			r := d.span()
			if d.err == nil && want(r.span.TraceID) {
				out = append(out, r)
			}
		}
		if d.err != nil {
			return nil, d.err
		}
	}
	return out, nil
}

func (s *segmentReader) readTrace(e traceEntry) ([]spanRec, error) {
	g := s.idx.groups[e.group]
	if uint64(e.off)+uint64(e.n) > g.n {
		return nil, corrupt("trace entry outside segment group %d", e.group)
	}
	buf := make([]byte, e.n)
	if _, err := s.f.ReadAt(buf, int64(g.pos+uint64(e.off))); err != nil { //nolint:gosec // G115: positions were checked against the file size
		return nil, err
	}
	if crc32.Checksum(buf, castagnoli) != e.crc {
		return nil, corrupt("trace entry checksum mismatch in segment group %d", e.group)
	}
	d := decoder{b: buf}
	var out []spanRec
	for len(d.b) > 0 && d.err == nil {
		r := d.span()
		if d.err == nil && r.span.TraceID != e.id {
			d.fail("the trace entry points at another trace")
		}
		out = append(out, r)
	}
	if d.err != nil {
		return nil, d.err
	}
	return out, nil
}

func (s *segmentReader) close() error { return s.f.Close() }

// --- Writing and opening blocks -------------------------------------------

// block is an open, immutable block.
type block struct {
	dir    string
	idx    *blockIndex
	reader blockReader
}

func blockName(minSeq, maxSeq uint64) string {
	return fmt.Sprintf("%016x-%016x", minSeq, maxSeq)
}

// sortRecs sorts spans by trace ID, start and span ID: the block order.
func sortRecs(recs []spanRec) {
	sort.Slice(recs, func(i, j int) bool {
		a, b := recs[i].span, recs[j].span
		if c := bytes.Compare(a.TraceID[:], b.TraceID[:]); c != 0 {
			return c < 0
		}
		if !a.Start.Equal(b.Start) {
			return a.Start.Before(b.Start)
		}
		return bytes.Compare(a.SpanID[:], b.SpanID[:]) < 0
	})
}

// writeBlock writes recs (sorted) as a new block under blocksDir and opens
// it.
func writeBlock(blocksDir string, format blockFormat, recs []spanRec, groupSize int) (*block, error) {
	var minSeq, maxSeq uint64
	for i, r := range recs {
		if i == 0 || r.seq < minSeq {
			minSeq = r.seq
		}
		if r.seq > maxSeq {
			maxSeq = r.seq
		}
	}
	name := blockName(minSeq, maxSeq)
	tmp := filepath.Join(blocksDir, ".tmp-"+name)
	if err := os.RemoveAll(tmp); err != nil {
		return nil, err
	}
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return nil, err
	}
	groups, traces, err := format.write(tmp, recs, groupSize)
	if err == nil {
		err = syncFile(filepath.Join(tmp, "index.bin"), buildIndex(format.id(), recs, groups, traces))
	}
	if err == nil {
		err = syncDir(tmp)
	}
	final := filepath.Join(blocksDir, name)
	if err == nil {
		err = os.Rename(tmp, final)
	}
	if err == nil {
		err = syncDir(blocksDir)
	}
	if err != nil {
		_ = os.RemoveAll(tmp)
		return nil, fmt.Errorf("tracestore: write block %s: %w", name, err)
	}
	return openBlock(final)
}

// openBlock opens a block directory.
func openBlock(dir string) (*block, error) {
	idx, err := readIndex(filepath.Join(dir, "index.bin"))
	if err != nil {
		return nil, fmt.Errorf("tracestore: block %s: %w", filepath.Base(dir), err)
	}
	format, err := formatByID(idx.format)
	if err != nil {
		return nil, fmt.Errorf("tracestore: block %s: %w", filepath.Base(dir), err)
	}
	r, err := format.open(dir, idx)
	if err != nil {
		_ = idx.close()
		return nil, fmt.Errorf("tracestore: block %s: %w", filepath.Base(dir), err)
	}
	return &block{dir: dir, idx: idx, reader: r}, nil
}

func (b *block) close() error {
	return errors.Join(b.reader.close(), b.idx.close())
}

// spansOf returns the block's spans of the given traces: one lookup per
// trace in the trace index for a few traces, a scan of the groups that can
// hold them for many.
func (b *block) spansOf(ids []store.TraceID) ([]spanRec, error) {
	if len(ids) <= pointLookups || uint64(len(ids))*16 < b.idx.traces {
		var out []spanRec
		for _, id := range ids {
			if !b.idx.bloom.mayContain(id) {
				continue
			}
			e, ok, err := b.idx.lookup(id)
			if err != nil {
				return nil, fmt.Errorf("tracestore: block %s: %w", filepath.Base(b.dir), err)
			}
			if !ok {
				continue
			}
			recs, err := b.reader.readTrace(e)
			if err != nil {
				return nil, fmt.Errorf("tracestore: block %s: %w", filepath.Base(b.dir), err)
			}
			out = append(out, recs...)
		}
		return out, nil
	}
	groups := b.idx.groupsFor(ids)
	if len(groups) == 0 {
		return nil, nil
	}
	want := make(map[store.TraceID]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	recs, err := b.reader.read(groups, func(id store.TraceID) bool { return want[id] })
	if err != nil {
		return nil, fmt.Errorf("tracestore: block %s: %w", filepath.Base(b.dir), err)
	}
	return recs, nil
}
