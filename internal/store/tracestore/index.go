package tracestore

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"hash/fnv"
	"os"
	"sort"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// Each block has an index file, index.bin, written after its data:
//
//	magic "OXTI", version 1, block format (1 Parquet, 2 segment)
//	min and max sequence, span count, trace count (uvarints)
//	min and max span start, Unix nanoseconds (varints)
//	trace-ID bloom filter: hash count (byte), word count (uvarint), words
//	groups: count, then per group first and last trace ID, position, length
//	        and CRC-32C (a Parquet row group, or a byte range of a segment)
//	traces: count, then per trace (sorted by ID) the trace ID, its group, and
//	        its first row and row count (Parquet) or byte offset in the group,
//	        length and CRC-32C (segment): 32 bytes each, the trace-ID index
//	services: count, then per service name, entry count and entry offset
//	service entries: per service, (start int64, trace ID) sorted by start,
//	        then trace ID: the service-and-time index
//	CRC-32C of everything before it
//
// Opening a block reads and checks the whole file but keeps only the header,
// the bloom filter, the groups and the service directory; service entries are
// and trace entries are read from the file when a query needs them.

var indexMagic = []byte("OXTI")

const (
	indexVersion   = 1
	indexEntrySize = 24
	traceEntrySize = 32
	bloomHashes    = 7
	bloomBitsPer   = 10 // about 1% false positives at 7 hashes
)

// bloom is a trace-ID bloom filter.
type bloom struct {
	k     uint8
	words []uint64
}

func newBloom(n int) *bloom {
	bits := n * bloomBitsPer
	words := (bits + 63) / 64
	if words < 1 {
		words = 1
	}
	return &bloom{k: bloomHashes, words: make([]uint64, words)}
}

func bloomHashes2(id store.TraceID) (uint64, uint64) {
	h := fnv.New64a()
	_, _ = h.Write(id[:])
	h1 := h.Sum64()
	h.Reset()
	_, _ = h.Write([]byte{0x9e})
	_, _ = h.Write(id[:])
	return h1, h.Sum64() | 1
}

func (b *bloom) positions(id store.TraceID, f func(word int, bit uint64)) {
	m := uint64(len(b.words)) * 64
	h1, h2 := bloomHashes2(id)
	for i := uint64(0); i < uint64(b.k); i++ {
		p := (h1 + i*h2) % m
		f(int(p/64), 1<<(p%64)) //nolint:gosec // G115: p/64 < len(words)
	}
}

func (b *bloom) add(id store.TraceID) {
	b.positions(id, func(w int, bit uint64) { b.words[w] |= bit })
}

func (b *bloom) mayContain(id store.TraceID) bool {
	ok := true
	b.positions(id, func(w int, bit uint64) {
		if b.words[w]&bit == 0 {
			ok = false
		}
	})
	return ok
}

// group locates a run of spans in a block's data, sorted by trace ID.
type group struct {
	first, last store.TraceID
	pos, n      uint64
	crc         uint32
}

// traceEntry locates one trace's spans in a block: in group, from off (a
// row, or a byte offset within the group), n rows or bytes, with a CRC-32C of
// those bytes for the segment format.
type traceEntry struct {
	id            store.TraceID
	group, off, n uint32
	crc           uint32
}

// svcDir locates one service's entries in the index file.
type svcDir struct {
	count  uint64
	offset uint64
}

// svcEntry is one span of a service: its start and trace.
type svcEntry struct {
	start int64
	trace store.TraceID
}

// blockIndex is what a block keeps in memory.
type blockIndex struct {
	format             byte
	minSeq, maxSeq     uint64
	spans, traces      uint64
	minStart, maxStart int64
	bloom              *bloom
	groups             []group
	services           map[string]svcDir
	tracesOff          uint64 // offset of the first trace entry in the file
	file               *os.File
}

func (idx *blockIndex) close() error {
	if idx.file == nil {
		return nil
	}
	return idx.file.Close()
}

// buildIndex encodes the index of recs, sorted by trace ID, start and span
// ID, stored in groups, with one entry per trace.
func buildIndex(format byte, recs []spanRec, groups []group, traces []traceEntry) []byte {
	var minSeq, maxSeq uint64
	var minStart, maxStart int64
	traceCount := 0
	bl := newBloom(len(recs))
	svc := map[string][]svcEntry{}
	for i, r := range recs {
		if i == 0 || r.seq < minSeq {
			minSeq = r.seq
		}
		if r.seq > maxSeq {
			maxSeq = r.seq
		}
		st := r.span.Start.UnixNano()
		if i == 0 || st < minStart {
			minStart = st
		}
		if i == 0 || st > maxStart {
			maxStart = st
		}
		if i == 0 || recs[i-1].span.TraceID != r.span.TraceID {
			traceCount++
			bl.add(r.span.TraceID)
		}
		svc[r.span.Service] = append(svc[r.span.Service], svcEntry{start: st, trace: r.span.TraceID})
	}
	names := make([]string, 0, len(svc))
	for name, es := range svc {
		names = append(names, name)
		sort.Slice(es, func(i, j int) bool {
			if es[i].start != es[j].start {
				return es[i].start < es[j].start
			}
			return bytes.Compare(es[i].trace[:], es[j].trace[:]) < 0
		})
	}
	sort.Strings(names)

	b := append([]byte{}, indexMagic...)
	b = append(b, indexVersion, format)
	b = binary.AppendUvarint(b, minSeq)
	b = binary.AppendUvarint(b, maxSeq)
	b = binary.AppendUvarint(b, uint64(len(recs)))
	b = binary.AppendUvarint(b, uint64(traceCount))
	b = binary.AppendVarint(b, minStart)
	b = binary.AppendVarint(b, maxStart)
	b = append(b, bl.k)
	b = binary.AppendUvarint(b, uint64(len(bl.words)))
	for _, w := range bl.words {
		b = binary.LittleEndian.AppendUint64(b, w)
	}
	b = binary.AppendUvarint(b, uint64(len(groups)))
	for _, g := range groups {
		b = append(b, g.first[:]...)
		b = append(b, g.last[:]...)
		b = binary.AppendUvarint(b, g.pos)
		b = binary.AppendUvarint(b, g.n)
		b = binary.LittleEndian.AppendUint32(b, g.crc)
	}
	b = binary.AppendUvarint(b, uint64(len(traces)))
	for _, e := range traces {
		b = append(b, e.id[:]...)
		b = binary.LittleEndian.AppendUint32(b, e.group)
		b = binary.LittleEndian.AppendUint32(b, e.off)
		b = binary.LittleEndian.AppendUint32(b, e.n)
		b = binary.LittleEndian.AppendUint32(b, e.crc)
	}
	// The directory holds absolute offsets of the entries, which follow it;
	// its own length depends on those offsets, so lay it out with fixed-width
	// offsets.
	b = binary.AppendUvarint(b, uint64(len(names)))
	dirLen := 0
	for _, name := range names {
		dirLen += len(binary.AppendUvarint(nil, uint64(len(name)))) + len(name) +
			len(binary.AppendUvarint(nil, uint64(len(svc[name])))) + 8
	}
	offset := uint64(len(b) + dirLen)
	for _, name := range names {
		b = appendString(b, name)
		b = binary.AppendUvarint(b, uint64(len(svc[name])))
		b = binary.LittleEndian.AppendUint64(b, offset)
		offset += uint64(len(svc[name])) * indexEntrySize
	}
	for _, name := range names {
		for _, e := range svc[name] {
			b = binary.LittleEndian.AppendUint64(b, uint64(e.start)) //nolint:gosec // G115: bit pattern of an int64, read back as int64
			b = append(b, e.trace[:]...)
		}
	}
	return binary.LittleEndian.AppendUint32(b, crc32.Checksum(b, castagnoli))
}

// parseIndex checks and decodes an index file's contents.
func parseIndex(data []byte) (*blockIndex, error) {
	if len(data) < len(indexMagic)+2+4 {
		return nil, corrupt("index of %d bytes", len(data))
	}
	body, sum := data[:len(data)-4], binary.LittleEndian.Uint32(data[len(data)-4:])
	if crc32.Checksum(body, castagnoli) != sum {
		return nil, corrupt("index checksum mismatch")
	}
	if !bytes.Equal(body[:4], indexMagic) || body[4] != indexVersion {
		return nil, corrupt("not a version %d index", indexVersion)
	}
	idx := &blockIndex{format: body[5], services: map[string]svcDir{}}
	d := decoder{b: body[6:]}
	idx.minSeq, idx.maxSeq = d.uvarint(), d.uvarint()
	idx.spans, idx.traces = d.uvarint(), d.uvarint()
	idx.minStart, idx.maxStart = d.varint(), d.varint()
	k := d.bytes(1)
	words := d.uvarint()
	if d.err == nil && words > uint64(len(d.b))/8 {
		d.fail("bloom filter of %d words in %d bytes", words, len(d.b))
	}
	if d.err == nil {
		if k[0] == 0 || k[0] > 32 || words == 0 {
			d.fail("bloom filter with %d hashes and %d words", k[0], words)
		}
	}
	if d.err != nil {
		return nil, d.err
	}
	idx.bloom = &bloom{k: k[0], words: make([]uint64, words)}
	for i := range idx.bloom.words {
		idx.bloom.words[i] = binary.LittleEndian.Uint64(d.bytes(8))
	}
	ng := d.uvarint()
	if d.err == nil && ng > uint64(len(d.b))/(32+2+4) {
		d.fail("%d groups in %d bytes", ng, len(d.b))
	}
	for i := uint64(0); i < ng && d.err == nil; i++ {
		var g group
		copy(g.first[:], d.bytes(16))
		copy(g.last[:], d.bytes(16))
		g.pos, g.n = d.uvarint(), d.uvarint()
		if c := d.bytes(4); c != nil {
			g.crc = binary.LittleEndian.Uint32(c)
		}
		if d.err == nil && bytes.Compare(g.first[:], g.last[:]) > 0 {
			d.fail("group %d ends before it starts", i)
		}
		idx.groups = append(idx.groups, g)
	}
	nt := d.uvarint()
	if d.err == nil && nt > uint64(len(d.b))/traceEntrySize {
		d.fail("%d trace entries in %d bytes", nt, len(d.b))
	}
	if d.err == nil && nt != idx.traces {
		d.fail("%d trace entries for %d traces", nt, idx.traces)
	}
	if d.err != nil {
		return nil, d.err
	}
	idx.tracesOff = uint64(len(body) - len(d.b)) //nolint:gosec // G115: d.b is a suffix of body
	entries := d.bytes(int(nt) * traceEntrySize) //nolint:gosec // G115: nt <= len(d.b)/traceEntrySize
	for i := uint64(0); i < nt && d.err == nil; i++ {
		e := decodeTraceEntry(entries[i*traceEntrySize:])
		if uint64(e.group) >= uint64(len(idx.groups)) {
			d.fail("trace entry %d points at group %d of %d", i, e.group, len(idx.groups))
		}
		if i > 0 {
			prev := decodeTraceEntry(entries[(i-1)*traceEntrySize:])
			if bytes.Compare(prev.id[:], e.id[:]) >= 0 {
				d.fail("trace entries not sorted at %d", i)
			}
		}
	}
	ns := d.uvarint()
	if d.err == nil && ns > uint64(len(d.b))/10 {
		d.fail("%d services in %d bytes", ns, len(d.b))
	}
	var total uint64
	for i := uint64(0); i < ns && d.err == nil; i++ {
		name := d.string()
		count := d.uvarint()
		off := d.bytes(8)
		if d.err != nil {
			break
		}
		dir := svcDir{count: count, offset: binary.LittleEndian.Uint64(off)}
		if count > uint64(len(body)) || dir.offset > uint64(len(body)) || dir.offset+count*indexEntrySize > uint64(len(body)) {
			d.fail("service %q entries lie outside the index", name)
			break
		}
		if _, dup := idx.services[name]; dup {
			d.fail("service %q listed twice", name)
			break
		}
		idx.services[name] = dir
		total += count
	}
	if d.err != nil {
		return nil, d.err
	}
	if uint64(len(d.b)) != total*indexEntrySize {
		return nil, corrupt("%d bytes of service entries, want %d", len(d.b), total*indexEntrySize)
	}
	return idx, nil
}

func decodeTraceEntry(b []byte) traceEntry {
	var e traceEntry
	copy(e.id[:], b[:16])
	e.group = binary.LittleEndian.Uint32(b[16:20])
	e.off = binary.LittleEndian.Uint32(b[20:24])
	e.n = binary.LittleEndian.Uint32(b[24:28])
	e.crc = binary.LittleEndian.Uint32(b[28:32])
	return e
}

// readIndex opens and checks a block's index file, and keeps it open for
// the entries read later.
func readIndex(path string) (*blockIndex, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: a file of the store's own block
	if err != nil {
		return nil, err
	}
	idx, err := parseIndex(data)
	if err != nil {
		return nil, err
	}
	if idx.file, err = os.Open(path); err != nil { //nolint:gosec // G304: a file of the store's own block
		return nil, err
	}
	return idx, nil
}

// lookup finds a trace's entry by binary search in the file.
func (idx *blockIndex) lookup(id store.TraceID) (traceEntry, bool, error) {
	var buf [traceEntrySize]byte
	var readErr error
	at := func(i uint64) traceEntry {
		if _, err := idx.file.ReadAt(buf[:], int64(idx.tracesOff+i*traceEntrySize)); err != nil && readErr == nil { //nolint:gosec // G115: offsets were checked against the file size
			readErr = err
		}
		return decodeTraceEntry(buf[:])
	}
	i := sort.Search(int(idx.traces), func(i int) bool { //nolint:gosec // G115: the trace count was checked against the file size
		e := at(uint64(i)) //nolint:gosec // G115: i >= 0
		return bytes.Compare(e.id[:], id[:]) >= 0
	})
	if readErr != nil {
		return traceEntry{}, false, readErr
	}
	if uint64(i) >= idx.traces { //nolint:gosec // G115: i >= 0
		return traceEntry{}, false, nil
	}
	e := at(uint64(i)) //nolint:gosec // G115: i >= 0
	if readErr != nil {
		return traceEntry{}, false, readErr
	}
	return e, e.id == id, nil
}

// serviceTraces returns the traces with a span of service starting in r.
func (idx *blockIndex) serviceTraces(service string, r store.TimeRange, into map[store.TraceID]struct{}) error {
	dir, ok := idx.services[service]
	if !ok || dir.count == 0 {
		return nil
	}
	start, end := r.Start.UnixNano(), r.End.UnixNano()
	if !storableTime(r.Start) {
		start = minTime.UnixNano()
	}
	if !storableTime(r.End) {
		end = maxTime.UnixNano()
	}
	if idx.maxStart < start || idx.minStart >= end {
		return nil
	}
	f := idx.file
	entry := func(i uint64) (svcEntry, error) {
		var buf [indexEntrySize]byte
		if _, err := f.ReadAt(buf[:], int64(dir.offset+i*indexEntrySize)); err != nil { //nolint:gosec // G115: offsets were checked against the file size
			return svcEntry{}, err
		}
		var e svcEntry
		e.start = int64(binary.LittleEndian.Uint64(buf[:8])) //nolint:gosec // G115: bit pattern of an int64
		copy(e.trace[:], buf[8:])
		return e, nil
	}
	// Binary search for the first entry at or after start.
	lo, hi := uint64(0), dir.count
	for lo < hi {
		mid := lo + (hi-lo)/2
		e, err := entry(mid)
		if err != nil {
			return err
		}
		if e.start < start {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	const chunk = 4096
	buf := make([]byte, chunk*indexEntrySize)
	for i := lo; i < dir.count; {
		n := dir.count - i
		if n > chunk {
			n = chunk
		}
		b := buf[:n*indexEntrySize]
		if _, err := f.ReadAt(b, int64(dir.offset+i*indexEntrySize)); err != nil { //nolint:gosec // G115: offsets were checked against the file size
			return err
		}
		for j := uint64(0); j < n; j++ {
			e := b[j*indexEntrySize : (j+1)*indexEntrySize]
			st := int64(binary.LittleEndian.Uint64(e[:8])) //nolint:gosec // G115: bit pattern of an int64
			if st >= end {
				return nil
			}
			var id store.TraceID
			copy(id[:], e[8:])
			into[id] = struct{}{}
		}
		i += n
	}
	return nil
}

// groupsFor returns the indexes of the groups that can hold one of ids.
func (idx *blockIndex) groupsFor(ids []store.TraceID) []int {
	seen := map[int]bool{}
	var out []int
	for _, id := range ids {
		if !idx.bloom.mayContain(id) {
			continue
		}
		// Groups are sorted and do not overlap, except that one trace can
		// continue from one group into the next.
		i := sort.Search(len(idx.groups), func(i int) bool { return bytes.Compare(idx.groups[i].last[:], id[:]) >= 0 })
		for ; i < len(idx.groups) && bytes.Compare(idx.groups[i].first[:], id[:]) <= 0; i++ {
			if !seen[i] {
				seen[i] = true
				out = append(out, i)
			}
		}
	}
	sort.Ints(out)
	return out
}
