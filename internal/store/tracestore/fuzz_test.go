package tracestore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// FuzzWALRecords feeds arbitrary bytes to log recovery: it must not panic,
// must keep only whole records, and what it keeps must re-encode to the same
// bytes.
func FuzzWALRecords(f *testing.F) {
	one, _ := encodeBatch(1, genSpans(20, 2, 2))
	two, _ := encodeBatch(2, genSpans(21, 1, 3))
	f.Add(one)
	f.Add(append(append([]byte{}, one...), two...))
	f.Add(append(append([]byte{}, one...), two[:len(two)/2]...))
	f.Add([]byte{})
	f.Add([]byte{255, 255, 255, 255, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		batches, good, tail := readRecords(data)
		if good > len(data) || (tail == nil) != (good == len(data)) {
			t.Fatalf("good %d of %d, tail %v", good, len(data), tail)
		}
		if tail != nil && !errors.Is(tail, errCorrupt) {
			t.Fatalf("tail error is not a corruption error: %v", tail)
		}
		var re []byte
		for _, b := range batches {
			spans := make([]store.Span, len(b.spans))
			for i, r := range b.spans {
				spans[i] = r.span
			}
			rec, err := encodeBatch(b.seq, spans)
			if err != nil {
				t.Fatalf("decoded batch does not re-encode: %v", err)
			}
			re = append(re, rec...)
		}
		again, good2, tail2 := readRecords(re)
		if tail2 != nil || good2 != len(re) || len(again) != len(batches) {
			t.Fatalf("re-encoded records do not read back: %v", tail2)
		}
		for i := range again {
			if !reflect.DeepEqual(again[i], batches[i]) {
				t.Fatalf("batch %d changed in a round trip", i)
			}
		}
	})
}

// FuzzBlockIndex feeds arbitrary bytes to the index parser, with the
// checksum fixed up so the fuzzer reaches the decoder. It must not panic,
// and a parsed index must be safe to query.
func FuzzBlockIndex(f *testing.F) {
	recs := make([]spanRec, 0)
	for _, sp := range genSpans(22, 5, 3) {
		recs = append(recs, spanRec{span: sp, seq: 1})
	}
	sortRecs(recs)
	groups, traces, err := segmentFormat{}.write(f.TempDir(), recs, 4)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(buildIndex(formatSegmentID, recs, groups, traces))
	f.Add(buildIndex(formatParquetID, nil, nil, nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) >= 4 {
			body := data[:len(data)-4]
			binary.LittleEndian.PutUint32(data[len(data)-4:], crc32.Checksum(body, castagnoli))
		}
		idx, err := parseIndex(data)
		if err != nil {
			if !errors.Is(err, errCorrupt) {
				t.Fatalf("not a corruption error: %v", err)
			}
			return
		}
		ids := []store.TraceID{{}, recs[0].span.TraceID, {0xff}}
		for _, g := range idx.groupsFor(ids) {
			if g < 0 || g >= len(idx.groups) {
				t.Fatalf("group %d of %d", g, len(idx.groups))
			}
		}
		path := filepath.Join(t.TempDir(), "index.bin")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if idx.file, err = os.Open(path); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = idx.close() }()
		got := map[store.TraceID]struct{}{}
		for name := range idx.services {
			_ = idx.serviceTraces(name, store.TimeRange{Start: minTime, End: maxTime}, got)
		}
		for _, id := range ids {
			if e, ok, err := idx.lookup(id); err == nil && ok && (e.id != id || uint64(e.group) >= uint64(len(idx.groups))) {
				t.Fatalf("lookup returned %+v for %s", e, id)
			}
		}
	})
}

// FuzzBlockReader opens a block whose data file the fuzzer chooses, with a
// valid index, and reads every group. Damage must surface as an error, not a
// panic or a hang.
func FuzzBlockReader(f *testing.F) {
	recs := make([]spanRec, 0)
	for _, sp := range genSpans(23, 6, 3) {
		recs = append(recs, spanRec{span: sp, seq: 3})
	}
	sortRecs(recs)
	originals := map[byte][]byte{}
	for _, format := range []blockFormat{parquetFormat{}, segmentFormat{}} {
		dir := f.TempDir()
		groups, _, err := format.write(dir, recs, 5)
		if err != nil {
			f.Fatal(err)
		}
		name := "spans.parquet"
		if format.id() == formatSegmentID {
			name = "spans.seg"
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			f.Fatal(err)
		}
		originals[format.id()] = data
		f.Add(format.id(), data, uint16(0), byte(0))
		f.Add(format.id(), data, uint16(len(data)/2), byte(0x40))
		_ = groups
	}
	f.Fuzz(func(t *testing.T, id byte, data []byte, at uint16, flip byte) {
		format, err := formatByID(id)
		if err != nil {
			return
		}
		if len(data) > 0 {
			data[int(at)%len(data)] ^= flip
		}
		// The index describes the original spans; the data may not match.
		dir := t.TempDir()
		groups, traces, err := format.write(dir, recs, 5)
		if err != nil {
			t.Fatal(err)
		}
		name := "spans.parquet"
		if id == formatSegmentID {
			name = "spans.seg"
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
		idx, err := parseIndex(buildIndex(id, recs, groups, traces))
		if err != nil {
			t.Fatal(err)
		}
		r, err := format.open(dir, idx)
		if err != nil {
			return
		}
		defer func() { _ = r.close() }()
		all := make([]int, len(idx.groups))
		for i := range all {
			all[i] = i
		}
		for _, e := range traces {
			_, _ = r.readTrace(e)
		}
		got, err := r.read(all, func(store.TraceID) bool { return true })
		if err != nil {
			return
		}
		// Undamaged data must read back exactly.
		if bytes.Equal(data, originals[id]) && !reflect.DeepEqual(got, recs) {
			t.Fatalf("undamaged block read back differently: %d spans of %d", len(got), len(recs))
		}
	})
}
