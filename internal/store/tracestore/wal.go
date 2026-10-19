package tracestore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// The write-ahead log is a series of segment files, wal/<number>.wal. Each
// WriteSpans call appends one record and syncs it to disk before returning:
//
//	[4 bytes: payload length, little-endian]
//	[4 bytes: CRC-32C of the payload]
//	[payload: version 1, sequence (uvarint), span count (uvarint), spans]
//
// A crash can leave a torn record at the end of the last segment. Recovery
// keeps every complete record before it and cuts the file there.

const (
	walVersion    = 1
	walHeaderSize = 8
	// maxBatchBytes caps one encoded WriteSpans call, and so one record.
	maxBatchBytes = 64 << 20
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// batch is one decoded record.
type batch struct {
	seq   uint64
	spans []spanRec
}

// encodeBatch builds a whole record, header included.
func encodeBatch(seq uint64, spans []store.Span) ([]byte, error) {
	b := make([]byte, walHeaderSize, walHeaderSize+64*len(spans))
	b = append(b, walVersion)
	b = binary.AppendUvarint(b, seq)
	b = binary.AppendUvarint(b, uint64(len(spans)))
	for _, s := range spans {
		b = appendSpan(b, spanRec{span: s, seq: seq})
		if len(b)-walHeaderSize > maxBatchBytes {
			return nil, store.Invalid("a WriteSpans call encodes to more than %d MiB; split it", maxBatchBytes>>20)
		}
	}
	payload := b[walHeaderSize:]
	binary.LittleEndian.PutUint32(b[0:4], uint32(len(payload))) //nolint:gosec // G115: at most maxBatchBytes, checked above
	binary.LittleEndian.PutUint32(b[4:8], crc32.Checksum(payload, castagnoli))
	return b, nil
}

// decodeBatch decodes a record's payload.
func decodeBatch(payload []byte) (batch, error) {
	d := decoder{b: payload}
	if v := d.bytes(1); d.err == nil && v[0] != walVersion {
		return batch{}, corrupt("record version %d", v[0])
	}
	bt := batch{seq: d.uvarint()}
	n := d.uvarint()
	// A span takes at least minSpanBytes, so a larger count is damage.
	if d.err == nil && n > uint64(len(d.b))/minSpanBytes {
		return batch{}, corrupt("%d spans in %d bytes", n, len(d.b))
	}
	bt.spans = make([]spanRec, 0, n)
	for i := uint64(0); i < n && d.err == nil; i++ {
		r := d.span()
		if d.err == nil && r.seq != bt.seq {
			d.fail("span sequence %d in record %d", r.seq, bt.seq)
		}
		bt.spans = append(bt.spans, r)
	}
	if d.err == nil && len(d.b) != 0 {
		d.fail("%d bytes after the last span", len(d.b))
	}
	if d.err != nil {
		return batch{}, d.err
	}
	return bt, nil
}

// readRecords decodes every complete record of a segment. It returns the
// records and the length of the file they cover; anything after that (a torn
// or damaged record) is reported through tail.
func readRecords(data []byte) (batches []batch, good int, tail error) {
	for off := 0; off < len(data); {
		if len(data)-off < walHeaderSize {
			return batches, off, corrupt("%d bytes of a record header at offset %d", len(data)-off, off)
		}
		n := int(binary.LittleEndian.Uint32(data[off : off+4]))
		sum := binary.LittleEndian.Uint32(data[off+4 : off+8])
		if n > maxBatchBytes || n > len(data)-off-walHeaderSize {
			return batches, off, corrupt("record of %d bytes at offset %d, %d left", n, off, len(data)-off-walHeaderSize)
		}
		payload := data[off+walHeaderSize : off+walHeaderSize+n]
		if crc32.Checksum(payload, castagnoli) != sum {
			return batches, off, corrupt("checksum mismatch at offset %d", off)
		}
		bt, err := decodeBatch(payload)
		if err != nil {
			return batches, off, fmt.Errorf("record at offset %d: %w", off, err)
		}
		batches = append(batches, bt)
		off += walHeaderSize + n
	}
	return batches, len(data), nil
}

// segmentName is the file name of WAL segment num.
func segmentName(num uint64) string { return fmt.Sprintf("%016d.wal", num) }

// listSegments returns the numbers of the segments in dir, ascending.
func listSegments(dir string) ([]uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var nums []uint64
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".wal") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(name, ".wal"), 10, 64)
		if err != nil {
			continue
		}
		nums = append(nums, n)
	}
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	return nums, nil
}

// walFile is the segment being appended to.
type walFile struct {
	num  uint64
	path string
	f    *os.File
	size int64
}

func createSegment(dir string, num uint64) (*walFile, error) {
	path := filepath.Join(dir, segmentName(num))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: the store's own log segment
	if err != nil {
		return nil, err
	}
	if err := syncDir(dir); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &walFile{num: num, path: path, f: f}, nil
}

// append writes a record and syncs it. A failed or short write is cut off
// again, so the segment never holds half a record that a later record
// follows.
func (w *walFile) append(rec []byte) error {
	n, err := w.f.Write(rec)
	if err == nil && n != len(rec) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = w.f.Sync()
	}
	if err != nil {
		if terr := w.f.Truncate(w.size); terr != nil {
			return fmt.Errorf("tracestore: write-ahead log write failed (%w) and could not be undone: %w", err, terr)
		}
		return fmt.Errorf("tracestore: write-ahead log: %w", err)
	}
	w.size += int64(n)
	return nil
}

func (w *walFile) close() error { return w.f.Close() }

// syncDir makes a directory's entries (new, renamed or removed files)
// durable. Windows cannot open a directory for syncing; NTFS journals
// metadata, so there it is skipped.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir) //nolint:gosec // G304: the store's own directory
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, os.ErrInvalid) {
		return nil
	}
	return err
}
