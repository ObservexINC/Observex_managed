// Package tracestore is the TraceStore v0 (technology row T7, ADR 0004, ADR
// 0011): a node-local store of spans in our own Go code.
//
// Writes go to a write-ahead log, synced before WriteSpans returns, and to an
// in-memory head. When the head is large or old enough it is frozen and a
// background flusher writes it as an immutable block (Parquet by default,
// with a trace-ID bloom filter and a service-and-time index), then deletes
// the log segments the block covers. Reads merge the heads and the blocks;
// for the same trace and span ID the latest write wins.
//
// The store keeps one copy on one node (IMP-2): it survives a crash of the
// process, not the loss of the disk.
package tracestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/node/selfmon"
	"github.com/ObservexINC/Observex_managed/internal/store"
)

// Options tunes the store. Zero values take the defaults.
type Options struct {
	// A head is frozen and written as a block when it holds MaxHeadSpans
	// spans, MaxHeadBytes of encoded spans, or is MaxHeadAge old.
	MaxHeadSpans int
	MaxHeadBytes int64
	MaxHeadAge   time.Duration
	// GroupSpans is the number of spans per Parquet row group or segment
	// group.
	GroupSpans int
	// Format is FormatParquet (the default) or FormatSegment.
	Format string
	// MaxFrozenHeads is how many frozen heads may wait for the flusher
	// before writes are refused.
	MaxFrozenHeads int
	// Logger receives flush errors and recovery notes. Nil discards them.
	Logger *slog.Logger
}

const (
	defaultMaxHeadSpans   = 100_000
	defaultMaxHeadBytes   = 64 << 20
	defaultMaxHeadAge     = 5 * time.Minute
	defaultGroupSpans     = 4096
	defaultMaxFrozenHeads = 4
)

func (o *Options) defaults() {
	if o.MaxHeadSpans <= 0 {
		o.MaxHeadSpans = defaultMaxHeadSpans
	}
	if o.MaxHeadBytes <= 0 {
		o.MaxHeadBytes = defaultMaxHeadBytes
	}
	if o.MaxHeadAge <= 0 {
		o.MaxHeadAge = defaultMaxHeadAge
	}
	if o.GroupSpans <= 0 {
		o.GroupSpans = defaultGroupSpans
	}
	if o.MaxFrozenHeads <= 0 {
		o.MaxFrozenHeads = defaultMaxFrozenHeads
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
}

// head holds the spans not yet in a block, and the log segments that hold
// them.
type head struct {
	traces   map[store.TraceID]map[store.SpanID]spanRec
	spans    int
	bytes    int64
	created  time.Time
	segments []string
}

func newHead() *head {
	return &head{traces: map[store.TraceID]map[store.SpanID]spanRec{}, created: time.Now()}
}

// put keeps the record with the highest sequence for each span.
func (h *head) put(r spanRec, size int) {
	tr, ok := h.traces[r.span.TraceID]
	if !ok {
		tr = map[store.SpanID]spanRec{}
		h.traces[r.span.TraceID] = tr
	}
	if old, ok := tr[r.span.SpanID]; ok {
		if old.seq > r.seq {
			return
		}
	} else {
		h.spans++
	}
	tr[r.span.SpanID] = r
	h.bytes += int64(size)
}

func (h *head) recs() []spanRec {
	out := make([]spanRec, 0, h.spans)
	for _, tr := range h.traces {
		for _, r := range tr {
			out = append(out, r)
		}
	}
	return out
}

// Store is the TraceStore.
type Store struct {
	dir      string
	walDir   string
	blockDir string
	opts     Options
	format   blockFormat
	log      *slog.Logger

	// writeMu serializes writers: sequence numbers, log appends and head
	// rotation.
	writeMu sync.Mutex
	seq     uint64
	wal     *walFile
	nextSeg uint64

	// mu guards the heads, the blocks and closed. Readers hold it only to
	// copy what they need; inflight keeps blocks open until they finish.
	mu       sync.RWMutex
	active   *head
	frozen   []*head
	blocks   []*block
	closed   bool
	inflight sync.WaitGroup
	flushErr error

	flushReq chan struct{}
	stop     chan struct{}
	done     chan struct{}

	stats stats
}

type stats struct {
	spansWritten, batches, walBytes  atomic.Uint64
	flushes, flushErrors, truncated  atomic.Uint64
	lastFlushNanos, recoveredBatches atomic.Uint64
	tmpRemovedAt                     atomic.Uint64
}

var _ store.TraceStore = (*Store)(nil)

// Open opens or creates a store in dir and recovers it: unfinished blocks are
// removed, blocks are opened and checked, and log records not yet in a block
// are replayed into the head.
func Open(dir string, opts Options) (*Store, error) {
	opts.defaults()
	format, err := formatByName(opts.Format)
	if err != nil {
		return nil, err
	}
	s := &Store{
		dir: dir, walDir: filepath.Join(dir, "wal"), blockDir: filepath.Join(dir, "blocks"),
		opts: opts, format: format, log: opts.Logger,
		flushReq: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
	}
	for _, d := range []string{dir, s.walDir, s.blockDir} {
		if err := os.MkdirAll(d, 0o700); err != nil { //nolint:gosec // G703: the store's directory, chosen by the operator
			return nil, fmt.Errorf("tracestore: %w", err)
		}
	}
	if err := s.recover(); err != nil {
		_ = s.closeFiles()
		return nil, err
	}
	go s.flusher()
	return s, nil
}

func (s *Store) recover() error {
	// Blocks: remove unfinished ones, open the rest.
	entries, err := os.ReadDir(s.blockDir)
	if err != nil {
		return fmt.Errorf("tracestore: %w", err)
	}
	var maxBlockSeq uint64
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(s.blockDir, e.Name())
		if strings.HasPrefix(e.Name(), ".tmp-") {
			if err := os.RemoveAll(path); err != nil {
				return fmt.Errorf("tracestore: remove unfinished block: %w", err)
			}
			s.stats.tmpRemovedAt.Add(1)
			continue
		}
		b, err := openBlock(path)
		if err != nil {
			return err
		}
		s.blocks = append(s.blocks, b)
		if b.idx.maxSeq > maxBlockSeq {
			maxBlockSeq = b.idx.maxSeq
		}
	}
	sort.Slice(s.blocks, func(i, j int) bool { return s.blocks[i].idx.minSeq < s.blocks[j].idx.minSeq })

	// Log: replay what no block holds yet.
	nums, err := listSegments(s.walDir)
	if err != nil {
		return fmt.Errorf("tracestore: %w", err)
	}
	h := newHead()
	s.seq = maxBlockSeq
	for i, num := range nums {
		path := filepath.Join(s.walDir, segmentName(num))
		data, err := os.ReadFile(path) //nolint:gosec // G304: the store's own log segment
		if err != nil {
			return fmt.Errorf("tracestore: %w", err)
		}
		batches, good, tail := readRecords(data)
		if tail != nil {
			// A torn record is expected only at the end of the last segment.
			level := slog.LevelWarn
			if i != len(nums)-1 {
				level = slog.LevelError
			}
			s.log.Log(context.Background(), level, "tracestore: cutting the write-ahead log after its last complete record",
				slog.String("segment", filepath.Base(path)), slog.Int("kept_bytes", good),
				slog.Int("cut_bytes", len(data)-good), slog.String("reason", tail.Error()))
			if err := os.Truncate(path, int64(good)); err != nil {
				return fmt.Errorf("tracestore: cut torn log record: %w", err)
			}
			s.stats.truncated.Add(uint64(len(data) - good)) //nolint:gosec // G115: good <= len(data)
		}
		pending := false
		for _, bt := range batches {
			if bt.seq > s.seq {
				s.seq = bt.seq
			}
			if bt.seq <= maxBlockSeq {
				continue // already in a block
			}
			pending = true
			s.stats.recoveredBatches.Add(1)
			for _, r := range bt.spans {
				h.put(r, encodedSize(r))
			}
		}
		if pending {
			h.segments = append(h.segments, path)
		} else if err := os.Remove(path); err != nil {
			return fmt.Errorf("tracestore: remove applied log segment: %w", err)
		}
		if num >= s.nextSeg {
			s.nextSeg = num + 1
		}
	}
	if s.nextSeg == 0 {
		s.nextSeg = 1
	}
	if err := syncDir(s.walDir); err != nil {
		return fmt.Errorf("tracestore: %w", err)
	}
	w, err := createSegment(s.walDir, s.nextSeg)
	if err != nil {
		return fmt.Errorf("tracestore: %w", err)
	}
	s.nextSeg++
	s.wal = w
	h.segments = append(h.segments, w.path)
	s.active = h
	return nil
}

func encodedSize(r spanRec) int { return len(appendSpan(nil, r)) }

// closedErr applies the contract's first checks: a closed store, then an
// ended context. The caller holds mu.
func (s *Store) closedErr(ctx context.Context) error {
	if s.closed {
		return store.ErrClosed
	}
	return ctx.Err()
}

// WriteSpans implements store.TraceStore. It returns once the spans are in
// the write-ahead log on disk.
func (s *Store) WriteSpans(ctx context.Context, spans []store.Span) error {
	s.mu.RLock()
	err := s.closedErr(ctx)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	for _, sp := range spans {
		if err := validate(sp); err != nil {
			return err
		}
	}
	if len(spans) == 0 {
		return nil
	}

	// Backpressure: while too many frozen heads wait for the flusher, wait
	// for it; if its last attempt failed, refuse instead of filling memory.
	for {
		s.mu.RLock()
		err = s.closedErr(ctx)
		frozen, ferr := len(s.frozen), s.flushErr
		s.mu.RUnlock()
		if err != nil {
			return err
		}
		if frozen < s.opts.MaxFrozenHeads {
			break
		}
		if ferr != nil {
			return fmt.Errorf("tracestore: %d heads are waiting to be written as blocks and the last attempt failed; refusing writes until one succeeds: %w", frozen, ferr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Millisecond):
		}
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.RLock()
	err = s.closedErr(ctx)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	seq := s.seq + 1
	rec, err := encodeBatch(seq, spans)
	if err != nil {
		return err
	}
	if err := s.wal.append(rec); err != nil {
		return err
	}
	s.seq = seq
	s.stats.batches.Add(1)
	s.stats.spansWritten.Add(uint64(len(spans)))
	s.stats.walBytes.Add(uint64(len(rec)))

	s.mu.Lock()
	for _, sp := range spans {
		r := spanRec{span: copySpan(sp), seq: seq}
		s.active.put(r, encodedSize(r))
	}
	full := s.active.spans >= s.opts.MaxHeadSpans || s.active.bytes >= s.opts.MaxHeadBytes
	s.mu.Unlock()
	if full {
		s.rotate()
	}
	return nil
}

// rotate freezes the active head and starts a new one with a new log
// segment. The caller holds writeMu.
func (s *Store) rotate() {
	w, err := createSegment(s.walDir, s.nextSeg)
	if err != nil {
		// The head grows until a segment can be created; writes still go to
		// the old segment, so nothing is lost.
		s.log.Error("tracestore: cannot start a new log segment", slog.String("error", err.Error()))
		return
	}
	s.nextSeg++
	old := s.wal
	s.wal = w
	if err := old.close(); err != nil {
		s.log.Warn("tracestore: close log segment", slog.String("error", err.Error()))
	}
	s.mu.Lock()
	if s.active.spans > 0 {
		s.frozen = append(s.frozen, s.active)
		s.active = newHead()
		s.active.segments = []string{w.path}
	} else {
		s.active.segments = append(s.active.segments, w.path)
	}
	s.mu.Unlock()
	select {
	case s.flushReq <- struct{}{}:
	default:
	}
}

// flusher writes frozen heads as blocks, and freezes the active head when it
// is too old.
func (s *Store) flusher() {
	defer close(s.done)
	tick := time.NewTicker(s.opts.MaxHeadAge / 4)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-s.flushReq:
		case <-tick.C:
			// A writer waiting for this flusher holds writeMu; never wait
			// for it here.
			if !s.writeMu.TryLock() {
				break
			}
			s.mu.RLock()
			old := !s.closed && s.active.spans > 0 && time.Since(s.active.created) >= s.opts.MaxHeadAge
			s.mu.RUnlock()
			if old {
				s.rotate()
			}
			s.writeMu.Unlock()
		}
		for s.flushOne() {
		}
	}
}

// flushOne writes the oldest frozen head as a block. It reports whether
// there may be more to do.
func (s *Store) flushOne() bool {
	select {
	case <-s.stop:
		return false
	default:
	}
	s.mu.RLock()
	if len(s.frozen) == 0 || s.closed {
		s.mu.RUnlock()
		return false
	}
	h := s.frozen[0]
	recs := h.recs()
	s.mu.RUnlock()

	start := time.Now()
	sortRecs(recs)
	b, err := writeBlock(s.blockDir, s.format, recs, s.opts.GroupSpans)
	if err != nil {
		s.stats.flushErrors.Add(1)
		s.log.Error("tracestore: flush failed; the head stays in memory and in the log", slog.String("error", err.Error()))
		s.mu.Lock()
		s.flushErr = err
		s.mu.Unlock()
		return false
	}
	// The block is durable; its log segments can go. Until the block is
	// published below, readers still find the spans in the frozen head.
	for _, seg := range h.segments {
		if err := os.Remove(seg); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.log.Warn("tracestore: remove flushed log segment", slog.String("error", err.Error()))
		}
	}
	if err := syncDir(s.walDir); err != nil {
		s.log.Warn("tracestore: sync log directory", slog.String("error", err.Error()))
	}
	s.stats.flushes.Add(1)
	s.stats.lastFlushNanos.Store(uint64(time.Since(start))) //nolint:gosec // G115: durations are positive
	s.mu.Lock()
	s.blocks = append(s.blocks, b)
	s.frozen = s.frozen[1:]
	s.flushErr = nil
	s.mu.Unlock()
	return true
}

// Flush freezes the active head and waits until every frozen head is a
// block. Tests and shutdown use it; normal operation does not need it.
func (s *Store) Flush(ctx context.Context) error {
	s.writeMu.Lock()
	s.mu.RLock()
	err := s.closedErr(ctx)
	s.mu.RUnlock()
	if err == nil {
		s.rotate()
	}
	s.writeMu.Unlock()
	if err != nil {
		return err
	}
	for {
		s.mu.RLock()
		n, ferr, closed := len(s.frozen), s.flushErr, s.closed
		s.mu.RUnlock()
		switch {
		case closed:
			return store.ErrClosed
		case n == 0:
			return nil
		case ferr != nil:
			return ferr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// snapshot is what a read needs, copied under the lock.
type snapshot struct {
	heads  []*head
	blocks []*block
}

// view takes the current heads and blocks, and keeps the blocks open until
// done is called.
func (s *Store) view(ctx context.Context) (snapshot, func(), error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.closedErr(ctx); err != nil {
		return snapshot{}, nil, err
	}
	s.inflight.Add(1)
	heads := append(append([]*head{}, s.frozen...), s.active)
	return snapshot{heads: heads, blocks: append([]*block{}, s.blocks...)}, s.inflight.Done, nil
}

// merged returns the latest version of each span of the given traces, from
// blocks and heads.
func (s *Store) merged(ctx context.Context, snap snapshot, ids []store.TraceID) (map[store.TraceID]map[store.SpanID]spanRec, error) {
	out := make(map[store.TraceID]map[store.SpanID]spanRec, len(ids))
	add := func(r spanRec) {
		tr, ok := out[r.span.TraceID]
		if !ok {
			tr = map[store.SpanID]spanRec{}
			out[r.span.TraceID] = tr
		}
		if old, ok := tr[r.span.SpanID]; !ok || r.seq > old.seq {
			tr[r.span.SpanID] = r
		}
	}
	for _, b := range snap.blocks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		recs, err := b.spansOf(ids)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			add(r)
		}
	}
	s.mu.RLock()
	for _, h := range snap.heads {
		for _, id := range ids {
			for _, r := range h.traces[id] {
				add(r)
			}
		}
	}
	s.mu.RUnlock()
	return out, nil
}

func sortedSpans(tr map[store.SpanID]spanRec) []store.Span {
	out := make([]store.Span, 0, len(tr))
	for _, r := range tr {
		out = append(out, copySpan(r.span))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Start.Equal(out[j].Start) {
			return out[i].Start.Before(out[j].Start)
		}
		return bytes.Compare(out[i].SpanID[:], out[j].SpanID[:]) < 0
	})
	return out
}

// GetTrace implements store.TraceStore.
func (s *Store) GetTrace(ctx context.Context, id store.TraceID) ([]store.Span, error) {
	snap, done, err := s.view(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	m, err := s.merged(ctx, snap, []store.TraceID{id})
	if err != nil {
		return nil, err
	}
	tr, ok := m[id]
	if !ok || len(tr) == 0 {
		return nil, store.ErrNotFound
	}
	return sortedSpans(tr), nil
}

// FindTraces implements store.TraceStore. Candidates come from the heads and
// from each block's service-and-time index; every candidate is then checked
// and summarised from the latest version of all its spans, so a rewritten
// span counts as rewritten.
func (s *Store) FindTraces(ctx context.Context, q store.TraceQuery) ([]store.TraceSummary, error) {
	snap, done, err := s.view(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if q.Service == "" {
		return nil, store.Invalid("trace query needs a service")
	}
	if err := q.Range.Validate(); err != nil {
		return nil, err
	}
	limit, err := store.NormaliseLimit(q.Limit)
	if err != nil {
		return nil, err
	}
	cand := map[store.TraceID]struct{}{}
	s.mu.RLock()
	for _, h := range snap.heads {
		for id, tr := range h.traces {
			for _, r := range tr {
				if r.span.Service == q.Service && q.Range.Contains(r.span.Start) {
					cand[id] = struct{}{}
					break
				}
			}
		}
	}
	s.mu.RUnlock()
	for _, b := range snap.blocks {
		if err := b.idx.serviceTraces(q.Service, q.Range, cand); err != nil {
			return nil, fmt.Errorf("tracestore: block %s: %w", filepath.Base(b.dir), err)
		}
	}
	ids := make([]store.TraceID, 0, len(cand))
	for id := range cand {
		ids = append(ids, id)
	}
	m, err := s.merged(ctx, snap, ids)
	if err != nil {
		return nil, err
	}
	out := []store.TraceSummary{}
	for id, tr := range m {
		spans := sortedSpans(tr)
		hit := false
		for _, sp := range spans {
			if sp.Service == q.Service && q.Range.Contains(sp.Start) {
				hit = true
				break
			}
		}
		if !hit {
			continue // an older version matched; the latest does not
		}
		sum := summarise(id, spans)
		if q.ErrorsOnly && !sum.Error {
			continue
		}
		out = append(out, sum)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Start.Equal(out[j].Start) {
			return out[i].Start.After(out[j].Start)
		}
		return bytes.Compare(out[i].TraceID[:], out[j].TraceID[:]) < 0
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func summarise(id store.TraceID, spans []store.Span) store.TraceSummary {
	sum := store.TraceSummary{TraceID: id, SpanCount: len(spans)}
	var end time.Time
	services := map[string]bool{}
	for i, sp := range spans {
		if i == 0 || sp.Start.Before(sum.Start) {
			sum.Start = sp.Start
		}
		if sp.End.After(end) {
			end = sp.End
		}
		if sp.Error {
			sum.Error = true
		}
		services[sp.Service] = true
	}
	sum.Duration = end.Sub(sum.Start)
	for svc := range services {
		sum.Services = append(sum.Services, svc)
	}
	sort.Strings(sum.Services)
	return sum
}

func copySpan(sp store.Span) store.Span {
	sp.Start = sp.Start.UTC()
	sp.End = sp.End.UTC()
	if sp.Attributes != nil {
		m := make(map[string]string, len(sp.Attributes))
		for k, v := range sp.Attributes {
			m[k] = v
		}
		sp.Attributes = m
	}
	return sp
}

// Close implements store.TraceStore. Spans still in the head stay in the
// write-ahead log and are replayed when the store is opened again.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	close(s.stop)
	<-s.done // the flusher finishes the block it is writing
	// A writer that passed the closed check before it was set finishes its
	// append; readers finish with the blocks.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.inflight.Wait()
	return s.closeFiles()
}

func (s *Store) closeFiles() error {
	var errs []error
	if s.wal != nil {
		errs = append(errs, s.wal.close())
	}
	for _, b := range s.blocks {
		errs = append(errs, b.close())
	}
	return errors.Join(errs...)
}

// Name implements selfmon.Collector.
func (s *Store) Name() string { return "tracestore" }

// Collect implements selfmon.Collector.
func (s *Store) Collect(b *selfmon.Batch) {
	s.mu.RLock()
	blocks, frozen := len(s.blocks), len(s.frozen)
	headSpans := 0
	if s.active != nil {
		headSpans = s.active.spans
	}
	for _, h := range s.frozen {
		headSpans += h.spans
	}
	var blockSpans uint64
	for _, bl := range s.blocks {
		blockSpans += bl.idx.spans
	}
	s.mu.RUnlock()
	st := &s.stats
	b.Counter("observex_tracestore_spans_written_total", "Spans accepted by WriteSpans.", float64(st.spansWritten.Load()))
	b.Counter("observex_tracestore_batches_total", "WriteSpans calls written to the log.", float64(st.batches.Load()))
	b.Counter("observex_tracestore_wal_bytes_total", "Bytes appended to the write-ahead log.", float64(st.walBytes.Load()))
	b.Counter("observex_tracestore_flushes_total", "Heads written as blocks.", float64(st.flushes.Load()))
	b.Counter("observex_tracestore_flush_errors_total", "Failed attempts to write a block.", float64(st.flushErrors.Load()))
	b.Counter("observex_tracestore_wal_cut_bytes_total", "Bytes of torn or damaged log records cut at recovery.", float64(st.truncated.Load()))
	b.Gauge("observex_tracestore_blocks", "Blocks on disk.", float64(blocks))
	b.Gauge("observex_tracestore_block_spans", "Spans in blocks, rewrites counted again.", float64(blockSpans))
	b.Gauge("observex_tracestore_head_spans", "Spans in memory, not yet in a block.", float64(headSpans))
	b.Gauge("observex_tracestore_frozen_heads", "Heads waiting to be written as blocks.", float64(frozen))
	b.Gauge("observex_tracestore_last_flush_seconds", "Duration of the last block write.", float64(st.lastFlushNanos.Load())/1e9)
}
