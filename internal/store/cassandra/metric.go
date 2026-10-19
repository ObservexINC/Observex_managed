// Package cassandra holds the store adapters on Apache Cassandra (technology
// rows T5 and T9). G02 brings the MetricStore; the History and Baseline
// tables follow in G08.
//
// The MetricStore keeps three tables in its keyspace:
//
//	metric_series      ((metric, shard), series_key) -> labels
//	metric_series_days ((series_key), day)
//	metric_points      ((series_key, day), t) -> value
//
// A series is identified by store.Series.Key, its canonical text. Its points
// are partitioned by UTC day and kept in Unix nanoseconds, so no precision is
// lost. A query lists the metric's series from 16 shards, filters them by the
// matchers, finds the days each matching series has points on, and reads
// only those partitions.
package cassandra

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"

	"github.com/ObservexINC/Observex_managed/internal/node/selfmon"
	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
	"github.com/ObservexINC/Observex_managed/internal/store"
)

// Config describes the connection and the keyspace.
type Config struct {
	// Hosts are host or host:port contact points (default port 9042).
	Hosts []string
	// Keyspace holds the tables: letters, digits and underscores, starting
	// with a letter, at most 48 characters.
	Keyspace string
	// Username and Password, for Cassandra's PasswordAuthenticator. The
	// password is a logging.Secret, so it never prints.
	Username string
	Password logging.Secret
	// CreateSchema creates the keyspace and tables when they are missing,
	// with NetworkTopologyStrategy and ReplicationFactor copies in
	// Datacenter (defaults: datacenter1, 1).
	CreateSchema      bool
	Datacenter        string
	ReplicationFactor int
	// Consistency for reads and writes; default LOCAL_QUORUM.
	Consistency gocql.Consistency
	// Timeout per request; default 10 s.
	Timeout time.Duration
	// Logger receives the driver's warnings and errors. Nil discards them.
	Logger *slog.Logger
}

var keyspaceRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,47}$`)

// LogValue keeps the configuration loggable: the password is redacted by its
// type, and only the fields useful in a log are shown.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("hosts", c.Hosts), slog.String("keyspace", c.Keyspace),
		slog.String("username", c.Username), slog.Any("password", c.Password),
	)
}

const (
	seriesShards  = 16
	nanosPerDay   = int64(24 * time.Hour)
	maxBatchBytes = 24 << 10 // below Cassandra's default 50 KiB batch limit
	workers       = 8        // concurrent requests per call
	seriesCache   = 100_000
)

// MetricStore is a store.MetricStore on Cassandra.
type MetricStore struct {
	session *gocql.Session
	ks      string
	closed  atomic.Bool

	// known remembers series and series-days already written, so repeated
	// writes do not rewrite them. It is cleared when it grows past
	// seriesCache entries.
	mu    sync.Mutex
	known map[string]bool

	samples, writeErrors, queries, queryErrors atomic.Uint64
}

var _ store.MetricStore = (*MetricStore)(nil)

// OpenMetricStore connects and, if asked, creates the schema.
func OpenMetricStore(ctx context.Context, c Config) (*MetricStore, error) {
	if len(c.Hosts) == 0 {
		return nil, store.Invalid("cassandra: no hosts")
	}
	if !keyspaceRE.MatchString(c.Keyspace) {
		return nil, store.Invalid("cassandra: keyspace %q must be a letter then up to 47 letters, digits or underscores", c.Keyspace)
	}
	if c.Datacenter == "" {
		c.Datacenter = "datacenter1"
	}
	if c.ReplicationFactor <= 0 {
		c.ReplicationFactor = 1
	}
	if c.Consistency == 0 {
		c.Consistency = gocql.LocalQuorum
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	cluster := gocql.NewCluster(c.Hosts...)
	cluster.Consistency = c.Consistency
	cluster.Timeout = c.Timeout
	cluster.ConnectTimeout = c.Timeout
	cluster.Logger = slogLogger{l: c.Logger}
	cluster.DefaultIdempotence = true // every write here can be repeated safely
	if c.Username != "" || c.Password != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: c.Username, Password: c.Password.Reveal(),
			AllowedAuthenticators: []string{"org.apache.cassandra.auth.PasswordAuthenticator"},
		}
	}
	session, err := cluster.CreateSession()
	if err != nil {
		return nil, fmt.Errorf("cassandra: connect: %w", err)
	}
	m := &MetricStore{session: session, ks: c.Keyspace, known: map[string]bool{}}
	if c.CreateSchema {
		if err := m.createSchema(ctx, c.Datacenter, c.ReplicationFactor); err != nil {
			session.Close()
			return nil, err
		}
	}
	return m, nil
}

func (m *MetricStore) createSchema(ctx context.Context, dc string, rf int) error {
	stmts := []string{
		fmt.Sprintf(`CREATE KEYSPACE IF NOT EXISTS %s WITH replication = {'class': 'NetworkTopologyStrategy', '%s': %d}`, m.ks, strings.ReplaceAll(dc, "'", "''"), rf),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.metric_series (
			metric text, shard int, series_key text, labels map<text, text>,
			PRIMARY KEY ((metric, shard), series_key))`, m.ks),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.metric_series_days (
			series_key text, day int,
			PRIMARY KEY ((series_key), day))`, m.ks),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.metric_points (
			series_key text, day int, t bigint, value double,
			PRIMARY KEY ((series_key, day), t))
			WITH CLUSTERING ORDER BY (t ASC)
			AND compaction = {'class': 'TimeWindowCompactionStrategy', 'compaction_window_unit': 'DAYS', 'compaction_window_size': 1}`, m.ks),
	}
	for _, s := range stmts {
		if err := m.session.Query(s).ExecContext(ctx); err != nil {
			return fmt.Errorf("cassandra: create schema: %w", err)
		}
	}
	return nil
}

func (m *MetricStore) begin(ctx context.Context) error {
	if m.closed.Load() {
		return store.ErrClosed
	}
	return ctx.Err()
}

func (m *MetricStore) fail(err error) error {
	if m.closed.Load() {
		return store.ErrClosed
	}
	return err
}

func shardOf(key string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % seriesShards)
}

// dayOf is the UTC day of t (Unix nanoseconds), rounding down.
func dayOf(t int64) int {
	d := t / nanosPerDay
	if t%nanosPerDay < 0 {
		d--
	}
	return int(d)
}

// Unix nanoseconds in an int64 cover 1678 to 2262.
var (
	minTime = time.Unix(0, math.MinInt64).UTC()
	maxTime = time.Unix(0, math.MaxInt64).UTC()
)

func storable(t time.Time) bool { return !t.Before(minTime) && !t.After(maxTime) }

// pointRow is one point to write.
type pointRow struct {
	key   string
	day   int
	t     int64
	value float64
}

// WriteSamples implements store.MetricStore. Every sample is checked before
// anything is written. Writes are idempotent; if Cassandra fails part way,
// the error is returned and repeating the call converges.
func (m *MetricStore) WriteSamples(ctx context.Context, samples []store.Sample) error {
	if err := m.begin(ctx); err != nil {
		return err
	}
	for _, s := range samples {
		if err := s.Validate(); err != nil {
			return err
		}
		if !storable(s.Point.Time) {
			return store.Invalid("sample for %q has a time outside 1678 to 2262, which the MetricStore cannot hold", s.Series.Name)
		}
	}
	series := map[string]store.Series{}
	days := map[string]bool{}
	rows := make([]pointRow, 0, len(samples))
	for _, s := range samples {
		key := s.Series.Key()
		t := s.Point.Time.UnixNano()
		r := pointRow{key: key, day: dayOf(t), t: t, value: s.Point.Value}
		rows = append(rows, r)
		series[key] = s.Series
		days[fmt.Sprintf("%s\x00%d", key, r.day)] = true
	}
	// Series and their days first, so a point is never stored where a query
	// cannot find it.
	m.mu.Lock()
	var newSeries []string
	for key := range series {
		if !m.known["s\x00"+key] {
			newSeries = append(newSeries, key)
		}
	}
	var newDays []string
	for kd := range days {
		if !m.known["d\x00"+kd] {
			newDays = append(newDays, kd)
		}
	}
	m.mu.Unlock()
	err := m.parallel(ctx, len(newSeries), func(ctx context.Context, i int) error {
		key := newSeries[i]
		s := series[key]
		return m.session.Query(fmt.Sprintf(`INSERT INTO %s.metric_series (metric, shard, series_key, labels) VALUES (?, ?, ?, ?)`, m.ks),
			s.Name, shardOf(key), key, map[string]string(s.Labels)).ExecContext(ctx)
	})
	if err == nil {
		err = m.parallel(ctx, len(newDays), func(ctx context.Context, i int) error {
			key, day, _ := strings.Cut(newDays[i], "\x00")
			d, err := strconv.Atoi(day)
			if err != nil {
				return err
			}
			return m.session.Query(fmt.Sprintf(`INSERT INTO %s.metric_series_days (series_key, day) VALUES (?, ?)`, m.ks), key, d).ExecContext(ctx)
		})
	}
	if err == nil {
		err = m.writePoints(ctx, rows)
	}
	if err != nil {
		m.writeErrors.Add(1)
		return m.fail(fmt.Errorf("cassandra: write samples: %w", err))
	}
	m.mu.Lock()
	if len(m.known)+len(newSeries)+len(newDays) > seriesCache {
		m.known = map[string]bool{}
	}
	for _, key := range newSeries {
		m.known["s\x00"+key] = true
	}
	for _, kd := range newDays {
		m.known["d\x00"+kd] = true
	}
	m.mu.Unlock()
	m.samples.Add(uint64(len(samples)))
	return nil
}

// writePoints writes points as unlogged batches, each within one partition
// and under the batch size limit. Within a call, the last sample for the
// same series and time wins, as in the contract.
func (m *MetricStore) writePoints(ctx context.Context, rows []pointRow) error {
	type part struct {
		key string
		day int
	}
	last := map[part]map[int64]float64{}
	var order []part
	for _, r := range rows {
		p := part{r.key, r.day}
		pts, ok := last[p]
		if !ok {
			pts = map[int64]float64{}
			last[p] = pts
			order = append(order, p)
		}
		pts[r.t] = r.value
	}
	type batch struct {
		p      part
		points [][2]any
	}
	var batches []batch
	for _, p := range order {
		ts := make([]int64, 0, len(last[p]))
		for t := range last[p] {
			ts = append(ts, t)
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
		per := maxBatchBytes / (len(p.key) + 64)
		if per < 1 {
			per = 1
		}
		for i := 0; i < len(ts); i += per {
			b := batch{p: p}
			for _, t := range ts[i:min(i+per, len(ts))] {
				b.points = append(b.points, [2]any{t, last[p][t]})
			}
			batches = append(batches, b)
		}
	}
	stmt := fmt.Sprintf(`INSERT INTO %s.metric_points (series_key, day, t, value) VALUES (?, ?, ?, ?)`, m.ks)
	return m.parallel(ctx, len(batches), func(ctx context.Context, i int) error {
		b := batches[i]
		if len(b.points) == 1 {
			return m.session.Query(stmt, b.p.key, b.p.day, b.points[0][0], b.points[0][1]).ExecContext(ctx)
		}
		batch := m.session.Batch(gocql.UnloggedBatch)
		for _, pt := range b.points {
			batch.Query(stmt, b.p.key, b.p.day, pt[0], pt[1])
		}
		return batch.ExecContext(ctx)
	})
}

// parallel runs f for 0..n-1 on up to workers goroutines and returns the
// first error; the others stop early.
func (m *MetricStore) parallel(parent context.Context, n int, f func(ctx context.Context, i int) error) error {
	if n == 0 {
		return parent.Err()
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var next atomic.Int64
	var once sync.Once
	var first error
	var wg sync.WaitGroup
	for w := 0; w < min(workers, n); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= n || ctx.Err() != nil {
					return
				}
				if err := f(ctx, i); err != nil {
					once.Do(func() { first = err; cancel() })
					return
				}
			}
		}()
	}
	wg.Wait()
	if first == nil {
		// A cancelled caller stops the workers without an error of their
		// own; the work is not complete, so say so.
		return parent.Err()
	}
	return first
}

// QuerySeries implements store.MetricStore.
func (m *MetricStore) QuerySeries(ctx context.Context, q store.MetricQuery) ([]store.SeriesPoints, error) {
	if err := m.begin(ctx); err != nil {
		return nil, err
	}
	if q.Name == "" {
		return nil, store.Invalid("metric query needs a name")
	}
	if err := q.Range.Validate(); err != nil {
		return nil, err
	}
	m.queries.Add(1)
	out, err := m.query(ctx, q)
	if err != nil {
		m.queryErrors.Add(1)
		return nil, m.fail(fmt.Errorf("cassandra: query series: %w", err))
	}
	return out, nil
}

func (m *MetricStore) query(ctx context.Context, q store.MetricQuery) ([]store.SeriesPoints, error) {
	start, end := q.Range.Start, q.Range.End
	if !storable(start) {
		start = minTime
	}
	if !storable(end) {
		end = maxTime
	}
	t0, t1 := start.UnixNano(), end.UnixNano()
	endInclusive := q.Range.End.After(maxTime) // the range reaches past the last storable time

	// Series of the metric that pass the matchers.
	var mu sync.Mutex
	var matched []store.Series
	err := m.parallel(ctx, seriesShards, func(ctx context.Context, shard int) error {
		it := m.session.Query(fmt.Sprintf(`SELECT series_key, labels FROM %s.metric_series WHERE metric = ? AND shard = ?`, m.ks), q.Name, shard).IterContext(ctx)
		var key string
		var labels map[string]string
		for it.Scan(&key, &labels) {
			if matches(labels, q.Matchers) {
				mu.Lock()
				matched = append(matched, store.Series{Name: q.Name, Labels: labels})
				mu.Unlock()
			}
			labels = nil
		}
		return it.Close()
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Key() < matched[j].Key() })

	results := make([]store.SeriesPoints, len(matched))
	err = m.parallel(ctx, len(matched), func(ctx context.Context, i int) error {
		key := matched[i].Key()
		var days []int
		it := m.session.Query(fmt.Sprintf(`SELECT day FROM %s.metric_series_days WHERE series_key = ? AND day >= ? AND day <= ?`, m.ks),
			key, dayOf(t0), dayOf(t1)).IterContext(ctx)
		var d int
		for it.Scan(&d) {
			days = append(days, d)
		}
		if err := it.Close(); err != nil {
			return err
		}
		var pts []store.Point
		for _, d := range days {
			cmp := "<"
			if endInclusive {
				cmp = "<="
			}
			it := m.session.Query(fmt.Sprintf(`SELECT t, value FROM %s.metric_points WHERE series_key = ? AND day = ? AND t >= ? AND t %s ?`, m.ks, cmp),
				key, d, t0, t1).IterContext(ctx)
			var t int64
			var v float64
			for it.Scan(&t, &v) {
				pts = append(pts, store.Point{Time: time.Unix(0, t).UTC(), Value: v})
			}
			if err := it.Close(); err != nil {
				return err
			}
		}
		results[i] = store.SeriesPoints{Series: matched[i], Points: pts}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := []store.SeriesPoints{}
	for _, r := range results {
		if len(r.Points) > 0 {
			out = append(out, r)
		}
	}
	return out, nil
}

func matches(labels map[string]string, ms []store.Matcher) bool {
	for _, m := range ms {
		if labels[m.Label] != m.Value {
			return false
		}
	}
	return true
}

// Close implements store.MetricStore.
func (m *MetricStore) Close() error {
	if !m.closed.Swap(true) {
		m.session.Close()
	}
	return nil
}

// DropKeyspace removes the store's keyspace and everything in it. Tests use
// it to clean up.
func (m *MetricStore) DropKeyspace(ctx context.Context) error {
	if err := m.begin(ctx); err != nil {
		return err
	}
	return m.session.Query(fmt.Sprintf(`DROP KEYSPACE IF EXISTS %s`, m.ks)).ExecContext(ctx)
}

// Name implements selfmon.Collector.
func (m *MetricStore) Name() string { return "metricstore" }

// Collect implements selfmon.Collector.
func (m *MetricStore) Collect(b *selfmon.Batch) {
	up := 1.0
	if m.closed.Load() || m.session.Closed() {
		up = 0
	}
	b.Gauge("observex_metricstore_up", "1 while the Cassandra session is open.", up)
	b.Counter("observex_metricstore_samples_written_total", "Samples written.", float64(m.samples.Load()))
	b.Counter("observex_metricstore_write_errors_total", "WriteSamples calls that failed in Cassandra.", float64(m.writeErrors.Load()))
	b.Counter("observex_metricstore_queries_total", "QuerySeries calls that reached Cassandra.", float64(m.queries.Load()))
	b.Counter("observex_metricstore_query_errors_total", "QuerySeries calls that failed in Cassandra.", float64(m.queryErrors.Load()))
}
