// Package selfmon is the managed node's self-monitoring: the node's own
// health as metrics (development plan G01).
//
// Collectors read their sources at every scrape. The registry writes the
// Prometheus text exposition format (version 0.0.4), which the Node
// Supervisor serves on its loopback status listener at /metrics.
//
// The development plan names the OpenTelemetry Go SDK for this module. It
// cannot be downloaded in Claude's workspace (the Go module proxy is not
// reachable), so this package uses the standard library only; its metric
// names follow OpenTelemetry's naming guidance and a later OTLP exporter can
// read the same Gather output (ADR 0009).
package selfmon

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Type is a metric type.
type Type string

// Metric types.
const (
	Gauge   Type = "gauge"
	Counter Type = "counter"
)

// Label is one label.
type Label struct{ Name, Value string }

// Sample is one value with its labels.
type Sample struct {
	Labels []Label
	Value  float64
}

// Family is all samples of one metric.
type Family struct {
	Name    string
	Help    string
	Type    Type
	Samples []Sample
}

// Batch collects samples during one scrape.
type Batch struct {
	fams   map[string]*Family
	errs   []string
	source string
}

var (
	nameRE  = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

func (b *Batch) add(t Type, name, help string, v float64, labels []Label) {
	if !nameRE.MatchString(name) {
		b.Errorf("metric name %q is not valid", name)
		return
	}
	for _, l := range labels {
		if !labelRE.MatchString(l.Name) || strings.HasPrefix(l.Name, "__") {
			b.Errorf("label name %q on %s is not valid", l.Name, name)
			return
		}
	}
	f, ok := b.fams[name]
	if !ok {
		f = &Family{Name: name, Help: help, Type: t}
		b.fams[name] = f
	} else if f.Type != t {
		b.Errorf("metric %s is both %s and %s", name, f.Type, t)
		return
	}
	f.Samples = append(f.Samples, Sample{Labels: append([]Label(nil), labels...), Value: v})
}

// Gauge adds a gauge sample.
func (b *Batch) Gauge(name, help string, v float64, labels ...Label) {
	b.add(Gauge, name, help, v, labels)
}

// Counter adds a counter sample.
func (b *Batch) Counter(name, help string, v float64, labels ...Label) {
	b.add(Counter, name, help, v, labels)
}

// Errorf records a collection problem. Problems are counted in
// observex_selfmon_errors{source} and never stop the scrape.
func (b *Batch) Errorf(format string, args ...any) {
	b.errs = append(b.errs, b.source+": "+fmt.Sprintf(format, args...))
}

// L builds a label.
func L(name, value string) Label { return Label{Name: name, Value: value} }

// Collector adds samples to a batch.
type Collector interface {
	Name() string
	Collect(b *Batch)
}

// Registry holds collectors.
type Registry struct {
	mu         sync.Mutex
	collectors []Collector
	lastErrors []string
}

// Register adds collectors.
func (r *Registry) Register(cs ...Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors = append(r.collectors, cs...)
}

// Gather runs every collector and returns the families sorted by name, with
// samples sorted by labels.
func (r *Registry) Gather() []Family {
	r.mu.Lock()
	cs := append([]Collector(nil), r.collectors...)
	r.mu.Unlock()
	b := &Batch{fams: map[string]*Family{}}
	errsBySource := map[string]int{}
	for _, c := range cs {
		b.source = c.Name()
		before := len(b.errs)
		c.Collect(b)
		errsBySource[c.Name()] += len(b.errs) - before
	}
	b.source = "selfmon"
	for _, c := range cs {
		b.Gauge("observex_selfmon_errors", "Problems while collecting the node's own metrics in the last scrape, by source.",
			float64(errsBySource[c.Name()]), L("source", c.Name()))
	}
	r.mu.Lock()
	r.lastErrors = b.errs
	r.mu.Unlock()

	out := make([]Family, 0, len(b.fams))
	for _, f := range b.fams {
		sort.SliceStable(f.Samples, func(i, j int) bool { return labelKey(f.Samples[i].Labels) < labelKey(f.Samples[j].Labels) })
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LastErrors returns the problems of the last Gather.
func (r *Registry) LastErrors() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lastErrors...)
}

func labelKey(ls []Label) string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Name)
		b.WriteByte(0)
		b.WriteString(l.Value)
		b.WriteByte(0)
	}
	return b.String()
}

// WriteText writes the families in the Prometheus text format. A
// bufio.Writer keeps its first write error and returns it from Flush, so
// the individual writes need no checks.
func WriteText(w io.Writer, fams []Family) error {
	bw := bufio.NewWriter(w)
	for _, f := range fams {
		_, _ = fmt.Fprintf(bw, "# HELP %s %s\n# TYPE %s %s\n", f.Name, escapeHelp(f.Help), f.Name, f.Type)
		for _, s := range f.Samples {
			_, _ = bw.WriteString(f.Name)
			if len(s.Labels) > 0 {
				_ = bw.WriteByte('{')
				for i, l := range s.Labels {
					if i > 0 {
						_ = bw.WriteByte(',')
					}
					_, _ = fmt.Fprintf(bw, `%s="%s"`, l.Name, escapeLabel(l.Value))
				}
				_ = bw.WriteByte('}')
			}
			_ = bw.WriteByte(' ')
			_, _ = bw.WriteString(formatValue(s.Value))
			_ = bw.WriteByte('\n')
		}
	}
	return bw.Flush()
}

// Handler serves the registry's metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = WriteText(w, r.Gather())
	})
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatInt(int64(v), 10) // whole numbers such as byte counts stay readable
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// CollectorFunc adapts a function to a Collector.
type CollectorFunc struct {
	CollectorName string
	Fn            func(b *Batch)
}

// Name returns the collector's name.
func (c CollectorFunc) Name() string { return c.CollectorName }

// Collect calls the function.
func (c CollectorFunc) Collect(b *Batch) { c.Fn(b) }

// Info returns a collector of one constant gauge with value 1, the usual
// way to publish facts such as versions as labels.
func Info(name, help string, labels ...Label) Collector {
	ls := append([]Label(nil), labels...)
	return CollectorFunc{CollectorName: name, Fn: func(b *Batch) { b.Gauge(name, help, 1, ls...) }}
}
