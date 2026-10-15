package store

import (
	"context"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

// labelKeyPattern accepts Prometheus label names plus the dots, dashes and
// slashes used in OpenTelemetry attribute keys.
var labelKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_./-]*$`)

var labelValueEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// Labels are a series' dimensions, such as service, host or status code.
type Labels map[string]string

// Series identifies one time series by metric name and labels.
type Series struct {
	Name   string
	Labels Labels
}

// Key returns a canonical, order-independent identity for a valid series:
// name{k1="v1",k2="v2"} with labels sorted by key and values escaped, so two
// different label sets never share a key.
func (s Series) Key() string {
	keys := make([]string, 0, len(s.Labels))
	for k := range s.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(s.Name)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(labelValueEscaper.Replace(s.Labels[k]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// Validate checks the series has a name and well-formed label keys.
func (s Series) Validate() error {
	if s.Name == "" {
		return Invalid("series needs a metric name")
	}
	if !labelKeyPattern.MatchString(s.Name) {
		return Invalid("metric name %q has characters outside letters, digits, _ . / -", s.Name)
	}
	for k := range s.Labels {
		if !labelKeyPattern.MatchString(k) {
			return Invalid("series %q has an invalid label key %q", s.Name, k)
		}
	}
	return nil
}

// Point is one value at one time.
type Point struct {
	Time  time.Time
	Value float64
}

// Sample is a point for a series, as written.
type Sample struct {
	Series Series
	Point  Point
}

// Validate checks the sample's series, time and value.
func (s Sample) Validate() error {
	if err := s.Series.Validate(); err != nil {
		return err
	}
	if s.Point.Time.IsZero() {
		return Invalid("sample for %q has no time", s.Series.Name)
	}
	if math.IsNaN(s.Point.Value) || math.IsInf(s.Point.Value, 0) {
		return Invalid("sample for %q is not a finite number", s.Series.Name)
	}
	return nil
}

// Matcher selects series whose label equals a value. Version 0 supports
// equality only; PromQL's other matchers are evaluated by the query layer.
type Matcher struct {
	Label string
	Value string
}

// MetricQuery selects points of one metric in a time range.
type MetricQuery struct {
	Name     string
	Matchers []Matcher
	Range    TimeRange
}

// SeriesPoints is one series and its points in the queried range.
type SeriesPoints struct {
	Series Series
	Points []Point
}

// MetricStore is the MetricStore contract.
//
//   - WriteSamples is all-or-nothing: if any sample is invalid, nothing is written.
//   - A second write for the same series and time replaces the first.
//   - QuerySeries returns series sorted by Key, points sorted by time, and an
//     empty result (not an error) when nothing matches.
type MetricStore interface {
	WriteSamples(ctx context.Context, samples []Sample) error
	QuerySeries(ctx context.Context, q MetricQuery) ([]SeriesPoints, error)
	Close() error
}
