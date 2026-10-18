package logging

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"
)

// Bounds on how much of a value the sanitizer walks. Anything beyond them
// is replaced by a marker, never rendered.
const (
	// MaxDepth is how deep nested values are followed.
	MaxDepth = 8
	// MaxItems is how many fields, entries or elements of one struct, map,
	// slice or array are kept.
	MaxItems = 256
	// MaxNodes is how many values in total one attribute may contribute.
	MaxNodes = 4096
	// MaxString is the longest string kept, in bytes, after redaction.
	MaxString = 64 << 10
)

// Markers that stand in for what the sanitizer does not render.
const (
	TruncatedMarker   = "[TRUNCATED]"
	CycleMarker       = "[CYCLE]"
	UnprintableMarker = "[UNPRINTABLE]"
	MoreMarker        = "[MORE]"
)

// sanitizer turns an arbitrary value into plain data (nil, bool, numbers,
// strings, []any, map[string]any) with every secret already removed, so
// the handlers that render it never see a secret and never call back into
// user code.
//
// Rules:
//   - A struct field, map key or JSON member whose name is sensitive keeps
//     its name; its whole value becomes Redacted, whatever its type.
//   - Strings pass through the text rules (and the JSON rules when they
//     are whole JSON documents).
//   - Errors are rendered with Error(), and slog.LogValuer values with
//     LogValue(), both under recover; the result is then sanitized like any
//     other value. These are the only user methods called.
//   - A few standard types are rendered by their safe text form: time.Time,
//     time.Duration, net.IP, net/netip addresses and url.URL (always with
//     its password removed).
//   - Other fmt.Stringer values are not called: structs, maps and slices
//     are walked field by field, so a String method cannot print a secret
//     field. Named numbers and booleans with a String method (enumerations)
//     use it, under recover, and the result is scrubbed.
//   - Unexported struct fields are read by reflection only; no methods are
//     called on them.
//   - Cycles become CycleMarker. Depth, item and total-size bounds apply.
type sanitizer struct {
	sensitive func(string) bool
	nodes     int
	onPath    map[uintptr]bool
}

func newSanitizer(sensitive func(string) bool) *sanitizer {
	if sensitive == nil {
		sensitive = IsSensitiveKey
	}
	return &sanitizer{sensitive: sensitive, onPath: map[uintptr]bool{}}
}

var (
	errorType     = reflect.TypeOf((*error)(nil)).Elem()
	logValuerType = reflect.TypeOf((*slog.LogValuer)(nil)).Elem()
	stringerType  = reflect.TypeOf((*fmt.Stringer)(nil)).Elem()
	timeType      = reflect.TypeOf(time.Time{})
	durationType  = reflect.TypeOf(time.Duration(0))
	ipType        = reflect.TypeOf(net.IP{})
	ipNetType     = reflect.TypeOf(net.IPNet{})
	urlType       = reflect.TypeOf(url.URL{})
	addrType      = reflect.TypeOf(netip.Addr{})
	addrPortType  = reflect.TypeOf(netip.AddrPort{})
	prefixType    = reflect.TypeOf(netip.Prefix{})
	secretType    = reflect.TypeOf(Secret(""))
)

func (s *sanitizer) any(v any) any {
	return s.value(reflect.ValueOf(v), 0)
}

// text redacts and bounds a string.
func (s *sanitizer) text(str string) string {
	out := redactString(str, s.sensitive)
	if len(out) > MaxString {
		out = strings.ToValidUTF8(out[:MaxString], "") + TruncatedMarker
	}
	return out
}

// call runs f, turning a panic into UnprintableMarker.
func call(f func() string) (out string) {
	defer func() {
		if recover() != nil {
			out = UnprintableMarker
		}
	}()
	return f()
}

func (s *sanitizer) value(rv reflect.Value, depth int) any {
	if !rv.IsValid() {
		return nil
	}
	s.nodes++
	if s.nodes > MaxNodes || depth > MaxDepth {
		return TruncatedMarker
	}
	t := rv.Type()

	// Interfaces and nil pointers first, so the checks below see the
	// concrete value.
	switch rv.Kind() {
	case reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return s.value(rv.Elem(), depth)
	case reflect.Pointer:
		if rv.IsNil() {
			return nil
		}
	}

	if rv.CanInterface() {
		if out, ok := s.special(rv, t, depth); ok {
			return out
		}
	}

	switch rv.Kind() {
	case reflect.Pointer:
		p := rv.Pointer()
		if s.onPath[p] {
			return CycleMarker
		}
		s.onPath[p] = true
		defer delete(s.onPath, p)
		return s.value(rv.Elem(), depth+1)
	case reflect.Struct:
		return s.structValue(rv, t, depth)
	case reflect.Map:
		if rv.IsNil() {
			return nil
		}
		p := rv.Pointer()
		if s.onPath[p] {
			return CycleMarker
		}
		s.onPath[p] = true
		defer delete(s.onPath, p)
		return s.mapValue(rv, depth)
	case reflect.Slice:
		if rv.IsNil() {
			return nil
		}
		if t.Elem().Kind() == reflect.Uint8 {
			return s.text(string(rv.Bytes()))
		}
		if rv.Len() > 0 {
			p := rv.Pointer()
			if s.onPath[p] {
				return CycleMarker
			}
			s.onPath[p] = true
			defer delete(s.onPath, p)
		}
		return s.list(rv, depth)
	case reflect.Array:
		return s.list(rv, depth)
	case reflect.String:
		return s.text(rv.String())
	case reflect.Bool:
		return rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return rv.Uint()
	case reflect.Float32, reflect.Float64:
		f := rv.Float()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Sprint(f) // JSON cannot hold NaN or infinities
		}
		return f
	case reflect.Complex64, reflect.Complex128:
		return fmt.Sprint(rv.Complex())
	default: // channels, functions, unsafe pointers
		return "<" + rv.Kind().String() + ">"
	}
}

// special handles values whose type has a known, safe rendering. It runs
// only for values reachable without unexported fields (CanInterface).
func (s *sanitizer) special(rv reflect.Value, t reflect.Type, depth int) (any, bool) {
	switch t {
	case secretType:
		return Redacted, true
	case timeType:
		return rv.Interface().(time.Time).Format(time.RFC3339Nano), true
	case durationType:
		return rv.Interface().(time.Duration).String(), true
	case ipType:
		return rv.Interface().(net.IP).String(), true
	case addrType:
		return rv.Interface().(netip.Addr).String(), true
	case addrPortType:
		return rv.Interface().(netip.AddrPort).String(), true
	case prefixType:
		return rv.Interface().(netip.Prefix).String(), true
	case urlType:
		u := rv.Interface().(url.URL)
		return s.text(u.Redacted()), true
	}
	if t.Kind() == reflect.Pointer {
		switch t.Elem() {
		case urlType:
			return s.text(rv.Interface().(*url.URL).Redacted()), true
		case ipNetType:
			return rv.Interface().(*net.IPNet).String(), true
		}
	}
	if t.Implements(logValuerType) {
		lv := resolve(slog.AnyValue(rv.Interface()))
		return s.slogValue(lv, depth+1), true
	}
	if t.Implements(errorType) {
		e := rv.Interface().(error)
		return s.text(call(e.Error)), true
	}
	if t.Implements(stringerType) {
		switch t.Kind() {
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
			st := rv.Interface().(fmt.Stringer)
			return s.text(call(st.String)), true
		}
	}
	return nil, false
}

func (s *sanitizer) structValue(rv reflect.Value, t reflect.Type, depth int) any {
	out := make(map[string]any, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		if i == MaxItems {
			out[MoreMarker] = t.NumField() - i
			break
		}
		f := t.Field(i)
		name := f.Name
		jsonName, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "_" {
			continue
		}
		if s.sensitive(name) || (jsonName != "" && jsonName != "-" && s.sensitive(jsonName)) {
			out[name] = Redacted
			continue
		}
		out[name] = s.value(rv.Field(i), depth+1)
	}
	return out
}

type mapEntry struct {
	key string
	val reflect.Value
}

func (s *sanitizer) mapValue(rv reflect.Value, depth int) any {
	entries := make([]mapEntry, 0, rv.Len())
	it := rv.MapRange()
	for it.Next() {
		k := it.Key()
		var ks string
		if k.Kind() == reflect.String {
			ks = s.text(k.String())
		} else {
			ks = fmt.Sprint(s.value(k, depth+1))
		}
		entries = append(entries, mapEntry{key: ks, val: it.Value()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	out := make(map[string]any, len(entries))
	for i, e := range entries {
		if i == MaxItems {
			out[MoreMarker] = len(entries) - i
			break
		}
		if s.sensitive(e.key) {
			out[e.key] = Redacted
			continue
		}
		out[e.key] = s.value(e.val, depth+1)
	}
	return out
}

func (s *sanitizer) list(rv reflect.Value, depth int) any {
	n := rv.Len()
	out := make([]any, 0, min(n, MaxItems+1))
	for i := 0; i < n; i++ {
		if i == MaxItems {
			out = append(out, fmt.Sprintf("%s %d", MoreMarker, n-i))
			break
		}
		out = append(out, s.value(rv.Index(i), depth+1))
	}
	return out
}

// slogValue sanitizes the result of a LogValue method.
func (s *sanitizer) slogValue(v slog.Value, depth int) any {
	s.nodes++
	if s.nodes > MaxNodes || depth > MaxDepth {
		return TruncatedMarker
	}
	switch v.Kind() {
	case slog.KindString:
		return s.text(v.String())
	case slog.KindGroup:
		out := map[string]any{}
		for i, a := range v.Group() {
			if i == MaxItems {
				out[MoreMarker] = len(v.Group()) - i
				break
			}
			if s.sensitive(a.Key) {
				out[a.Key] = Redacted
				continue
			}
			out[a.Key] = s.slogValue(resolve(a.Value), depth+1)
		}
		return out
	case slog.KindAny:
		return s.value(reflect.ValueOf(v.Any()), depth)
	case slog.KindTime:
		return v.Time().Format(time.RFC3339Nano)
	case slog.KindDuration:
		return v.Duration().String()
	default: // bool, int64, uint64, float64
		return s.value(reflect.ValueOf(v.Any()), depth)
	}
}

// jsonValue sanitizes a value decoded from JSON with UseNumber.
func (s *sanitizer) jsonValue(v any, depth int) any {
	s.nodes++
	if s.nodes > MaxNodes || depth > MaxDepth {
		return TruncatedMarker
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(x))
		for i, k := range keys {
			if i == MaxItems {
				out[MoreMarker] = len(keys) - i
				break
			}
			rk := s.text(k)
			if s.sensitive(k) || s.sensitive(rk) {
				out[rk] = Redacted
				continue
			}
			out[rk] = s.jsonValue(x[k], depth+1)
		}
		return out
	case []any:
		out := make([]any, 0, min(len(x), MaxItems+1))
		for i, e := range x {
			if i == MaxItems {
				out = append(out, fmt.Sprintf("%s %d", MoreMarker, len(x)-i))
				break
			}
			out = append(out, s.jsonValue(e, depth+1))
		}
		return out
	case string:
		return s.text(x)
	case json.Number, bool, nil:
		return x
	default:
		return UnprintableMarker
	}
}
