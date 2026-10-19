package logging_test

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// --- S01: a composite map key that the bounds stop from being read in
// full counts as sensitive; a key read in full keeps its value visible. ---

// entryValue logs a map with one composite key and returns how its value
// was rendered.
func entryValue(t *testing.T, key reflect.Value, marker string) any {
	t.Helper()
	m := reflect.MakeMap(reflect.MapOf(key.Type(), reflect.TypeOf("")))
	m.SetMapIndex(key, reflect.ValueOf(marker))
	var line struct{ Payload map[string]any }
	if err := json.Unmarshal([]byte(logLine(t, m.Interface())), &line); err != nil || len(line.Payload) != 1 {
		t.Fatalf("want one entry: %v %v", err, line.Payload)
	}
	for _, v := range line.Payload {
		return v
	}
	return nil
}

// stringArray returns a [n]string whose last element is last and the
// others "ordinary".
func stringArray(n int, last string) reflect.Value {
	a := reflect.New(reflect.ArrayOf(n, reflect.TypeOf(""))).Elem()
	for i := 0; i < n; i++ {
		a.Index(i).SetString("ordinary")
	}
	a.Index(n - 1).SetString(last)
	return a
}

// stringStruct returns a struct with n exported string fields, the last
// one set to last.
func stringStruct(n int, last string) reflect.Value {
	fields := make([]reflect.StructField, n)
	for i := range fields {
		fields[i] = reflect.StructField{Name: "F" + strconv.Itoa(i), Type: reflect.TypeOf("")}
	}
	v := reflect.New(reflect.StructOf(fields)).Elem()
	for i := 0; i < n; i++ {
		v.Field(i).SetString("ordinary")
	}
	v.Field(n - 1).SetString(last)
	return v
}

type wrapped struct{ Value any }

// wrappedKey returns s inside n wrapped structs, as an interface: the
// string is n levels deep, as the sanitizer counts depth.
func wrappedKey(n int, s string) reflect.Value {
	var v any = s
	for i := 0; i < n; i++ {
		v = wrapped{v}
	}
	return reflect.ValueOf(&v).Elem() // keeps the interface type
}

// nodeKey returns struct{ A [15][256]string; B [m]string } with B's last
// element set to last: 3858 + m values in all (the struct, A, its 15
// arrays and 3840 strings, B and its m strings).
func nodeKey(m int, last string) reflect.Value {
	inner := reflect.ArrayOf(logging.MaxItems, reflect.TypeOf(""))
	t := reflect.StructOf([]reflect.StructField{
		{Name: "A", Type: reflect.ArrayOf(15, inner)},
		{Name: "B", Type: reflect.ArrayOf(m, reflect.TypeOf(""))},
	})
	v := reflect.New(t).Elem()
	v.Field(1).Index(m - 1).SetString(last)
	return v
}

func TestCompositeKeyBoundsFailClosed(t *testing.T) {
	const m = "ZZKEYLIMITMARKERZZ"
	// The node bound: 3858 + 238 = MaxNodes values is read in full.
	atNodes := logging.MaxNodes - 3858
	cases := []struct {
		name string
		key  func(last string) reflect.Value
		// How an ordinary key's value is rendered: the value itself when
		// the key is read in full; Redacted when a bound stopped the
		// reading. A key of about MaxNodes values also spends the
		// attribute's own node bound when it is shown, so a value it
		// keeps is rendered as TruncatedMarker, which shows nothing.
		ordinary any
	}{
		{"array, MaxItems-1 elements", func(l string) reflect.Value { return stringArray(logging.MaxItems-1, l) }, m},
		{"array, MaxItems elements", func(l string) reflect.Value { return stringArray(logging.MaxItems, l) }, m},
		{"array, MaxItems+1 elements", func(l string) reflect.Value { return stringArray(logging.MaxItems+1, l) }, logging.Redacted},
		{"struct, MaxItems-1 fields", func(l string) reflect.Value { return stringStruct(logging.MaxItems-1, l) }, m},
		{"struct, MaxItems fields", func(l string) reflect.Value { return stringStruct(logging.MaxItems, l) }, m},
		{"struct, MaxItems+1 fields", func(l string) reflect.Value { return stringStruct(logging.MaxItems+1, l) }, logging.Redacted},
		{"depth MaxDepth-1", func(l string) reflect.Value { return wrappedKey(logging.MaxDepth-1, l) }, m},
		{"depth MaxDepth", func(l string) reflect.Value { return wrappedKey(logging.MaxDepth, l) }, m},
		{"depth MaxDepth+1", func(l string) reflect.Value { return wrappedKey(logging.MaxDepth+1, l) }, logging.Redacted},
		{"depth MaxDepth+2 (Astra's case)", func(l string) reflect.Value { return wrappedKey(logging.MaxDepth+2, l) }, logging.Redacted},
		{"nodes MaxNodes-1", func(l string) reflect.Value { return nodeKey(atNodes-1, l) }, logging.TruncatedMarker},
		{"nodes MaxNodes", func(l string) reflect.Value { return nodeKey(atNodes, l) }, logging.TruncatedMarker},
		{"nodes MaxNodes+1", func(l string) reflect.Value { return nodeKey(atNodes+1, l) }, logging.Redacted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// A secret word in the last place read hides the value always:
			// found when the key is read in full, unknown otherwise.
			for _, word := range []string{"password", "api_key", "client_secret"} {
				if got := entryValue(t, c.key(word), m); got != logging.Redacted {
					t.Fatalf("key holding %q: value rendered as %v", word, got)
				}
			}
			// The control: an ordinary key keeps its value when read in
			// full, and loses it when a bound stopped the reading.
			if got := entryValue(t, c.key("ordinary"), m); got != c.ordinary {
				t.Fatalf("ordinary key: value rendered as %v, want %v", got, c.ordinary)
			}
		})
	}
}

type keyNode struct {
	Name string
	Next *keyNode
}

func TestCompositeKeyCyclesAndOpaqueParts(t *testing.T) {
	const m = "ZZKEYCYCLEMARKERZZ"
	// A pointer cycle is read once: an ordinary key keeps its value, a
	// secret word in it hides the value.
	for _, c := range []struct {
		name string
		show bool
	}{{"ordinary", true}, {"password", false}} {
		n := &keyNode{Name: c.name}
		n.Next = n
		out := logLine(t, map[*keyNode]string{n: m})
		if strings.Contains(out, m) != c.show {
			t.Fatalf("cycle with %q: value shown = %v: %s", c.name, !c.show, out)
		}
	}
	// A pointer chain to a string deeper than MaxDepth is not read in full.
	s := "ordinary"
	var p any = &s
	for i := 0; i < logging.MaxDepth+1; i++ {
		q := p
		p = &q
	}
	if out := logLine(t, map[any]string{p: m}); strings.Contains(out, m) {
		t.Fatalf("pointer chain past MaxDepth showed its value: %s", out)
	}
	// Opaque parts are never read; they decide only how they are shown.
	type withSecret struct {
		Name string
		Tok  logging.Secret
	}
	out := logLine(t, map[withSecret]string{{"ordinary", logging.Secret("ZZOPAQUEKEYZZ")}: m})
	mustNotContain(t, out, "ZZOPAQUEKEYZZ")
	if !strings.Contains(out, m) {
		t.Fatalf("an ordinary key with an opaque part lost its value: %s", out)
	}
}

func TestCompositeKeysBeyondBoundsKeepDistinctEntries(t *testing.T) {
	// Two keys that differ only past the item bound are shown the same;
	// both values are hidden and neither entry hides the other.
	a, b := stringArray(logging.MaxItems+1, "x"), stringArray(logging.MaxItems+1, "y")
	mt := reflect.MapOf(a.Type(), reflect.TypeOf(""))
	mp := reflect.MakeMap(mt)
	mp.SetMapIndex(a, reflect.ValueOf("ZZONEZZ"))
	mp.SetMapIndex(b, reflect.ValueOf("ZZTWOZZ"))
	out := logLine(t, mp.Interface())
	mustNotContain(t, out, "ZZONEZZ", "ZZTWOZZ")
	if strings.Count(out, logging.Redacted) != 2 || !strings.Contains(out, " #2") {
		t.Fatalf("want two hidden entries, one with a suffix: %s", out)
	}
}
