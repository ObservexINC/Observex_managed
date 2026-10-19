package logging_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// F01 and F02 from Astra's follow-up report of 18 October 2026. Every
// marker is invented.

// logLine logs v as one attribute and returns the JSON line.
func logLine(t *testing.T, v any, opts ...logging.Option) string {
	t.Helper()
	var out bytes.Buffer
	l := slog.New(logging.NewHandler(slog.NewJSONHandler(&out, nil), opts...))
	l.Info("follow-up", "payload", v)
	if !json.Valid(bytes.TrimSpace(out.Bytes())) {
		t.Fatalf("log line is not valid JSON: %.300s", out.String())
	}
	return out.String()
}

func mustNotContain(t *testing.T, out string, markers ...string) {
	t.Helper()
	for _, m := range markers {
		if strings.Contains(out, m) {
			t.Fatalf("%s reached the output: %.400s", m, out)
		}
	}
}

// --- F01: explicit secret types in every position ---

// opaqueToken defines its own log form, like logging.Secret does.
type opaqueToken string

func (opaqueToken) LogValue() slog.Value { return slog.StringValue("opaque") }

type wrap struct{ v any }

func TestSecretTypeStaysOpaqueEverywhere(t *testing.T) {
	const m = "ZZSECRETTYPEMARKERZZ"
	s := logging.Secret(m)
	ps := &s
	pps := &ps
	tok := opaqueToken(m)
	cases := map[string]any{
		"unexported value":            struct{ value logging.Secret }{s},
		"unexported pointer":          struct{ value *logging.Secret }{&s},
		"unexported pointer chain":    struct{ value **logging.Secret }{pps},
		"unexported interface":        struct{ value any }{s},
		"unexported interface to ptr": struct{ value any }{&s},
		"unexported Stringer":         struct{ value fmt.Stringer }{s},
		"unexported slice":            struct{ value []logging.Secret }{[]logging.Secret{s, s}},
		"unexported array":            struct{ value [2]logging.Secret }{[2]logging.Secret{s, s}},
		"unexported map value":        struct{ value map[string]logging.Secret }{map[string]logging.Secret{"k": s}},
		"unexported map key":          struct{ value map[logging.Secret]string }{map[logging.Secret]string{s: "v"}},
		"unexported nested": struct {
			a struct{ b struct{ c logging.Secret } }
		}{},
		"unexported in any slice":     struct{ value []any }{[]any{1, s, &s}},
		"wrapped five times":          wrap{wrap{wrap{wrap{wrap{s}}}}},
		"exported value":              struct{ Value logging.Secret }{s},
		"exported pointer":            struct{ Value *logging.Secret }{&s},
		"exported map key":            map[logging.Secret]int{s: 1},
		"exported slice":              []logging.Secret{s},
		"unexported LogValuer":        struct{ value opaqueToken }{tok},
		"unexported LogValuer in any": struct{ value any }{tok},
	}
	nested := struct {
		a struct{ b struct{ c logging.Secret } }
	}{}
	nested.a.b.c = s
	cases["unexported nested"] = nested
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			mustNotContain(t, logLine(t, v), m)
		})
	}
}

func TestOrdinaryUnexportedFieldsStayUseful(t *testing.T) {
	type reading struct {
		name  string
		count int
		tags  []string
		where map[string]string
	}
	out := logLine(t, reading{name: "disk-7", count: 3, tags: []string{"ssd"}, where: map[string]string{"rack": "r12"}})
	for _, want := range []string{`"disk-7"`, `"count":3`, `"ssd"`, `"rack":"r12"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in %s", want, out)
		}
	}
}

// --- F02: map keys classified on their full text ---

func TestLongMapKeysAreClassifiedInFull(t *testing.T) {
	const m = "ZZLONGKEYMARKERZZ"
	const frag = "password"
	for _, n := range []int{
		logging.MaxString - len(frag) - 1, // the whole key is shown
		logging.MaxString - len(frag),     // exactly MaxString
		logging.MaxString - len(frag) + 1, // the fragment's last byte is cut
		logging.MaxString,                 // the fragment is cut entirely
		logging.MaxString + 1,             // Astra's case
		3 * logging.MaxString,
	} {
		key := strings.Repeat("x", n) + frag
		if !logging.IsSensitiveKey(key) {
			t.Fatal("key must be sensitive")
		}
		t.Run(fmt.Sprintf("map %d", len(key)), func(t *testing.T) {
			mustNotContain(t, logLine(t, map[string]string{key: m}), m)
		})
		t.Run(fmt.Sprintf("nested map %d", len(key)), func(t *testing.T) {
			mustNotContain(t, logLine(t, struct{ Data map[string]any }{map[string]any{"ok": 1, key: []string{m}}}), m)
		})
		t.Run(fmt.Sprintf("JSON member %d", len(key)), func(t *testing.T) {
			raw, _ := json.Marshal(map[string]string{key: m})
			mustNotContain(t, logLine(t, string(raw)), m)
		})
	}
}

func TestKeysWhoseShownFormLosesTheSensitiveWord(t *testing.T) {
	const m = "ZZSHOWNKEYMARKERZZ"
	for _, key := range []string{
		// The JWT rule replaces the whole key, "password" included. Built
		// from parts so secret scanners do not take it for a token.
		"eyJ" + "hbGciOiJub25lIn0." + "eyJ" + "zdWIiOiIxMjM0In0." + "password_signature",
		// The URL rule removes the password, which here is the word itself.
		"https://user:password@db.example.test/x",
	} {
		if !logging.IsSensitiveKey(key) {
			t.Fatalf("%q must be sensitive", key)
		}
		mustNotContain(t, logLine(t, map[string]string{key: m}), m)
		raw, _ := json.Marshal(map[string]string{key: m})
		mustNotContain(t, logging.RedactString(string(raw)), m)
	}
}

func TestKeysThatLookEqualWhenShownKeepTheirValues(t *testing.T) {
	long := strings.Repeat("y", logging.MaxString)
	out := logLine(t, map[string]string{long + "a": "first-value", long + "b": "second-value"})
	if !strings.Contains(out, "first-value") || !strings.Contains(out, "second-value") || !strings.Contains(out, " #2") {
		t.Fatalf("an entry hid another: %.200s ... %.300s", out, out[len(out)-300:])
	}
	const m = "ZZCOLLIDEMARKERZZ"
	out = logLine(t, map[string]string{long + "password": m, long + "name": "kept"})
	mustNotContain(t, out, m)
	if !strings.Contains(out, "kept") {
		t.Fatal("the ordinary value was lost")
	}
}
