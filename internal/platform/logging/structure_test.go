package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every value below is an invented marker. Tests fail if a marker reaches
// output.
const marker = "ZZLEAKMARKERZZ"

func logOne(t *testing.T, opts []Option, f func(l *slog.Logger)) string {
	t.Helper()
	var b bytes.Buffer
	f(New(&b, slog.LevelDebug, opts...))
	return b.String()
}

func mustNotLeak(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, marker) {
		t.Fatalf("marker leaked:\n%s", out)
	}
}

type stringerSecret struct{ User, Password string }

func (s stringerSecret) String() string { return s.User + ":" + s.Password }

type panicStringer struct{ N int }

func (panicStringer) String() string { panic("boom") }

type panicError struct{}

func (panicError) Error() string { panic("boom") }

type valuer struct{ v string }

func (v valuer) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user", "alice"), slog.String("token", v.v))
}

type panicValuer struct{}

func (panicValuer) LogValue() slog.Value { panic("boom") }

type enum int

func (e enum) String() string { return "state-" + strconv.Itoa(int(e)) }

type node struct {
	Name string
	Next *node
}

func TestStructuredValuesRedactBeforeRendering(t *testing.T) {
	type inner struct {
		Host  string
		Creds map[string]string
	}
	type tagged struct {
		Pwd    string `json:"pwd"`
		Remark string `json:"remark,omitempty"`
	}
	type unexported struct {
		user     string
		password string
	}
	cases := map[string]any{
		"nested pointer struct":        &struct{ In *inner }{&inner{Host: "h", Creds: map[string]string{"x": marker}}},
		"abbreviated creds key":        map[string]any{"dbCreds": marker},
		"slice of maps":                []map[string]any{{"ok": 1}, {"apiKey": marker}},
		"array of structs":             [2]struct{ Token string }{{marker}, {marker}},
		"interface holding struct":     any(struct{ Secret any }{Secret: []string{marker, marker}}),
		"json tag names the secret":    tagged{Pwd: marker, Remark: "fine"},
		"unexported secret field":      unexported{user: "u", password: marker},
		"stringer is not called":       stringerSecret{User: "bob", Password: marker},
		"pointer to stringer":          &stringerSecret{User: "bob", Password: marker},
		"map with non-string keys":     map[int]map[string]string{1: {"password": marker}},
		"multiword password":           struct{ Password string }{"dummy " + marker},
		"slice-valued password":        struct{ Password []string }{[]string{marker}},
		"nested credentials map":       struct{ Credentials map[string]string }{map[string]string{"value": marker}},
		"cookie field":                 struct{ Cookie string }{marker},
		"logvaluer group":              valuer{v: marker},
		"logvaluer inside struct":      struct{ V valuer }{valuer{v: marker}},
		"secret type":                  struct{ S Secret }{Secret(marker)},
		"url with password":            mustURL(t, "https://bob:"+marker+"@db.example/x"),
		"error text with dsn":          fmt.Errorf("dial postgres://u:%s@h: refused", marker),
		"bytes with key=value":         []byte("password=" + marker),
		"string with json body":        `{"user":"a","password":"` + marker + `"}`,
		"pointer to pointer to secret": ptr(ptr(struct{ Token string }{marker})),
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			out := logOne(t, nil, func(l *slog.Logger) { l.Info("m", "v", v) })
			mustNotLeak(t, out)
			if !json.Valid(bytes.TrimSpace([]byte(out))) {
				t.Fatalf("output is not valid JSON: %s", out)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestStructuredValuesKeepUsefulData(t *testing.T) {
	out := logOne(t, nil, func(l *slog.Logger) {
		l.Info("m", "v", struct {
			Host  string
			Port  int
			Ratio float64
			Up    bool
			At    time.Time
			Wait  time.Duration
			State enum
			Tags  []string
		}{"db.internal", 5432, 0.5, true, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), 3 * time.Second, 2, []string{"a", "b"}})
	})
	for _, want := range []string{`"Host":"db.internal"`, `"Port":5432`, `"Ratio":0.5`, `"Up":true`,
		`"At":"2026-10-18T00:00:00Z"`, `"Wait":"3s"`, `"State":"state-2"`, `"Tags":["a","b"]`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
}

func TestStructuredBoundsAndCycles(t *testing.T) {
	// Self-referencing pointer.
	n := &node{Name: "a"}
	n.Next = n
	out := logOne(t, nil, func(l *slog.Logger) { l.Info("m", "v", n) })
	if !strings.Contains(out, CycleMarker) {
		t.Fatalf("cycle not marked: %s", out)
	}
	// Map and slice that contain themselves.
	m := map[string]any{}
	m["self"] = m
	s := []any{nil}
	s[0] = s
	out = logOne(t, nil, func(l *slog.Logger) { l.Info("m", "m", m, "s", s) })
	if strings.Count(out, CycleMarker) != 2 {
		t.Fatalf("map/slice cycles not marked: %s", out)
	}
	// Depth.
	var deep any = marker
	for i := 0; i < MaxDepth+5; i++ {
		deep = []any{deep}
	}
	out = logOne(t, nil, func(l *slog.Logger) { l.Info("m", "v", deep) })
	if !strings.Contains(out, TruncatedMarker) || strings.Contains(out, marker) {
		t.Fatalf("depth not bounded: %s", out)
	}
	// Items.
	big := make([]int, MaxItems+10)
	out = logOne(t, nil, func(l *slog.Logger) { l.Info("m", "v", big) })
	if !strings.Contains(out, MoreMarker+" 10") {
		t.Fatalf("items not bounded: %.300s", out)
	}
	bigMap := map[string]int{}
	for i := 0; i < MaxItems+3; i++ {
		bigMap[fmt.Sprintf("k%04d", i)] = i
	}
	out = logOne(t, nil, func(l *slog.Logger) { l.Info("m", "v", bigMap) })
	if !strings.Contains(out, `"`+MoreMarker+`":3`) {
		t.Fatalf("map items not bounded: %.300s", out)
	}
	// Total nodes.
	wide := make([][]int, 100)
	for i := range wide {
		wide[i] = make([]int, 100)
	}
	out = logOne(t, nil, func(l *slog.Logger) { l.Info("m", "v", wide) })
	if !strings.Contains(out, TruncatedMarker) {
		t.Fatal("node budget not applied")
	}
	// Long strings are cut after redaction.
	long := strings.Repeat("x", MaxString+100)
	out = logOne(t, nil, func(l *slog.Logger) { l.Info("m", "v", struct{ S string }{long}) })
	if !strings.Contains(out, TruncatedMarker) || len(out) > MaxString+500 {
		t.Fatalf("string not bounded: %d bytes", len(out))
	}
}

func TestUserMethodsThatPanic(t *testing.T) {
	out := logOne(t, nil, func(l *slog.Logger) {
		l.Info("m", "s", panicStringer{N: 1}, "e", panicError{}, "v", panicValuer{}, "nested", struct{ E error }{panicError{}})
	})
	if strings.Count(out, UnprintableMarker) < 3 {
		t.Fatalf("panics not contained: %s", out)
	}
	// A struct whose String panics is walked, not called.
	if !strings.Contains(out, `"s":{"N":1}`) {
		t.Fatalf("struct stringer was called: %s", out)
	}
}

func TestOddValues(t *testing.T) {
	ch := make(chan int)
	out := logOne(t, nil, func(l *slog.Logger) {
		l.Info("m", "nan", math.NaN(), "inf", struct{ F float64 }{math.Inf(1)}, "ch", ch, "fn", func() {}, "nilmap", map[string]int(nil), "nilptr", (*node)(nil), "c", complex(1, 2))
	})
	if !json.Valid(bytes.TrimSpace([]byte(out))) {
		t.Fatalf("not valid JSON: %s", out)
	}
	for _, want := range []string{`"F":"+Inf"`, `"ch":"<chan>"`, `"fn":"<func>"`, `"nilmap":null`, `"nilptr":null`, `"c":"(1+2i)"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
}

func TestCustomSensitiveKeysReachNestedValues(t *testing.T) {
	opts := []Option{WithSensitiveKeys("license_key", "vault")}
	out := logOne(t, opts, func(l *slog.Logger) {
		l.Info("m", "v", struct{ LicenseKey string }{marker}, "m", map[string]string{"license-key": marker},
			"body", `{"vault":"`+marker+`"}`)
		l.WithGroup("vault").Info("m", "x", marker)
	})
	mustNotLeak(t, out)
}

func TestEscapedQuotesAndMalformedText(t *testing.T) {
	jsonBody := func(v string) string {
		b, _ := json.Marshal(map[string]string{"password": v, "user": "u"})
		return string(b)
	}
	single := jsonBody(`a"b\c` + marker)
	double, _ := json.Marshal(single)
	cases := map[string]string{
		"whole JSON body":                 single,
		"JSON with unicode escapes":       `{"password":"\u0022` + marker + `\u0022"}`,
		"JSON body inside text":           "request body=" + single + " status=500",
		"double-encoded JSON as text":     "body=" + string(double),
		"double-encoded JSON whole":       string(double),
		"go-quoted value":                 "password=" + strconv.Quote(`a"b`+marker),
		"single-quoted with escape":       `password='a\'` + marker + `'`,
		"truncated double-quoted value":   `{"password":"abc\"` + marker,
		"truncated single-quoted value":   `password='abc` + marker,
		"trailing backslash truncated":    `password="` + marker + `\`,
		"truncated double-encoded":        `{\"password\":\"x\\\"` + marker,
		"newline inside quoted value":     "password=\"a\n" + marker + "\" next",
		"JSON array of objects":           `[{"token":"` + marker + `"},{"ok":true}]`,
		"nested JSON in JSON string":      `{"payload":"{\"secret\":\"` + marker + `\"}"}`,
		"truncated JSON whole":            `{"user":"u","password":"` + marker,
		"PEM without END":                 "-----BEGIN EC PRIVATE KEY-----\n" + marker,
		"authorization header in message": "Authorization: Bearer " + marker,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got := RedactString(in)
			if strings.Contains(got, marker) {
				t.Fatalf("leak:\n in:  %q\n out: %q", in, got)
			}
			if again := RedactString(got); again != got {
				t.Fatalf("not idempotent:\n once:  %q\n twice: %q", got, again)
			}
			// The same text through the message and a string attribute.
			mustNotLeak(t, logOne(t, nil, func(l *slog.Logger) { l.Info(in, "body", in) }))
		})
	}
}

func TestJSONRedactionKeepsStructure(t *testing.T) {
	got := RedactString(`{"b":2,"a":{"password":{"x":1},"list":[1,"ok"]},"u":"<tag>"}`)
	want := `{"a":{"list":[1,"ok"],"password":"[REDACTED]"},"b":2,"u":"<tag>"}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	// Numbers keep their exact text.
	if got := RedactString(`{"n":1.50,"big":12345678901234567890}`); got != `{"big":12345678901234567890,"n":1.50}` {
		t.Fatalf("numbers changed: %s", got)
	}
	// Text that is not a whole JSON document is left to the text rules.
	if got := RedactString(`status {"a":1} ok`); got != `status {"a":1} ok` {
		t.Fatalf("partial JSON rewritten: %s", got)
	}
}

func TestSensitiveGroupsAcrossAPIs(t *testing.T) {
	cases := map[string]func(l *slog.Logger){
		"WithGroup then Info":          func(l *slog.Logger) { l.WithGroup("credentials").Info("m", "value", marker) },
		"WithGroup then With":          func(l *slog.Logger) { l.WithGroup("credentials").With("value", marker).Info("m") },
		"sensitive group nested below": func(l *slog.Logger) { l.WithGroup("db").WithGroup("secret").Info("m", "v", marker) },
		"plain group below sensitive":  func(l *slog.Logger) { l.WithGroup("auth").WithGroup("db").Info("m", "v", marker) },
		"group attr inside group":      func(l *slog.Logger) { l.WithGroup("token").Info("m", slog.Group("g", "v", marker)) },
		"inline sensitive group":       func(l *slog.Logger) { l.Info("m", slog.Group("password", "v", marker)) },
		"struct inside sensitive group": func(l *slog.Logger) {
			l.WithGroup("apikey").Info("m", "v", struct{ Name string }{marker})
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) { mustNotLeak(t, logOne(t, nil, f)) })
	}
}

func TestSensitiveGroupDoesNotAffectSiblings(t *testing.T) {
	var b bytes.Buffer
	base := New(&b, slog.LevelInfo)
	creds := base.WithGroup("credentials")
	other := base.WithGroup("db")
	creds.Info("m", "v", marker)
	other.Info("m", "host", "visible-host")
	base.Info("m", "value", "visible-base")
	out := b.String()
	mustNotLeak(t, out)
	for _, want := range []string{"visible-host", "visible-base"} {
		if !strings.Contains(out, want) {
			t.Fatalf("sibling logger redacted %s: %s", want, out)
		}
	}
}

func TestHandlerIsSafeForConcurrentDerivation(t *testing.T) {
	var mu sync.Mutex
	var b bytes.Buffer
	base := New(&lockedWriter{mu: &mu, w: &b}, slog.LevelInfo)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				base.WithGroup("secret").With("v", marker).Info("m")
			} else {
				base.WithGroup("public").With("v", "ok").Info("m", "n", i)
			}
		}(i)
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	mustNotLeak(t, b.String())
	if strings.Count(b.String(), `"v":"ok"`) != 16 {
		t.Fatalf("public lines redacted or lost: %s", b.String())
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestErrorsAreScrubbedText(t *testing.T) {
	err := fmt.Errorf("connect: %w", errors.New("password="+marker))
	mustNotLeak(t, logOne(t, nil, func(l *slog.Logger) { l.Error("failed", "err", err) }))
}

// FuzzRedactConfidential puts a fixed marker inside a secret with arbitrary
// surrounding bytes (quotes, backslashes, newlines, invalid UTF-8) and
// checks the marker never survives in any encoding whose boundaries are
// unambiguous: JSON (single and double encoded, whole or inside text), Go
// and single quoting, structured values and sensitive groups.
func FuzzRedactConfidential(f *testing.F) {
	f.Add("", "")
	f.Add(`a"b`, `\`)
	f.Add("x\\\"", "\n'")
	f.Add("\xff\xfe", `\u0022`)
	f.Add(`\\\"`, `"}`)
	f.Fuzz(func(t *testing.T, pre, post string) {
		secret := pre + marker + post
		single, _ := json.Marshal(map[string]string{"password": secret, "user": "u"})
		double, _ := json.Marshal(string(single))
		texts := []string{
			string(single),
			"body=" + string(single) + " tail",
			string(double),
			"body=" + string(double),
			"password=" + strconv.Quote(secret),
			"token: " + strconv.Quote(secret),
		}
		for _, s := range texts {
			got := RedactString(s)
			if strings.Contains(got, marker) {
				t.Fatalf("leak:\n in:  %q\n out: %q", s, got)
			}
			if RedactString(got) != got {
				t.Fatalf("not idempotent for %q", s)
			}
		}
		var b bytes.Buffer
		l := New(&b, slog.LevelInfo)
		l.Info("m", "a", struct{ Password string }{secret}, "b", map[string]any{"nested": map[string]string{"token": secret}},
			"c", []any{struct{ Credentials []string }{[]string{secret}}}, "d", Secret(secret), "e", string(single))
		l.WithGroup("secret").Info("m", "v", secret, "w", struct{ X string }{secret})
		l.WithGroup("credentials").With("v", secret).Info("m")
		if strings.Contains(b.String(), marker) {
			t.Fatalf("leak through the logger:\n%s", b.String())
		}
	})
}
