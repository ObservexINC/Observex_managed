package logging_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// --- T01 to T03 (Astra's QA of fix4): quote levels mixed inside one
// value, separators written as escapes, and valid JSON kept valid across
// every pass. Fixtures write a backslash as @ (see fix); each test checks
// that its escapes reached the text. ---

// redactionProblem runs in through RedactString and the handler and
// describes what went wrong, or returns "": the secret must not show,
// valid JSON must stay valid, and a second pass must give the same result.
func redactionProblem(t *testing.T, in, secret string) string {
	t.Helper()
	got := logging.RedactString(in)
	switch {
	case strings.Contains(got, secret):
		return fmt.Sprintf("leak: %.300q -> %.300q", in, got)
	case json.Valid([]byte(in)) && !json.Valid([]byte(got)):
		return fmt.Sprintf("valid JSON became invalid: %.300q -> %.300q", in, got)
	}
	if again := logging.RedactString(got); again != got {
		return fmt.Sprintf("not idempotent: %.300q -> %.300q -> %.300q", in, got, again)
	}
	if out := logLine(t, in); strings.Contains(out, secret) {
		return fmt.Sprintf("leak through the handler: %.300q", in)
	}
	return ""
}

// tally counts the cases of one test and their problems.
type tally struct {
	t        *testing.T
	total    int
	failures int
}

func (c *tally) check(in, secret string) {
	c.t.Helper()
	c.total++
	if p := redactionProblem(c.t, in, secret); p != "" {
		c.failures++
		if c.failures <= 5 {
			c.t.Error(p)
		}
	}
}

func (c *tally) done(want int) {
	c.t.Helper()
	if c.failures > 0 {
		c.t.Fatalf("%d of %d cases fail", c.failures, c.total)
	}
	if want > 0 && c.total != want {
		c.t.Fatalf("ran %d cases, want %d", c.total, want)
	}
}

// jsonOf returns s as a JSON string.
func jsonOf(s string) string {
	q, _ := json.Marshal(s)
	return string(q)
}

// quoteSpellings write a quote inside text as itself, as an escaped quote
// (one level deeper), as a Unicode escape, or not at all (a bare word).
var quoteSpellings = []string{`"`, `@"`, `@u0022`, ``}

// valueQuote is how a field written with quote spelling q quotes its
// value: q itself, or an escaped quote for a bare name.
func valueQuote(q string) string {
	if q == "" {
		return `@"`
	}
	return q
}

func TestMixedQuoteLevelsInOneValue(t *testing.T) {
	const m = "ZZMIXEDLEVELMARKERZZ"
	names := []string{
		`credentials: `, `api_key=`, // unquoted names
		`"credentials":`, `@"credentials@":`, `@u0022credentials@u0022:`,
	}
	escapes := 0
	for _, q := range quoteSpellings {
		escapes += strings.Count(fix(q), "\\")
	}
	if escapes != 2 {
		t.Fatalf("quote spellings hold %d backslashes; want 2 (fixtures must keep their escapes)", escapes)
	}
	c := tally{t: t}
	for _, name := range names {
		for _, q1 := range quoteSpellings { // the first field
			for _, q2 := range quoteSpellings { // the field holding the marker
				for _, pad := range []string{"]", "}"} {
					// A bare spelling applies to the name only: a bracket
					// written with no quote at all is structure, not a
					// value, so its value keeps an escaped quote (as in
					// Astra's mixed_bare_field case).
					field1 := q1 + "pad" + q1 + ":" + valueQuote(q1) + pad + valueQuote(q1)
					field2 := q2 + "value" + q2 + ":" + valueQuote(q2) + m + valueQuote(q2)
					value := "{" + field1 + "," + field2 + "}"
					for _, prefix := range []string{`prefix " `, `a "b" `} {
						inner := fix(prefix + name + value)
						if strings.HasPrefix(name, `"`) || strings.HasPrefix(name, `@`) {
							inner = fix(prefix + "{" + name + value + "}")
						}
						forms := []string{inner, jsonOf(inner), jsonOf(jsonOf(inner)), `{"body":` + jsonOf(inner) + `}`}
						for _, form := range forms {
							for _, cut := range []bool{false, true} {
								in, secret := form, m
								if cut {
									in, secret = form[:strings.Index(form, m)+8], m[:8]
								}
								c.check(in, secret)
							}
						}
					}
				}
			}
		}
	}
	c.done(5 * 4 * 4 * 2 * 2 * 4 * 2)
}

func TestMixedQuoteLevelsOverTheParseLimit(t *testing.T) {
	// The same shapes inside valid JSON over MaxJSONRedact, once each.
	const m = "ZZMIXEDBIGMARKERZZ"
	pad := strings.Repeat("p", logging.MaxJSONRedact)
	c := tally{t: t}
	for _, q := range quoteSpellings[1:3] {
		inner := fix(`prefix " credentials: {` + q + `pad` + q + `:"]","value":"` + m + `"}`)
		for _, doc := range []string{
			`{"pad":"` + pad + `","body":` + jsonOf(inner) + `}`,
			`["` + pad + `",` + jsonOf(jsonOf(inner)) + `]`,
		} {
			c.check(doc, m)
		}
	}
	c.done(4)
}

func TestEncodedSeparatorsInJSONStrings(t *testing.T) {
	const m = "ZZSEPARATORMARKERZZ"
	inners := []string{
		`{"password":"M"}`,
		`{"user":"bob","credentials":{"pad":"]","value":"M"}}`,
		`prefix " credentials: {"pad":"]","value":"M"}`,
		`retry credentials={"value":"M"} later`,
		`retry api_key=["M"] later`,
		`login password=M ok`,
	}
	encodings := []func(string) string{
		func(s string) string { return s },
		func(s string) string { return strings.ReplaceAll(s, ":", `@u003a`) },
		func(s string) string { return strings.ReplaceAll(s, ":", `@u003A`) },
		func(s string) string { return strings.ReplaceAll(s, "=", `@u003d`) },
		func(s string) string { return strings.ReplaceAll(s, "=", `@u003D`) },
		func(s string) string {
			return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, ":", `@u003a`), "=", `@u003d`), `@"`, `@u0022`)
		},
	}
	pad := strings.Repeat("p", logging.MaxJSONRedact)
	c := tally{t: t}
	for _, raw := range inners {
		inner := strings.ReplaceAll(raw, "M", m)
		for i, encode := range encodings {
			lit := fix(encode(jsonOf(inner)))
			var decoded string
			if err := json.Unmarshal([]byte(lit), &decoded); err != nil || decoded != inner {
				t.Fatalf("encoding %d must decode to the same text: %v %q", i, err, decoded)
			}
			for _, doc := range []string{
				lit,
				"[" + lit + "]",
				`{"body":` + lit + `}`,
				`["` + pad + `",` + lit + `]`,
				`{"pad":"` + pad + `","body":` + lit + `}`,
				"request body=" + lit + " status=500", // not JSON around it
				"request body " + lit + " end",        // nor any raw ':' or '='
			} {
				c.check(doc, m)
			}
		}
	}
	c.done(6 * 6 * 7)
}

func TestValidJSONStaysValidAcrossEveryPass(t *testing.T) {
	// Values already hidden, escaped at several levels, with and without
	// the text rules' words, in every form valid JSON takes.
	contents := []string{
		`credentials: @"[REDACTED]@"`,
		`credentials: @@@"[REDACTED]@@@"`,
		`password=@"[REDACTED]@" token: @"[REDACTED]@"`,
		`Authorization: Bearer [REDACTED] and "quoted" text`,
		`{@"token@":@"[REDACTED]@"}`,
		`secret: @@"`,
	}
	pad := strings.Repeat("p", logging.MaxJSONRedact)
	c := tally{t: t}
	for _, raw := range contents {
		lit := jsonOf(fix(raw))
		for _, doc := range []string{
			lit, jsonOf(lit), "[" + lit + "]", `{"body":` + lit + `}`,
			`["` + pad + `",` + lit + `]`, `{"pad":"` + pad + `","body":` + jsonOf(lit) + `}`,
		} {
			c.check(doc, "ZZABSENTZZ")
			got := logging.RedactString(doc)
			for i := 0; i < 3; i++ { // repeated application stays put
				if got = logging.RedactString(got); !json.Valid([]byte(got)) {
					t.Errorf("pass %d broke JSON: %.200q", i+2, got)
				}
			}
		}
	}
	c.done(6 * 6)
}

func TestTextRulesReadDecodedStrings(t *testing.T) {
	// Valid JSON is no longer searched as text: the text rules read its
	// decoded strings instead, so secrets in them are still found, at any
	// size, and ordinary strings keep their exact bytes.
	pad := strings.Repeat("p", logging.MaxJSONRedact)
	secrets := map[string]string{
		"bearer":  "Authorization: Bearer ZZBEARERSECRETZZ1",
		"pair":    "password=ZZPAIRSECRETZZ",
		"escaped": "password@u003dZZESCAPEDPAIRZZ",
		"url":     "postgres://u:ZZURLSECRETZZ@db/x",
		// Built from parts so the source holds no JWT-shaped literal (the
		// secrets scan would flag it); the test still logs a whole one.
		"jwt":       "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiJaWkpXVFNFQ1JFVFpaIn0" + "." + "ZZJWTSIGNATUREZZ",
		"multiline": "-----BEGIN PRIVATE KEY-----\nZZPEMSECRETZZ\n-----END PRIVATE KEY-----",
	}
	for name, raw := range secrets {
		lit := jsonOf(raw) // raw is the decoded text; only "escaped" writes an escape
		if name == "escaped" {
			lit = `"` + fix(raw) + `"`
			if !strings.Contains(lit, `\u003d`) {
				t.Fatal("the escaped fixture must keep its escape")
			}
		}
		marker := "ZZ" + strings.Split(strings.SplitAfter(raw, "ZZ")[1], "ZZ")[0] + "ZZ"
		for _, doc := range []string{lit, `["` + pad + `",` + lit + `]`, "body=" + lit + " end"} {
			t.Run(name, func(t *testing.T) {
				c := tally{t: t}
				c.check(doc, marker)
				c.done(1)
			})
		}
	}
	ordinary := `["` + pad + `","caf@u00e9 @/ 12:30 a=b","x@"y"]`
	ordinary = fix(ordinary)
	if got := logging.RedactString(ordinary); got != ordinary {
		t.Fatal("ordinary strings changed")
	}
}

func TestNamesOnlyOnePassCanRead(t *testing.T) {
	// Each case needs one particular part of the repair: a name whose
	// letters are escaped is decoded only by the first pass, and one
	// whose separator is an escape only by recovery.
	const m = "ZZONEPASSMARKERZZ"
	c := tally{t: t}
	for _, raw := range []string{
		// An escaped letter in an unquoted name inside a string that broken
		// quoting made up: the first pass must not trust that string's end.
		`prefix " cred@u0065ntials: {@"pad@":"]","value":"M"}`,
		// The same name and an escaped separator, no quote in the string:
		// the first pass must follow the string to read the name.
		`body="cred@u0065ntials@u003a{v@u003a M}" end`,
		// Broken quoting inside a JSON string and an escaped separator
		// after a quoted name (the shaped fuzzer's input ef8e27d3ab35fcf1,
		// cut inside the marker): only recovery reads that member.
		`{"body"@u003a"@"open {@"credentials@"@u003a{@@u0022pad@@u0022:@@u0022{@@u0022,@@u0022value@@u0022:@@u0022M`,
	} {
		in := strings.ReplaceAll(fix(raw), "M", m)
		if !strings.Contains(in, `\u00`) {
			t.Fatalf("fixture lost its escapes: %q", in)
		}
		c.check(in, m[:10])
	}
	c.done(3)
}
