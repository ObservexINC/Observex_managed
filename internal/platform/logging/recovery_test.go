package logging_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// --- S02: where recovery ends a sensitive value. Quotes and escapes in
// the value are respected; when the value or the quoting after it is not
// sound, the value runs to the end of its text. ---

// recoveryValues are sensitive values whose strings hold brackets, braces,
// escaped quotes and backslashes; M stands for the marker. Raw strings: the
// escapes reach the text as written.
var recoveryValues = []string{
	`{"pad":"]","value":"M"}`,
	`{"pad":"}","value":"M"}`,
	`{"pad":"[","value":"M"}`,
	`{"pad":"{","value":"M"}`,
	`{"pad":"a@"]b","value":"M"}`,
	`{"pad":"a@@","value":"M"}`,
	`{"pad":"@@@"}","value":"M"}`,
	`["]",{"value":"M"}]`,
	`[{"a":"}"},"M"]`,
	`{"a":{"b":["]","M"]}}`,
	`{value: M, pad: x}`,
}

// recoveryNames hold the name and separator before the value: unquoted
// names (no quote can show their level), quoted ones, and a quoted name
// with an escape.
var recoveryNames = []string{
	`credentials: `,
	`api_key=`,
	`"credentials":`,
	`"cred@u0065ntials":`,
}

// recoveryPrefixes break the quoting before the member.
var recoveryPrefixes = []string{`prefix " `, `a "b" c" `, `"open `, `5": `}

func TestRecoveryValueBoundaries(t *testing.T) {
	const m = "ZZBOUNDARYMARKERZZ"
	escaped := 0
	for _, v := range recoveryValues {
		if strings.Contains(fix(v), "\\") {
			escaped++
		}
	}
	if escaped != 3 {
		t.Fatalf("%d values hold a backslash; want 3 (fixtures must keep their escapes)", escaped)
	}
	failures, total := 0, 0
	for _, prefix := range recoveryPrefixes {
		for _, name := range recoveryNames {
			for _, value := range recoveryValues {
				inner := prefix + fix(name) + strings.ReplaceAll(fix(value), "M", m)
				if strings.HasPrefix(name, `"`) {
					inner = prefix + "{" + fix(name) + strings.ReplaceAll(fix(value), "M", m) + "}"
				}
				for form := 0; form < 4; form++ {
					text := encodeForm(inner, form)
					for _, cut := range []bool{false, true} {
						in := text
						if cut {
							in = text[:strings.Index(text, m)+5]
						}
						total++
						got := logging.RedactString(in)
						if strings.Contains(got, m[:5]) {
							failures++
							if failures <= 5 {
								t.Errorf("leak: form %d, cut %v: %q -> %q", form, cut, in, got)
							}
							continue
						}
						if logging.RedactString(got) != got {
							t.Errorf("not idempotent: %q", in)
						}
						if json.Valid([]byte(in)) && !json.Valid([]byte(got)) {
							t.Errorf("valid JSON became invalid: %q -> %q", in, got)
						}
						if out := logLine(t, in); strings.Contains(out, m[:5]) {
							t.Errorf("leak through the handler: %q", in)
						}
					}
				}
			}
		}
	}
	if failures > 0 {
		t.Fatalf("%d of %d combinations leak", failures, total)
	}
	if total != 4*4*11*4*2 {
		t.Fatalf("ran %d combinations", total)
	}
}

// fix turns the fixtures' @ into a backslash.
func fix(s string) string { return strings.ReplaceAll(s, "@", "\\") }

// encodeForm writes text as is (0), JSON-encoded once or twice inside
// other text (1, 2), or as a JSON string literal, which is valid JSON (3).
func encodeForm(text string, form int) string {
	switch form {
	case 1, 2:
		for i := 0; i < form; i++ {
			q, _ := json.Marshal(text)
			text = string(q)
		}
		return "body=" + text + " end"
	case 3:
		q, _ := json.Marshal(text)
		return string(q)
	}
	return text
}

func TestRecoveryKeepsTextAfterASoundValue(t *testing.T) {
	// Text after a sensitive value is kept only when the value cannot have
	// been misread: it holds no quote, or the JSON string holding it is
	// valid JSON on its own.
	const m = "ZZKEEPMARKERZZ"
	once, _ := json.Marshal(`{"credentials":{"pad":"]","value":"` + m + `"},"user":"bob"}`)
	for _, c := range []struct{ in, keep string }{
		{`prefix " credentials: {value: ` + m + `, n: [1, 2]} tail ok`, " tail ok"},
		{`prefix " {"credentials":{value: ` + m + `}, "user":"bob"} x`, `, "user":"bob"} x`},
		{`prefix " api_key=[` + m + `, x] then "quoted" text`, ` then "quoted" text`},
		{`request " failed body=` + string(once) + ` status=500`, fix(`,@"user@":@"bob@"}" status=500`)},
	} {
		got := logging.RedactString(c.in)
		mustNotContain(t, got, m)
		if !strings.Contains(got, c.keep) || !strings.HasPrefix(got, strings.Fields(c.in)[0]) {
			t.Errorf("%q: lost text around the value: %q", c.in, got)
		}
		if logging.RedactString(got) != got {
			t.Errorf("not idempotent: %q", c.in)
		}
	}
}

func TestRecoveryRunsToTheEndWhenTheValueIsNotSound(t *testing.T) {
	const m = "ZZUNSOUNDMARKERZZ"
	quoted := []string{
		// Quotes in the value, in text whose quoting is broken: any of them
		// may be an unescaped quote of its content.
		`prefix " credentials: {"pad":"]","value":"` + m + `"} tail`,
		`prefix " {"credentials":{"pad":"}"},"user":"` + m + `"} tail`,
		`prefix " credentials: {"pad":"a"}","value":"` + m + `"} tail`,
		`prefix " {"credentials":{"pad":"a"}","value":"` + m + `"}} tail`,
		`prefix " credentials: {pad: "a", value: ` + m + `} tail`,
		// Brackets of the wrong kind.
		`prefix " credentials: {"pad":"a"],"value":"` + m + `"} tail`,
		`prefix " credentials: {pad: a],value: ` + m + `} tail`,
		// Never closes.
		`prefix " credentials: {"pad":"]","value":"` + m + ` tail`,
	}
	var cases []string
	for _, in := range quoted {
		once, _ := json.Marshal(in)
		cases = append(cases, in, "body="+string(once)+" end", string(once))
	}
	// The fuzzer's case: an unescaped quote in the value, a JSON string,
	// then a cut inside the marker, which removes the quote that would
	// have shown the value going on.
	cut, _ := json.Marshal(`5": "password":{"pad":"a"}","value":"` + m + `"} tail "x" end`)
	cases = append(cases, string(cut)[:strings.Index(string(cut), m)+10])
	for _, in := range cases {
		got := logging.RedactString(in)
		mustNotContain(t, got, m[:10], "tail")
		if logging.RedactString(got) != got {
			t.Errorf("not idempotent: %q", in)
		}
		if out := logLine(t, in); strings.Contains(out, m[:10]) {
			t.Errorf("leak through the handler: %q", in)
		}
	}
}

// --- Valid JSON whose strings hold JSON with broken quoting (found while
// repairing S02): the first pass reads valid JSON exactly, but not the
// content of its strings, so they get a look of their own. ---

func TestValidJSONStringsHoldingBrokenJSON(t *testing.T) {
	const m = "ZZSTRINGMARKERZZ"
	inners := []string{
		`prefix " {"cred@u0065ntials":{"value":"M"}}`,
		`prefix " credentials: {"pad":"]","value":"M"}`,
		`prefix " {"credentials":["]",{"value":"M"}]}`,
		`a "b" c" api_key=[{"a":"}"},"M"] end`,
	}
	for _, raw := range inners {
		inner := strings.ReplaceAll(fix(raw), "M", m)
		once, _ := json.Marshal(inner)
		twice, _ := json.Marshal(`{"body":` + string(once) + `}`)
		for name, doc := range map[string]string{
			"string literal":           string(once),
			"string literal, twice":    string(twice),
			"member of a small object": `{"log":` + string(once) + `}`,
			"over the parse limit":     `{"pad":"` + strings.Repeat("p", logging.MaxJSONRedact) + `","log":` + string(once) + `}`,
			"over the limit, twice":    `{"pad":"` + strings.Repeat("p", logging.MaxJSONRedact) + `","log":` + string(twice) + `}`,
		} {
			if !json.Valid([]byte(doc)) {
				t.Fatalf("%s: test document must be valid JSON", name)
			}
			got := logging.RedactString(doc)
			if strings.Contains(got, m[:5]) {
				t.Errorf("%s: leak: %.300q", name, got)
				continue
			}
			if !json.Valid([]byte(got)) {
				t.Errorf("%s: no longer valid JSON: %.300q", name, got)
			}
			if logging.RedactString(got) != got {
				t.Errorf("%s: not idempotent", name)
			}
			if out := logLine(t, doc); strings.Contains(out, m[:5]) {
				t.Errorf("%s: leak through the handler", name)
			}
		}
	}
}

func TestValidJSONStringsWithoutSecretsAreUnchanged(t *testing.T) {
	// Strings holding JSON, broken or not, with nothing sensitive are left
	// byte for byte as they were, escapes included.
	inner := `prefix " {"user":"b@u006fb","note":["]","x"]} ` + "é"
	once, _ := json.Marshal(fix(inner))
	doc := `{"pad":"` + strings.Repeat("p", logging.MaxJSONRedact) + `","log":` + string(once) + `,"esc":"@u00e9@/"}`
	doc = strings.ReplaceAll(doc, `"@u00e9@/"`, `"`+fix(`@u00e9@/`)+`"`)
	if got := logging.RedactString(doc); got != doc {
		t.Fatalf("an ordinary document changed")
	}
}
