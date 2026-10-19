package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

func qaBoundaryJSONString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func qaBoundaryCheck(t *testing.T, in, marker string) {
	t.Helper()
	got := logging.RedactString(in)
	var buf bytes.Buffer
	logging.New(&buf, slog.LevelInfo).Info("qa", "payload", in)
	// Limit diagnostics for the >1 MiB cases; the full marker is invented.
	tail := func(s string) string {
		if len(s) > 350 {
			return "..." + s[len(s)-350:]
		}
		return s
	}
	if strings.Contains(got, marker) {
		t.Errorf("RedactString leaked marker: input=%q output=%q", tail(in), tail(got))
	}
	if strings.Contains(buf.String(), marker) {
		t.Errorf("logger leaked marker: %s", tail(buf.String()))
	}
	if json.Valid([]byte(in)) && !json.Valid([]byte(got)) {
		t.Errorf("valid JSON became invalid: output=%q", tail(got))
	}
	if next := logging.RedactString(got); next != got {
		t.Errorf("output is not idempotent: first=%q second=%q", tail(got), tail(next))
	}
}

// T01: a damaged object can mix quote encodings. Seeing an escaped quote
// in its first field does not prove that a later plain quote closes an
// enclosing JSON string. The whole sensitive value still needs hiding.
func TestQAMixedQuoteBoundaryRedaction(t *testing.T) {
	const marker = "QA_MIXED_QUOTE_VALUE_MARKER"
	values := []struct{ name, value string }{
		{"control_plain_quotes", `{"pad":"]","value":"M"}`},
		{"control_all_escaped", `{\"pad\":\"]\",\"value\":\"M\"}`},
		{"mixed_backslash_quotes", `{\"pad\":"]","value":"M"}`},
		{"mixed_unicode_quotes", `{\u0022pad\u0022:"]","value":"M"}`},
		{"mixed_bare_field", `{pad: \"x", value:"M"}`},
	}
	for _, c := range values {
		inner := `prefix " credentials: ` + strings.ReplaceAll(c.value, "M", marker)
		once := qaBoundaryJSONString(t, inner)
		forms := []struct{ name, text string }{
			{"plain", inner},
			{"json_string", once},
			{"json_string_twice", qaBoundaryJSONString(t, once)},
			{"small_object", `{"body":` + once + `}`},
			{"large_object", `{"pad":"` + strings.Repeat("p", logging.MaxJSONRedact) + `","body":` + once + `}`},
		}
		for _, form := range forms {
			t.Run(c.name+"/"+form.name, func(t *testing.T) {
				qaBoundaryCheck(t, form.text, marker)
			})
		}
	}
}

// T02: JSON permits a colon to be written as \u003a inside a string.
// Every variant decodes to the SAME inner document; this test verifies
// that property before asking the redactor to inspect it.
func TestQAUnicodeSeparatorInJSONString(t *testing.T) {
	const marker = "QA_ENCODED_SEPARATOR_MARKER"
	inners := []struct{ name, text string }{
		{"valid_inner", `{"password":"` + marker + `"}`},
		{"broken_inner", `prefix " credentials: {"pad":"]","value":"` + marker + `"}`},
	}
	for _, inner := range inners {
		once := qaBoundaryJSONString(t, inner.text)
		colon := strings.ReplaceAll(once, ":", `\u003a`)
		encodings := []struct{ name, text string }{
			{"control_literal_separator", once},
			{"unicode_separator", colon},
			{"unicode_separator_and_quotes", strings.ReplaceAll(colon, `\"`, `\u0022`)},
		}
		for _, encoded := range encodings {
			var decoded string
			if err := json.Unmarshal([]byte(encoded.text), &decoded); err != nil || decoded != inner.text {
				t.Fatalf("fixture must decode unchanged: %v", err)
			}
			forms := []struct{ name, text string }{
				{"json_string", encoded.text},
				{"small_array", `[` + encoded.text + `]`},
				{"large_array", `["` + strings.Repeat("p", logging.MaxJSONRedact) + `",` + encoded.text + `]`},
				{"large_object", `{"pad":"` + strings.Repeat("p", logging.MaxJSONRedact) + `","body":` + encoded.text + `}`},
			}
			for _, form := range forms {
				t.Run(inner.name+"/"+encoded.name+"/"+form.name, func(t *testing.T) {
					if !json.Valid([]byte(form.text)) {
						t.Fatal("outer document must be valid JSON")
					}
					qaBoundaryCheck(t, form.text, marker)
				})
			}
		}
	}
}

// T03: even an already-hidden value must not cause valid outer JSON to
// become invalid. The literal has three backslashes before each inner
// quote; json.Unmarshal checks that the fixture keeps its actual escapes.
func TestQAEncodedRedactionKeepsJSONValid(t *testing.T) {
	const encoded = `"credentials: \\\"[REDACTED]\\\""`
	var decoded string
	if err := json.Unmarshal([]byte(encoded), &decoded); err != nil || decoded != `credentials: \"[REDACTED]\"` {
		t.Fatalf("escaped fixture changed: %v, %q", err, decoded)
	}
	forms := []struct{ name, text string }{
		{"json_string", encoded},
		{"small_object", `{"body":` + encoded + `}`},
		{"large_array", `["` + strings.Repeat("p", logging.MaxJSONRedact) + `",` + encoded + `]`},
		{"large_object", `{"pad":"` + strings.Repeat("p", logging.MaxJSONRedact) + `","body":` + encoded + `}`},
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			if !json.Valid([]byte(form.text)) {
				t.Fatal("outer document must be valid JSON")
			}
			qaBoundaryCheck(t, form.text, "QA_ABSENT_MARKER")
		})
	}
}
