package logging_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// F03 from Astra's follow-up report: JSON beyond the parse limit,
// malformed, truncated, embedded in text or in JSON strings. Every marker
// is invented. Helpers are in secrettypes_test.go.

func TestCustomSensitiveKeysInMapsAndJSON(t *testing.T) {
	const m = "ZZCUSTOMKEYMARKERZZ"
	opt := logging.WithSensitiveKeys("employee_ref")
	mustNotContain(t, logLine(t, map[string]string{"Employee-Ref": m}, opt), m)
	mustNotContain(t, logLine(t, `{"pad":"`+strings.Repeat("p", logging.MaxJSONRedact)+`","employee_ref":{"v":"`+m+`"}}`, opt), m)
}

// --- F03: JSON beyond the parse limit, malformed, truncated, embedded ---

// padded builds a JSON document whose length is exactly size, with members
// after the padding.
func padded(t *testing.T, size int, members string) string {
	t.Helper()
	head, tail := `{"padding":"`, `",`+members+`}`
	n := size - len(head) - len(tail)
	if n < 0 {
		t.Fatalf("size %d too small", size)
	}
	doc := head + strings.Repeat("p", n) + tail
	if len(doc) != size {
		t.Fatalf("built %d bytes, want %d", len(doc), size)
	}
	return doc
}

func TestJSONAroundTheParseLimit(t *testing.T) {
	const m = "ZZBIGJSONMARKERZZ"
	members := `"status":"ok","credentials":{"value":"` + m + `","more":[1,{"x":"` + m + `"}]}`
	for _, size := range []int{logging.MaxJSONRedact - 1, logging.MaxJSONRedact, logging.MaxJSONRedact + 1, logging.MaxJSONRedact + 4096} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			doc := padded(t, size, members)
			if !json.Valid([]byte(doc)) {
				t.Fatal("test document must be valid JSON")
			}
			got := logging.RedactString(doc)
			mustNotContain(t, got, m)
			if !strings.Contains(got, `"status":"ok"`) || !strings.Contains(got, strings.Repeat("p", 1000)) {
				t.Fatal("ordinary members were lost")
			}
			if !json.Valid([]byte(got)) {
				t.Fatal("redacted document is no longer JSON")
			}
			if again := logging.RedactString(got); again != got {
				t.Fatal("not idempotent")
			}
			mustNotContain(t, logLine(t, doc), m)
		})
	}
}

func TestJSONShapesBeyondTheParseLimit(t *testing.T) {
	// One document over the limit holds every shape, each with its own
	// marker, so the large path runs once.
	shapes := map[string]string{
		"array value":          `"credentials":[{"value":"M"},"M"]`,
		"deep nesting":         `"a":{"b":{"c":{"api_key":{"x":{"y":["M"]}}}}}`,
		"object in an array":   `"list":[{"pad":"x"},{"token":{"v":"M"}}]`,
		"escaped member name":  `"cred\u0065ntials":{"value":"M"}`,
		"escaped underscore":   `"api\u005fkey":"M"`,
		"number value":         `"password":98765432123`,
		"string with escapes":  `"secret":"a\"b\\M"`,
		"double-encoded":       `"body":"{\"credentials\":{\"value\":\"M\"}}"`,
		"triple-encoded":       `"body3":"{\"inner\":\"{\\\"token\\\":{\\\"v\\\":\\\"M\\\"}}\"}"`,
		"unicode-escaped JSON": `"body4":"{\u0022password\u0022:{\u0022v\u0022:\u0022M\u0022}}"`,
	}
	var members []string
	marker := map[string]string{}
	i := 0
	for name, member := range shapes {
		m := fmt.Sprintf("ZZSHAPE%02dMARKERZZ", i)
		if name == "number value" {
			m = "98765432123" // the number itself is the secret
		}
		i++
		marker[name] = m
		members = append(members, strings.ReplaceAll(member, "M", m))
	}
	doc := `{"pad":"` + strings.Repeat("p", logging.MaxJSONRedact+1) + `",` + strings.Join(members, ",") + `}`
	if !json.Valid([]byte(doc)) {
		t.Fatal("test document must be valid JSON")
	}
	got := logging.RedactString(doc)
	for name, m := range marker {
		if strings.Contains(got, m) {
			t.Errorf("%s: marker reached the output", name)
		}
	}
	if !json.Valid([]byte(got)) {
		t.Fatal("redacted document is no longer JSON")
	}
	if logging.RedactString(got) != got {
		t.Fatal("not idempotent")
	}
}

func TestTruncatedAndMalformedJSON(t *testing.T) {
	const m = "ZZCUTMARKERZZ"
	full := `{"pad":"` + strings.Repeat("p", 64) + `","credentials":{"value":"` + m + `","n":[1,2]}}`
	at := strings.Index(full, m)
	cases := map[string]string{
		"cut inside the marker":  full[:at+5],
		"cut after the marker":   full[:at+len(m)+1],
		"cut before the brace":   full[:len(full)-1],
		"cut inside the array":   full[:strings.Index(full, "[1")+2],
		"trailing comma":         `{"credentials":{"value":"` + m + `",},}`,
		"missing comma":          `{"a":"x" "credentials":{"value":"` + m + `"}}`,
		"stray quote before":     `{"a":"x"y", "credentials":{"value":"` + m + `"}}`,
		"text around it":         `upstream said {"credentials":{"value":"` + m + `"}} (retrying)`,
		"double-encoded in text": `body="{\"credentials\":{\"value\":\"` + m + `\"}}" status=500`,
		"unquoted key, object":   `credentials: {value: ` + m + `}`,
		"unquoted key, list":     `token=[` + m + `, b]`,
	}
	// Size does not change the path for text that is not valid JSON; one
	// large case shows it.
	cases["cut inside the marker, over the parse limit"] = `{"pad":"` + strings.Repeat("p", logging.MaxJSONRedact) + full[len(`{"pad":"`):at+5]
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got := logging.RedactString(in)
			mustNotContain(t, got, m, m[:5])
			if logging.RedactString(got) != got {
				t.Fatal("not idempotent")
			}
		})
	}
}

func TestTextOverTheRedactionLimitIsReplaced(t *testing.T) {
	const m = "ZZLIMITMARKERZZ"
	member := `"credentials":{"value":"` + m + `"}`
	at := strings.Repeat("p", logging.MaxRedactInput-len(member)) + member
	if !raceEnabled { // 8 MiB is slow under the race detector; make cover runs it
		got := logging.RedactString(at)
		mustNotContain(t, got, m)
		if !strings.Contains(got, strings.Repeat("p", 1000)) {
			t.Fatal("text at the limit should still be shown")
		}
	}
	over := "p" + at
	got := logging.RedactString(over)
	mustNotContain(t, got, m, "pppp")
	if !strings.HasPrefix(got, logging.Redacted) || logging.RedactString(got) != got {
		t.Fatalf("over the limit: %q", got)
	}
}

func TestEscapedCharactersInMemberNames(t *testing.T) {
	const m = "ZZNAMEESCAPEMARKERZZ"
	pad := strings.Repeat("p", logging.MaxJSONRedact+1)
	for _, name := range []string{`my\/token`, `pass\\word_secret`, `\"secret\"`, `T\u004fKEN`, `api\u005Fkey`} {
		doc := `{"pad":"` + pad + `","` + name + `":{"v":"` + m + `"}}`
		if !json.Valid([]byte(doc)) {
			t.Fatalf("%s: test document must be valid JSON", name)
		}
		mustNotContain(t, logging.RedactString(doc), m)
	}
}
