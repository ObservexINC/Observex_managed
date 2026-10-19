package logging_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// FuzzSensitiveShapes builds the shapes that random short strings rarely
// reach: explicit secret types behind pointers, interfaces and unexported
// fields; map keys around MaxString; JSON around MaxJSONRedact, nested,
// escaped, cut short, double-encoded or inside other text. The invented
// marker must never reach the log line, the line must stay valid JSON, and
// redacting a string twice must give the same result.
func FuzzSensitiveShapes(f *testing.F) {
	// Shapes 3 and 4 build documents over 1 MiB; one seed each keeps the
	// seed run short.
	for shape := uint8(0); shape < 8; shape++ {
		f.Add(shape, int16(1), uint8(3), uint16(5), "api_key")
		if shape != 3 && shape != 4 {
			f.Add(shape, int16(0), uint8(1), uint16(0), "password")
		}
	}
	f.Add(uint8(2), int16(-9), uint8(0), uint16(0), "client_secret")
	f.Fuzz(func(t *testing.T, shape uint8, delta int16, depth uint8, cut uint16, word string) {
		const m = "ZZFUZZSHAPEMARKERZZ"
		if !utf8.ValidString(word) || len(word) > 64 || !logging.IsSensitiveKey(word) || strings.ContainsAny(strings.ToUpper(word), "Z") {
			word = "password"
		}
		name, _ := json.Marshal(word) // the word as a JSON string, any characters
		d := int(depth % 6)
		var v any
		switch shape % 8 {
		case 0: // an explicit secret behind d unexported wrappers
			var x any = logging.Secret(m)
			if delta&1 != 0 {
				s := logging.Secret(m)
				x = &s
			}
			for i := 0; i < d; i++ {
				x = wrap{x}
			}
			v = x
		case 1: // explicit secrets in collections in unexported fields
			s := logging.Secret(m)
			v = struct {
				a []any
				b map[string]any
			}{[]any{1, s}, map[string]any{"k": &s, "l": []logging.Secret{s}}}
		case 2: // a sensitive map key around the display limit
			n := max(logging.MaxString+int(delta)%64-len(word), 0)
			v = map[string]string{strings.Repeat("x", n) + word: m}
		case 3: // JSON around the parse limit, the member d levels deep, maybe cut
			obj := `{` + string(name) + `:{"value":"` + m + `"}}`
			for i := 0; i < d; i++ {
				obj = `{"x":` + obj + `}`
			}
			tail := `","data":` + obj + `}`
			pad := max(logging.MaxJSONRedact+int(delta)%512-len(`{"padding":"`)-len(tail), 0)
			doc := `{"padding":"` + strings.Repeat("p", pad) + tail
			if cut > 0 {
				doc = doc[:len(doc)-int(cut)%len(tail)]
			}
			v = doc
		case 4: // an array value under a name with an escaped first letter
			esc := string(name)
			if word[0] < utf8.RuneSelf && name[1] == word[0] {
				esc = fmt.Sprintf(`"\u%04x`, word[0]) + string(name[2:])
			}
			pad := strings.Repeat("p", max(logging.MaxJSONRedact+int(delta)%512, 0))
			v = `[{"pad":"` + pad + `"},{` + esc + `:[{"v":"` + m + `"},"` + m + `"]}]`
		case 5: // JSON written into a JSON string, inside other text
			inner := `{` + string(name) + `:{"v":"` + m + `"}}`
			for i := 0; i < d%3; i++ {
				q, _ := json.Marshal(inner)
				inner = `{"body":` + string(q) + `}`
			}
			q, _ := json.Marshal(inner)
			v = "request failed: body=" + string(q) + " status=500"
		case 6: // an unquoted key with an object or list value
			key := word
			if strings.IndexFunc(key, notKeyRune) >= 0 {
				key = "token"
			}
			open, closing := "{v: ", "}"
			if delta&1 != 0 {
				open, closing = "[", "]"
			}
			v = "retry " + key + "=" + open + m + ", more" + closing + " later"
		case 7: // the same document, cut at every few bytes near the member
			doc := `{"a":1,` + string(name) + `:{"value":"` + m + `","n":[1,2,{"x":"` + m + `"}]}}`
			at := strings.Index(doc, m) + int(cut)%(len(doc)-strings.Index(doc, m))
			v = doc[:at]
		}
		out := logLine(t, v)
		if strings.Contains(out, m) {
			t.Fatalf("marker reached the output (shape %d): %.500s", shape%8, out)
		}
		if s, ok := v.(string); ok {
			r := logging.RedactString(s)
			if logging.RedactString(r) != r {
				t.Fatalf("not idempotent (shape %d)", shape%8)
			}
		}
	})
}

// notKeyRune reports characters an unquoted key in this test may not hold.
func notKeyRune(r rune) bool {
	return (r < 'a' || r > 'z') && (r < 'A' || r > 'Y') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.'
}
