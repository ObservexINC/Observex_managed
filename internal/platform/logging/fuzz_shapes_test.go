package logging_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// FuzzSensitiveShapes builds the shapes that random short strings rarely
// reach: explicit secret types behind pointers, interfaces and unexported
// fields; map keys around MaxString; composite map keys around the item,
// depth and node bounds; JSON around MaxJSONRedact, nested, escaped, cut
// short, double-encoded or inside other text. The invented
// marker must never reach the log line, the line must stay valid JSON, and
// redacting a string twice must give the same result.
func FuzzSensitiveShapes(f *testing.F) {
	// Shapes 3 and 4 build documents over 1 MiB; one seed each keeps the
	// seed run short.
	for shape := uint8(0); shape < shapes; shape++ {
		f.Add(shape, int16(1), uint8(3), uint16(5), "api_key")
		if shape != 3 && shape != 4 {
			f.Add(shape, int16(0), uint8(1), uint16(0), "password")
		}
	}
	f.Add(uint8(2), int16(-9), uint8(0), uint16(0), "client_secret")
	f.Add(uint8(9), int16(2), uint8(2), uint16(0), "secret") // nodes, one past the bound
	f.Fuzz(func(t *testing.T, shape uint8, delta int16, depth uint8, cut uint16, word string) {
		const m = "ZZFUZZSHAPEMARKERZZ"
		if !utf8.ValidString(word) || len(word) > 64 || !logging.IsSensitiveKey(word) || strings.ContainsAny(strings.ToUpper(word), "Z") {
			word = "password"
		}
		name, _ := json.Marshal(word) // the word as a JSON string, any characters
		d := int(depth % 6)
		secret := m // what must not reach the output
		var v any
		switch shape % shapes {
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
		case 2: // a sensitive map key around the display limit, maybe boxed
			// Padding keeps a word sensitive only when it holds a secret
			// fragment; a name sensitive only as a whole ("pass", "dsn")
			// is not sensitive once padded, so it is padded with
			// "password" instead and tested unpadded as well. The padded
			// key's sensitivity is checked, not assumed.
			frag := word
			if !logging.IsSensitiveKey("x" + word) {
				frag = "password"
			}
			key := strings.Repeat("x", max(logging.MaxString+int(delta)%64-len(frag), 0)) + frag
			if !logging.IsSensitiveKey(key) {
				t.Fatalf("generator: the padded key (%d bytes) is not sensitive", len(key))
			}
			exact := word
			switch (delta >> 1) & 3 {
			case 0:
				v = map[string]string{key: m, exact: m}
			case 1:
				v = map[any]string{key: m, exact: m}
			case 2:
				v = map[*string]string{&key: m, &exact: m}
			default:
				v = map[any]string{&key: m, exact: m}
			}
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
		case 8: // broken quoting before an escaped name, a structured value, 0 to 2 encodings, maybe cut
			prefixes := []string{"", `prefix " `, `a "b" c" `, `"open `, `5": `}
			esc := string(name)
			if word[0] < utf8.RuneSelf && name[1] == word[0] {
				esc = fmt.Sprintf(`"\u%04x`, word[0]) + string(name[2:])
			}
			values := []string{`{"value":"M"}`, `["M",{"v":"M"}]`, `"M"`, `{"a":{"b":["M"]}}`}
			text := prefixes[d%len(prefixes)] + `{` + esc + `:` + strings.ReplaceAll(values[int(cut)%len(values)], "M", m) + `}`
			levels := int(depth/8) % 3
			for i := 0; i < levels; i++ {
				q, _ := json.Marshal(text)
				text = string(q)
			}
			if levels > 0 {
				text = "body=" + text + " end"
			}
			if delta&1 != 0 { // cut inside the marker; what is left of it must not show
				n := 4 + int(cut)%(len(m)-4)
				secret = m[:n]
				text = text[:strings.Index(text, m)+n]
			}
			v = text
		case 9: // a composite map key with the word just below, at or past a bound
			off := int(delta%3+3)%3 - 1 // -1, 0 or +1
			switch d % 3 {
			case 0: // items: the word is the last of MaxItems+off elements
				v = oneEntry(stringArray(logging.MaxItems+off, word), m)
			case 1: // depth: the word inside MaxDepth+off wrappers
				v = oneEntry(wrappedKey(logging.MaxDepth+off, word), m)
			default: // nodes: the word is the last of MaxNodes+off values
				v = oneEntry(nodeKey(logging.MaxNodes-3858+off, word), m)
			}
		}
		out := logLine(t, v)
		if strings.Contains(out, secret) {
			t.Fatalf("marker reached the output (shape %d): %.500s", shape%shapes, out)
		}
		if s, ok := v.(string); ok {
			r := logging.RedactString(s)
			if strings.Contains(r, secret) {
				t.Fatalf("marker survived RedactString (shape %d): %.500s", shape%shapes, r)
			}
			if logging.RedactString(r) != r {
				t.Fatalf("not idempotent (shape %d)", shape%shapes)
			}
		}
	})
}

// shapes is how many shapes FuzzSensitiveShapes builds.
const shapes = 10

// oneEntry returns a map holding value under key.
func oneEntry(key reflect.Value, value string) any {
	mp := reflect.MakeMap(reflect.MapOf(key.Type(), reflect.TypeOf("")))
	mp.SetMapIndex(key, reflect.ValueOf(value))
	return mp.Interface()
}

// notKeyRune reports characters an unquoted key in this test may not hold.
func notKeyRune(r rune) bool {
	return (r < 'a' || r > 'z') && (r < 'A' || r > 'Y') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.'
}
