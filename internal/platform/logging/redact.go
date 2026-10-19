// Package logging builds structured loggers that never write secret values.
//
// Every ObserveX process logs through NewHandler, which redacts in three
// layers (docs/adr/0007-logging-and-secret-redaction.md):
//
//   - Keys. An attribute, struct field, map entry, JSON member or group
//     whose name says it holds a secret (password, token, authorization,
//     cookie and similar) has its whole value replaced, whatever its type.
//   - Structure. Arbitrary values (structs, maps, slices, pointers) are
//     walked with reflection before anything is rendered, so a secret field
//     is dropped before it can become text. Strings that are whole JSON
//     documents are parsed and redacted member by member.
//   - Text. What remains as free text (messages, string values, error
//     messages) is scrubbed for secret-looking patterns: credentials in
//     URLs, bearer tokens, key=value secrets with escape-aware quoting, PEM
//     private keys, JSON Web Tokens, cloud access keys and password hashes.
//
// Text patterns are a safety net. The primary rule stays: never put a
// secret into a log call.
package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Redacted replaces every secret value in log output.
const Redacted = "[REDACTED]"

// Secret holds a value that must never be logged or printed. Its String,
// GoString and LogValue methods all return Redacted.
type Secret string

// String returns Redacted.
func (Secret) String() string { return Redacted }

// GoString returns Redacted, so %#v does not reveal the value either.
func (Secret) GoString() string { return Redacted }

// LogValue returns Redacted.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// Reveal returns the underlying value. Call it only where the value is used,
// never to build a log line.
func (s Secret) Reveal() string { return string(s) }

// keyFragments name secrets when they appear anywhere in a normalised key.
var keyFragments = []string{
	"password", "passwd", "passphrase", "secret", "token", "apikey",
	"privatekey", "credential", "creds", "authorization", "cookie",
	"connectionstring", "accesskey", "sessionkey", "signingkey",
}

// exactKeys name secrets only when they are the whole normalised key.
var exactKeys = map[string]struct{}{
	"pwd": {}, "pass": {}, "dsn": {}, "auth": {}, "jwt": {}, "bearer": {},
}

var keyNormaliser = strings.NewReplacer("_", "", "-", "", ".", "", " ", "")

func normaliseKey(k string) string {
	return keyNormaliser.Replace(strings.ToLower(k))
}

// IsSensitiveKey reports whether an attribute key names a secret.
func IsSensitiveKey(key string) bool {
	n := normaliseKey(key)
	if _, ok := exactKeys[n]; ok {
		return true
	}
	for _, f := range keyFragments {
		if strings.Contains(n, f) {
			return true
		}
	}
	return false
}

type rule struct {
	re   *regexp.Regexp
	repl string
	// fn, when set, does the rule's work instead of re and repl.
	fn func(string) string
	// need lists literals of which every match contains at least one (in
	// lower case when fold is set). Text holding none of them cannot match,
	// so the expression is not run on it: large text is mostly ordinary.
	need []string
	fold bool
}

// Quoted values in key=value text. Each form consumes escape sequences, so
// an escaped quote does not end the value, and a value whose closing quote
// never comes is redacted to the end of the text (fail closed).
const (
	// \"...\" inside JSON that is itself inside a JSON string (double
	// encoding). An escaped backslash (\\) followed by any token belongs to
	// the inner string, so it never ends it.
	doubleQuoted = `\\"(?:\\\\(?:\\[\s\S]|[^\\])|\\[^"\\]|[^\\])*(?:\\"|\\*$)`
	// "..." with backslash escapes (JSON, Go and most loggers).
	dquoted = `"(?:[^"\\]|\\[\s\S])*(?:"|\\?$)`
	// '...' with backslash escapes.
	squoted = `'(?:[^'\\]|\\[\s\S])*(?:'|\\?$)`
	// Unquoted values end at whitespace or a separator.
	unquoted = `[^\s,;&"'}\[\]]+`
)

// rules run in order. Each replacement keeps enough context to read the log
// line, and replaces only the secret part.
var rules = []rule{
	// PEM private keys, including encrypted and PKCS#8 variants. A key whose
	// END line never comes is redacted to the end of the text.
	{re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`), repl: Redacted,
		need: []string{"PRIVATE KEY-----"}},
	// Credentials in URLs and DSNs: scheme://user:password@host
	{re: regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://[^:/?#\s@]*):[^@/\s]*@`), repl: "${1}:" + Redacted + "@",
		need: []string{"://"}},
	// Authorization schemes followed by a credential.
	{re: regexp.MustCompile(`(?i)\b(bearer|basic|token|digest)(\s+)[A-Za-z0-9._~+/=\-]{6,}`), repl: "${1}${2}" + Redacted,
		need: []string{"bearer", "basic", "token", "digest"}, fold: true},
	// key=value, key: value, "key":"value" and \"key\":\"value\" pairs whose
	// key ends in a secret word (password, db_password, APIToken,
	// client_secret and so on): see redactPairs.
	{fn: redactPairs,
		need: []string{"passw", "passphrase", "pwd", "secret", "token", "api", "access", "private", "session", "authorization", "credential"}, fold: true},
	// JSON Web Tokens.
	{re: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`), repl: Redacted,
		need: []string{"eyJ"}},
	// AWS access key IDs.
	{re: regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), repl: Redacted,
		need: []string{"AKIA", "ASIA"}},
	// Password hashes: bcrypt, argon2, scrypt and SHA-crypt formats.
	{re: regexp.MustCompile(`\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}`), repl: Redacted, need: []string{"$2"}},
	{re: regexp.MustCompile(`\$(?:argon2(?:id|i|d)|scrypt|[56])\$[^\s"']+`), repl: Redacted, need: []string{"$"}},
}

// mayMatch reports whether r can match s. lower is s in ASCII lower case,
// or "" when s is not all ASCII: Unicode case folding (the Kelvin sign
// matches k under (?i)) is then left to the expression itself.
func (r rule) mayMatch(s, lower string) bool {
	if len(r.need) == 0 || (r.fold && lower == "") {
		return true
	}
	in := s
	if r.fold {
		in = lower
	}
	for _, n := range r.need {
		if strings.Contains(in, n) {
			return true
		}
	}
	return false
}

func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return ""
		}
	}
	return strings.ToLower(s)
}

// MaxJSONRedact is the largest whole-JSON string that is parsed and
// redacted member by member, then written back in canonical form. Larger
// or invalid JSON-like text gets the bounded structural pass
// (redactMembers), which replaces the whole value of every sensitive
// member without parsing the document.
const MaxJSONRedact = 1 << 20

// RedactString removes secret-looking text from s:
//
//   - text longer than MaxRedactInput is replaced as a whole;
//   - a whole JSON object or array of at most MaxJSONRedact bytes is
//     parsed, redacted by member name and written back with sorted keys;
//   - anything else (larger, truncated or malformed JSON, JSON inside other
//     text or inside JSON strings, and plain text) first has the whole
//     value of every sensitive member replaced, then the text rules.
//
// It is safe on any input, and applying it twice gives the same result as
// applying it once.
func RedactString(s string) string {
	return redactString(s, IsSensitiveKey)
}

func redactString(s string, sensitive func(string) bool) string {
	return redactStringAt(s, sensitive, 0)
}

// redactStringAt is redactString for text found inside depth levels of
// JSON strings (see redactStrings).
func redactStringAt(s string, sensitive func(string) bool, depth int) string {
	if s == "" {
		return s
	}
	if len(s) > MaxRedactInput {
		return tooLarge(len(s))
	}
	if out, ok := redactJSON(s, sensitive); ok {
		return out
	}
	t := redactText(redactMembers(s, sensitive, depth))
	// The rules can turn invalid JSON into valid JSON (rarely); give that
	// the JSON treatment too, so the function stays idempotent.
	if out, ok := redactJSON(t, sensitive); ok {
		return out
	}
	return t
}

func redactText(s string) string {
	lower := asciiLower(s)
	for _, r := range rules {
		if !r.mayMatch(s, lower) {
			continue
		}
		if r.fn != nil {
			s = r.fn(s)
		} else {
			s = r.re.ReplaceAllString(s, r.repl)
		}
	}
	return s
}

// Pairs whose key ends in a secret word. redactPairs evaluates
//
//	(?i)\b([A-Za-z0-9_\-]*(?:words))(\\?"?\s*[=:]\s*)(value)
//
// from each '=' or ':' backwards (the separator, then the word, then the
// rest of the key) and matches only the value with a regular expression.
// Run as one expression, the leading [A-Za-z0-9_\-]* is tried at every
// offset of a long word, which made large text slow.
var (
	pairWords = []string{
		"password", "passwd", "passphrase", "pwd", "secret", "token",
		"apikey", "api_key", "api-key", "accesskey", "access_key", "access-key",
		"privatekey", "private_key", "private-key", "sessionkey", "session_key", "session-key",
		"authorization", "credentials", "credential",
	}
	// (?i) as in the expression: it matters only for [REDACTED] itself.
	pairValue = regexp.MustCompile(`(?i)^(?:\[REDACTED\]|` + doubleQuoted + `|` + dquoted + `|` + squoted + `|` + unquoted + `)`)
)

// foldEq reports whether r matches the ASCII character c under (?i):
// simple case folding, so the Kelvin sign matches k and the long s
// matches s, as in package regexp.
func foldEq(r rune, c byte) bool {
	want := rune(c)
	if r == want {
		return true
	}
	for f := unicode.SimpleFold(want); f != want; f = unicode.SimpleFold(f) {
		if f == r {
			return true
		}
	}
	return false
}

// wordBefore returns where a secret word that ends at k starts, not
// looking before lo.
func wordBefore(s string, k, lo int) (int, bool) {
	for _, w := range pairWords {
		p, j := k, len(w)-1
		for ; j >= 0 && p > lo; j-- {
			r, size := utf8.DecodeLastRuneInString(s[lo:p])
			if !foldEq(r, w[j]) {
				break
			}
			p -= size
		}
		if j < 0 {
			return p, true
		}
	}
	return 0, false
}

func isSpaceByte(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' }

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func isWordByte(c byte) bool { return isKeyChar(c) && c != '-' }

// boundaryAt reports a word boundary (\b) before s[i].
func boundaryAt(s string, i int) bool {
	before := i > 0 && isWordByte(s[i-1])
	after := i < len(s) && isWordByte(s[i])
	return before != after
}

// redactPairs replaces the value of every key=value pair whose key ends in
// a secret word. A value that is already a quoted [REDACTED] is kept, so
// redacting stays idempotent and JSON-like text keeps its quotes.
func redactPairs(s string) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '=' && s[i] != ':' {
			continue
		}
		// Backwards: \s* then an optional " then an optional \.
		k := i
		for k > last && isSpaceByte(s[k-1]) {
			k--
		}
		if k > last && s[k-1] == '"' {
			k--
		}
		if k > last && s[k-1] == '\\' {
			k--
		}
		word, ok := wordBefore(s, k, last)
		if !ok {
			continue
		}
		// The key is the run of key characters that ends with the word,
		// from its first word boundary (\b[A-Za-z0-9_\-]*).
		start := word
		for start > last && isKeyChar(s[start-1]) {
			start--
		}
		for start < word && !boundaryAt(s, start) {
			start++
		}
		if !boundaryAt(s, start) {
			continue
		}
		sepEnd := i + 1
		for sepEnd < len(s) && isSpaceByte(s[sepEnd]) {
			sepEnd++
		}
		v := pairValue.FindStringIndex(s[sepEnd:])
		if v == nil {
			continue
		}
		valEnd := sepEnd + v[1]
		if value := s[sepEnd:valEnd]; value != Redacted && strings.Trim(value, `\"`) == Redacted {
			i = valEnd - 1 // already a quoted [REDACTED]
			continue
		}
		b.WriteString(s[last:sepEnd])
		b.WriteString(Redacted)
		last = valEnd
		i = valEnd - 1
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// redactJSON redacts s when it is a whole JSON object or array.
func redactJSON(s string, sensitive func(string) bool) (string, bool) {
	t := strings.TrimSpace(s)
	if len(t) < 2 || len(t) > MaxJSONRedact || (t[0] != '{' && t[0] != '[') || !json.Valid([]byte(t)) {
		return "", false
	}
	dec := json.NewDecoder(strings.NewReader(t))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", false
	}
	sz := newSanitizer(sensitive)
	clean := sz.jsonValue(v, 0)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(clean); err != nil {
		return "", false
	}
	return strings.TrimSuffix(buf.String(), "\n"), true
}

// Option configures NewHandler.
type Option func(*handler)

// WithSensitiveKeys adds attribute keys, beyond the built-in list, whose
// values are always redacted. Keys are compared after normalisation.
func WithSensitiveKeys(keys ...string) Option {
	return func(h *handler) {
		for _, k := range keys {
			h.extra[normaliseKey(k)] = struct{}{}
		}
	}
}

// handler is immutable after NewHandler returns: WithAttrs and WithGroup
// return new handlers and never change the receiver, so loggers derived
// from one another do not affect each other.
type handler struct {
	next  slog.Handler
	extra map[string]struct{} // read-only after construction
	// redactAll is set inside a group whose name is sensitive (for example
	// WithGroup("credentials")); every attribute value below it is redacted,
	// exactly as for slog.Group("credentials", ...).
	redactAll bool
}

// NewHandler wraps next so that secrets never reach it.
func NewHandler(next slog.Handler, opts ...Option) slog.Handler {
	h := &handler{next: next, extra: map[string]struct{}{}}
	for _, o := range opts {
		o(h)
	}
	return h
}

// New returns a JSON logger writing to w at level, with redaction.
func New(w io.Writer, level slog.Leveler, opts ...Option) *slog.Logger {
	return slog.New(NewHandler(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}), opts...))
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, h.redactText(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = h.redactAttr(a)
	}
	return &handler{next: h.next.WithAttrs(red), extra: h.extra, redactAll: h.redactAll}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{next: h.next.WithGroup(name), extra: h.extra, redactAll: h.redactAll || (name != "" && h.sensitive(name))}
}

func (h *handler) sensitive(key string) bool {
	if IsSensitiveKey(key) {
		return true
	}
	_, ok := h.extra[normaliseKey(key)]
	return ok
}

func (h *handler) redactText(s string) string { return redactString(s, h.sensitive) }

func (h *handler) redactAttr(a slog.Attr) slog.Attr {
	if h.redactAll || h.sensitive(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	v := resolve(a.Value)
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.redactText(v.String()))
	case slog.KindGroup:
		group := v.Group()
		red := make([]any, len(group))
		for i, g := range group {
			red[i] = h.redactAttr(g)
		}
		return slog.Group(a.Key, red...)
	case slog.KindAny:
		return slog.Attr{Key: a.Key, Value: toSlogValue(newSanitizer(h.sensitive).any(v.Any()))}
	default:
		// Numbers, booleans, times and durations cannot hold secret text.
		return slog.Attr{Key: a.Key, Value: v}
	}
}

// resolve calls LogValue methods like slog.Value.Resolve, but turns a
// panic into UnprintableMarker instead of a stack trace.
func resolve(v slog.Value) slog.Value {
	for i := 0; i < 100 && v.Kind() == slog.KindLogValuer; i++ {
		lv := v.LogValuer()
		ok := true
		func() {
			defer func() {
				if recover() != nil {
					ok = false
				}
			}()
			v = lv.LogValue()
		}()
		if !ok {
			return slog.StringValue(UnprintableMarker)
		}
	}
	if v.Kind() == slog.KindLogValuer {
		return slog.StringValue(UnprintableMarker)
	}
	return v
}

// toSlogValue keeps strings as strings and everything else as a value the
// JSON and text handlers render without calling back into user code.
func toSlogValue(v any) slog.Value {
	if s, ok := v.(string); ok {
		return slog.StringValue(s)
	}
	return slog.AnyValue(v)
}
