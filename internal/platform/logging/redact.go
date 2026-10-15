// Package logging builds structured loggers that never write secret values.
//
// Every ObserveX process logs through NewHandler. It redacts attribute values
// whose key names a secret (password, token, authorization and similar),
// scrubs secret-looking text inside messages and string values (credentials
// in URLs, bearer tokens, private keys, password hashes), and renders
// arbitrary values to text before scrubbing them, so a struct that carries a
// password cannot leak it through reflection. See
// docs/adr/0007-logging-and-secret-redaction.md.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
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
	"privatekey", "credential", "authorization", "cookie",
	"connectionstring", "accesskey", "sessionkey", "signingkey",
}

// exactKeys name secrets only when they are the whole normalised key.
var exactKeys = map[string]struct{}{
	"pwd": {}, "pass": {}, "dsn": {}, "auth": {}, "jwt": {}, "bearer": {},
}

func normaliseKey(k string) string {
	k = strings.ToLower(k)
	return strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(k)
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
}

// rules run in order. Each replacement keeps enough context to read the log
// line, and replaces only the secret part.
var rules = []rule{
	// PEM private keys, including encrypted and PKCS#8 variants.
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`), Redacted},
	// Credentials in URLs and DSNs: scheme://user:password@host
	{regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://[^:/?#\s@]*):[^@/\s]*@`), "${1}:" + Redacted + "@"},
	// Authorization schemes followed by a credential.
	{regexp.MustCompile(`(?i)\b(bearer|basic|token|digest)(\s+)[A-Za-z0-9._~+/=\-]{6,}`), "${1}${2}" + Redacted},
	// key=value, key: value and "key":"value" pairs whose key ends in a secret
	// word (password, db_password, APIToken, client_secret and so on).
	{regexp.MustCompile(`(?i)\b([A-Za-z0-9_\-]*(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key|authorization|credentials?))("?\s*[=:]\s*)(\[REDACTED\]|"[^"]*"|'[^']*'|[^\s,;&"'}\[\]]+)`), "${1}${2}" + Redacted},
	// JSON Web Tokens.
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`), Redacted},
	// AWS access key IDs.
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), Redacted},
	// Password hashes: bcrypt, argon2, scrypt and SHA-crypt formats.
	{regexp.MustCompile(`\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}`), Redacted},
	{regexp.MustCompile(`\$(?:argon2(?:id|i|d)|scrypt|[56])\$[^\s"']+`), Redacted},
}

// RedactString removes secret-looking text from s. It is safe on any input and
// applying it twice gives the same result as applying it once.
func RedactString(s string) string {
	if s == "" {
		return s
	}
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
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

type handler struct {
	next  slog.Handler
	extra map[string]struct{}
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
	out := slog.NewRecord(r.Time, r.Level, RedactString(r.Message), r.PC)
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
	return &handler{next: h.next.WithAttrs(red), extra: h.extra}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{next: h.next.WithGroup(name), extra: h.extra}
}

func (h *handler) sensitive(key string) bool {
	if IsSensitiveKey(key) {
		return true
	}
	_, ok := h.extra[normaliseKey(key)]
	return ok
}

func (h *handler) redactAttr(a slog.Attr) slog.Attr {
	if h.sensitive(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, RedactString(v.String()))
	case slog.KindGroup:
		group := v.Group()
		red := make([]any, len(group))
		for i, g := range group {
			red[i] = h.redactAttr(g)
		}
		return slog.Group(a.Key, red...)
	case slog.KindAny:
		return slog.String(a.Key, RedactString(renderAny(v.Any())))
	default:
		// Numbers, booleans, times and durations cannot hold secret text.
		return slog.Attr{Key: a.Key, Value: v}
	}
}

// renderAny turns an arbitrary value into text before it is scrubbed. Errors
// use their message; everything else uses fmt's %+v, which includes struct
// field names so key-based rules can match them.
func renderAny(v any) string {
	switch x := v.(type) {
	case nil:
		return "<nil>"
	case error:
		return x.Error()
	case fmt.Stringer:
		return x.String()
	case []byte:
		return string(x)
	default:
		return fmt.Sprintf("%+v", x)
	}
}
