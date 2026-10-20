package logging

import (
	"regexp"
	"strings"
	"testing"
)

// pairExpression is the single regular expression that redactPairs
// replaced (it was slow on large text). The differential fuzz test below
// checks that both find the same pairs and values. Since G02 a
// double-quoted value keeps its quotes (pairMarker, tested on its own in
// TestPairMarker), so the reference writes the same marker.
var pairExpression = regexp.MustCompile(`(?i)\b([A-Za-z0-9_\-]*(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key|authorization|credentials?))(\\?"?\s*[=:]\s*)(\[REDACTED\]|` +
	doubleQuoted + `|` + dquoted + `|` + squoted + `|` + unquoted + `)`)

func pairsByExpression(s string) string {
	return pairExpression.ReplaceAllStringFunc(s, func(match string) string {
		g := pairExpression.FindStringSubmatch(match)
		if g[3] != Redacted && strings.Trim(g[3], `\"`) == Redacted {
			return match
		}
		return g[1] + g[2] + pairMarker(g[3])
	})
}

func TestPairMarker(t *testing.T) {
	for _, c := range []struct{ value, want string }{
		{`hunter2`, `[REDACTED]`},
		{`0\`, `[REDACTED]\`},     // the backslash escapes what follows: it stays
		{`0\\\`, `[REDACTED]\\\`}, // as does a longer run
		{`'a\'b'`, `[REDACTED]`},  // single quotes do not shape JSON
		{`""`, `"[REDACTED]"`},
		{`"x y"`, `"[REDACTED]"`},
		{`"a\"b"`, `"[REDACTED]"`},
		{`"cut`, `"[REDACTED]`},
		{`"cut\"`, `"[REDACTED]`}, // the last quote is escaped: unclosed
		{`"`, `"[REDACTED]`},
		{`\"v\"`, `\"[REDACTED]\"`},
		{`\"\"`, `\"[REDACTED]\"`},
		{`\"cut`, `\"[REDACTED]`},
		{`\"a\\\"b\"`, `\"[REDACTED]\"`},
		{`[REDACTED]`, `[REDACTED]`},
	} {
		if got := pairMarker(c.value); got != c.want {
			t.Errorf("pairMarker(%s) = %s, want %s", c.value, got, c.want)
		}
	}
	// The quotes of the text pair up as before: as many quotes, and as many
	// escaped quotes, around the markers.
	for _, in := range []string{
		`"CredentiAl:""\bCredentiA":00`, `a "password": "x" "b": 1`, `{\"token\":\"v\",\"n\":\"m\"}`,
		`password="cut`, `x "secret=\"q\"" y`,
	} {
		out := redactPairs(in)
		if out == in {
			t.Errorf("redactPairs(%s) changed nothing", in)
		}
		if strings.Count(out, `"`) != strings.Count(in, `"`) || strings.Count(out, `\"`) != strings.Count(in, `\"`) {
			t.Errorf("redactPairs(%s) = %s changes the quotes", in, out)
		}
	}
}

func FuzzPairsMatchExpression(f *testing.F) {
	for _, s := range []string{
		"password=abc", `"db_password": "x y"`, `token: 'a\'b' next`, "a-password=1 xpassword=2",
		`\"apiKey\":\"v\"`, "-pwd=1", "my_password_token=3", "PassWord = 4,", "secret=", "secret= ,",
		"toKen=5", "paſsword=6", "é-token=7", "password=[REDACTED]", `password="[REDACTED]"`,
		"credentials:x credential=y", "x=1 password:2 password : 3", `session-key="a\\"b"`,
		strings.Repeat("p", 300) + "password=9",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := redactPairs(s), pairsByExpression(s); got != want {
			t.Fatalf("redactPairs(%q)\n got %q\nwant %q", s, got, want)
		}
	})
}
