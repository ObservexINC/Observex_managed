package logging

import (
	"regexp"
	"strings"
	"testing"
)

// pairExpression is the single regular expression that redactPairs
// replaced (it was slow on large text). The differential fuzz test below
// checks that both give the same result.
var pairExpression = regexp.MustCompile(`(?i)\b([A-Za-z0-9_\-]*(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|session[_-]?key|authorization|credentials?))(\\?"?\s*[=:]\s*)(\[REDACTED\]|` +
	doubleQuoted + `|` + dquoted + `|` + squoted + `|` + unquoted + `)`)

func pairsByExpression(s string) string {
	return pairExpression.ReplaceAllStringFunc(s, func(match string) string {
		g := pairExpression.FindStringSubmatch(match)
		if g[3] != Redacted && strings.Trim(g[3], `\"`) == Redacted {
			return match
		}
		return g[1] + g[2] + Redacted
	})
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
