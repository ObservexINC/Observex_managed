package logging_test

import (
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// settlesInOnePass checks the rules themselves: one pass already gives text
// that a second pass leaves alone. (RedactString repeats passes until the
// text settles, so it is idempotent whatever the rules do; this keeps the
// rules from relying on that.)
func (c *tally) settlesInOnePass(in string) {
	c.t.Helper()
	once := logging.RedactOnce(in)
	if twice := logging.RedactOnce(once); twice != once {
		c.failures++
		if c.failures <= 5 {
			c.t.Errorf("one pass does not settle: %.300q -> %.300q -> %.300q", in, once, twice)
		}
	}
}

// TestTextRuleMarkersAtStringEnds covers the shape FuzzRedactString found
// in G02 (input 8e01a429a99efb2e): an unquoted sensitive name whose scalar
// value ends where a JSON string ends, in text that is not JSON. A text
// rule hides the value with a bare [REDACTED]; a second pass must leave
// that marker as it is, not read it as an array and stretch it to the end
// of the text. Fixtures write a backslash as @.
func TestTextRuleMarkersAtStringEnds(t *testing.T) {
	const secret = "ZZSCALARZZ"
	if strings.Count(fix(`@"`), "\\") != 1 {
		t.Fatal("fixtures lost their escapes")
	}
	c := tally{t: t}
	for _, open := range []string{`"`, `"@"@"`, `"x @"`, `a "b" "`} {
		for _, name := range []string{"CredentiAl", "password", "api_key", "token"} {
			for _, sep := range []string{":", "=", ": "} {
				for _, value := range []string{"0", secret, "1.5", "true", "[REDACTED]"} {
					for _, tail := range []string{`"0`, `"`, `"x"`, `@"`, ``, `" more text`} {
						inner := fix(open + name + sep + value + tail)
						for _, form := range []string{inner, jsonOf(inner), `{"m":` + jsonOf(inner) + `}`} {
							c.check(form, secret)
							c.settlesInOnePass(form)
							if i := strings.Index(form, secret); i >= 0 {
								c.check(form[:i+4], secret[:4]) // cut inside the value
							}
						}
					}
				}
			}
		}
	}
	// Every input once, and inputs holding the secret a second time, cut.
	c.done(4*4*3*5*6*3 + 4*4*3*6*3)
}

// TestPairValuesKeepQuoteStructure covers the shape FuzzRedactString found
// next (input 04952a76895d42bc): a key=value pair whose value is a quoted
// string standing between two strings of the text. Replacing the value and
// its quotes by a bare marker joined the strings around it into one whose
// text read as a sensitive name, so a second pass hid more. The marker now
// keeps the value's quotes. Fixtures write a backslash as @.
func TestPairValuesKeepQuoteStructure(t *testing.T) {
	const secret = "ZZQUOTEDZZ"
	c := tally{t: t}
	for _, open := range []string{`"`, `x "`, `{"m": "`} {
		for _, key := range []string{"CredentiAl", "password", "token"} {
			for _, sep := range []string{":", "=", ": "} {
				for _, value := range []string{`""`, `"` + secret + `"`, `@"` + secret + `@"`, `"a@"` + secret + `"`} {
					for _, mid := range []string{`@b`, ``, `x `} {
						for _, tail := range []string{`CredentiA":00`, `token":"` + secret + `"`, `x"=1`, `CredentiA@":00`} {
							inner := fix(open + key + sep + value + mid + tail)
							for _, form := range []string{inner, jsonOf(inner)} {
								c.check(form, secret)
								c.settlesInOnePass(form)
							}
						}
					}
				}
			}
		}
	}
	c.done(3 * 3 * 3 * 4 * 3 * 4 * 2)
}

// TestPairValuesEndingInBackslashes covers the third shape (input
// 1db91fde4b2f65bd): an unquoted value that ends in a backslash escaping
// the quote after it. Replacing the backslash with the value unescaped
// that quote, which joined strings as above. Fixtures write a backslash as
// @.
func TestPairValuesEndingInBackslashes(t *testing.T) {
	const secret = "ZZBACKSLASHZZ"
	c := tally{t: t}
	for _, open := range []string{`"`, `x "`, `{"m": "`} {
		for _, key := range []string{"CredentiAl", "password", "token"} {
			for _, sep := range []string{":", "=", ": "} {
				for _, value := range []string{`0@`, secret + `@`, secret + `@@@`, secret + `@@`} {
					// The tails hold no secret: an unquoted value ends at a quote,
					// escaped or not, and what follows is not part of it.
					for _, tail := range []string{`":0`, `"`, `":"x"`, `"x":1`} {
						inner := fix(open + key + sep + value + tail)
						for _, form := range []string{inner, jsonOf(inner)} {
							c.check(form, secret)
							c.settlesInOnePass(form)
						}
					}
				}
			}
		}
	}
	c.done(3 * 3 * 3 * 4 * 4 * 2)
}
