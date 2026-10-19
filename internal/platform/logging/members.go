package logging

import (
	"encoding/json"
	"math/bits"
	"sort"
	"strings"
	"unicode/utf8"
)

// MaxRedactInput is the longest text, in bytes, that the redaction rules
// examine. Longer text is replaced as a whole (see tooLarge): reaching a
// work limit must never lower the protection.
const MaxRedactInput = 8 << 20

// maxEncodingDepth is how many times JSON written inside a JSON string
// (double encoding, and so on) is followed.
const maxEncodingDepth = 3

// tooLarge stands in for text longer than MaxRedactInput.
func tooLarge(n int) string {
	return Redacted + " (" + itoa(n) + " bytes; longer than the redaction limit of " + itoa(MaxRedactInput) + " bytes)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// redactMembers replaces the whole value of every member whose name is
// sensitive, in JSON-like text of any size, validity or encoding depth: a
// document too large for redactJSON, a truncated or malformed one, JSON
// inside other text, and JSON written into JSON strings. A value is
// replaced however it is shaped (string, number, object, array), and a
// value that never ends (truncated input) is replaced to the end of the
// text that holds it, so a cut can only remove more.
//
// Names are decoded (escapes such as \u0065 included) and classified on
// their full text. Quoted names followed by ':' are members; an unquoted
// name followed by ':' or '=' counts when its value is an object or array
// (the text rules handle unquoted scalar values).
//
// Text that is not valid JSON afterwards gets a second look (recover),
// which does not rely on the quoting being sound. The work is bounded:
// linear for each encoding level followed, within a budget for recover,
// and the text is at most MaxRedactInput bytes. Text recover cannot finish
// within its budget is replaced as a whole.
func redactMembers(src string, sensitive func(string) bool) string {
	if !strings.ContainsAny(src, ":=") {
		return src // nothing can be a member
	}
	m := &memberScanner{src: src, sensitive: sensitive}
	m.scan(0, 0, len(src))
	out := m.apply()
	if json.Valid([]byte(out)) {
		return out // well-formed: the first pass read every member exactly
	}
	// Second look, for text whose quoting may be broken (see recover).
	m2 := &memberScanner{src: out, sensitive: sensitive}
	if !m2.recover() {
		return tooAmbiguous(len(src))
	}
	return m2.apply()
}

// tooAmbiguous stands in for text that recover could not finish checking
// within its work budget.
func tooAmbiguous(n int) string {
	return Redacted + " (" + itoa(n) + " bytes of JSON-like text too ambiguous to check within the work limit)"
}

type span struct {
	start, end int
	repl       string
}

type memberScanner struct {
	src       string
	sensitive func(string) bool
	work      int // bytes recover has looked at
	budget    int // recover's limit
	spans     []span
}

// char reads one character of encoding level `level` at byte offset p,
// never at or beyond end. Level 0 is the text itself; level n+1 is the
// content of a level-n JSON string with its escapes decoded. raw is true
// when c is the byte at p taken as it is (so a name keeps its UTF-8), false
// when an escape produced it. ok is false at end.
func (m *memberScanner) char(level, p, end int) (c rune, next int, raw, ok bool) {
	if p >= end {
		return 0, p, false, false
	}
	if level == 0 {
		return rune(m.src[p]), p + 1, true, true
	}
	c, q, raw, ok := m.char(level-1, p, end)
	if !ok || c != '\\' {
		return c, q, raw, ok
	}
	e, q2, _, ok := m.char(level-1, q, end)
	if !ok {
		return '\\', q, raw, true // a trailing backslash stands for itself
	}
	switch e {
	case 'b':
		return '\b', q2, false, true
	case 'f':
		return '\f', q2, false, true
	case 'n':
		return '\n', q2, false, true
	case 'r':
		return '\r', q2, false, true
	case 't':
		return '\t', q2, false, true
	case 'u':
		var r rune
		p := q2
		for i := 0; i < 4; i++ {
			h, n, _, ok := m.char(level-1, p, end)
			v := hexVal(h)
			if !ok || v < 0 {
				return e, q2, false, true // not an escape after all: keep the 'u'
			}
			r = r<<4 | v
			p = n
		}
		return r, p, false, true
	default: // \" \\ \/ and anything else: the escaped character itself
		return e, q2, false, true
	}
}

func hexVal(c rune) rune {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return -1
}

func isSpace(c rune) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// isWord reports characters of an unquoted name.
func isWord(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
}

// quoteAt is how a double quote of level `level` is written in the text.
func quoteAt(level int) string {
	return strings.Repeat(`\`, (1<<level)-1) + `"`
}

// text decodes [a, b) at level, for classifying a name.
func (m *memberScanner) text(level, a, b int) string {
	buf := make([]byte, 0, min(b-a, 256))
	for p := a; p < b; {
		c, q, raw, ok := m.char(level, p, b)
		if !ok {
			break
		}
		if raw {
			buf = append(buf, m.src[p]) // a raw character is the byte at p
		} else {
			buf = utf8.AppendRune(buf, c)
		}
		p = q
	}
	return string(buf)
}

// skipString reads a level string whose opening quote ends at p. It
// returns where its content ends, where the string ends, and whether its
// closing quote was found.
func (m *memberScanner) skipString(level, p, end int) (contentEnd, after int, closed bool) {
	if level == 0 {
		for p < end {
			i := strings.IndexAny(m.src[p:end], `"\`)
			if i < 0 {
				return end, end, false
			}
			p += i
			if m.src[p] == '"' {
				return p, p + 1, true
			}
			if p+1 >= end {
				return end, end, false
			}
			p += 2 // a backslash and the character it escapes
		}
		return end, end, false
	}
	for p < end {
		c, q, _, _ := m.char(level, p, end)
		switch c {
		case '\\':
			_, q2, _, ok := m.char(level, q, end)
			if !ok {
				return end, end, false
			}
			p = q2
			continue
		case '"':
			return p, q, true
		}
		p = q
	}
	return end, end, false
}

// skipSpace returns the offset of the first non-space character at or
// after p.
func (m *memberScanner) skipSpace(level, p, end int) int {
	for p < end {
		c, q, _, _ := m.char(level, p, end)
		if !isSpace(c) {
			return p
		}
		p = q
	}
	return end
}

// valueStart returns where a member's value starts when the text at p is
// optional space, one of seps and optional space.
func (m *memberScanner) valueStart(level, p, end int, seps string) (int, bool) {
	p = m.skipSpace(level, p, end)
	c, q, _, ok := m.char(level, p, end)
	if !ok || !strings.ContainsRune(seps, c) {
		return 0, false
	}
	return m.skipSpace(level, q, end), true
}

// valueEnd returns where the value starting at v ends. A value that does
// not end before end (truncated input) runs to end.
func (m *memberScanner) valueEnd(level, v, end int) int {
	c, q, _, ok := m.char(level, v, end)
	if !ok {
		return v
	}
	switch c {
	case '"':
		_, after, closed := m.skipString(level, q, end)
		if !closed {
			return end
		}
		return after
	case '{', '[':
		depth := 1
		for p := q; p < end; {
			if level == 0 {
				i := strings.IndexAny(m.src[p:end], `"{}[]`)
				if i < 0 {
					return end
				}
				p += i
			}
			c, q, _, _ := m.char(level, p, end)
			switch c {
			case '"':
				_, after, closed := m.skipString(level, q, end)
				if !closed {
					return end
				}
				p = after
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return q
				}
			}
			p = q
		}
		return end
	default: // a number, literal or unquoted word
		for p := v; p < end; {
			c, q, _, _ := m.char(level, p, end)
			if c == ',' || c == '}' || c == ']' || isSpace(c) {
				return p
			}
			p = q
		}
		return end
	}
}

// redactValue records the replacement of the value at v and returns where
// it ends. A value that is already Redacted is kept as it is.
func (m *memberScanner) redactValue(level, v, end int) int {
	e := m.valueEnd(level, v, end)
	if e == v {
		return e
	}
	if e-v <= 64 && strings.Trim(m.text(level, v, e), `"`) == Redacted {
		return e
	}
	m.spans = append(m.spans, span{v, e, quoteAt(level) + Redacted + quoteAt(level)})
	return e
}

// scan walks [a, b) as level text.
func (m *memberScanner) scan(level, a, b int) {
	if level == 0 {
		m.scanText(a, b)
		return
	}
	for p := a; p < b; {
		c, q, _, _ := m.char(level, p, b)
		switch {
		case c == '"':
			p = m.quoted(level, q, b)
		case isWord(c):
			start := p
			for p = q; p < b; {
				c, q, _, _ := m.char(level, p, b)
				if !isWord(c) {
					break
				}
				p = q
			}
			p = m.unquoted(level, start, p, b)
		default:
			p = q
		}
	}
}

// scanText is scan at level 0, where only quotes and separators can start
// anything of interest, so it jumps from one to the next.
func (m *memberScanner) scanText(a, b int) {
	from := a // unquoted names are looked for back to here
	for p := a; p < b; {
		i := strings.IndexAny(m.src[p:b], `":=`)
		if i < 0 {
			return
		}
		p += i
		if m.src[p] == '"' {
			p = m.quoted(0, p+1, b)
			from = p
			continue
		}
		// A separator: is an unquoted name right before it?
		k := p
		for k > from && isSpace(rune(m.src[k-1])) {
			k--
		}
		start := k
		for start > from && isWord(rune(m.src[start-1])) {
			start--
		}
		if next := m.unquoted(0, start, k, b); next > k {
			p, from = next, next
			continue
		}
		p++
	}
}

// quoted handles a string whose opening quote ends at q: a member name
// (when ':' follows) whose value is replaced when the name is sensitive,
// or a string that may hold encoded JSON. It returns where to go on.
func (m *memberScanner) quoted(level, q, b int) int {
	contentEnd, after, closed := m.skipString(level, q, b)
	if closed {
		if v, ok := m.valueStart(level, after, b, ":"); ok && m.sensitive(m.text(level+1, q, contentEnd)) {
			return m.redactValue(level, v, b)
		}
	}
	// A string that holds encoded JSON: follow it one level down.
	if level < maxEncodingDepth {
		content := m.src[q:contentEnd]
		if strings.Contains(content, quoteAt(level+1)) || strings.Contains(content, "u0022") {
			m.scan(level+1, q, contentEnd)
		}
	}
	return after
}

// unquoted handles an unquoted name [start, end): when ':' or '=' and an
// object or array follow and the name is sensitive, the value is replaced.
// It returns where to go on (end when nothing was replaced).
func (m *memberScanner) unquoted(level, start, end, b int) int {
	if start == end {
		return end
	}
	v, ok := m.valueStart(level, end, b, ":=")
	if !ok {
		return end
	}
	if c, _, _, ok := m.char(level, v, b); !ok || (c != '{' && c != '[') || !m.sensitive(m.text(level, start, end)) {
		return end
	}
	return m.redactValue(level, v, b)
}

// maxRecoverName is how far back recover looks for the opening quote of a
// member name. A name whose opening quote is further away is treated as
// sensitive: a work limit must not hand a value to a weaker rule.
const maxRecoverName = MaxString

// quoteLevel returns the encoding level of a double quote at offset q: the
// number of trailing one bits in the length of the backslash run before
// it. 0 backslashes (or an even number, escaped backslashes) is a level-0
// quote; 1 is \" (level 1); 3 is \\\" (level 2); 5 is an escaped backslash
// then a level-1 quote; and so on. It also returns the run's start.
func (m *memberScanner) quoteLevel(q, floor int) (level, runStart int) {
	r := q
	for r > floor && m.src[r-1] == '\\' {
		r--
	}
	return bits.TrailingZeros(^uint(q - r)), r
}

// spend charges n bytes of work to recover's budget and reports whether
// it is exhausted.
func (m *memberScanner) spend(n int) bool {
	m.work += n
	return m.work > m.budget
}

// recover is a second look for text that is not valid JSON, whose quoting
// may be broken: a stray quote shifts every string the first pass reads,
// so a member it should have seen can go unnoticed. From every ':' recover
// reads the quoted name before it backwards, at the encoding level its
// closing quote shows, decodes it (escapes included) and classifies it; a
// sensitive name has its value replaced at that level, whatever the
// value's shape. When the opening quote is not within maxRecoverName
// bytes, the name is treated as sensitive. From every ':' or '=' it also
// reads an unquoted name; a sensitive one followed by an object or array
// has that value replaced by a bare [REDACTED] (valid in text and inside a
// JSON string), up to its matching bracket, or to the end of the text when
// the brackets never balance.
//
// The work is bounded (recover's budget is a few times the length of the
// text). It returns false when the budget runs out: the caller then
// replaces the whole text rather than show it partly checked.
func (m *memberScanner) recover() bool {
	src := m.src
	m.budget = 8*len(src) + maxRecoverName
	bounds := map[int]int{} // level -> end of the enclosing string, cached
	for i := 0; i < len(src); {
		j := strings.IndexAny(src[i:], ":=")
		if j < 0 {
			return true
		}
		i += j
		k := i
		for k > 0 && isSpace(rune(src[k-1])) {
			k--
		}
		if src[i] == ':' && k > 0 && src[k-1] == '"' {
			end, ok, done := m.recoverQuoted(k-1, i, bounds)
			if !done {
				return false
			}
			if ok {
				i = end
				continue
			}
		}
		start := k
		for start > 0 && isWord(rune(src[start-1])) {
			start--
		}
		if start < k {
			v := i + 1
			for v < len(src) && isSpace(rune(src[v])) {
				v++
			}
			if v < len(src) && (src[v] == '{' || src[v] == '[') && m.sensitive(src[start:k]) {
				e := bracketEnd(src, v)
				if m.spend(e - v) {
					return false
				}
				if src[v:e] != Redacted {
					m.spans = append(m.spans, span{v, e, Redacted})
				}
				i = e
				continue
			}
		}
		i++
	}
	return true
}

// recoverQuoted handles a ':' at sep whose name ends with the quote at q.
// It returns where to go on and whether a value was replaced; done is
// false when the work budget ran out.
func (m *memberScanner) recoverQuoted(q, sep int, bounds map[int]int) (next int, replaced, done bool) {
	src := m.src
	level, runStart := m.quoteLevel(q, 0)
	nameEnd := q - (1<<level - 1) // where the closing quote's encoding starts
	if nameEnd < runStart {
		nameEnd = runStart
	}
	// Find the opening quote of the same level, skipping deeper quotes
	// (they are inside the name) and stopping at a shallower one (the name
	// is not a string of this level, so this is not a member).
	lo := max(0, nameEnd-maxRecoverName)
	p, nameStart := nameEnd, -1
	for {
		o := strings.LastIndexByte(src[lo:p], '"')
		if o < 0 {
			break
		}
		o += lo
		lv, rs := m.quoteLevel(o, lo)
		if m.spend(p - rs) {
			return 0, false, false
		}
		if lv == level {
			nameStart = o + 1
			break
		}
		if lv < level {
			return 0, false, true
		}
		p = rs
	}
	sensitive := false
	switch {
	case nameStart >= 0:
		sensitive = m.sensitive(m.text(level+1, nameStart, nameEnd))
	case lo > 0:
		sensitive = true // the name is longer than the window: fail closed
	default:
		return 0, false, true // a quote with nothing opening it: not a member
	}
	if !sensitive {
		return 0, false, true
	}
	// The value ends at the latest where the string holding this level
	// ends: the next quote of a shallower level.
	end := len(src)
	if level > 0 {
		if b, ok := bounds[level]; ok && b > sep {
			end = b
		} else {
			for x := sep + 1; x < len(src); {
				y := strings.IndexByte(src[x:], '"')
				if y < 0 {
					break
				}
				y += x
				if lv, _ := m.quoteLevel(y, sep); lv < level {
					end = y
					break
				}
				x = y + 1
			}
			if m.spend(end - sep) {
				return 0, false, false
			}
			bounds[level] = end
		}
	}
	v := m.skipSpace(level, sep+1, end)
	e := m.redactValue(level, v, end)
	return max(e, sep+1), true, true
}

// bracketEnd returns where the object or array starting at v ends, by its
// brackets alone (quoting may be broken here), or the end of the text.
func bracketEnd(s string, v int) int {
	depth := 0
	for i := v; i < len(s); i++ {
		switch s[i] {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
}

// apply returns the text with the recorded replacements.
func (m *memberScanner) apply() string {
	if len(m.spans) == 0 {
		return m.src
	}
	sort.SliceStable(m.spans, func(i, j int) bool { return m.spans[i].start < m.spans[j].start })
	var b strings.Builder
	b.Grow(len(m.src))
	last := 0
	for _, s := range m.spans {
		if s.start < last {
			continue // inside a value already replaced
		}
		b.WriteString(m.src[last:s.start])
		b.WriteString(s.repl)
		last = s.end
	}
	b.WriteString(m.src[last:])
	return b.String()
}
