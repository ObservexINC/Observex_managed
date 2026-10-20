package logging

import (
	"bytes"
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
// sensitive, in text that is not valid JSON: a document truncated or
// malformed, JSON inside other text, and JSON written into JSON strings
// there. (Valid JSON goes to redactValidJSON.) A value is replaced however
// it is shaped (string, number, object, array), and a value that never
// ends (truncated input) is replaced to the end of the text, so a cut can
// only remove more.
//
// Names are decoded (escapes such as \u0065 included) and classified on
// their full text. Quoted names followed by ':' are members; an unquoted
// name followed by ':' or '=' counts when its value is an object or array
// (the text rules handle unquoted scalar values).
//
// Two passes read the same original text and the union of what they
// replace is hidden: the first follows the quoting, JSON strings included
// (down to maxEncodingDepth); the second (recover) does not trust the
// quoting at all. In this text a string's end may itself come from broken
// quoting, so where a value ends is not taken from it either (see
// memberValue and recoverEnd). The work is bounded: linear for each
// encoding level followed, within a budget for recover, and the text is at
// most MaxRedactInput bytes. Text recover cannot finish within its budget
// is replaced as a whole.
func redactMembers(src string, sensitive func(string) bool) string {
	if !mayHoldMembers(src) {
		return src // nothing can be a member
	}
	m := &memberScanner{src: src, sensitive: sensitive, strict: true}
	m.scan(0, 0, len(src))
	if !m.recover() {
		return tooAmbiguous(len(src))
	}
	return m.apply()
}

// mayHoldMembers reports whether src can hold a member: it has a ':' or an
// '=', or one written as a JSON escape (\u003a, \u003d), which a string
// at a deeper encoding level decodes to the separator.
func mayHoldMembers(src string) bool {
	if strings.ContainsAny(src, ":=") {
		return true
	}
	for _, e := range []string{"u003a", "u003A", "u003d", "u003D"} {
		if strings.Contains(src, e) {
			return true
		}
	}
	return false
}

// redactValidJSON redacts valid JSON and returns valid JSON. Its members
// are read exactly: a sensitive member's whole value is replaced by a
// "[REDACTED]" string. The JSON itself is never searched as text, since a
// text rule could cut through an escaped value and break the quoting;
// instead every string that could hold something sensitive (a member, a
// secret pattern, or an escape) is decoded, redacted as text of its own
// and written back as a JSON string (redactStrings). depth counts the
// encoding levels already followed.
func redactValidJSON(doc string, sensitive func(string) bool, depth int) string {
	out := doc
	if strings.Contains(doc, ":") { // a member of valid JSON has a ':' at this level
		m := &memberScanner{src: doc, sensitive: sensitive, flat: true}
		m.scan(0, 0, len(doc))
		out = m.apply()
	}
	return redactStrings(out, sensitive, depth)
}

// redactStrings redacts the content of every string of valid JSON text
// that could hold something sensitive: content with an escape is decoded
// first, and a decoded string is redacted like any text, down to
// maxEncodingDepth levels of JSON written into JSON strings (beyond that
// only the text rules apply). A string that changed is written back as a
// JSON string, so the text stays valid JSON; strings that did not change
// keep their exact bytes.
func redactStrings(doc string, sensitive func(string) bool, depth int) string {
	var b strings.Builder
	last := 0
	for p := 0; p < len(doc); {
		i := strings.IndexByte(doc[p:], '"')
		if i < 0 {
			break
		}
		q := p + i
		e := q + 1 // valid JSON: the string ends at the next unescaped quote
		for e < len(doc) {
			j := strings.IndexAny(doc[e:], `"\`)
			if j < 0 {
				e = len(doc)
				break
			}
			e += j
			if doc[e] == '"' {
				break
			}
			e += 2
		}
		if e >= len(doc) {
			break
		}
		content := doc[q+1 : e]
		escaped := strings.IndexByte(content, '\\') >= 0
		// Without an escape the content is what it says, and it has no
		// quote (JSON escapes those), so a member in it can only be an
		// unquoted name with an object or array value.
		member := strings.ContainsAny(content, ":=") && strings.ContainsAny(content, "{[")
		if escaped || member || textMayMatch(content) {
			text := content
			if escaped {
				if json.Unmarshal([]byte(doc[q:e+1]), &text) != nil {
					text = content // cannot happen in valid JSON
				}
			}
			var r string
			if depth < maxEncodingDepth {
				r = redactStringAt(text, sensitive, depth+1)
			} else {
				r = redactText(text)
			}
			if r != text {
				b.WriteString(doc[last:q])
				b.WriteString(jsonString(r))
				last = e + 1
			}
		}
		p = e + 1
	}
	if last == 0 {
		return doc
	}
	b.WriteString(doc[last:])
	return b.String()
}

// jsonString writes s as a JSON string.
func jsonString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return strings.TrimSuffix(buf.String(), "\n")
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
	texts     map[int]levelText  // recover: the level text last found, per level
	sound     map[levelText]bool // whether a level text is valid JSON on its own
	strict    bool               // the text is not valid JSON (see memberValue)
	rawAt     int                // recover: the next ':' or '=', or len(src)
	escAt     int                // recover: the next escaped separator, or len(src)
	flat      bool               // the text is valid JSON: strings are not followed
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

// replaceValue records the replacement of [v, e) by a Redacted string of
// the level. A value that is already Redacted is kept as it is.
func (m *memberScanner) replaceValue(level, v, e int) {
	if e == v {
		return
	}
	if e-v <= 64 && strings.Trim(m.text(level, v, e), `"`) == Redacted {
		return
	}
	m.spans = append(m.spans, span{v, e, quoteAt(level) + Redacted + quoteAt(level)})
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
			p = m.quoted(level, q, a, b)
		case isWord(c):
			start := p
			for p = q; p < b; {
				c, q, _, _ := m.char(level, p, b)
				if !isWord(c) {
					break
				}
				p = q
			}
			p = m.unquoted(level, start, p, a, b)
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
			p = m.quoted(0, p+1, a, b)
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
		if next := m.unquoted(0, start, k, a, b); next > k {
			p, from = next, next
			continue
		}
		p++
	}
}

// quoted handles a string whose opening quote ends at q, in the level
// text [a, b): a member name (when ':' follows) whose value is replaced
// when the name is sensitive, or a string that may hold encoded JSON. It
// returns where to go on.
func (m *memberScanner) quoted(level, q, a, b int) int {
	contentEnd, after, closed := m.skipString(level, q, b)
	if closed {
		if v, ok := m.valueStart(level, after, b, ":"); ok && m.sensitive(m.text(level+1, q, contentEnd)) {
			return m.memberValue(level, v, a, b)
		}
	}
	// A string that holds encoded JSON: follow it one level down.
	if !m.flat && level < maxEncodingDepth {
		content := m.src[q:contentEnd]
		if strings.Contains(content, quoteAt(level+1)) || strings.Contains(content, "u0022") || mayHoldEscapedSeparator(content) {
			m.scan(level+1, q, contentEnd)
		}
	}
	return after
}

// mayHoldEscapedSeparator reports a ':' or '=' written as a JSON escape.
func mayHoldEscapedSeparator(s string) bool {
	return !strings.ContainsAny(s, ":=") && mayHoldMembers(s)
}

// memberValue replaces the value at v of a sensitive member found in the
// level text [a, b) and returns where to go on. In text that is not valid
// JSON (strict), a string's end may come from broken quoting, so for a
// member inside a JSON string (level > 0) the value's own end is used only
// when it can be trusted, as recover decides (recoverEnd): the value holds
// no quote and its brackets match, or the string's content is valid JSON
// on its own. Otherwise the value runs to the end of the whole text.
func (m *memberScanner) memberValue(level, v, a, b int) int {
	e := m.valueEnd(level, v, b)
	if m.strict && level > 0 && !m.trustedEnd(level, v, e, levelText{level, a, b}) {
		m.replaceValue(level, v, len(m.src)) // kept when it is already a marker
		return b
	}
	m.replaceValue(level, v, e)
	return e
}

// trustedEnd reports whether the value [v, e) read at level in the text t
// can be trusted to end at e: its text t is valid JSON on its own, or it
// ends before t does, holds no quote and its brackets match.
func (m *memberScanner) trustedEnd(level, v, e int, t levelText) bool {
	if m.isSound(t) {
		return true
	}
	if e >= t.end {
		return false
	}
	d := m.text(level, v, e)
	return quoteFree(d) && bracketsMatch(d)
}

// quoteFree reports text with no quote in any spelling: as itself, escaped
// (which includes a quote) or as a Unicode escape (u0022), at any level.
func quoteFree(s string) bool {
	return !strings.Contains(s, `"`) && !strings.Contains(s, "u0022")
}

// isSound reports, once per level text, whether its content decoded at its
// level is valid JSON on its own. Level 0 is never: this scanner reads it
// only when it is not.
func (m *memberScanner) isSound(t levelText) bool {
	if t.level == 0 {
		return false
	}
	if m.sound == nil {
		m.sound = map[levelText]bool{}
	}
	sound, known := m.sound[t]
	if !known {
		sound = json.Valid([]byte(m.text(t.level, t.start, t.end)))
		m.sound[t] = sound
	}
	return sound
}

// unquoted handles an unquoted name [start, end) in the level text [a, b):
// when ':' or '=' and an object or array follow and the name is sensitive,
// the value is replaced. It returns where to go on (end when nothing was
// replaced).
func (m *memberScanner) unquoted(level, start, end, a, b int) int {
	if start == end {
		return end
	}
	v, ok := m.valueStart(level, end, b, ":=")
	if !ok {
		return end
	}
	c, _, _, ok := m.char(level, v, b)
	if !ok || (c != '{' && c != '[') || !m.sensitive(m.text(level, start, end)) {
		return end
	}
	// A bare marker reads as an array, but here it is what a text rule wrote
	// for a scalar value (key: 0 becomes key: [REDACTED]). Scalar values of
	// unquoted names are the text rules' to end, so the marker stays as it
	// is; read as an array, it could be stretched to the end of the text by
	// a second pass, and redaction would not be idempotent.
	if c == '[' && m.text(level, v, m.valueEnd(level, v, b)) == Redacted {
		return end
	}
	return m.memberValue(level, v, a, b)
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
// JSON string).
//
// Where a sensitive value ends is decided without trusting the quoting
// (see recoverEnd): a value with no quote ends where its brackets close; a
// value holding quotes runs to the end of the whole text, unless the JSON
// string holding it is valid JSON on its own. So a bracket inside a
// string never ends a value early, and neither can an unescaped quote or
// a string end that broken quoting made up.
//
// The work is bounded (recover's budget is a few times the length of the
// text). It returns false when the budget runs out: the caller then
// replaces the whole text rather than show it partly checked.
func (m *memberScanner) recover() bool {
	src := m.src
	m.budget = 8*len(src) + maxRecoverName
	m.texts = map[int]levelText{}
	m.rawAt, m.escAt = -1, -1
	for i := 0; i < len(src); {
		sepStart, sepEnd, colon, found := m.nextSeparator(i)
		if !found {
			return true
		}
		last := sepEnd - 1 // the separator's last byte: a value starts after it
		k := sepStart
		for k > 0 && isSpace(rune(src[k-1])) {
			k--
		}
		if colon && k > 0 && src[k-1] == '"' {
			end, ok, done := m.recoverQuoted(k-1, last)
			if !done {
				return false
			}
			if ok {
				i = end
				continue
			}
		}
		if colon && endsWithUnicodeQuote(src, k) {
			end, ok, done := m.recoverUnicodeQuoted(k, last)
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
			v := sepEnd
			for v < len(src) && isSpace(rune(src[v])) {
				v++
			}
			if v < len(src) && (src[v] == '{' || src[v] == '[') && m.sensitive(src[start:k]) {
				e, done := m.unquotedEnd(v)
				if !done {
					return false
				}
				if src[v:e] != Redacted {
					m.spans = append(m.spans, span{v, e, Redacted})
				}
				i = e
				continue
			}
		}
		i = sepEnd
	}
	return true
}

// nextSeparator finds the first ':' or '=' at or after i, written as
// itself or as a JSON escape (\u003a, \u003d, any case and any number of
// backslashes before it, so at any encoding level): where it starts and
// ends, and whether it is a colon. recover only moves forward, so where
// the next separator of each kind is is remembered, and the text is read
// once.
func (m *memberScanner) nextSeparator(i int) (start, end int, colon, found bool) {
	src := m.src
	if m.rawAt < i {
		m.rawAt = len(src)
		if j := strings.IndexAny(src[i:], ":="); j >= 0 {
			m.rawAt = i + j
		}
	}
	if m.escAt < i {
		m.escAt = len(src)
		for p := i; p < len(src); {
			u := strings.Index(src[p:], "u003")
			if u < 0 {
				break
			}
			u += p
			if u > 0 && src[u-1] == '\\' && u+5 <= len(src) && strings.IndexByte("aAdD", src[u+4]) >= 0 {
				m.escAt = u
				break
			}
			p = u + 1
		}
	}
	switch {
	case m.escAt < m.rawAt && m.escAt < len(src):
		u := m.escAt
		r := u - 1
		for r > 0 && src[r-1] == '\\' {
			r--
		}
		return r, u + 5, src[u+4] == 'a' || src[u+4] == 'A', true
	case m.rawAt < len(src):
		return m.rawAt, m.rawAt + 1, src[m.rawAt] == ':', true
	}
	return 0, 0, false, false
}

// recoverQuoted handles a ':' at sep whose name ends with the quote at q.
// It returns where to go on and whether a value was replaced; done is
// false when the work budget ran out.
func (m *memberScanner) recoverQuoted(q, sep int) (next int, replaced, done bool) {
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
	t, done := m.levelText(level, sep)
	if !done {
		return 0, false, false
	}
	v := m.skipSpace(level, sep+1, t.end)
	e, bare, done := m.recoverEnd(level, v, t)
	if !done {
		return 0, false, false
	}
	if !bare {
		m.replaceValue(level, v, e)
	} else if e > v && src[v:e] != Redacted {
		// A quote-free value in text that is not JSON: the marker is
		// written without quotes too, so a second look reads it the same.
		m.spans = append(m.spans, span{v, e, Redacted})
	}
	return max(e, sep+1), true, true
}

// endsWithUnicodeQuote reports whether src[:k] ends with a quote written
// as a Unicode escape (\u0022, at any level of escaping).
func endsWithUnicodeQuote(src string, k int) bool {
	return k >= 6 && src[k-5:k] == "u0022" && src[k-6] == '\\'
}

// recoverUnicodeQuoted handles a ':' at sep whose name ends with a quote
// written as \u0022 that ends at k: JSON written into a string and then
// shown with its quotes escaped as Unicode. The name back to the previous
// such quote is decoded at every encoding level and is sensitive when any
// reading is (or when no opening quote is within maxRecoverName bytes).
// Its value is then ended as recoverEnd decides for broken text at level
// 0: a value holding quotes in any spelling runs to the end of the text.
func (m *memberScanner) recoverUnicodeQuoted(k, sep int) (next int, replaced, done bool) {
	src := m.src
	r := k - 6
	for r > 0 && src[r-1] == '\\' {
		r--
	}
	lo := max(0, r-maxRecoverName)
	o := strings.LastIndex(src[lo:r], "u0022")
	if m.spend(r - lo) {
		return 0, false, false
	}
	sensitive := false
	switch {
	case o >= 0 && lo+o > 0 && src[lo+o-1] == '\\':
		start := lo + o + len("u0022")
		sensitive = m.sensitive(src[start:r])
		for level := 1; level <= maxEncodingDepth && !sensitive; level++ {
			sensitive = m.sensitive(m.text(level, start, r))
		}
	case lo > 0:
		sensitive = true // the name is longer than the window: fail closed
	default:
		return 0, false, true
	}
	if !sensitive {
		return 0, false, true
	}
	t := levelText{0, 0, len(src)}
	v := m.skipSpace(0, sep+1, t.end)
	e, bare, done := m.recoverEnd(0, v, t)
	if !done {
		return 0, false, false
	}
	if bare {
		if e > v && src[v:e] != Redacted {
			m.spans = append(m.spans, span{v, e, Redacted})
		}
	} else {
		m.replaceValue(0, v, e)
	}
	return max(e, sep+1), true, true
}

// levelText is the stretch [start, end) of the text that holds the
// characters of one encoding level around an offset: the content of the
// string that holds them (level > 0), or the whole text (level 0).
type levelText struct{ level, start, end int }

// levelText returns the text of encoding level `level` that holds offset
// p: for level > 0 the content of the string around it, between the
// nearest quotes of a shallower level before and after p (the encoding
// of the closing quote is not part of it). Answers are cached.
func (m *memberScanner) levelText(level, p int) (levelText, bool) {
	src := m.src
	if level == 0 {
		return levelText{0, 0, len(src)}, true
	}
	if t, ok := m.texts[level]; ok && t.start <= p && p < t.end {
		return t, true
	}
	t := levelText{level, 0, len(src)}
	for x := p; x > 0; {
		y := strings.LastIndexByte(src[:x], '"')
		if y < 0 {
			break
		}
		lv, rs := m.quoteLevel(y, 0)
		if lv < level {
			t.start = y + 1
			break
		}
		x = rs
	}
	for x := p + 1; x < len(src); {
		y := strings.IndexByte(src[x:], '"')
		if y < 0 {
			break
		}
		y += x
		if lv, _ := m.quoteLevel(y, p); lv < level {
			t.end = max(y-(1<<lv-1), p+1) // before the quote's backslashes
			break
		}
		x = y + 1
	}
	if m.spend(t.end - t.start) {
		return levelText{}, false
	}
	m.texts[level] = t
	return t, true
}

// unquotedEnd returns where the object or array at v, the value of an
// unquoted sensitive name, ends. With no quote before its brackets close,
// its brackets decide, when they match. A value holding quotes runs to
// the end of the text: an unquoted name means the text around it is not
// JSON, so neither its quoting nor any string end in it can be trusted.
func (m *memberScanner) unquotedEnd(v int) (int, bool) {
	src := m.src
	e := bracketEnd(src, v)
	if m.spend(e - v) {
		return 0, false
	}
	if quoteFree(src[v:e]) && bracketsMatch(src[v:e]) {
		return e, true
	}
	return len(src), true
}

// recoverEnd returns where the sensitive value at v, read at level in the
// text t, ends. Its own end (valueEnd: strings and escapes respected, so
// a bracket in a string does not close anything) is used when it can be
// trusted:
//   - a value with no quote in it cannot be misread by quoting: its end
//     is trusted when its brackets match;
//   - a value holding quotes is trusted only when the text holding it is
//     valid JSON on its own (a JSON string written into this broken text).
//
// Otherwise it runs to the end of the whole text. In text whose quoting is
// broken, any quote in the value may be an unescaped quote of its content,
// and even the end of the JSON string holding it may come from a stray
// quote, so everything after it may belong to the value; a cut can remove
// whatever would show it, so no reading of the rest can prove it does not.
// bare is true for a quote-free value kept to its own end in text that is
// not JSON: its marker is written without quotes. done is false when the
// work budget ran out.
func (m *memberScanner) recoverEnd(level, v int, t levelText) (e int, bare, done bool) {
	e = m.valueEnd(level, v, t.end)
	if m.spend(2 * (e - v)) { // valueEnd, then decoding it
		return 0, false, false
	}
	if level > 0 {
		if _, known := m.sound[t]; !known && m.spend(t.end-t.start) {
			return 0, false, false
		}
		if m.isSound(t) {
			return e, false, true
		}
	}
	if e < t.end {
		d := m.text(level, v, e)
		if quoteFree(d) && bracketsMatch(d) {
			return e, true, true
		}
	}
	return len(m.src), false, true
}

// bracketsMatch reports whether every bracket in s is closed by its own
// kind, in order. Text without brackets matches.
func bracketsMatch(s string) bool {
	var open []byte
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '{', '[':
			open = append(open, c)
		case '}', ']':
			if len(open) == 0 || (c == '}') != (open[len(open)-1] == '{') {
				return false
			}
			open = open[:len(open)-1]
		}
	}
	return len(open) == 0
}

// bracketEnd returns where the object or array starting at v ends by its
// brackets alone, or the end of the text. unquotedEnd uses it only for a
// value with no quote in it, where the brackets cannot be inside strings.
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

// apply returns the text with the recorded replacements. Replacements
// may overlap (two passes read the same text): the union of what they
// cover is hidden, and where they overlap the one starting first (the
// longest of those, then the shortest marker) is written.
func (m *memberScanner) apply() string {
	if len(m.spans) == 0 {
		return m.src
	}
	sort.SliceStable(m.spans, func(i, j int) bool {
		a, b := m.spans[i], m.spans[j]
		if a.start != b.start {
			return a.start < b.start
		}
		if a.end != b.end {
			return a.end > b.end
		}
		// The same value from both passes: the bare marker recover writes
		// for a quote-free value wins, so a second pass reads it the same.
		return len(a.repl) < len(b.repl)
	})
	var b strings.Builder
	b.Grow(len(m.src))
	last := 0
	for _, s := range m.spans {
		if s.start < last {
			last = max(last, s.end) // inside a value already replaced
			continue
		}
		b.WriteString(m.src[last:s.start])
		b.WriteString(s.repl)
		last = s.end
	}
	b.WriteString(m.src[last:])
	return b.String()
}
