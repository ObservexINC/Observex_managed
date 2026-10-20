package logging

// RedactOnce is one pass of RedactString, without the repetition that makes
// RedactString idempotent by construction. Tests use it to check that the
// rules themselves leave the quote structure alone.
var RedactOnce = func(s string) string { return redactStringAt(s, IsSensitiveKey, 0) }
