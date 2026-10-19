package logging_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// Invented markers only; these tests use no real credentials.
func TestQAInterfaceMapKeysKeepFullClassification(t *testing.T) {
	const marker = "QA_INTERFACE_KEY_VALUE_MARKER"
	key := strings.Repeat("x", logging.MaxString+1) + "password"
	if !logging.IsSensitiveKey(key) {
		t.Fatal("key must be sensitive")
	}
	for name, payload := range map[string]any{
		"string_key_control": map[string]string{key: marker},
		"interface_key":      map[any]string{key: marker},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			logging.New(&out, slog.LevelInfo).Info("qa", "payload", payload)
			if strings.Contains(out.String(), marker) {
				t.Fatalf("sensitive value survived interface map-key truncation (output %d bytes)", out.Len())
			}
		})
	}
}

func TestQAStrayQuoteEscapedSensitiveMember(t *testing.T) {
	const marker = "QA_ESCAPED_MEMBER_VALUE_MARKER"
	for name, raw := range map[string]string{
		"plain_control": `prefix " {"credentials":{"value":"` + marker + `"}}`,
		"escaped_name":  `prefix " {"cred\u0065ntials":{"value":"` + marker + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			out := logging.RedactString(raw)
			if strings.Contains(out, marker) {
				t.Errorf("sensitive subtree survived malformed JSON redaction: %s", out)
			}
			var log bytes.Buffer
			logging.New(&log, slog.LevelInfo).Info("qa", "payload", raw)
			if strings.Contains(log.String(), marker) {
				t.Errorf("sensitive subtree also reached the JSON log handler: %s", log.String())
			}
		})
	}
}
