package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// Invented markers only. No live credentials are used.
func TestQASecretTypeInUnexportedFields(t *testing.T) {
	const marker = "QA_UNEXPORTED_SECRET_MARKER"
	secret := logging.Secret(marker)
	cases := map[string]any{
		"value":   struct{ value logging.Secret }{secret},
		"pointer": struct{ value *logging.Secret }{&secret},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			logging.New(&out, slog.LevelInfo).Info("qa", "payload", value)
			if strings.Contains(out.String(), marker) {
				t.Fatalf("logging.Secret disclosed through an unexported field: %s", out.String())
			}
		})
	}
}

func TestQALongSensitiveMapKey(t *testing.T) {
	const marker = "QA_LONG_KEY_SECRET_MARKER"
	key := strings.Repeat("x", logging.MaxString+1) + "password"
	if !logging.IsSensitiveKey(key) {
		t.Fatal("test key must be sensitive")
	}
	var out bytes.Buffer
	logging.New(&out, slog.LevelInfo).Info("qa", "payload", map[string]string{key: marker})
	if strings.Contains(out.String(), marker) {
		t.Fatalf("secret value survived truncation of a sensitive map key (output %d bytes)", out.Len())
	}
}

func TestQAOversizedJSONSensitiveObject(t *testing.T) {
	const marker = "QA_LARGE_JSON_SECRET_MARKER"
	for _, size := range []int{32, logging.MaxJSONRedact + 1} {
		raw, err := json.Marshal(map[string]any{
			"padding":     strings.Repeat("p", size),
			"credentials": map[string]string{"value": marker},
		})
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		logging.New(&out, slog.LevelInfo).Info("qa", "payload", string(raw))
		if strings.Contains(out.String(), marker) {
			t.Errorf("nested secret leaked from valid JSON at padding size %d (input %d bytes)", size, len(raw))
		}
	}
}
