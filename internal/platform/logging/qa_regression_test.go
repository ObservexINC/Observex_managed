package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// All values here are invented test markers, never live credentials.
func TestQAAnySecretValuesRemainFullyRedacted(t *testing.T) {
	cases := map[string]any{
		"struct_with_spaces":    struct{ Password string }{"dummy-qa PREFIX_FRAGMENT_MARKER"},
		"map_with_spaces":       map[string]string{"password": "dummy-qa PREFIX_FRAGMENT_MARKER"},
		"slice_in_secret_field": struct{ Password []string }{[]string{"PREFIX_FRAGMENT_MARKER"}},
		"map_in_secret_field":   struct{ Credentials map[string]string }{map[string]string{"value": "PREFIX_FRAGMENT_MARKER"}},
		"cookie_in_struct":      struct{ Cookie string }{"PREFIX_FRAGMENT_MARKER"},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			logging.New(&out, slog.LevelInfo).Info("qa", "payload", value)
			if strings.Contains(out.String(), "PREFIX_FRAGMENT_MARKER") {
				t.Fatalf("invented secret fragment survived: %s", out.String())
			}
		})
	}
}

func TestQAJSONStringEscapedQuotesRemainRedacted(t *testing.T) {
	raw, err := json.Marshal(map[string]string{"password": "dummy-qa\"ESCAPED_QUOTE_MARKER"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	logging.New(&out, slog.LevelInfo).Info("qa", "body", string(raw))
	if strings.Contains(out.String(), "ESCAPED_QUOTE_MARKER") {
		t.Fatalf("invented JSON password fragment survived: %s", out.String())
	}
}

func TestQASensitiveGroupConsistentAcrossAPIs(t *testing.T) {
	for _, withAttrs := range []bool{false, true} {
		var out bytes.Buffer
		log := logging.New(&out, slog.LevelInfo).WithGroup("credentials")
		if withAttrs {
			log.With("value", "SENSITIVE_GROUP_MARKER").Info("qa")
		} else {
			log.Info("qa", "value", "SENSITIVE_GROUP_MARKER")
		}
		if strings.Contains(out.String(), "SENSITIVE_GROUP_MARKER") {
			t.Errorf("WithGroup leaked (WithAttrs=%v): %s", withAttrs, out.String())
		}
	}
	var out bytes.Buffer
	logging.New(&out, slog.LevelInfo).Info("qa", slog.Group("credentials", "value", "SENSITIVE_GROUP_MARKER"))
	if strings.Contains(out.String(), "SENSITIVE_GROUP_MARKER") {
		t.Fatal("slog.Group control unexpectedly leaked")
	}
}
