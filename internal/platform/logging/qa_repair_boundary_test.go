package logging_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// All markers are invented; no live secrets are used.
func TestQACompositeKeyLimitFailsClosed(t *testing.T) {
	const marker = "QA_COMPOSITE_LIMIT_VALUE_MARKER"
	var within [logging.MaxItems]string
	within[len(within)-1] = "password"
	var beyond [logging.MaxItems + 1]string
	beyond[len(beyond)-1] = "password"
	type wrapped struct{ Value any }
	var deep any = "password"
	for i := 0; i < logging.MaxDepth+2; i++ {
		deep = wrapped{deep}
	}
	for name, payload := range map[string]any{
		"within_item_limit_control": map[[logging.MaxItems]string]string{within: marker},
		"beyond_item_limit":         map[[logging.MaxItems + 1]string]string{beyond: marker},
		"beyond_depth_limit":        map[any]string{deep: marker},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			logging.New(&out, slog.LevelInfo).Info("qa", "payload", payload)
			if strings.Contains(out.String(), marker) {
				t.Fatalf("key-classification limit exposed the associated sensitive value: %s", out.String())
			}
		})
	}
}

func TestQARecoveryBracketInsideQuotedValue(t *testing.T) {
	const marker = "QA_QUOTED_BRACKET_VALUE_MARKER"
	for name, raw := range map[string]string{
		"ordinary_control":  `prefix " credentials: {"pad":"ordinary","value":"` + marker + `"}`,
		"bracket_in_string": `prefix " credentials: {"pad":"]","value":"` + marker + `"}`,
		"brace_in_string":   `prefix " credentials: {"pad":"}","value":"` + marker + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			got := logging.RedactString(raw)
			if strings.Contains(got, marker) {
				t.Errorf("sensitive value tail survived recovery: %s", got)
			}
			var out bytes.Buffer
			logging.New(&out, slog.LevelInfo).Info("qa", "payload", raw)
			if strings.Contains(out.String(), marker) {
				t.Errorf("sensitive tail reached log handler: %s", out.String())
			}
		})
	}
}
