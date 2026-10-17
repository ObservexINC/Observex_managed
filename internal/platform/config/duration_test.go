package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDurationJSON(t *testing.T) {
	var v struct {
		Timeout Duration `json:"timeout"`
	}
	if err := Decode([]byte(`{"timeout":"1m30s"}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.Timeout.D() != 90*time.Second || v.Timeout.String() != "1m30s" {
		t.Fatalf("got %v", v.Timeout.D())
	}
	out, err := json.Marshal(v)
	if err != nil || string(out) != `{"timeout":"1m30s"}` {
		t.Fatalf("marshal: %s %v", out, err)
	}
	for _, bad := range []string{`{"timeout":30}`, `{"timeout":"thirty"}`, `{"timeout":"-5s"}`, `{"timeout":null}`} {
		var w struct {
			Timeout Duration `json:"timeout"`
		}
		err := Decode([]byte(bad), &w)
		if bad == `{"timeout":null}` {
			// null leaves the zero value, which means "default".
			if err != nil || w.Timeout != 0 {
				t.Fatalf("%s: %v %v", bad, err, w.Timeout)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "duration") {
			t.Fatalf("%s: want a duration error, got %v", bad, err)
		}
	}
}
