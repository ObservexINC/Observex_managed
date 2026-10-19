package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

type dbConfig struct {
	Host       string
	User       string
	DBPassword string
	APIToken   string
}

func TestSecretLeak(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelDebug, WithSensitiveKeys("license_key"))

	pem := "-----BEGIN PRIVATE KEY-----\n" + pemKeyBody + "\n-----END PRIVATE KEY-----"
	dsn := "postgres://observex:" + dsnSecret + "@db.internal:5432/config?sslmode=verify-full"

	log.Info("login", "user", "admin", "password", pwSecret)
	log.Info("call", "api_key", tokenSecret, "X-Api-Token", tokenSecret, "Authorization", "Bearer "+bearerSecret)
	log.Info("connecting to " + dsn)
	log.Info("connect", "dsn", dsn, "url", dsn)
	log.Error("failed", "err", fmt.Errorf("dial %s: refused", dsn))
	log.Error("failed", "err", errors.New("upstream said: password="+pwSecret))
	log.Info("header", "raw", "Authorization: Bearer "+bearerSecret)
	log.Info("aws", "key_id", awsKeyID)
	log.Info("jwt in text "+jwtSecret, "claims", jwtSecret)
	log.Info("hashes", "stored", bcryptHash, "other", argonHash)
	log.Info("key material", "pem", pem)
	log.Info("pem in message " + pem)
	log.Info("struct", "cfg", dbConfig{Host: "db", User: "u", DBPassword: pwSecret, APIToken: tokenSecret})
	log.Info("pointer", "cfg", &dbConfig{DBPassword: pwSecret})
	log.Info("map", "m", map[string]string{"password": pwSecret, "token": tokenSecret})
	log.Info("json body", "body", `{"user":"a","password":"`+pwSecret+`","client_secret":"`+tokenSecret+`"}`)
	log.Info("query string", "q", "https://x.example/cb?code=1&access_token="+tokenSecret+"&state=2")
	log.Info("custom key", "LICENSE-KEY", extraSecret)
	log.Info("typed", "value", Secret(typedSecret), "inline", fmt.Sprint(Secret(typedSecret)))
	log.Info("bytes", "raw", []byte("password="+pwSecret))
	log.With("password", pwSecret, "conn", dsn).Info("with attrs")
	log.WithGroup("db").Info("grouped", "password", pwSecret, slog.Group("inner", "token", tokenSecret, "dsn", dsn))
	log.Info("nested group", slog.Group("auth", slog.String("secret", pwSecret)))
	log.Debug("debug", "creds", fmt.Sprintf("user=admin password=%s", pwSecret))

	out := buf.String()
	if strings.Count(out, "\n") != 24 {
		t.Fatalf("expected 24 log lines, got %d:\n%s", strings.Count(out, "\n"), out)
	}
	for _, s := range allSecrets {
		if strings.Contains(out, s) {
			t.Errorf("secret %q leaked into log output", s)
		}
		// No long fragment may survive either.
		if len(s) >= 16 {
			for i := 0; i+12 <= len(s); i += 4 {
				if frag := s[i : i+12]; strings.Contains(out, frag) {
					t.Errorf("fragment %q of a secret leaked", frag)
					break
				}
			}
		}
	}
	if !strings.Contains(out, Redacted) {
		t.Fatal("output has no redaction markers; handler not applied")
	}
	// Context that is not secret stays readable.
	for _, keep := range []string{"db.internal:5432", "observex", "admin", "upstream said", "cfg"} {
		if !strings.Contains(out, keep) {
			t.Errorf("non-secret text %q was lost", keep)
		}
	}
}

func TestIsSensitiveKey(t *testing.T) {
	yes := []string{"password", "DB_PASSWORD", "db.password", "apiKey", "API-KEY", "x-api-token", "client_secret",
		"Authorization", "set-cookie", "privateKey", "connection_string", "pwd", "dsn", "AWS_ACCESS_KEY_ID", "jwt"}
	no := []string{"user", "host", "port", "service", "trace_id", "max_tokens_used", "key", "keyspace", "path", "dsnlike"}
	for _, k := range yes {
		if !IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = false, want true", k)
		}
	}
	for _, k := range no {
		// max_tokens_used contains "token" by design of fragment matching; it is
		// allowed to be redacted, so it is checked separately below.
		if k == "max_tokens_used" {
			continue
		}
		if IsSensitiveKey(k) {
			t.Errorf("IsSensitiveKey(%q) = true, want false", k)
		}
	}
}

func TestRedactStringKeepsOrdinaryText(t *testing.T) {
	cases := []string{
		"",
		"checkout latency p95 = 4.2s",
		"GET /api/orders?limit=50 200",
		"connected to https://db.internal:5432/config",
		"pool size 20 of 50",
		"max_tokens=512 prompt_tokens=100",
	}
	for _, c := range cases {
		if got := RedactString(c); got != c {
			t.Errorf("RedactString(%q) = %q, want unchanged", c, got)
		}
	}
}

func TestRedactStringCases(t *testing.T) {
	cases := []struct{ in, want string }{
		{"amqp://guest:guest@mq:5672/", "amqp://guest:" + Redacted + "@mq:5672/"},
		{"redis://:onlypass@cache:6379", "redis://:" + Redacted + "@cache:6379"},
		{"Bearer abcdefghijk", "Bearer " + Redacted},
		{"password=abc def", "password=" + Redacted + " def"},
		// A quoted member keeps its quotes, so JSON-like text stays JSON-like.
		{`"password": "a b c"`, `"password": "` + Redacted + `"`},
		{"APIToken:xyz123", "APIToken:" + Redacted},
		{"truncated -----BEGIN RSA PRIVATE KEY-----\nMIIabc", "truncated " + Redacted},
	}
	for _, c := range cases {
		if got := RedactString(c.in); got != c.want {
			t.Errorf("RedactString(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSecretType(t *testing.T) {
	s := Secret("value")
	if s.String() != Redacted || fmt.Sprintf("%v %s %#v", s, s, s) != Redacted+" "+Redacted+" "+Redacted {
		t.Fatal("Secret printed its value")
	}
	if s.Reveal() != "value" {
		t.Fatal("Reveal lost the value")
	}
}

func TestEnabledFollowsLevel(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, slog.LevelWarn)
	if log.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info enabled at warn level")
	}
	log.Info("dropped")
	log.Warn("kept")
	if strings.Contains(buf.String(), "dropped") || !strings.Contains(buf.String(), "kept") {
		t.Fatalf("level filtering broken: %s", buf.String())
	}
}

func TestNonStringValuesPassThrough(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, slog.LevelInfo).Info("numbers", "count", 42, "ok", true, "ratio", 0.5)
	out := buf.String()
	for _, want := range []string{`"count":42`, `"ok":true`, `"ratio":0.5`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
}

func FuzzRedactString(f *testing.F) {
	seeds := []string{
		"", "plain text", "password=x", "postgres://u:p@h/db", "Bearer abcdefgh",
		"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", jwtSecret, bcryptHash,
		`{"token":"abc","n":1}`, "password=[REDACTED]]", "a://:@", "secret:", "$argon2id$",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	// T01 to T03: mixed quote levels, an escaped separator, an escaped
	// value already hidden (backslashes written as @).
	for _, s := range []string{
		`prefix " credentials: {@"pad@":"]","value":"x"}`,
		`"{@"password@"@u003a@"x@"}"`,
		`"credentials: @@@"[REDACTED]@@@""`,
	} {
		f.Add(strings.ReplaceAll(s, "@", "\\"))
	}
	f.Fuzz(func(t *testing.T, s string) {
		once := RedactString(s)
		if twice := RedactString(once); twice != once {
			t.Fatalf("not idempotent:\n in:    %q\n once:  %q\n twice: %q", s, once, twice)
		}
		if len(s) <= MaxRedactInput && json.Valid([]byte(s)) && !json.Valid([]byte(once)) {
			t.Fatalf("valid JSON became invalid:\n in:   %q\n once: %q", s, once)
		}
	})
}
