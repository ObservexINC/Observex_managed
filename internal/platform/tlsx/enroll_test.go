package tlsx

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

func TestEnrollmentTokenRoundTrip(t *testing.T) {
	tok, rec, err := NewEnrollmentToken(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	plain := tok.Reveal()
	if !strings.HasPrefix(plain, TokenPrefix) {
		t.Fatalf("token %q lacks prefix", plain)
	}
	if err := rec.Verify(plain, now.Add(59*time.Minute)); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	id, err := TokenID(plain)
	if err != nil || id != rec.ID {
		t.Fatalf("TokenID = %q, %v; want %q", id, err, rec.ID)
	}
}

func TestEnrollmentTokenNeverPrints(t *testing.T) {
	tok, _, err := NewEnrollmentToken(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprintf("%v %s %#v", tok, tok, tok)} {
		if strings.Contains(s, TokenPrefix) {
			t.Fatalf("token printed: %s", s)
		}
	}
}

func TestEnrollmentTokenRecordHoldsNoSecret(t *testing.T) {
	tok, rec, err := NewEnrollmentToken(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, _ := strings.Cut(strings.TrimPrefix(tok.Reveal(), TokenPrefix), ".")
	if strings.Contains(fmt.Sprintf("%+v", rec), secret) {
		t.Fatal("record contains the plaintext secret")
	}
}

func TestEnrollmentTokenFailures(t *testing.T) {
	tok, rec, err := NewEnrollmentToken(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	plain := tok.Reveal()
	other, _, _ := NewEnrollmentToken(now, time.Hour)

	used := rec
	used.Used = true

	tampered := []byte(plain)
	tampered[len(tampered)-1] ^= 1

	cases := []struct {
		name  string
		rec   TokenRecord
		token string
		at    time.Time
		want  error
	}{
		{"expired exactly at expiry", rec, plain, now.Add(time.Hour), ErrTokenExpired},
		{"expired later", rec, plain, now.Add(2 * time.Hour), ErrTokenExpired},
		{"already used", used, plain, now, ErrTokenUsed},
		{"another token", rec, other.Reveal(), now, ErrTokenInvalid},
		{"tampered secret", rec, string(tampered), now, ErrTokenInvalid},
		{"no prefix", rec, strings.TrimPrefix(plain, TokenPrefix), now, ErrTokenInvalid},
		{"no separator", rec, strings.Replace(plain, ".", "", 1), now, ErrTokenInvalid},
		{"empty", rec, "", now, ErrTokenInvalid},
		{"too long", rec, plain + strings.Repeat("a", 200), now, ErrTokenInvalid},
		{"bad id", rec, TokenPrefix + "zzzzzzzzzzzzzzzz.abc", now, ErrTokenInvalid},
	}
	for _, c := range cases {
		if err := c.rec.Verify(c.token, c.at); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestNewEnrollmentTokenRejectsBadTTL(t *testing.T) {
	if _, _, err := NewEnrollmentToken(now, 0); err == nil {
		t.Fatal("zero ttl accepted")
	}
}

func TestTokensAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok, _, err := NewEnrollmentToken(now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok.Reveal()] {
			t.Fatal("duplicate token")
		}
		seen[tok.Reveal()] = true
	}
}

func FuzzVerifyToken(f *testing.F) {
	tok, rec, err := NewEnrollmentToken(now, time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(tok.Reveal())
	f.Add("")
	f.Add(TokenPrefix)
	f.Add(TokenPrefix + "0011223344556677.")
	f.Add(TokenPrefix + "0011223344556677.x")
	f.Fuzz(func(t *testing.T, s string) {
		err := rec.Verify(s, now)
		if err == nil && s != tok.Reveal() {
			t.Fatalf("accepted a different token %q", s)
		}
	})
}
