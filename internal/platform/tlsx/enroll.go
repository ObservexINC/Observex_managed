package tlsx

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Voxmatic/observe/internal/platform/logging"
)

// TokenPrefix starts every enrollment token, so scanners and people recognise
// one when they see it.
const TokenPrefix = "oxe_"

const (
	tokenIDBytes     = 8
	tokenSecretBytes = 32
	maxTokenLength   = 128
)

var (
	// ErrTokenInvalid is returned for malformed or unknown tokens and for
	// tokens whose secret does not match. The caller cannot tell which, by design.
	ErrTokenInvalid = errors.New("tlsx: enrollment token invalid")
	// ErrTokenExpired is returned for a matching token past its expiry.
	ErrTokenExpired = errors.New("tlsx: enrollment token expired")
	// ErrTokenUsed is returned for a matching token that was already used.
	ErrTokenUsed = errors.New("tlsx: enrollment token already used")
)

// TokenRecord is what the cluster stores for an enrollment token. It holds a
// SHA-256 hash of the secret, never the secret itself.
type TokenRecord struct {
	ID        string
	Hash      [sha256.Size]byte
	ExpiresAt time.Time
	Used      bool
}

// NewEnrollmentToken creates a one-time token valid until now+ttl. The
// plaintext token is returned as a logging.Secret so it cannot be logged by
// accident; show it once to the operator and store only the record.
func NewEnrollmentToken(now time.Time, ttl time.Duration) (logging.Secret, TokenRecord, error) {
	if ttl <= 0 {
		return "", TokenRecord{}, fmt.Errorf("tlsx: token ttl must be positive, got %v", ttl)
	}
	idRaw := make([]byte, tokenIDBytes)
	secret := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(idRaw); err != nil {
		return "", TokenRecord{}, fmt.Errorf("tlsx: random id: %w", err)
	}
	if _, err := rand.Read(secret); err != nil {
		return "", TokenRecord{}, fmt.Errorf("tlsx: random secret: %w", err)
	}
	id := hex.EncodeToString(idRaw)
	encSecret := base64.RawURLEncoding.EncodeToString(secret)
	rec := TokenRecord{
		ID:        id,
		Hash:      sha256.Sum256([]byte(encSecret)),
		ExpiresAt: now.Add(ttl).UTC(),
	}
	return logging.Secret(TokenPrefix + id + "." + encSecret), rec, nil
}

// TokenID extracts the lookup ID from a plaintext token without checking the
// secret. It returns ErrTokenInvalid for malformed input.
func TokenID(token string) (string, error) {
	id, _, err := splitToken(token)
	return id, err
}

func splitToken(token string) (id, secret string, err error) {
	if len(token) > maxTokenLength || !strings.HasPrefix(token, TokenPrefix) {
		return "", "", ErrTokenInvalid
	}
	id, secret, ok := strings.Cut(strings.TrimPrefix(token, TokenPrefix), ".")
	if !ok || len(id) != 2*tokenIDBytes || secret == "" {
		return "", "", ErrTokenInvalid
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", "", ErrTokenInvalid
	}
	return id, secret, nil
}

// Verify checks a plaintext token against the stored record at time now. The
// secret comparison takes the same time whether or not it matches. Marking the
// record used is the caller's job, through a compare-and-set in the
// ConfigurationStore, so two concurrent enrollments cannot both succeed.
func (r TokenRecord) Verify(token string, now time.Time) error {
	id, secret, err := splitToken(token)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(secret))
	idMatch := subtle.ConstantTimeCompare([]byte(id), []byte(r.ID))
	hashMatch := subtle.ConstantTimeCompare(sum[:], r.Hash[:])
	if idMatch&hashMatch != 1 {
		return ErrTokenInvalid
	}
	if r.Used {
		return ErrTokenUsed
	}
	if !now.Before(r.ExpiresAt) {
		return ErrTokenExpired
	}
	return nil
}
