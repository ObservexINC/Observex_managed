// Package config loads ObserveX configuration documents.
//
// Documents are JSON. Decoding is strict: unknown fields, trailing data and
// oversized documents are rejected, and a value that implements Validator is
// validated after decoding. Configuration pushed to Agents and Gateways is
// signed with Ed25519; LoadSigned refuses a document whose detached signature
// does not verify against the trusted public key. JSON keeps the shared
// platform free of third-party dependencies; see
// docs/adr/0002-technology-choices.md.
package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// MaxSize is the largest configuration document accepted, in bytes.
const MaxSize = 4 << 20

// SignatureSuffix is appended to a document's path to find its detached
// signature file. The signature file holds the base64 (standard encoding)
// Ed25519 signature of the document's exact bytes.
const SignatureSuffix = ".sig"

var (
	// ErrTooLarge is returned for documents over MaxSize.
	ErrTooLarge = errors.New("config: document too large")
	// ErrTrailingData is returned when more than one JSON value is present.
	ErrTrailingData = errors.New("config: unexpected data after the document")
	// ErrBadSignature is returned when a signature does not verify.
	ErrBadSignature = errors.New("config: signature does not verify")
	// ErrNoKey is returned when no usable public key is supplied.
	ErrNoKey = errors.New("config: no valid Ed25519 public key")
)

// Validator is implemented by configuration types that check their own values.
type Validator interface {
	Validate() error
}

// Decode strictly decodes data into v, then validates v if it is a Validator.
func Decode(data []byte, v any) error {
	if len(data) > MaxSize {
		return ErrTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("config: decode: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrTrailingData
	}
	if val, ok := v.(Validator); ok {
		if err := val.Validate(); err != nil {
			return fmt.Errorf("config: invalid: %w", err)
		}
	}
	return nil
}

// Load reads the document at path and decodes it into v.
func Load(path string, v any) error {
	data, err := readLimited(path)
	if err != nil {
		return err
	}
	return Decode(data, v)
}

// Verify checks that sig is a valid Ed25519 signature of data by pub.
func Verify(data, sig []byte, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrNoKey
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, data, sig) {
		return ErrBadSignature
	}
	return nil
}

// Sign returns the detached signature file contents for data. It is used by
// the Server when it publishes configuration, and by tests.
func Sign(data []byte, priv ed25519.PrivateKey) []byte {
	sig := ed25519.Sign(priv, data)
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
}

// LoadSigned reads the document at path and its signature at
// path+SignatureSuffix, verifies the signature with pub, then decodes. Nothing
// is decoded unless the signature verifies.
func LoadSigned(path string, pub ed25519.PublicKey, v any) error {
	data, err := readLimited(path)
	if err != nil {
		return err
	}
	rawSig, err := readLimited(path + SignatureSuffix)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawSig)))
	if err != nil {
		return ErrBadSignature
	}
	if err := Verify(data, sig, pub); err != nil {
		return err
	}
	return Decode(data, v)
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- paths come from the operator's own configuration.
	if err != nil {
		return nil, fmt.Errorf("config: open: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("config: read: %w", err)
	}
	if len(data) > MaxSize {
		return nil, ErrTooLarge
	}
	return data, nil
}
