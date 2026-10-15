package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type nodeConfig struct {
	NodeID  string   `json:"node_id"`
	Listen  string   `json:"listen"`
	Peers   []string `json:"peers"`
	MaxConn int      `json:"max_conn"`
}

func (c *nodeConfig) Validate() error {
	if c.NodeID == "" {
		return errors.New("node_id is required")
	}
	if c.MaxConn < 0 {
		return errors.New("max_conn must not be negative")
	}
	return nil
}

const good = `{"node_id":"node-1","listen":":7443","peers":["node-2","node-3"],"max_conn":100}`

func TestDecodeValid(t *testing.T) {
	var c nodeConfig
	if err := Decode([]byte(good), &c); err != nil {
		t.Fatal(err)
	}
	if c.NodeID != "node-1" || len(c.Peers) != 2 || c.MaxConn != 100 {
		t.Fatalf("decoded %+v", c)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":  `{"node_id":"n","colour":"red"}`,
		"trailing data":  good + ` {"node_id":"x"}`,
		"trailing junk":  good + `]`,
		"wrong type":     `{"node_id":"n","max_conn":"many"}`,
		"invalid value":  `{"node_id":"n","max_conn":-1}`,
		"missing id":     `{"listen":":1"}`,
		"not json":       `node_id: n`,
		"empty document": ``,
	}
	for name, doc := range cases {
		var c nodeConfig
		if err := Decode([]byte(doc), &c); err == nil {
			t.Errorf("%s: accepted %q", name, doc)
		}
	}
}

func TestDecodeTooLarge(t *testing.T) {
	big := make([]byte, MaxSize+1)
	var c nodeConfig
	if err := Decode(big, &c); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	var c nodeConfig
	if err := Load(path, &c); err != nil {
		t.Fatal(err)
	}
	if err := Load(filepath.Join(dir, "missing.json"), &c); err == nil {
		t.Fatal("missing file accepted")
	}
	bigPath := filepath.Join(dir, "big.json")
	if err := os.WriteFile(bigPath, []byte(strings.Repeat(" ", MaxSize+10)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Load(bigPath, &c); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("big file: err = %v, want ErrTooLarge", err)
	}
}

func writeSigned(t *testing.T, dir, doc string, priv ed25519.PrivateKey) string {
	t.Helper()
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+SignatureSuffix, Sign([]byte(doc), priv), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSigned(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	path := writeSigned(t, dir, good, priv)

	var c nodeConfig
	if err := LoadSigned(path, pub, &c); err != nil {
		t.Fatalf("valid signed config rejected: %v", err)
	}
	if err := LoadSigned(path, otherPub, &c); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong key: err = %v, want ErrBadSignature", err)
	}
	if err := LoadSigned(path, nil, &c); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no key: err = %v, want ErrNoKey", err)
	}

	// Tampering with one byte after signing must be caught, and nothing decoded.
	tampered := strings.Replace(good, `"max_conn":100`, `"max_conn":900`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	var c2 nodeConfig
	if err := LoadSigned(path, pub, &c2); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered: err = %v, want ErrBadSignature", err)
	}
	if c2.MaxConn != 0 {
		t.Fatal("tampered document was decoded")
	}

	// A garbage or missing signature file is rejected.
	if err := os.WriteFile(path+SignatureSuffix, []byte("not base64!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LoadSigned(path, pub, &c2); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("garbage sig: err = %v, want ErrBadSignature", err)
	}
	if err := os.Remove(path + SignatureSuffix); err != nil {
		t.Fatal(err)
	}
	if err := LoadSigned(path, pub, &c2); err == nil {
		t.Fatal("missing signature accepted")
	}
}

func TestVerifyRejectsShortSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Verify([]byte("x"), []byte("short"), pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{good, `{}`, `{"node_id":"n"}`, `[]`, `null`, `{"peers":[1,2]}`, `{"node_id":"\u0000"}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var c nodeConfig
		if err := Decode(data, &c); err == nil && c.NodeID == "" {
			t.Fatalf("accepted a document without node_id: %q", data)
		}
	})
}
