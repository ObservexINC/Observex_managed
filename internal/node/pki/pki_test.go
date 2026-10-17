package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func initTemp(t *testing.T, opt Options) (Files, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tls")
	f, err := Init(dir, opt)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return f, dir
}

func parseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" {
		t.Fatalf("%s: no certificate", path)
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestInitCreatesAVerifiableSet(t *testing.T) {
	f, dir := initTemp(t, Options{NodeName: "node-1", Hosts: []string{"node-1.example.internal", "10.0.0.11", "NODE-1.example.internal", " ", "::1"}})
	if f != Paths(dir) {
		t.Fatalf("paths: %+v", f)
	}
	ca := parseCert(t, f.CACert)
	if !ca.IsCA || !ca.MaxPathLenZero || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("CA certificate is not a path-length-0 CA: %+v", ca.KeyUsage)
	}
	leaf := parseCert(t, f.NodeCert)
	if leaf.IsCA || leaf.Subject.CommonName != "node-1" {
		t.Fatalf("leaf: CA=%v CN=%q", leaf.IsCA, leaf.Subject.CommonName)
	}
	if strings.Join(leaf.DNSNames, ",") != "node-1.example.internal" {
		t.Fatalf("DNS names (duplicates, case and blanks folded): %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 2 {
		t.Fatalf("IP addresses: %v", leaf.IPAddresses)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("extended key usage: %v", leaf.ExtKeyUsage)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d > DefaultCertValidity+10*time.Minute {
		t.Fatalf("leaf validity %v is longer than the default", d)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, name := range []string{"node-1.example.internal", "10.0.0.11"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Fatalf("verify for %s: %v", name, err)
		}
	}
	if _, err := tls.LoadX509KeyPair(f.NodeCert, f.NodeKey); err != nil {
		t.Fatalf("node pair: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(f.CACert, f.CAKey); err != nil {
		t.Fatalf("CA pair: %v", err)
	}
	s, err := Check(f.NodeCert, f.NodeKey, f.CACert, time.Now())
	if err != nil || len(s.Warnings) != 0 || s.Subject == "" {
		t.Fatalf("Check: %+v %v", s, err)
	}
}

func TestInitFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are Unix permissions")
	}
	f, dir := initTemp(t, Options{NodeName: "n", Hosts: []string{"n.local"}})
	want := map[string]os.FileMode{f.CAKey: CAKeyMode, f.NodeKey: NodeKeyMode, f.CACert: CertMode, f.NodeCert: CertMode, dir: DirMode}
	for p, m := range want {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != m {
			t.Errorf("%s: mode %v, want %v", filepath.Base(p), st.Mode().Perm(), m)
		}
	}
}

func TestInitNeverOverwrites(t *testing.T) {
	f, dir := initTemp(t, Options{NodeName: "n", Hosts: []string{"n.local"}})
	before, _ := os.ReadFile(f.CAKey)
	if _, err := Init(dir, Options{NodeName: "n", Hosts: []string{"n.local"}}); !errors.Is(err, ErrExists) {
		t.Fatalf("second Init: %v", err)
	}
	after, _ := os.ReadFile(f.CAKey)
	if string(before) != string(after) {
		t.Fatal("the CA key changed")
	}

	// One file present (for example a customer's own certificate) is enough
	// to refuse.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, NodeCertName), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(dir2, Options{NodeName: "n", Hosts: []string{"n.local"}}); !errors.Is(err, ErrExists) {
		t.Fatalf("Init over a customer file: %v", err)
	}
	entries, _ := os.ReadDir(dir2)
	if len(entries) != 1 {
		t.Fatalf("Init left files behind: %d entries", len(entries))
	}
}

func TestInitRejectsBadInput(t *testing.T) {
	cases := map[string]Options{
		"no node name":    {Hosts: []string{"a"}},
		"no hosts":        {NodeName: "n"},
		"bad host":        {NodeName: "n", Hosts: []string{"bad host;rm"}},
		"cert outlive CA": {NodeName: "n", Hosts: []string{"a"}, CAValidity: time.Hour, CertValidity: 2 * time.Hour},
	}
	for name, opt := range cases {
		dir := filepath.Join(t.TempDir(), "tls")
		if _, err := Init(dir, opt); err == nil {
			t.Errorf("%s: no error", name)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: directory created despite the error", name)
		}
	}
}

func TestCheckFindsProblems(t *testing.T) {
	now := time.Now()
	a, _ := initTemp(t, Options{NodeName: "a", Hosts: []string{"a.local"}})
	b, _ := initTemp(t, Options{NodeName: "b", Hosts: []string{"b.local"}})

	if _, err := Check(a.NodeCert, b.NodeKey, a.CACert, now); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatched key: %v", err)
	}
	if _, err := Check(a.NodeCert, a.NodeKey, b.CACert, now); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("other CA: %v", err)
	}
	if _, err := Check(a.NodeCert, a.NodeKey, a.NodeKey, now); err == nil {
		t.Fatal("CA file without a certificate accepted")
	}
	if _, err := Check(a.NodeCert, a.NodeKey, a.CACert, now.Add(DefaultCertValidity+time.Hour)); err == nil {
		t.Fatal("expired certificate accepted")
	}
	s, err := Check(a.NodeCert, a.NodeKey, a.CACert, now.Add(DefaultCertValidity-10*24*time.Hour))
	if err != nil || len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "expires in") {
		t.Fatalf("near expiry: %+v %v", s, err)
	}
	// Check must never need the CA key.
	if err := os.Remove(a.CAKey); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(a.NodeCert, a.NodeKey, a.CACert, now); err != nil {
		t.Fatalf("Check read the CA key: %v", err)
	}
}

func TestFrontDoorCanServeTheCertificate(t *testing.T) {
	f, _ := initTemp(t, Options{NodeName: "n", Hosts: []string{"127.0.0.1", "localhost"}})
	pair, err := tls.LoadX509KeyPair(f.NodeCert, f.NodeKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(f.CACert)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("handshake against the generated certificate: %v", err)
	}
	_ = conn.Close()
}

func TestCheckPairIgnoresTheIssuer(t *testing.T) {
	now := time.Now()
	a, _ := initTemp(t, Options{NodeName: "a", Hosts: []string{"a.local"}})
	b, _ := initTemp(t, Options{NodeName: "b", Hosts: []string{"b.local"}})
	// A Console certificate from another CA (the customer's) is fine.
	if s, err := CheckPair(a.NodeCert, a.NodeKey, now); err != nil || s.Issuer == "" {
		t.Fatalf("CheckPair: %+v %v", s, err)
	}
	if _, err := CheckPair(a.NodeCert, b.NodeKey, now); err == nil {
		t.Fatal("mismatched key accepted")
	}
	if _, err := CheckPair(a.NodeCert, a.NodeKey, now.Add(-time.Hour)); err == nil || !strings.Contains(err.Error(), "not valid until") {
		t.Fatalf("not yet valid: %v", err)
	}
	if _, err := CheckPair(a.NodeCert, a.NodeKey, now.Add(DefaultCertValidity+time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
}
