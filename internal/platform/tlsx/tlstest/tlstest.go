// Package tlstest creates throwaway certificate authorities and certificates
// for tests. Keys live in memory; they reach disk only when a test calls
// WriteCA or WritePair, and then only inside that test's temporary
// directory, for programs such as NGINX that read files.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// WriteCA writes the CA certificate (not its key) as PEM into dir and
// returns the file's path.
func (ca *CA) WriteCA(t testing.TB, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	writePEM(t, p, "CERTIFICATE", ca.Cert.Raw, 0o644)
	return p
}

// WritePair writes a certificate and its private key as PEM into dir and
// returns their paths. The key file is readable only by its owner.
func WritePair(t testing.TB, dir, name string, cert tls.Certificate) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	writePEM(t, certPath, "CERTIFICATE", cert.Certificate[0], 0o644)
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("tlstest: marshal key: %v", err)
	}
	writePEM(t, keyPath, "PRIVATE KEY", der, 0o600)
	return certPath, keyPath
}

func writePEM(t testing.TB, path, kind string, der []byte, mode os.FileMode) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("tlstest: write %s: %v", filepath.Base(path), err)
	}
}

// CA is an in-memory certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	Pool *x509.CertPool
}

// NewCA creates a self-signed CA valid for one day.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"ObserveX test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("tlstest: create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("tlstest: parse CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, Key: key, Pool: pool}
}

// Server issues a server certificate for the given DNS names and loopback IPs.
func (ca *CA) Server(t testing.TB, dnsNames ...string) tls.Certificate {
	t.Helper()
	return ca.issue(t, dnsNames[0], dnsNames, x509.ExtKeyUsageServerAuth)
}

// Client issues a client certificate with the given common name, such as an
// Agent or Gateway identity.
func (ca *CA) Client(t testing.TB, commonName string) tls.Certificate {
	t.Helper()
	return ca.issue(t, commonName, nil, x509.ExtKeyUsageClientAuth)
}

func (ca *CA) issue(t testing.TB, cn string, dnsNames []string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("tlstest: issue %s: %v", cn, err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tlstest: key: %v", err)
	}
	return key
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("tlstest: serial: %v", err)
	}
	return n
}
