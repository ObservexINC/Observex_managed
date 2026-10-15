// Package tlstest creates throwaway certificate authorities and certificates
// for tests. Keys live only in memory and are never written to disk.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

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
