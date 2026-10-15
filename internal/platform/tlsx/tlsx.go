// Package tlsx builds the TLS configuration every ObserveX connection uses and
// issues enrollment tokens for new Agents and Gateways.
//
// All connections are TLS 1.3 with mutual authentication. Key exchange prefers
// the hybrid post-quantum X25519MLKEM768 group and falls back to X25519 and
// P-256 for peers that do not support it. See
// docs/adr/0008-tls-identity-and-enrollment.md.
package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// MinVersion is the lowest TLS version ObserveX accepts.
const MinVersion = tls.VersionTLS13

// Curves lists key-exchange groups in order of preference.
var Curves = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}

var (
	// ErrNoCertificate is returned when a config is built without a certificate.
	ErrNoCertificate = errors.New("tlsx: a certificate is required")
	// ErrNoPool is returned when a config is built without trusted CAs.
	ErrNoPool = errors.New("tlsx: a pool of trusted CAs is required")
	// ErrNoServerName is returned when a client config has no server name.
	ErrNoServerName = errors.New("tlsx: a server name is required")
)

// ServerConfig returns a server configuration that requires and verifies a
// client certificate signed by one of clientCAs.
func ServerConfig(cert tls.Certificate, clientCAs *x509.CertPool) (*tls.Config, error) {
	if len(cert.Certificate) == 0 {
		return nil, ErrNoCertificate
	}
	if clientCAs == nil {
		return nil, ErrNoPool
	}
	return &tls.Config{
		MinVersion:       MinVersion,
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        clientCAs,
		CurvePreferences: append([]tls.CurveID(nil), Curves...),
	}, nil
}

// ClientConfig returns a client configuration that presents cert and verifies
// the server against rootCAs and serverName.
func ClientConfig(cert tls.Certificate, rootCAs *x509.CertPool, serverName string) (*tls.Config, error) {
	if len(cert.Certificate) == 0 {
		return nil, ErrNoCertificate
	}
	if rootCAs == nil {
		return nil, ErrNoPool
	}
	if serverName == "" {
		return nil, ErrNoServerName
	}
	return &tls.Config{
		MinVersion:       MinVersion,
		Certificates:     []tls.Certificate{cert},
		RootCAs:          rootCAs,
		ServerName:       serverName,
		CurvePreferences: append([]tls.CurveID(nil), Curves...),
	}, nil
}

// LoadKeyPair loads a PEM certificate chain and private key from disk.
func LoadKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tlsx: load key pair: %w", err)
	}
	return cert, nil
}

// LoadCertPool loads one or more PEM certificates into a new pool.
func LoadCertPool(pemFile string) (*x509.CertPool, error) {
	data, err := os.ReadFile(pemFile) // #nosec G304 -- path comes from the operator's configuration.
	if err != nil {
		return nil, fmt.Errorf("tlsx: read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("tlsx: no certificates found in %s", pemFile)
	}
	return pool, nil
}
