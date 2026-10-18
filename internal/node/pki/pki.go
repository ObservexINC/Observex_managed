// Package pki creates and checks the TLS files a managed node needs on
// first install (development plan G01; ADR 0010):
//
//   - a cluster CA, which signs Agent and Gateway client certificates and
//     the nodes' server certificates;
//   - the node's server certificate for the Front Door.
//
// This is interim. Until G04 moves the cluster CA into the
// ConfigurationStore, protected by the customer's KMS or HSM, the CA key is
// a file readable only by root on the first node. A customer can instead
// supply its own certificates and skip Init entirely.
//
// Init never overwrites an existing file, so running it twice cannot
// replace a key that is in use.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 is what RFC 5280 uses for key identifiers, not for signatures
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// File names inside the TLS directory. The Front Door configuration uses
// the same names (frontdoor package tests).
const (
	CACertName   = "cluster-ca.crt"
	CAKeyName    = "cluster-ca.key"
	NodeCertName = "node.crt"
	NodeKeyName  = "node.key"
)

// File modes. The node key is group-readable so the service group can read
// it; the CA key is readable by its owner (root) only.
const (
	CertMode    os.FileMode = 0o644
	CAKeyMode   os.FileMode = 0o600
	NodeKeyMode os.FileMode = 0o640
	DirMode     os.FileMode = 0o750
)

// Validity periods.
const (
	DefaultCAValidity   = 10 * 365 * 24 * time.Hour
	DefaultCertValidity = 397 * 24 * time.Hour // the longest browsers accept
	// RenewWithin is when Check starts warning about expiry.
	RenewWithin = 30 * 24 * time.Hour
)

// ErrExists is returned by Init when any of its files already exists.
var ErrExists = errors.New("pki: TLS files already exist; refusing to overwrite them")

// Files are the paths of a node's TLS files.
type Files struct {
	Dir      string `json:"dir"`
	CACert   string `json:"ca_cert"`
	CAKey    string `json:"ca_key"`
	NodeCert string `json:"node_cert"`
	NodeKey  string `json:"node_key"`
}

// Paths returns the file paths inside dir, a directory on the host that
// runs this code. Init uses it to write the files.
func Paths(dir string) Files {
	return Files{
		Dir:      dir,
		CACert:   filepath.Join(dir, CACertName),
		CAKey:    filepath.Join(dir, CAKeyName),
		NodeCert: filepath.Join(dir, NodeCertName),
		NodeKey:  filepath.Join(dir, NodeKeyName),
	}
}

// NodePaths returns the file paths inside dir as they appear in a node
// configuration. Managed nodes run on Linux, so configuration paths are
// slash-separated whatever system reads or checks the configuration; host
// paths from Paths would turn them into backslash paths on Windows.
func NodePaths(dir string) Files {
	return Files{
		Dir:      dir,
		CACert:   path.Join(dir, CACertName),
		CAKey:    path.Join(dir, CAKeyName),
		NodeCert: path.Join(dir, NodeCertName),
		NodeKey:  path.Join(dir, NodeKeyName),
	}
}

// Options control Init.
type Options struct {
	// NodeName is the node certificate's common name, usually the node ID.
	NodeName string
	// Hosts are the DNS names and IP addresses users, Agents and other
	// nodes use to reach this node. At least one is required.
	Hosts        []string
	CAValidity   time.Duration
	CertValidity time.Duration
	Now          func() time.Time
}

var dnsRE = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

func splitHosts(hosts []string) (dns []string, ips []net.IP, err error) {
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" || seen[strings.ToLower(h)] {
			continue
		}
		seen[strings.ToLower(h)] = true
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if len(h) > 253 || !dnsRE.MatchString(h) {
			return nil, nil, fmt.Errorf("pki: %q is neither an IP address nor a valid host name", h)
		}
		dns = append(dns, strings.ToLower(h))
	}
	if len(dns)+len(ips) == 0 {
		return nil, nil, errors.New("pki: at least one host name or IP address is required")
	}
	return dns, ips, nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func keyID(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(der) //nolint:gosec // key identifier, see import comment
	return sum[:], nil
}

type material struct {
	caCert, caKey, nodeCert, nodeKey []byte
}

func generate(opt Options) (material, error) {
	var m material
	if strings.TrimSpace(opt.NodeName) == "" {
		return m, errors.New("pki: node name is required")
	}
	dns, ips, err := splitHosts(opt.Hosts)
	if err != nil {
		return m, err
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	t0 := now().UTC().Add(-5 * time.Minute) // tolerate small clock differences between hosts
	if opt.CAValidity <= 0 {
		opt.CAValidity = DefaultCAValidity
	}
	if opt.CertValidity <= 0 {
		opt.CertValidity = DefaultCertValidity
	}
	if opt.CertValidity > opt.CAValidity {
		return m, errors.New("pki: the node certificate cannot outlive the CA")
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return m, err
	}
	caSerial, err := serial()
	if err != nil {
		return m, err
	}
	caSKI, err := keyID(&caKey.PublicKey)
	if err != nil {
		return m, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			Organization: []string{"ObserveX Managed"},
			CommonName:   "ObserveX cluster CA " + hex.EncodeToString(caSKI[:4]),
		},
		NotBefore:             t0,
		NotAfter:              t0.Add(opt.CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          caSKI,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return m, fmt.Errorf("pki: create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return m, err
	}

	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return m, err
	}
	nodeSerial, err := serial()
	if err != nil {
		return m, err
	}
	nodeSKI, err := keyID(&nodeKey.PublicKey)
	if err != nil {
		return m, err
	}
	nodeTmpl := &x509.Certificate{
		SerialNumber:   nodeSerial,
		Subject:        pkix.Name{Organization: []string{"ObserveX Managed"}, CommonName: opt.NodeName},
		NotBefore:      t0,
		NotAfter:       t0.Add(opt.CertValidity),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:       dns,
		IPAddresses:    ips,
		SubjectKeyId:   nodeSKI,
		AuthorityKeyId: caSKI,
	}
	nodeDER, err := x509.CreateCertificate(rand.Reader, nodeTmpl, caCert, &nodeKey.PublicKey, caKey)
	if err != nil {
		return m, fmt.Errorf("pki: create node certificate: %w", err)
	}

	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return m, err
	}
	nodeKeyDER, err := x509.MarshalPKCS8PrivateKey(nodeKey)
	if err != nil {
		return m, err
	}
	m.caCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	m.caKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER})
	m.nodeCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nodeDER})
	m.nodeKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nodeKeyDER})
	return m, nil
}

// Init creates the cluster CA and the node certificate in dir. It refuses
// to run when any of the four files exists. On a failed write it removes
// the files it created, so no half-written set is left behind.
func Init(dir string, opt Options) (Files, error) {
	f := Paths(dir)
	for _, p := range []string{f.CACert, f.CAKey, f.NodeCert, f.NodeKey} {
		if _, err := os.Lstat(p); err == nil {
			return Files{}, ErrExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return Files{}, fmt.Errorf("pki: %w", err)
		}
	}
	m, err := generate(opt)
	if err != nil {
		return Files{}, err
	}
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return Files{}, fmt.Errorf("pki: create %s: %w", dir, err)
	}
	var written []string
	for _, w := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{f.CAKey, m.caKey, CAKeyMode},
		{f.NodeKey, m.nodeKey, NodeKeyMode},
		{f.CACert, m.caCert, CertMode},
		{f.NodeCert, m.nodeCert, CertMode},
	} {
		if err := writeNew(w.path, w.data, w.mode); err != nil {
			for _, p := range written {
				_ = os.Remove(p)
			}
			return Files{}, err
		}
		written = append(written, w.path)
	}
	return f, nil
}

// writeNew creates a file that must not exist yet, with an exact mode
// (independent of the umask).
func writeNew(path string, data []byte, mode os.FileMode) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- a fixed name inside the TLS directory the administrator chose
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return fmt.Errorf("pki: create %s: %w", filepath.Base(path), err)
	}
	if err := fh.Chmod(mode); err != nil {
		_ = fh.Close()
		_ = os.Remove(path)
		return fmt.Errorf("pki: set mode of %s: %w", filepath.Base(path), err)
	}
	if _, err := fh.Write(data); err != nil {
		_ = fh.Close()
		_ = os.Remove(path)
		return fmt.Errorf("pki: write %s: %w", filepath.Base(path), err)
	}
	if err := fh.Sync(); err != nil {
		_ = fh.Close()
		_ = os.Remove(path)
		return fmt.Errorf("pki: sync %s: %w", filepath.Base(path), err)
	}
	return fh.Close()
}

// Summary describes a node certificate.
type Summary struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dns_names,omitempty"`
	IPs       []string  `json:"ip_addresses,omitempty"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// Warnings are problems that do not stop the node yet, such as an
	// expiry within RenewWithin.
	Warnings []string `json:"warnings,omitempty"`
}

// CheckPair verifies that a certificate and key belong together, that the
// certificate is valid now and names at least one host, and warns when it
// expires within RenewWithin. It does not check who issued it: the Console
// listener may use a certificate from the customer's own CA.
func CheckPair(certFile, keyFile string, now time.Time) (Summary, error) {
	s, _, err := loadPair(certFile, keyFile)
	if err != nil {
		return Summary{}, err
	}
	return s, s.validAt(now)
}

// Check does what CheckPair does and also verifies that the certificate
// chains to the CA certificate in caFile for server authentication. It
// never reads the CA key.
func Check(certFile, keyFile, caFile string, now time.Time) (Summary, error) {
	s, pair, err := loadPair(certFile, keyFile)
	if err != nil {
		return Summary{}, err
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 -- the configured CA certificate
	if err != nil {
		return s, fmt.Errorf("pki: read CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return s, errors.New("pki: the CA file holds no certificate")
	}
	inter := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	if _, err := pair.Leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return s, fmt.Errorf("pki: the node certificate does not verify against the CA: %w", err)
	}
	return s, s.validAt(now)
}

func loadPair(certFile, keyFile string) (Summary, tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return Summary{}, pair, errors.New("pki: the certificate and key cannot be loaded or do not match")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return Summary{}, pair, fmt.Errorf("pki: certificate: %w", err)
	}
	pair.Leaf = leaf
	s := Summary{
		Subject:   leaf.Subject.String(),
		Issuer:    leaf.Issuer.String(),
		DNSNames:  append([]string(nil), leaf.DNSNames...),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}
	for _, ip := range leaf.IPAddresses {
		s.IPs = append(s.IPs, ip.String())
	}
	return s, pair, nil
}

// validAt checks the validity window and names, and adds expiry warnings.
func (s *Summary) validAt(now time.Time) error {
	if now.Before(s.NotBefore) {
		return fmt.Errorf("pki: the certificate is not valid until %s", s.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(s.NotAfter) {
		return fmt.Errorf("pki: the certificate expired on %s", s.NotAfter.Format(time.RFC3339))
	}
	if len(s.DNSNames)+len(s.IPs) == 0 {
		return errors.New("pki: the certificate names no host (no subject alternative names)")
	}
	if left := s.NotAfter.Sub(now); left < RenewWithin {
		s.Warnings = append(s.Warnings, fmt.Sprintf("the certificate expires in %d days (%s)", int(left.Hours()/24), s.NotAfter.Format(time.DateOnly)))
	}
	return nil
}
