// Package frontdoor generates, checks and describes the managed node's NGINX
// Front Door configuration (OD-25 DEV-02; development plan G01).
//
// The Front Door is the only part of a node that listens on a non-loopback
// address. It has two listeners:
//
//   - Console: the Console, the public API and /node/health, forwarded to the
//     ObserveX Server. It never asks for a client certificate, so browsers
//     never prompt for one.
//   - Agents: Agent and Gateway traffic, forwarded to the Embedded Gateway:
//     OTLP over gRPC and HTTP, the ObserveX intake service and enrollment.
//     It asks for a client certificate from the cluster CA. Every route
//     except Enroll requires one; Enroll is how a host gets its certificate.
//
// The routes are fixed in this package, not configurable, so no setting can
// open a path that the product does not define. Every configurable value
// that reaches the file is validated, so no value can inject an NGINX
// directive.
//
// TLS is version 1.3 only. Key-exchange groups are chosen automatically:
// the hybrid post-quantum group X25519MLKEM768 first when the host's NGINX
// runs with OpenSSL 3.5 or later, then X25519 and P-256. The groups in use
// are reported (EffectiveGroups) rather than chosen silently; a group the
// host cannot offer is refused at Render.
//
// The Front Door passes the result of client certificate verification to
// the Gateway in X-ObserveX-Client-* headers. It always sets those headers
// itself, so a client cannot supply them.
//
// Logging: one JSON access-log line per request, with the path but no query
// string and no headers. The error log keeps only critical messages,
// because NGINX writes the request line, query string included, into its
// error-level messages (Astra's M1 finding 002).
//
// Ported in part from the M1/M2 Front Door of the earlier ObserveX codebase
// (Voxmatic/observex, internal/node/frontdoor at a23009a); TLS, the Agents
// listener and gRPC routes are new.
package frontdoor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Header names the Front Door sets towards the Gateway.
const (
	HeaderClientVerify = "X-ObserveX-Client-Verify" // SUCCESS, NONE or FAILED:<reason>
	HeaderClientDN     = "X-ObserveX-Client-DN"     // subject DN of the client certificate
	HeaderClientCert   = "X-ObserveX-Client-Cert"   // URL-escaped PEM of the client certificate
	HeaderRequestID    = "X-Request-ID"
)

// Group names, as OpenSSL spells them.
const (
	GroupHybridPQ = "X25519MLKEM768"
	GroupX25519   = "X25519"
	GroupP256     = "prime256v1"
	GroupP384     = "secp384r1"
)

var knownGroups = map[string]bool{GroupHybridPQ: true, GroupX25519: true, GroupP256: true, GroupP384: true}

// Listener is one of the Front Door's public listeners.
type Listener struct {
	// Listen is host:port, for example "0.0.0.0:443".
	Listen string `json:"listen"`
	// CertFile and KeyFile are the server certificate and key (PEM).
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	// ClientCAFile is the CA that issues Agent and Gateway certificates.
	// Required on the Agents listener, not allowed on the Console listener.
	ClientCAFile string `json:"client_ca_file,omitempty"`
	// Groups are the key-exchange groups in order of preference. Empty
	// chooses automatically.
	Groups []string `json:"groups,omitempty"`
}

// Config is what the configuration is generated from.
type Config struct {
	Console Listener `json:"console"`
	Agents  Listener `json:"agents"`
	// ProbeListen is a loopback address that answers the supervisor's
	// liveness probe (/livez).
	ProbeListen string `json:"probe_listen"`
	// Upstreams, all on loopback.
	ServerAddr     string `json:"server_addr"`
	GatewayAddr    string `json:"gateway_addr"`
	SupervisorAddr string `json:"supervisor_addr"`

	MaxBodyBytes      int64 `json:"max_body_bytes"`
	WorkerProcesses   int   `json:"worker_processes"`
	WorkerConnections int   `json:"worker_connections"`
	// RunDir is an absolute directory for the pid file and NGINX's
	// temporary files.
	RunDir string `json:"run_dir"`
	// Plaintext turns TLS off on both listeners. It is for development on a
	// trusted machine only; without TLS no client certificate can be
	// checked, so the Agents listener cannot require one.
	Plaintext bool `json:"plaintext,omitempty"`
}

var (
	hostRE = regexp.MustCompile(`^[A-Za-z0-9.-]+$|^\[[0-9A-Fa-f:.]+\]$`)
	pathRE = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

// Validate checks every value that goes into the file.
func (c Config) Validate() error {
	addrs := []struct{ name, addr string }{
		{"console.listen", c.Console.Listen}, {"agents.listen", c.Agents.Listen},
		{"probe_listen", c.ProbeListen}, {"server_addr", c.ServerAddr},
		{"gateway_addr", c.GatewayAddr}, {"supervisor_addr", c.SupervisorAddr},
	}
	seen := map[string]string{}
	for _, a := range addrs {
		if err := checkAddr(a.addr); err != nil {
			return fmt.Errorf("frontdoor: %s: %w", a.name, err)
		}
		if prev, dup := seen[a.addr]; dup {
			return fmt.Errorf("frontdoor: %s and %s are both %s", prev, a.name, a.addr)
		}
		seen[a.addr] = a.name
	}
	for _, a := range addrs[2:] {
		if !isLoopback(a.addr) {
			return fmt.Errorf("frontdoor: %s must be a loopback address", a.name)
		}
	}
	// Two addresses on one port collide when they share a host or either is
	// a wildcard (0.0.0.0 also binds loopback).
	for i := range addrs {
		for j := i + 1; j < len(addrs); j++ {
			_, pi, _ := net.SplitHostPort(addrs[i].addr)
			_, pj, _ := net.SplitHostPort(addrs[j].addr)
			if pi == pj && sameHostClass(addrs[i].addr, addrs[j].addr) {
				return fmt.Errorf("frontdoor: %s and %s would both bind port %s", addrs[i].name, addrs[j].name, pi)
			}
		}
	}
	if c.Plaintext {
		for _, l := range []Listener{c.Console, c.Agents} {
			if l.CertFile != "" || l.KeyFile != "" || l.ClientCAFile != "" || len(l.Groups) > 0 {
				return errors.New("frontdoor: plaintext is set, so no TLS settings are allowed")
			}
		}
	} else {
		if err := c.Console.validateTLS("console", false); err != nil {
			return err
		}
		if err := c.Agents.validateTLS("agents", true); err != nil {
			return err
		}
	}
	if c.MaxBodyBytes <= 0 || c.MaxBodyBytes > 1<<30 {
		return errors.New("frontdoor: max_body_bytes must be between 1 and 1 GiB")
	}
	if c.WorkerProcesses < 1 || c.WorkerProcesses > 64 {
		return errors.New("frontdoor: worker_processes must be between 1 and 64")
	}
	if c.WorkerConnections < 64 || c.WorkerConnections > 65536 {
		return errors.New("frontdoor: worker_connections must be between 64 and 65536")
	}
	if err := checkPath(c.RunDir); err != nil {
		return fmt.Errorf("frontdoor: run_dir: %w", err)
	}
	return nil
}

func (l Listener) validateTLS(name string, agents bool) error {
	for _, f := range []struct{ field, path string }{{"cert_file", l.CertFile}, {"key_file", l.KeyFile}} {
		if err := checkPath(f.path); err != nil {
			return fmt.Errorf("frontdoor: %s.%s: %w", name, f.field, err)
		}
	}
	switch {
	case agents:
		if err := checkPath(l.ClientCAFile); err != nil {
			return fmt.Errorf("frontdoor: agents.client_ca_file: %w", err)
		}
	case l.ClientCAFile != "":
		return errors.New("frontdoor: console.client_ca_file is not allowed; the Console listener never asks for client certificates")
	}
	seen := map[string]bool{}
	for _, g := range l.Groups {
		if !knownGroups[g] {
			return fmt.Errorf("frontdoor: %s.groups: %q is not a supported group", name, g)
		}
		if seen[g] {
			return fmt.Errorf("frontdoor: %s.groups: %q appears twice", name, g)
		}
		seen[g] = true
	}
	return nil
}

func checkAddr(a string) error {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return errors.New("must be host:port")
	}
	if !hostRE.MatchString(host) && !hostRE.MatchString("["+host+"]") {
		return fmt.Errorf("host %q is not allowed", host)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("port %q is not valid", port)
	}
	return nil
}

func checkPath(p string) error {
	if p == "" {
		return errors.New("is required")
	}
	if !pathRE.MatchString(p) || strings.Contains(p, "..") || strings.Contains(p, "//") {
		return fmt.Errorf("%q must be an absolute path of letters, digits, '.', '_', '-' and '/'", p)
	}
	return nil
}

func isLoopback(a string) bool {
	host, _, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sameHostClass reports whether two listen addresses could collide on one
// port: the same host, or either one a wildcard.
func sameHostClass(a, b string) bool {
	ha, _, _ := net.SplitHostPort(a)
	hb, _, _ := net.SplitHostPort(b)
	wild := func(h string) bool { return h == "0.0.0.0" || h == "::" || h == "" }
	return ha == hb || wild(ha) || wild(hb)
}

// EffectiveGroups returns the key-exchange groups a listener will offer on
// a host with these features.
func EffectiveGroups(l Listener, f Features) ([]string, error) {
	if len(l.Groups) == 0 {
		if f.HybridPQ {
			return []string{GroupHybridPQ, GroupX25519, GroupP256}, nil
		}
		return []string{GroupX25519, GroupP256}, nil
	}
	for _, g := range l.Groups {
		if g == GroupHybridPQ && !f.HybridPQ {
			return nil, fmt.Errorf("frontdoor: group %s needs NGINX with OpenSSL 3.5 or later; this NGINX runs with %q", GroupHybridPQ, f.TLSLibrary)
		}
	}
	return append([]string(nil), l.Groups...), nil
}

// Render returns the NGINX configuration for a host with these features.
func Render(c Config, f Features) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	d := tmplData{Config: c, HTTP2Directive: f.HTTP2Directive, TLS: !c.Plaintext, GRPCRoutes: grpcRoutes, HTTPRoutes: httpRoutes}
	if d.TLS {
		if f.TLSLibrary == "" {
			return nil, errors.New("frontdoor: this NGINX has no TLS library; TLS is required unless plaintext is set")
		}
		cg, err := EffectiveGroups(c.Console, f)
		if err != nil {
			return nil, err
		}
		ag, err := EffectiveGroups(c.Agents, f)
		if err != nil {
			return nil, err
		}
		d.ConsoleGroups, d.AgentsGroups = strings.Join(cg, ":"), strings.Join(ag, ":")
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, d); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Check runs "nginx -t" on a configuration file and returns NGINX's output
// on failure. prefix is the NGINX prefix directory (the run directory).
func Check(ctx context.Context, nginx, prefix, confPath string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, nginx, CheckArgs(prefix, confPath)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("frontdoor: nginx -t failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// CheckArgs is NGINX's command line for testing a configuration.
func CheckArgs(prefix, confPath string) []string {
	return []string{"-t", "-q", "-e", "stderr", "-p", prefix, "-c", confPath}
}

// Args is NGINX's command line for running a configuration in the
// foreground (the configuration sets "daemon off").
func Args(prefix, confPath string) []string {
	return []string{"-e", "stderr", "-p", prefix, "-c", confPath}
}
