package tlsx_test

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Voxmatic/observe/internal/platform/tlsx"
	"github.com/Voxmatic/observe/internal/platform/tlsx/tlstest"
)

const serverName = "node-1.observex.test"

type serverResult struct {
	err    error
	hello  *tls.ClientHelloInfo
	peerCN string
}

// handshake runs a TLS handshake over loopback TCP and returns the server's
// error, the client's error, and what the server saw from the client.
func handshake(t *testing.T, srvCfg, cliCfg *tls.Config) (srvErr, cliErr error, hello *tls.ClientHelloInfo, peerCN string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	results := make(chan serverResult, 1)
	go func() {
		var res serverResult
		defer func() { results <- res }()
		conn, err := ln.Accept()
		if err != nil {
			res.err = err
			return
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		cfg := srvCfg.Clone()
		base := srvCfg.Clone()
		cfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			res.hello = h
			return base, nil
		}
		srv := tls.Server(conn, cfg)
		defer srv.Close()
		if res.err = srv.Handshake(); res.err != nil {
			return
		}
		if st := srv.ConnectionState(); len(st.PeerCertificates) > 0 {
			res.peerCN = st.PeerCertificates[0].Subject.CommonName
		}
		buf := make([]byte, 1)
		_, res.err = srv.Read(buf)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	cli := tls.Client(conn, cliCfg)
	cliErr = cli.Handshake()
	if cliErr == nil {
		_, cliErr = cli.Write([]byte{1})
	}
	res := <-results
	_ = cli.Close()
	return res.err, cliErr, res.hello, res.peerCN
}

func setup(t *testing.T) (*tlstest.CA, *tls.Config, *tls.Config) {
	t.Helper()
	ca := tlstest.NewCA(t, "observex-test-ca")
	srv, err := tlsx.ServerConfig(ca.Server(t, serverName), ca.Pool)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := tlsx.ClientConfig(ca.Client(t, "agent-7f3a"), ca.Pool, serverName)
	if err != nil {
		t.Fatal(err)
	}
	return ca, srv, cli
}

func TestMutualTLSSucceeds(t *testing.T) {
	_, srv, cli := setup(t)
	srvErr, cliErr, hello, peer := handshake(t, srv, cli)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("handshake failed: server=%v client=%v", srvErr, cliErr)
	}
	if peer != "agent-7f3a" {
		t.Fatalf("server saw client %q, want agent-7f3a", peer)
	}
	if hello == nil || !slices.Contains(hello.SupportedVersions, tls.VersionTLS13) {
		t.Fatal("client did not offer TLS 1.3")
	}
}

func TestClientOffersHybridPostQuantum(t *testing.T) {
	_, srv, cli := setup(t)
	_, _, hello, _ := handshake(t, srv, cli)
	if hello == nil || len(hello.SupportedCurves) == 0 || hello.SupportedCurves[0] != tls.X25519MLKEM768 {
		t.Fatalf("client curves = %v, want X25519MLKEM768 first", hello.SupportedCurves)
	}
}

func TestHybridOnlyServerAcceptsObserveXClient(t *testing.T) {
	_, srv, cli := setup(t)
	pqOnly := srv.Clone()
	pqOnly.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	if srvErr, cliErr, _, _ := handshake(t, pqOnly, cli); srvErr != nil || cliErr != nil {
		t.Fatalf("hybrid-only handshake failed: server=%v client=%v", srvErr, cliErr)
	}
	// A classical-only client cannot reach a hybrid-only server, which shows
	// the successful handshake above really negotiated the hybrid group.
	classical := cli.Clone()
	classical.CurvePreferences = []tls.CurveID{tls.X25519}
	if srvErr, cliErr, _, _ := handshake(t, pqOnly, classical); srvErr == nil && cliErr == nil {
		t.Fatal("classical-only client connected to a hybrid-only server")
	}
}

func TestRejectsClientWithoutCertificate(t *testing.T) {
	ca, srv, _ := setup(t)
	noCert := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.Pool, ServerName: serverName}
	if srvErr, _, _, _ := handshake(t, srv, noCert); srvErr == nil {
		t.Fatal("server accepted a client with no certificate")
	}
}

func TestRejectsClientFromAnotherCA(t *testing.T) {
	ca, srv, _ := setup(t)
	rogue := tlstest.NewCA(t, "rogue-ca")
	cli, err := tlsx.ClientConfig(rogue.Client(t, "intruder"), ca.Pool, serverName)
	if err != nil {
		t.Fatal(err)
	}
	if srvErr, _, _, _ := handshake(t, srv, cli); srvErr == nil {
		t.Fatal("server accepted a client certificate from another CA")
	}
}

func TestClientRejectsServerFromAnotherCA(t *testing.T) {
	ca, _, cli := setup(t)
	rogue := tlstest.NewCA(t, "rogue-ca")
	srv, err := tlsx.ServerConfig(rogue.Server(t, serverName), ca.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, cliErr, _, _ := handshake(t, srv, cli); cliErr == nil {
		t.Fatal("client accepted a server certificate from another CA")
	}
}

func TestClientRejectsWrongServerName(t *testing.T) {
	ca, srv, _ := setup(t)
	cli, err := tlsx.ClientConfig(ca.Client(t, "agent"), ca.Pool, "other-node.observex.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, cliErr, _, _ := handshake(t, srv, cli); cliErr == nil {
		t.Fatal("client accepted a certificate for another host name")
	}
}

func TestRejectsTLS12(t *testing.T) {
	ca, srv, _ := setup(t)
	old := &tls.Config{
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{ca.Client(t, "old-agent")},
		RootCAs:      ca.Pool, ServerName: serverName,
	}
	if srvErr, cliErr, _, _ := handshake(t, srv, old); srvErr == nil && cliErr == nil {
		t.Fatal("TLS 1.2 connection accepted")
	}
}

func TestConfigBuildersValidateInput(t *testing.T) {
	ca := tlstest.NewCA(t, "ca")
	cert := ca.Client(t, "x")
	if _, err := tlsx.ServerConfig(tls.Certificate{}, ca.Pool); !errors.Is(err, tlsx.ErrNoCertificate) {
		t.Errorf("server without cert: %v", err)
	}
	if _, err := tlsx.ServerConfig(cert, nil); !errors.Is(err, tlsx.ErrNoPool) {
		t.Errorf("server without pool: %v", err)
	}
	if _, err := tlsx.ClientConfig(tls.Certificate{}, ca.Pool, "h"); !errors.Is(err, tlsx.ErrNoCertificate) {
		t.Errorf("client without cert: %v", err)
	}
	if _, err := tlsx.ClientConfig(cert, nil, "h"); !errors.Is(err, tlsx.ErrNoPool) {
		t.Errorf("client without pool: %v", err)
	}
	if _, err := tlsx.ClientConfig(cert, ca.Pool, ""); !errors.Is(err, tlsx.ErrNoServerName) {
		t.Errorf("client without server name: %v", err)
	}
}

func TestBuildersCopyCurveList(t *testing.T) {
	ca := tlstest.NewCA(t, "ca")
	cfg, err := tlsx.ServerConfig(ca.Server(t, "h"), ca.Pool)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CurvePreferences[0] = tls.CurveP521
	if tlsx.Curves[0] != tls.X25519MLKEM768 {
		t.Fatal("changing one config changed the package default")
	}
}

func TestLoadCertPoolAndKeyPairErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := tlsx.LoadCertPool(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("missing CA file accepted")
	}
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("no certs here"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsx.LoadCertPool(empty); err == nil {
		t.Error("CA file without certificates accepted")
	}
	if _, err := tlsx.LoadKeyPair(empty, empty); err == nil {
		t.Error("bad key pair accepted")
	}
}
