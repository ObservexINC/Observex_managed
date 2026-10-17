package frontdoor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/platform/tlsx/tlstest"
)

// These tests run a real NGINX with a rendered configuration, in front of
// fake upstreams written in Go, and talk to it over real TLS.

// portSource returns a function that hands out distinct free loopback
// addresses.
func portSource(t *testing.T) func() string {
	t.Helper()
	used := map[string]bool{}
	var mu sync.Mutex
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		for i := 0; i < 50; i++ {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			a := ln.Addr().String()
			_ = ln.Close()
			if !used[a] {
				used[a] = true
				return a
			}
		}
		t.Fatal("no free port")
		return ""
	}
}

type seenRequest struct {
	Proto  int
	Method string
	Path   string
	Header http.Header
	Body   int
}

// upstream is a fake Server, Gateway or Supervisor that records requests.
// It speaks HTTP/1.1 and cleartext HTTP/2, as NGINX's grpc_pass needs.
type upstream struct {
	srv  *http.Server
	mu   sync.Mutex
	seen []seenRequest
}

func startUpstream(t *testing.T, addr string, h http.HandlerFunc) *upstream {
	t.Helper()
	u := &upstream{}
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	u.srv = &http.Server{Protocols: &p, ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		u.mu.Lock()
		u.seen = append(u.seen, seenRequest{Proto: r.ProtoMajor, Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: int(n)})
		u.mu.Unlock()
		h(w, r)
	})}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = u.srv.Serve(ln) }()
	t.Cleanup(func() { _ = u.srv.Close() })
	return u
}

func (u *upstream) last(t *testing.T) seenRequest {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.seen) == 0 {
		t.Fatal("the upstream received nothing")
	}
	return u.seen[len(u.seen)-1]
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.seen)
}

func okJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func grpcOK(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/grpc" {
		okJSON(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte{0, 0, 0, 0, 0})
	w.Header().Set("Grpc-Status", "0")
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startNginx renders c, starts NGINX in the foreground and waits for its
// probe listener.
func startNginx(t *testing.T, nginx string, c Config) *syncBuf {
	t.Helper()
	f, err := Probe(context.Background(), nginx)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := Render(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		// As root, NGINX's workers run as an unprivileged user and must be
		// able to reach the run directory inside the test's private
		// temporary directory.
		for d := c.RunDir; d != "/" && d != os.TempDir(); d = filepath.Dir(d) {
			_ = os.Chmod(d, 0o755)
		}
	}
	path := filepath.Join(c.RunDir, "nginx.conf")
	if err := os.WriteFile(path, conf, 0o644); err != nil {
		t.Fatal(err)
	}
	out := &syncBuf{}
	cmd := exec.Command(nginx, Args(c.RunDir, path)...)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGQUIT)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get("http://" + c.ProbeListen + "/livez")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return out
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("NGINX did not start; output:\n%s", out.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// httpsClient talks to the Front Door over TLS, with HTTP/2 when the
// listener offers it.
func httpsClient(ca *tlstest.CA, cert *tls.Certificate, maxVersion uint16) *http.Client {
	cfg := &tls.Config{RootCAs: ca.Pool, ServerName: "node-1.observex.test", MinVersion: tls.VersionTLS12, MaxVersion: maxVersion}
	if cert != nil {
		// Send the certificate whatever CAs the server names, as an
		// attacker's client would; Go's default would hold back a
		// certificate from a CA the server did not name.
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: cfg, ForceAttemptHTTP2: true, Proxy: nil,
	}}
}

type reply struct {
	code   int
	proto  int
	header http.Header
	body   string
	err    error
}

func do(c *http.Client, method, url string, body []byte, hdr map[string]string) reply {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return reply{err: err}
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return reply{err: err}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return reply{code: resp.StatusCode, proto: resp.ProtoMajor, header: resp.Header, body: string(b)}
}

var grpcHeaders = map[string]string{"Content-Type": "application/grpc", "TE": "trailers"}

func TestFrontDoorOverTLS(t *testing.T) {
	nginx := nginxBinary(t)
	lf := newLiveFiles(t)
	c := liveConfig(t, lf, false, portSource(t))
	server := startUpstream(t, c.ServerAddr, okJSON)
	gateway := startUpstream(t, c.GatewayAddr, grpcOK)
	startUpstream(t, c.SupervisorAddr, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ready"}`)
	})
	logs := startNginx(t, nginx, c)

	agentCert := lf.ca.Client(t, "agent-1")
	otherCA := tlstest.NewCA(t, "someone else")
	foreignCert := otherCA.Client(t, "intruder")
	anon := httpsClient(lf.ca, nil, 0)
	agent := httpsClient(lf.ca, &agentCert, 0)
	foreign := httpsClient(lf.ca, &foreignCert, 0)
	console := "https://" + c.Console.Listen
	agents := "https://" + c.Agents.Listen

	t.Run("console forwards to the server and strips identity headers", func(t *testing.T) {
		r := do(anon, "GET", console+"/api/v1/problems", nil, map[string]string{
			HeaderClientVerify: "SUCCESS", HeaderClientDN: "CN=admin", HeaderClientCert: "forged"})
		if r.err != nil || r.code != 200 || r.body != `{"ok":true}` {
			t.Fatalf("reply = %+v", r)
		}
		got := server.last(t)
		if got.Header.Get(HeaderClientVerify) != "" || got.Header.Get(HeaderClientDN) != "" || got.Header.Get(HeaderClientCert) != "" {
			t.Fatalf("forged identity headers reached the server: %v", got.Header)
		}
		if got.Header.Get(HeaderRequestID) == "" || got.Header.Get(HeaderRequestID) != r.header.Get(HeaderRequestID) {
			t.Fatalf("request ID not passed through: upstream %q, client %q", got.Header.Get(HeaderRequestID), r.header.Get(HeaderRequestID))
		}
		if r.header.Get("Server") != "nginx" || r.header.Get("Strict-Transport-Security") == "" || r.header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("response headers = %v", r.header)
		}
	})

	t.Run("node health on both listeners", func(t *testing.T) {
		for _, base := range []string{console, agents} {
			if r := do(anon, "GET", base+"/node/health", nil, nil); r.code != 200 || r.body != `{"status":"ready"}` {
				t.Fatalf("%s: %+v", base, r)
			}
			if r := do(anon, "POST", base+"/node/health", nil, nil); r.code != 405 || !strings.Contains(r.body, "method not allowed") {
				t.Fatalf("%s POST: %+v", base, r)
			}
		}
	})

	t.Run("enroll works without a client certificate and cannot forge one", func(t *testing.T) {
		hdr := map[string]string{HeaderClientVerify: "SUCCESS", HeaderClientDN: "CN=admin", HeaderClientCert: "forged"}
		for k, v := range grpcHeaders {
			hdr[k] = v
		}
		r := do(anon, "POST", agents+"/observex.agent.v1.EnrollmentService/Enroll", []byte{0, 0, 0, 0, 0}, hdr)
		if r.err != nil || r.code != 200 || r.proto != 2 {
			t.Fatalf("reply = %+v", r)
		}
		got := gateway.last(t)
		if got.Proto != 2 || got.Path != "/observex.agent.v1.EnrollmentService/Enroll" {
			t.Fatalf("gateway saw %+v", got)
		}
		if got.Header.Get(HeaderClientVerify) != "NONE" || got.Header.Get(HeaderClientDN) != "" || got.Header.Get(HeaderClientCert) != "" {
			t.Fatalf("identity headers at the gateway: %v", got.Header)
		}
	})

	t.Run("every other gRPC method needs a certificate", func(t *testing.T) {
		for _, route := range grpcRoutes {
			if !route.NeedsClientCert {
				continue
			}
			before := gateway.count()
			r := do(anon, "POST", agents+route.Path, []byte{0, 0, 0, 0, 0}, grpcHeaders)
			if r.code != 403 || !strings.Contains(r.body, "client certificate required") || gateway.count() != before {
				t.Fatalf("%s without a certificate: %+v", route.Path, r)
			}
			r = do(agent, "POST", agents+route.Path, []byte{0, 0, 0, 0, 0}, grpcHeaders)
			if r.code != 200 {
				t.Fatalf("%s with a certificate: %+v", route.Path, r)
			}
			got := gateway.last(t)
			if got.Header.Get(HeaderClientVerify) != "SUCCESS" || !strings.Contains(got.Header.Get(HeaderClientDN), "CN=agent-1") || got.Header.Get(HeaderClientCert) == "" {
				t.Fatalf("%s: gateway headers %v", route.Path, got.Header)
			}
		}
	})

	t.Run("OTLP over HTTP needs a certificate", func(t *testing.T) {
		for _, route := range httpRoutes {
			if r := do(anon, "POST", agents+route.Path, []byte("{}"), nil); r.code != 403 {
				t.Fatalf("%s without a certificate: %+v", route.Path, r)
			}
			r := do(agent, "POST", agents+route.Path, []byte("{}"), map[string]string{"Content-Type": "application/json"})
			if r.code != 200 {
				t.Fatalf("%s: %+v", route.Path, r)
			}
			if got := gateway.last(t); got.Path != route.Path || got.Header.Get(HeaderClientVerify) != "SUCCESS" {
				t.Fatalf("%s: gateway saw %+v", route.Path, got)
			}
			if r := do(agent, "GET", agents+route.Path, nil, nil); r.code != 405 {
				t.Fatalf("GET %s: %+v", route.Path, r)
			}
		}
	})

	t.Run("a certificate from another CA is refused", func(t *testing.T) {
		before := gateway.count()
		r := do(foreign, "POST", agents+"/v1/metrics", []byte("{}"), nil)
		if r.code != 403 || !strings.Contains(r.body, "not accepted") || gateway.count() != before {
			t.Fatalf("reply = %+v", r)
		}
	})

	t.Run("limits and unknown paths", func(t *testing.T) {
		big := bytes.Repeat([]byte("x"), int(c.MaxBodyBytes)+1024)
		if r := do(agent, "POST", agents+"/v1/logs", big, nil); r.code != 413 || !strings.Contains(r.body, "too large") {
			t.Fatalf("large body: %+v", r)
		}
		if r := do(agent, "POST", agents+"/observex.ingest.v1.IngestService/Send", big, grpcHeaders); r.code != 413 {
			t.Fatalf("large gRPC body: %+v", r)
		}
		if r := do(agent, "GET", agents+"/admin", nil, nil); r.code != 404 || r.body != "{\"error\":\"not found\"}\n" {
			t.Fatalf("unknown path: %+v", r)
		}
		if r := do(agent, "POST", agents+"/observex.agent.v1.EnrollmentService/Unknown", nil, grpcHeaders); r.code != 404 {
			t.Fatalf("unknown gRPC method: %+v", r)
		}
	})

	t.Run("TLS 1.2 is refused on both listeners", func(t *testing.T) {
		old := httpsClient(lf.ca, &agentCert, tls.VersionTLS12)
		for _, base := range []string{console, agents} {
			if r := do(old, "GET", base+"/node/health", nil, nil); r.err == nil {
				t.Fatalf("%s accepted TLS 1.2: %+v", base, r)
			}
		}
	})

	t.Run("query strings never reach the log", func(t *testing.T) {
		const secret = "QUERYSECRET0123456789"
		_ = do(agent, "POST", agents+"/v1/traces?api_token="+secret, []byte("{}"), nil)
		_ = do(anon, "GET", console+"/api/x?password="+secret, nil, nil)
		_ = do(anon, "GET", agents+"/nope?token="+secret, nil, nil)
		out := logs.String()
		if strings.Contains(out, secret) {
			t.Fatalf("a query string reached NGINX's output:\n%s", out)
		}
		var line map[string]any
		found := false
		for _, l := range strings.Split(out, "\n") {
			if json.Unmarshal([]byte(l), &line) == nil && line["path"] == "/v1/traces" && line["listener"] == "agents" {
				found = line["client_verify"] == "SUCCESS"
			}
		}
		if !found {
			t.Fatalf("no JSON access-log line for /v1/traces with client_verify SUCCESS:\n%s", out)
		}
	})

	t.Run("a stopped upstream gives 503", func(t *testing.T) {
		_ = gateway.srv.Close()
		_ = server.srv.Close()
		if r := do(agent, "POST", agents+"/v1/metrics", []byte("{}"), nil); r.code != 503 || !strings.Contains(r.body, "service unavailable") {
			t.Fatalf("gateway down: %+v", r)
		}
		if r := do(agent, "POST", agents+"/observex.ingest.v1.IngestService/Send", []byte{0, 0, 0, 0, 0}, grpcHeaders); r.code != 503 {
			t.Fatalf("gateway down, gRPC: %+v", r)
		}
		if r := do(anon, "GET", console+"/", nil, nil); r.code != 503 {
			t.Fatalf("server down: %+v", r)
		}
	})
}

func TestFrontDoorPlaintext(t *testing.T) {
	nginx := nginxBinary(t)
	lf := newLiveFiles(t)
	c := liveConfig(t, lf, true, portSource(t))
	startUpstream(t, c.ServerAddr, okJSON)
	gateway := startUpstream(t, c.GatewayAddr, grpcOK)
	startNginx(t, nginx, c)
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}

	r := do(plain, "POST", "http://"+c.Agents.Listen+"/v1/metrics", []byte("{}"), map[string]string{HeaderClientVerify: "SUCCESS"})
	if r.err != nil || r.code != 200 {
		t.Fatalf("reply = %+v", r)
	}
	if got := gateway.last(t); got.Header.Get(HeaderClientVerify) != "NONE" {
		t.Fatalf("plaintext must say NONE, gateway saw %q", got.Header.Get(HeaderClientVerify))
	}
	if r := do(plain, "GET", "http://"+c.Console.Listen+"/api/x", nil, nil); r.code != 200 {
		t.Fatalf("console: %+v", r)
	}
	if r := do(plain, "GET", "http://"+c.Console.Listen+"/node/health", nil, nil); r.code != 503 {
		t.Fatalf("health with no supervisor: %+v", r)
	}
	var tlsErr error
	if _, tlsErr = httpsClient(lf.ca, nil, 0).Get("https://" + c.Console.Listen + "/"); tlsErr == nil {
		t.Fatal("plaintext listener answered TLS")
	}
	if errors.Is(tlsErr, context.DeadlineExceeded) {
		t.Fatalf("TLS attempt timed out instead of failing: %v", tlsErr)
	}
}
