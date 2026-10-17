package frontdoor

import (
	"bytes"
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/tlsx/tlstest"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// Features of NGINX builds the goldens cover.
var (
	nginx124 = Features{Version: "1.24.0", TLSLibrary: "OpenSSL 3.0.13", HTTP2Directive: false, HybridPQ: false}
	nginx129 = Features{Version: "1.29.1", TLSLibrary: "OpenSSL 3.5.1", HTTP2Directive: true, HybridPQ: true}
)

// goldenConfig uses fixed paths so the rendered file is stable.
func goldenConfig(plaintext bool) Config {
	c := Config{
		Console:           Listener{Listen: "0.0.0.0:443", CertFile: "/etc/observex/tls/node.crt", KeyFile: "/etc/observex/tls/node.key"},
		Agents:            Listener{Listen: "0.0.0.0:9443", CertFile: "/etc/observex/tls/node.crt", KeyFile: "/etc/observex/tls/node.key", ClientCAFile: "/etc/observex/tls/cluster-ca.crt"},
		ProbeListen:       "127.0.0.1:8181",
		ServerAddr:        "127.0.0.1:8182",
		GatewayAddr:       "127.0.0.1:8183",
		SupervisorAddr:    "127.0.0.1:8180",
		MaxBodyBytes:      16 << 20,
		WorkerProcesses:   2,
		WorkerConnections: 4096,
		RunDir:            "/run/observex/frontdoor",
	}
	if plaintext {
		c.Plaintext = true
		c.Console = Listener{Listen: "0.0.0.0:8080"}
		c.Agents = Listener{Listen: "0.0.0.0:8443"}
	}
	return c
}

func TestParseFeatures(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want Features
	}{
		{"ubuntu 24.04", "nginx version: nginx/1.24.0 (Ubuntu)\nbuilt with OpenSSL 3.0.13 30 Jan 2024\nTLS SNI support enabled\nconfigure arguments: --with-http_ssl_module",
			Features{Version: "1.24.0", TLSLibrary: "OpenSSL 3.0.13", HTTP2Directive: false, HybridPQ: false}},
		{"running with a newer library", "nginx version: nginx/1.27.2\nbuilt with OpenSSL 3.3.2 3 Sep 2024 (running with OpenSSL 3.5.0 8 Apr 2025)\n",
			Features{Version: "1.27.2", TLSLibrary: "OpenSSL 3.5.0", HTTP2Directive: true, HybridPQ: true}},
		{"exactly 1.25.1", "nginx version: nginx/1.25.1\nbuilt with OpenSSL 3.5.2 5 Aug 2025\n",
			Features{Version: "1.25.1", TLSLibrary: "OpenSSL 3.5.2", HTTP2Directive: true, HybridPQ: true}},
		{"1.25.0", "nginx version: nginx/1.25.0\nbuilt with OpenSSL 3.4.0\n",
			Features{Version: "1.25.0", TLSLibrary: "OpenSSL 3.4.0", HTTP2Directive: false, HybridPQ: false}},
		{"openssl 4", "nginx version: nginx/2.0.0\nbuilt with OpenSSL 4.0.0\n",
			Features{Version: "2.0.0", TLSLibrary: "OpenSSL 4.0.0", HTTP2Directive: true, HybridPQ: true}},
		{"libressl", "nginx version: nginx/1.26.2\nbuilt with LibreSSL 3.9.2\n",
			Features{Version: "1.26.2", TLSLibrary: "LibreSSL 3.9.2", HTTP2Directive: true, HybridPQ: false}},
		{"no tls", "nginx version: nginx/1.24.0\nconfigure arguments: --without-http_ssl_module\n",
			Features{Version: "1.24.0", HTTP2Directive: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseFeatures(tc.out)
			if err != nil || got != tc.want {
				t.Fatalf("ParseFeatures = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
	if _, err := ParseFeatures("command not found"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestValidateAcceptsGoldenConfigs(t *testing.T) {
	for _, plain := range []bool{false, true} {
		if err := goldenConfig(plain).Validate(); err != nil {
			t.Fatalf("plaintext=%v: %v", plain, err)
		}
	}
	c := goldenConfig(false)
	c.Console.Listen, c.Agents.Listen = "[::]:443", "[::]:9443"
	c.ProbeListen = "[::1]:8181"
	if err := c.Validate(); err != nil {
		t.Fatalf("IPv6: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"directive injection in listen", func(c *Config) { c.Console.Listen = "0.0.0.0:443; include /etc/passwd" }, "console.listen"},
		{"bad port", func(c *Config) { c.Agents.Listen = "0.0.0.0:99999" }, "port"},
		{"missing port", func(c *Config) { c.ProbeListen = "127.0.0.1" }, "host:port"},
		{"host with brace", func(c *Config) { c.ServerAddr = "a}b:80" }, "not allowed"},
		{"upstream not on loopback", func(c *Config) { c.GatewayAddr = "10.0.0.5:8183" }, "gateway_addr must be a loopback"},
		{"probe not on loopback", func(c *Config) { c.ProbeListen = "0.0.0.0:8181" }, "probe_listen must be a loopback"},
		{"same address twice", func(c *Config) { c.GatewayAddr = c.ServerAddr }, "are both"},
		{"same port as a wildcard listener", func(c *Config) { c.ServerAddr = "127.0.0.1:443" }, "would both bind port 443"},
		{"listeners on one port", func(c *Config) { c.Agents.Listen = "10.0.0.1:443" }, "would both bind port 443"},
		{"path with space", func(c *Config) { c.RunDir = "/run/observex/front door" }, "run_dir"},
		{"path injection", func(c *Config) { c.Console.CertFile = "/etc/x.crt;\n    include /etc/passwd" }, "console.cert_file"},
		{"relative path", func(c *Config) { c.Agents.KeyFile = "tls/node.key" }, "agents.key_file"},
		{"dot dot", func(c *Config) { c.Agents.ClientCAFile = "/etc/observex/../shadow" }, "agents.client_ca_file"},
		{"missing client CA", func(c *Config) { c.Agents.ClientCAFile = "" }, "agents.client_ca_file"},
		{"client CA on console", func(c *Config) { c.Console.ClientCAFile = "/etc/observex/tls/cluster-ca.crt" }, "console.client_ca_file is not allowed"},
		{"unknown group", func(c *Config) { c.Console.Groups = []string{"X25519", "ffdhe2048"} }, "not a supported group"},
		{"group injection", func(c *Config) { c.Agents.Groups = []string{"X25519;"} }, "not a supported group"},
		{"duplicate group", func(c *Config) { c.Agents.Groups = []string{"X25519", "X25519"} }, "twice"},
		{"zero body limit", func(c *Config) { c.MaxBodyBytes = 0 }, "max_body_bytes"},
		{"huge body limit", func(c *Config) { c.MaxBodyBytes = 2 << 30 }, "max_body_bytes"},
		{"no workers", func(c *Config) { c.WorkerProcesses = 0 }, "worker_processes"},
		{"few connections", func(c *Config) { c.WorkerConnections = 10 }, "worker_connections"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := goldenConfig(false)
			tc.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want an error containing %q", err, tc.want)
			}
			if _, rerr := Render(c, nginx124); rerr == nil {
				t.Fatal("Render accepted an invalid configuration")
			}
		})
	}
	t.Run("TLS settings with plaintext", func(t *testing.T) {
		c := goldenConfig(true)
		c.Agents.ClientCAFile = "/etc/observex/tls/cluster-ca.crt"
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "plaintext") {
			t.Fatalf("Validate = %v", err)
		}
	})
}

func TestEffectiveGroups(t *testing.T) {
	auto := Listener{}
	if g, _ := EffectiveGroups(auto, nginx124); strings.Join(g, ":") != "X25519:prime256v1" {
		t.Fatalf("auto on OpenSSL 3.0 = %v", g)
	}
	if g, _ := EffectiveGroups(auto, nginx129); strings.Join(g, ":") != "X25519MLKEM768:X25519:prime256v1" {
		t.Fatalf("auto on OpenSSL 3.5 = %v", g)
	}
	pq := Listener{Groups: []string{GroupHybridPQ, GroupX25519}}
	if _, err := EffectiveGroups(pq, nginx124); err == nil || !strings.Contains(err.Error(), "OpenSSL 3.5") {
		t.Fatalf("hybrid group on OpenSSL 3.0: %v", err)
	}
	if g, err := EffectiveGroups(pq, nginx129); err != nil || strings.Join(g, ":") != "X25519MLKEM768:X25519" {
		t.Fatalf("explicit groups = %v, %v", g, err)
	}
	c := goldenConfig(false)
	c.Agents.Groups = pq.Groups
	if _, err := Render(c, nginx124); err == nil {
		t.Fatal("Render accepted a group this NGINX cannot offer")
	}
	if _, err := Render(goldenConfig(false), Features{Version: "1.24.0"}); err == nil || !strings.Contains(err.Error(), "no TLS library") {
		t.Fatalf("Render without TLS library: %v", err)
	}
	if _, err := Render(goldenConfig(true), Features{Version: "1.24.0"}); err != nil {
		t.Fatalf("plaintext needs no TLS library: %v", err)
	}
}

func TestRenderGolden(t *testing.T) {
	cases := []struct {
		file     string
		features Features
		plain    bool
	}{
		{"tls-nginx1.24-openssl3.0.conf", nginx124, false},
		{"tls-nginx1.29-openssl3.5.conf", nginx129, false},
		{"plaintext-nginx1.24.conf", nginx124, true},
		{"plaintext-nginx1.29.conf", nginx129, true},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			got, err := Render(goldenConfig(tc.plain), tc.features)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", tc.file)
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("rendered configuration differs from %s; run go test -run TestRenderGolden -update and review the diff", path)
			}
		})
	}
}

func TestRenderedProperties(t *testing.T) {
	tlsConf, _ := Render(goldenConfig(false), nginx124)
	pqConf, _ := Render(goldenConfig(false), nginx129)
	plainConf, _ := Render(goldenConfig(true), nginx124)
	s, pq, plain := string(tlsConf), string(pqConf), string(plainConf)

	mustContain := func(name, conf string, parts ...string) {
		t.Helper()
		for _, p := range parts {
			if !strings.Contains(conf, p) {
				t.Fatalf("%s lacks %q", name, p)
			}
		}
	}
	mustNotContain := func(name, conf string, parts ...string) {
		t.Helper()
		for _, p := range parts {
			if strings.Contains(conf, p) {
				t.Fatalf("%s contains %q", name, p)
			}
		}
	}
	mustContain("tls", s, "ssl_protocols TLSv1.3;", "server_tokens off;", "error_log stderr crit;", "daemon off;",
		"ssl_verify_client optional;", "ssl_ecdh_curve X25519:prime256v1;", "listen 0.0.0.0:9443 ssl http2;",
		`"path":"$uri"`, "Strict-Transport-Security", "error_page 495 = @bad_certificate;")
	mustNotContain("tls", s, "$request_uri", "$args", "$query_string", "$http_authorization", "TLSv1.2", "http2 on;")
	mustContain("pq", pq, "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;", "http2 on;", "listen 0.0.0.0:9443 ssl;")
	mustContain("plaintext", plain, "set $observex_client_verify NONE;")
	mustNotContain("plaintext", plain, "ssl", "Strict-Transport-Security", "http2", "return 403;")

	// The Console listener never asks for a client certificate: exactly one
	// ssl_verify_client line, in the Agents server.
	if n := strings.Count(s, "ssl_verify_client"); n != 1 {
		t.Fatalf("ssl_verify_client appears %d times", n)
	}
	// Every route that needs a certificate checks for one; Enroll does not.
	for _, r := range grpcRoutes {
		block := locationBlock(t, s, r.Path)
		has := strings.Contains(block, "if ($ssl_client_verify != SUCCESS)")
		if has != r.NeedsClientCert {
			t.Fatalf("%s: certificate check present=%v, want %v", r.Path, has, r.NeedsClientCert)
		}
		if !strings.Contains(block, "grpc_set_header X-ObserveX-Client-Verify $observex_client_verify;") {
			t.Fatalf("%s does not set the verify header itself", r.Path)
		}
	}
	for _, r := range httpRoutes {
		block := locationBlock(t, s, r.Path)
		if !strings.Contains(block, "if ($ssl_client_verify != SUCCESS)") || !strings.Contains(block, "proxy_pass http://observex_gateway;") {
			t.Fatalf("%s:\n%s", r.Path, block)
		}
	}
}

// locationBlock returns the text of "location = path { ... }".
func locationBlock(t *testing.T, conf, path string) string {
	t.Helper()
	start := strings.Index(conf, "location = "+path+" {")
	if start < 0 {
		t.Fatalf("no location for %s", path)
	}
	end := strings.Index(conf[start:], "\n        }\n")
	return conf[start : start+end]
}

// TestRoutesMatchTheProtobufDefinitions keeps the Front Door's gRPC routes
// and the ObserveX services Agents call in step.
func TestRoutesMatchTheProtobufDefinitions(t *testing.T) {
	root := filepath.Join("..", "..", "..", "proto", "observex")
	want := map[string]bool{}
	for _, f := range []string{"agent/v1/enroll.proto", "ingest/v1/ingest.proto"} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		pkg := regexp.MustCompile(`(?m)^package ([a-z0-9.]+);`).FindStringSubmatch(src)[1]
		for _, svc := range regexp.MustCompile(`(?s)service (\w+) \{(.*?)\n\}`).FindAllStringSubmatch(src, -1) {
			for _, rpc := range regexp.MustCompile(`rpc (\w+)\(`).FindAllStringSubmatch(svc[2], -1) {
				want["/"+pkg+"."+svc[1]+"/"+rpc[1]] = true
			}
		}
	}
	got := map[string]bool{}
	for _, r := range grpcRoutes {
		if strings.HasPrefix(r.Path, "/observex.") {
			got[r.Path] = true
		}
	}
	if len(want) == 0 || !equalSets(want, got) {
		t.Fatalf("proto methods %v, Front Door routes %v", keys(want), keys(got))
	}
	if GRPCRoutes()[0] != grpcRoutes[0] || len(HTTPRoutes()) != len(httpRoutes) {
		t.Fatal("route accessors do not return the routes")
	}
}

func equalSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestArgs(t *testing.T) {
	if got := strings.Join(Args("/run/x", "/run/x/nginx.conf"), " "); got != "-e stderr -p /run/x -c /run/x/nginx.conf" {
		t.Fatal(got)
	}
	if got := strings.Join(CheckArgs("/run/x", "/run/x/nginx.conf"), " "); got != "-t -q -e stderr -p /run/x -c /run/x/nginx.conf" {
		t.Fatal(got)
	}
}

// nginxBinary returns the path of NGINX, or skips the test when it is not
// installed. With OBSERVEX_REQUIRE_NGINX=1 (CI) a missing NGINX fails the
// test instead, so these tests cannot be skipped silently.
func nginxBinary(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"nginx", "/usr/sbin/nginx", "/usr/local/sbin/nginx"} {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
	}
	if os.Getenv("OBSERVEX_REQUIRE_NGINX") == "1" {
		t.Fatal("NGINX is required (OBSERVEX_REQUIRE_NGINX=1) but not installed")
	}
	t.Skip("NGINX is not installed; set OBSERVEX_REQUIRE_NGINX=1 to make this a failure")
	return ""
}

// liveConfig is a configuration with real certificate files in a temporary
// directory, on free loopback ports.
type liveFiles struct {
	dir                 string
	ca                  *tlstest.CA
	caFile, crt, key    string
	clientCrt, clientKy string
}

func newLiveFiles(t *testing.T) liveFiles {
	t.Helper()
	dir := t.TempDir()
	ca := tlstest.NewCA(t, "ObserveX test cluster CA")
	lf := liveFiles{dir: dir, ca: ca}
	lf.caFile = ca.WriteCA(t, dir, "cluster-ca.crt")
	lf.crt, lf.key = tlstest.WritePair(t, dir, "node", ca.Server(t, "node-1.observex.test", "localhost"))
	return lf
}

func liveConfig(t *testing.T, lf liveFiles, plaintext bool, addr func() string) Config {
	t.Helper()
	c := Config{
		Console:           Listener{Listen: addr(), CertFile: lf.crt, KeyFile: lf.key},
		Agents:            Listener{Listen: addr(), CertFile: lf.crt, KeyFile: lf.key, ClientCAFile: lf.caFile},
		ProbeListen:       addr(),
		ServerAddr:        addr(),
		GatewayAddr:       addr(),
		SupervisorAddr:    addr(),
		MaxBodyBytes:      64 << 10,
		WorkerProcesses:   1,
		WorkerConnections: 256,
		RunDir:            filepath.Join(lf.dir, "run"),
	}
	if plaintext {
		c.Plaintext = true
		c.Console = Listener{Listen: c.Console.Listen}
		c.Agents = Listener{Listen: c.Agents.Listen}
	}
	if err := os.MkdirAll(c.RunDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestNginxAcceptsEveryVariant runs "nginx -t" on every configuration this
// host's NGINX can run, and checks that the one it cannot run is refused
// before NGINX sees it.
func TestNginxAcceptsEveryVariant(t *testing.T) {
	nginx := nginxBinary(t)
	f, err := Probe(context.Background(), nginx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NGINX %s with %s; hybrid post-quantum: %v", f.Version, f.TLSLibrary, f.HybridPQ)
	lf := newLiveFiles(t)
	ports := portSource(t)
	variants := map[string]func(*Config){
		"tls automatic groups": func(*Config) {},
		"plaintext":            nil,
		"tls classic groups only": func(c *Config) {
			c.Console.Groups = []string{GroupX25519, GroupP256}
			c.Agents.Groups = []string{GroupP384, GroupP256}
		},
		"tls hybrid group": func(c *Config) {
			c.Console.Groups = []string{GroupHybridPQ, GroupX25519}
			c.Agents.Groups = []string{GroupHybridPQ, GroupX25519}
		},
	}
	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			c := liveConfig(t, lf, mutate == nil, ports)
			if mutate != nil {
				mutate(&c)
			}
			conf, err := Render(c, f)
			if name == "tls hybrid group" && !f.HybridPQ {
				if err == nil {
					t.Fatal("Render accepted the hybrid group on a host that cannot offer it")
				}
				t.Logf("refused before NGINX, as it should be on %s: %v", f.TLSLibrary, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(c.RunDir, "nginx.conf")
			if err := os.WriteFile(path, conf, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := Check(context.Background(), nginx, c.RunDir, path); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("nginx -t catches a broken file", func(t *testing.T) {
		c := liveConfig(t, lf, true, ports)
		path := filepath.Join(c.RunDir, "broken.conf")
		if err := os.WriteFile(path, []byte("events {}\nhttp { server { listen 127.0.0.1:1; unknown_directive on; } }\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := Check(context.Background(), nginx, c.RunDir, path); err == nil || !strings.Contains(err.Error(), "unknown_directive") {
			t.Fatalf("Check = %v", err)
		}
	})
	if _, err := Probe(context.Background(), filepath.Join(t.TempDir(), "no-nginx")); err == nil {
		t.Fatal("Probe of a missing binary succeeded")
	}
}
