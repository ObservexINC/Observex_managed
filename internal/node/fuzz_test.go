package node

import (
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/node/frontdoor"
)

var fuzzFeatures = frontdoor.Features{Version: "1.29.0", TLSLibrary: "OpenSSL 3.5.0", HTTP2Directive: true, HybridPQ: true}

// directiveWords returns the first word of every line of a rendered NGINX
// configuration.
func directiveWords(conf []byte) map[string]bool {
	words := map[string]bool{}
	for _, line := range strings.Split(string(conf), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			words[f[0]] = true
		}
	}
	return words
}

// FuzzParse checks that any configuration Parse accepts keeps every
// internal address on loopback and renders an NGINX configuration made only
// of the template's own directives: no configured value can add a
// directive, a block or a line.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		`{"node_id":"n"}`,
		`{"node_id":"n","front_door":{"plaintext":true,"console":{"listen":"127.0.0.1:8080"},"agents":{"listen":"127.0.0.1:8443"}}}`,
		`{"node_id":"n","peers":["10.0.0.2","node-3.internal"],"supervisor":{"start_timeout":"10s","max_restarts":3}}`,
		`{"node_id":"n","front_door":{"console":{"listen":"[::]:443","groups":["X25519MLKEM768","X25519"]},"agents":{"listen":"0.0.0.0:9443"}}}`,
		`{"node_id":"n","tls_dir":"/etc/x;\n  include /etc/passwd"}`,
		`{"node_id":"n","run_dir":"/run/o bs"}`,
	} {
		f.Add([]byte(s))
	}
	base := map[bool]map[string]bool{}
	for _, plain := range []bool{false, true} {
		doc := `{"node_id":"n"}`
		if plain {
			doc = `{"node_id":"n","front_door":{"plaintext":true}}`
		}
		c, err := Parse([]byte(doc))
		if err != nil {
			f.Fatal(err)
		}
		conf, err := frontdoor.Render(c.FrontDoorConfig(), fuzzFeatures)
		if err != nil {
			f.Fatal(err)
		}
		base[plain] = directiveWords(conf)
	}

	f.Fuzz(func(t *testing.T, doc []byte) {
		c, err := Parse(doc)
		if err != nil {
			return
		}
		fd := c.FrontDoorConfig()
		for name, a := range map[string]string{
			"supervisor": fd.SupervisorAddr, "probe": fd.ProbeListen,
			"server": fd.ServerAddr, "gateway": fd.GatewayAddr,
		} {
			if !isLoopback(a) {
				t.Fatalf("accepted a non-loopback %s address %q", name, a)
			}
		}
		if _, err := c.FirewallPlan(); err != nil {
			t.Fatalf("accepted a configuration whose firewall plan is invalid: %v", err)
		}
		conf, err := frontdoor.Render(fd, fuzzFeatures)
		if err != nil {
			t.Fatalf("accepted a configuration that does not render: %v", err)
		}
		for w := range directiveWords(conf) {
			if !base[c.FrontDoor.Plaintext][w] {
				t.Fatalf("a configured value added %q to the NGINX configuration", w)
			}
		}
		if strings.Count(string(conf), "server {") != strings.Count(string(mustRender(t, c.FrontDoor.Plaintext)), "server {") {
			t.Fatal("a configured value changed the number of server blocks")
		}
	})
}

func mustRender(t *testing.T, plain bool) []byte {
	t.Helper()
	doc := `{"node_id":"n"}`
	if plain {
		doc = `{"node_id":"n","front_door":{"plaintext":true}}`
	}
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	conf, err := frontdoor.Render(c.FrontDoorConfig(), fuzzFeatures)
	if err != nil {
		t.Fatal(err)
	}
	return conf
}
