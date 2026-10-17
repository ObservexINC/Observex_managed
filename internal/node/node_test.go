package node

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/node/firewall"
	"github.com/ObservexINC/Observex_managed/internal/platform/config"
)

func TestParseFillsDefaults(t *testing.T) {
	c, err := Parse([]byte(`{"node_id":"node-1","supervisor":{},"front_door":{"console":{},"agents":{}},"upstreams":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string][2]string{
		"run_dir":         {c.RunDir, DefaultRunDir},
		"data_dir":        {c.DataDir, DefaultDataDir},
		"supervisor":      {c.Supervisor.Listen, DefaultSupervisorListen},
		"console":         {c.FrontDoor.Console.Listen, DefaultConsoleListen},
		"agents":          {c.FrontDoor.Agents.Listen, DefaultAgentsListen},
		"console cert":    {c.FrontDoor.Console.CertFile, "/etc/observex/tls/node.crt"},
		"agents key":      {c.FrontDoor.Agents.KeyFile, "/etc/observex/tls/node.key"},
		"agents CA":       {c.FrontDoor.Agents.ClientCAFile, "/etc/observex/tls/cluster-ca.crt"},
		"console CA":      {c.FrontDoor.Console.ClientCAFile, ""},
		"server upstream": {c.Upstreams.Server, DefaultServerAddr},
		"nginx":           {c.FrontDoor.Nginx, DefaultNginx},
	}
	for name, v := range checks {
		if v[0] != v[1] {
			t.Errorf("%s: got %q, want %q", name, v[0], v[1])
		}
	}
	if c.FrontDoor.StopTimeout.D() != DefaultFrontDoorStop || c.FrontDoor.MaxBodyBytes != DefaultMaxBodyBytes {
		t.Fatalf("front door defaults: %+v", c.FrontDoor)
	}
	if c.NginxConfPath() != "/run/observex/frontdoor/nginx.conf" {
		t.Fatalf("nginx.conf path: %s", c.NginxConfPath())
	}
}

func TestParsePlaintextHasNoTLSPaths(t *testing.T) {
	c, err := Parse([]byte(`{"node_id":"dev","front_door":{"plaintext":true,"console":{"listen":"127.0.0.1:8080"},"agents":{"listen":"127.0.0.1:8443"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.FrontDoor.Console.CertFile != "" || c.FrontDoor.Agents.ClientCAFile != "" {
		t.Fatalf("plaintext config got TLS paths: %+v", c.FrontDoor)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":          `{"node_id":"n","nodeid":"x"}`,
		"no node id":             `{}`,
		"upper-case node id":     `{"node_id":"Node1"}`,
		"relative run dir":       `{"node_id":"n","run_dir":"run"}`,
		"unclean data dir":       `{"node_id":"n","data_dir":"/var/lib/../x"}`,
		"root run dir":           `{"node_id":"n","run_dir":"/"}`,
		"public supervisor":      `{"node_id":"n","supervisor":{"listen":"0.0.0.0:8180"}}`,
		"public server upstream": `{"node_id":"n","upstreams":{"server":"10.0.0.5:8182"}}`,
		"port collision":         `{"node_id":"n","front_door":{"agents":{"listen":"0.0.0.0:443"}}}`,
		"negative duration":      `{"node_id":"n","supervisor":{"start_timeout":"-1s"}}`,
		"numeric duration":       `{"node_id":"n","supervisor":{"start_timeout":30}}`,
		"negative restarts":      `{"node_id":"n","supervisor":{"max_restarts":-1}}`,
		"injection in path":      `{"node_id":"n","tls_dir":"/etc/x;daemon on"}`,
		"bad peer":               `{"node_id":"n","peers":["node-2:2380"]}`,
		"trailing data":          `{"node_id":"n"} {}`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "node.json")
	if err := os.WriteFile(p, []byte(`{"node_id":"node-7"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil || c.NodeID != "node-7" {
		t.Fatalf("Load: %+v %v", c, err)
	}
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file accepted")
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(strings.Repeat(" ", config.MaxSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(big); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized file: %v", err)
	}
}

func TestPolicyMapsDurations(t *testing.T) {
	c, err := Parse([]byte(`{"node_id":"n","supervisor":{"start_timeout":"45s","max_backoff":"1m","max_restarts":9,"restart_after_not_ready":"2m"}}`))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Policy()
	if p.StartTimeout != 45*time.Second || p.MaxBackoff != time.Minute || p.MaxRestarts != 9 || p.RestartAfterNotReady != 2*time.Minute {
		t.Fatalf("policy: %+v", p)
	}
	if p.InitialBackoff != 0 {
		t.Fatalf("unset fields must stay zero so the supervisor default applies: %v", p.InitialBackoff)
	}
}

func TestFirewallPlan(t *testing.T) {
	c, err := Parse([]byte(`{"node_id":"n","peers":["node-2.internal","10.0.0.13"]}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.FirewallPlan()
	if err != nil {
		t.Fatal(err)
	}
	count := map[firewall.Exposure]int{}
	planned := 0
	for _, p := range plan.Ports {
		count[p.Exposure]++
		if p.Goal != "" {
			planned++
		}
	}
	if count[firewall.Public] != 2 || count[firewall.Local] != 4 || count[firewall.Cluster] != len(PlannedClusterPorts) {
		t.Fatalf("exposures: %v", count)
	}
	if planned != 2+len(PlannedClusterPorts) {
		t.Fatalf("planned ports: %d", planned)
	}
	if len(plan.Peers) != 2 {
		t.Fatalf("peers: %v", plan.Peers)
	}
}

func TestSpecs(t *testing.T) {
	c, err := Parse([]byte(`{"node_id":"n","front_door":{"stop_timeout":"7s"}}`))
	if err != nil {
		t.Fatal(err)
	}
	specs := c.Specs()
	if len(specs) != 1 || specs[0].Name != "front-door" || specs[0].Path != DefaultNginx {
		t.Fatalf("specs: %+v", specs)
	}
	sp := specs[0]
	args := strings.Join(sp.Args, " ")
	if !strings.Contains(args, "-p /run/observex/frontdoor") || !strings.Contains(args, "-c /run/observex/frontdoor/nginx.conf") {
		t.Fatalf("args: %s", args)
	}
	if sp.Env != nil {
		t.Fatal("the front door must get the supervisor's minimal default environment")
	}
	if sp.StopTimeout != 7*time.Second || sp.StopSignal != gracefulStop || sp.Ready == nil {
		t.Fatalf("stop and readiness: %+v", sp)
	}
}

func TestCheckPortsNamesTheConflict(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	busy := ln.Addr().String()
	free := freeAddrs(t, 3)
	doc := `{"node_id":"n","front_door":{"plaintext":true,"console":{"listen":"` + free[0] + `"},"agents":{"listen":"` + free[1] + `"},"probe_listen":"` + free[2] + `"},"supervisor":{"listen":"` + busy + `"}}`
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	_, err = CheckPorts(context.Background(), c, firewall.Options{})
	if err == nil || !strings.Contains(err.Error(), "Node Supervisor status and metrics") || !strings.Contains(err.Error(), busy) {
		t.Fatalf("want the supervisor port named as in use, got %v", err)
	}
	ln.Close()
	if _, err := CheckPorts(context.Background(), c, firewall.Options{}); err != nil {
		t.Fatalf("free ports: %v", err)
	}
}

// freeAddrs returns n distinct loopback addresses that were free a moment
// ago.
func freeAddrs(t *testing.T, n int) []string {
	t.Helper()
	var out []string
	var lns []net.Listener
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
		out = append(out, ln.Addr().String())
	}
	for _, ln := range lns {
		_ = ln.Close()
	}
	return out
}
