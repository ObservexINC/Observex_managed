package firewall

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHost answers the read-only commands with canned output and records
// every command it is asked to run.
type fakeHost struct {
	mu   sync.Mutex
	out  map[string]string
	fail map[string]error
	ran  [][]string
}

func (h *fakeHost) run(_ context.Context, argv []string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ran = append(h.ran, append([]string(nil), argv...))
	k := strings.Join(argv, " ")
	if err, ok := h.fail[k]; ok {
		return "", err
	}
	if o, ok := h.out[k]; ok {
		return o, nil
	}
	return "", errors.New("exec: not found")
}

func mustPort(t *testing.T, bind, purpose string, exp Exposure) Port {
	t.Helper()
	p, err := NewPort(bind, purpose, exp)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// nodePlan uses ports that are free in tests: binding is replaced.
func nodePlan(t *testing.T) Plan {
	etcd := mustPort(t, "0.0.0.0:2380", "etcd peer", Cluster)
	etcd.Goal = "G02"
	return Plan{
		Ports: []Port{
			mustPort(t, "127.0.0.1:8180", "supervisor status", Local),
			mustPort(t, "0.0.0.0:9443", "Front Door, Agents", Public),
			mustPort(t, "0.0.0.0:443", "Front Door, Console", Public),
			mustPort(t, "0.0.0.0:8444", "Server cluster RPC", Cluster),
			etcd,
		},
		Peers: []string{"10.0.0.12", "node-3.example.com"},
	}
}

type fakeListener struct{ net.Listener }

func (fakeListener) Close() error { return nil }

func freeListen(string) (net.Listener, error) { return fakeListener{}, nil }

func dialAll(err error) func(context.Context, string) (net.Conn, error) {
	return func(context.Context, string) (net.Conn, error) {
		if err != nil {
			return nil, err
		}
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
}

func TestReadOnlyCommandsAreReadOnly(t *testing.T) {
	forbidden := []string{"--add", "--remove", "--permanent", "--reload", "--set", "--zone", "allow", "deny", "reject", "delete",
		"insert", "enable", "disable", "reset", "flush", "-A", "-I", "-D", "-F", "-X", "-P", "-N", "add", "replace", "create"}
	for _, c := range ReadOnlyCommands {
		for _, a := range c[1:] {
			for _, f := range forbidden {
				if a == f || strings.HasPrefix(a, f+"=") {
					t.Fatalf("command %v contains %q, which changes a firewall", c, a)
				}
			}
		}
	}
	for _, argv := range [][]string{{"ufw", "allow", "443/tcp"}, {"firewall-cmd", "--add-port=443/tcp"}, {"iptables", "-F"}, {"sh", "-c", "true"}, {"ufw", "status", "verbose"}} {
		if _, err := ExecRunner(context.Background(), argv); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("ExecRunner(%v) = %v, want ErrNotAllowed", argv, err)
		}
	}
	// An allowed command that is not installed is reported, not run.
	if _, err := ExecRunner(context.Background(), []string{"firewall-cmd", "--state"}); err == nil {
		t.Log("firewall-cmd is installed here; its state was read")
	}
}

func TestCheckRunsOnlyReadOnlyCommands(t *testing.T) {
	// A runner that would happily run anything: Check must still refuse to
	// pass it a command off the list.
	h := &fakeHost{out: map[string]string{"firewall-cmd --state": "running", "firewall-cmd --list-ports": "", "firewall-cmd --list-services": ""}}
	if _, err := Check(context.Background(), nodePlan(t), Options{Run: h.run, Listen: freeListen, Dial: dialAll(nil)}); err != nil {
		t.Fatal(err)
	}
	if len(h.ran) == 0 {
		t.Fatal("nothing was read")
	}
	for _, argv := range h.ran {
		if !allowed(argv) {
			t.Fatalf("ran %v", argv)
		}
	}
}

func TestFirewalld(t *testing.T) {
	h := &fakeHost{out: map[string]string{
		"firewall-cmd --state":         "running\n",
		"firewall-cmd --list-ports":    "9443/tcp 8080/tcp\n",
		"firewall-cmd --list-services": "ssh https dhcpv6-client\n",
	}}
	r, err := Check(context.Background(), nodePlan(t), Options{Run: h.run, Listen: freeListen, Dial: dialAll(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Firewall != "firewalld" {
		t.Fatalf("firewall = %s", r.Firewall)
	}
	want := map[int]string{443: StatusAllowed, 9443: StatusAllowed, 8444: StatusBlocked}
	for _, f := range r.Findings {
		if f.Check == "firewall" {
			if w, ok := want[f.Port]; !ok || w != f.Status {
				t.Fatalf("finding %+v", f)
			}
			delete(want, f.Port)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing firewall findings for %v", want)
	}
	if r.Problems != 1 {
		t.Fatalf("problems = %d, want 1 (8444 not allowed): %+v", r.Problems, r.Findings)
	}
	s := strings.Join(r.Suggested, "\n")
	for _, w := range []string{
		"firewall-cmd --permanent --add-port=443/tcp",
		`source address="10.0.0.12" port port="8444"`,
		`source address="10.0.0.12" port port="2380" protocol="tcp" accept'   # needed from G02`,
		"# allow TCP 2380 from node-3.example.com (etcd peer): firewalld needs its IP address, not the host name   # needed from G02",
		"firewall-cmd --reload",
	} {
		if !strings.Contains(s, w) {
			t.Fatalf("suggestions lack %q:\n%s", w, s)
		}
	}
	if strings.Contains(s, "8180") {
		t.Fatal("a local port was suggested for opening")
	}
}

func TestFirewalldUnreadable(t *testing.T) {
	h := &fakeHost{out: map[string]string{"firewall-cmd --state": "running"}, fail: map[string]error{"firewall-cmd --list-ports": errors.New("authorization failed")}}
	r, _ := Check(context.Background(), nodePlan(t), Options{Run: h.run, Listen: freeListen, SkipPeers: true})
	if !hasFinding(r, "firewall", StatusUnknown, "run the check as root") {
		t.Fatalf("findings = %+v", r.Findings)
	}
}

func TestUfw(t *testing.T) {
	h := &fakeHost{out: map[string]string{"ufw status": "Status: active\n\nTo                         Action      From\n--                         ------      ----\n443/tcp                    ALLOW       Anywhere\n9443                       DENY        Anywhere\n8444/tcp                   ALLOW       10.0.0.12\n"}}
	r, err := Check(context.Background(), nodePlan(t), Options{Run: h.run, Listen: freeListen, SkipPeers: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Firewall != "ufw" {
		t.Fatalf("firewall = %s", r.Firewall)
	}
	if !hasPortStatus(r, 443, StatusAllowed) || !hasPortStatus(r, 9443, StatusBlocked) || !hasPortStatus(r, 8444, StatusAllowed) {
		t.Fatalf("findings = %+v", r.Findings)
	}
	s := strings.Join(r.Suggested, "\n")
	if !strings.Contains(s, "ufw allow 9443/tcp") || !strings.Contains(s, "ufw allow from 10.0.0.12 to any port 8444 proto tcp") {
		t.Fatalf("suggestions:\n%s", s)
	}
	h.fail = map[string]error{}
	h.out = map[string]string{"ufw status": "Status: inactive", "iptables -S INPUT": "-P INPUT ACCEPT\n"}
	r, _ = Check(context.Background(), nodePlan(t), Options{Run: h.run, Listen: freeListen, SkipPeers: true})
	if r.Firewall != "none" || !hasFinding(r, "firewall", StatusInfo, "no host firewall rules") {
		t.Fatalf("inactive ufw: firewall = %s, findings %+v", r.Firewall, r.Findings)
	}
}

func TestNftablesAndIptablesAreLeftForReview(t *testing.T) {
	cases := map[string]map[string]string{
		"nftables": {"nft list ruleset": "table inet filter {\n chain input {\n  type filter hook input priority 0; policy drop;\n }\n}\n"},
		"iptables": {"iptables -S INPUT": "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j DROP\n"},
		"unknown":  {},
	}
	for want, out := range cases {
		r, _ := Check(context.Background(), nodePlan(t), Options{Run: (&fakeHost{out: out}).run, Listen: freeListen, SkipPeers: true})
		if r.Firewall != want || !hasFinding(r, "firewall", StatusUnknown, "") {
			t.Fatalf("%s: firewall = %s, findings %+v", want, r.Firewall, r.Findings)
		}
		if want != "unknown" && !strings.Contains(strings.Join(r.Suggested, "\n"), "# allow TCP 443 from users") {
			t.Fatalf("%s: generic suggestions missing: %v", want, r.Suggested)
		}
	}
}

func TestBindChecks(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeAddr := free.Addr().String()
	_ = free.Close()
	plan := Plan{Ports: []Port{
		mustPort(t, busy.Addr().String(), "Front Door probe", Local),
		mustPort(t, freeAddr, "supervisor status", Local),
		mustPort(t, "0.0.0.0:65001", "server status", Local),
	}}
	h := &fakeHost{}
	r, err := Check(context.Background(), plan, Options{Run: h.run, SkipPeers: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(r, "bind", StatusInUse, "already in use") || !hasFinding(r, "bind", StatusOK, "supervisor status: free") {
		t.Fatalf("findings = %+v", r.Findings)
	}
	if !hasFinding(r, "loopback", StatusNotLoopback, "server status must bind a loopback address") {
		t.Fatalf("a local port on 0.0.0.0 was not reported: %+v", r.Findings)
	}
	r, _ = Check(context.Background(), plan, Options{Run: h.run, SkipPeers: true, NodeRunning: true})
	if hasFinding(r, "bind", StatusInUse, "") || !hasFinding(r, "bind", StatusInfo, "expected while the node runs") {
		t.Fatalf("NodeRunning: %+v", r.Findings)
	}
	for _, msg := range []struct{ err, want string }{
		{"listen tcp :80: bind: permission denied", "CAP_NET_BIND_SERVICE"},
		{"bind: cannot assign requested address", "no such address"},
		{"something else", "cannot bind: something else"},
	} {
		if got := bindError(errors.New(msg.err)); !strings.Contains(got, msg.want) {
			t.Fatalf("bindError(%q) = %q", msg.err, got)
		}
	}
}

func TestPlannedPortsAreNotChecked(t *testing.T) {
	p := mustPort(t, "0.0.0.0:2380", "etcd peer", Cluster)
	p.Goal = "G02"
	listenCalled := false
	r, _ := Check(context.Background(), Plan{Ports: []Port{p}, Peers: []string{"10.0.0.2"}}, Options{
		Run: (&fakeHost{}).run, Dial: dialAll(errors.New("must not dial")),
		Listen: func(string) (net.Listener, error) { listenCalled = true; return fakeListener{}, nil },
	})
	if listenCalled || !hasFinding(r, "bind", StatusInfo, "not used yet (from G02)") || hasFinding(r, "peer", "", "") {
		t.Fatalf("findings = %+v", r.Findings)
	}
}

func TestPeerChecks(t *testing.T) {
	plan := Plan{Ports: []Port{mustPort(t, "0.0.0.0:8444", "Server cluster RPC", Cluster)}, Peers: []string{"10.0.0.2"}}
	cases := []struct {
		err  error
		want string
	}{
		{nil, StatusReachable},
		{errors.New("dial tcp 10.0.0.2:8444: connect: connection refused"), StatusRefused},
		{errors.New("dial tcp 10.0.0.2:8444: i/o timeout"), StatusTimeout},
	}
	for _, tc := range cases {
		r, _ := Check(context.Background(), plan, Options{Run: (&fakeHost{}).run, Listen: freeListen, Dial: dialAll(tc.err)})
		if !hasFinding(r, "peer", tc.want, "") {
			t.Fatalf("dial error %v: findings %+v", tc.err, r.Findings)
		}
	}
	// A real refused connection on loopback.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()
	p := mustPort(t, "0.0.0.0:"+port, "Server cluster RPC", Cluster)
	r, _ := Check(context.Background(), Plan{Ports: []Port{p}, Peers: []string{"127.0.0.1"}}, Options{Run: (&fakeHost{}).run, Listen: freeListen, DialTimeout: time.Second})
	if !hasFinding(r, "peer", StatusRefused, "") {
		t.Fatalf("findings = %+v", r.Findings)
	}
}

func TestPlanValidation(t *testing.T) {
	good := mustPort(t, "0.0.0.0:443", "console", Public)
	cases := []Plan{
		{Ports: []Port{{Bind: "0.0.0.0:1", Port: 1, Purpose: "x", Exposure: "everyone"}}},
		{Ports: []Port{good, good}},
		{Ports: []Port{good}, Peers: []string{`10.0.0.1" accept'; rm -rf /`}},
		{Ports: []Port{good}, Peers: []string{"node-2:8444"}},
		{Ports: []Port{good}, Peers: []string{""}},
	}
	for i, p := range cases {
		if _, err := Check(context.Background(), p, Options{Run: (&fakeHost{}).run, Listen: freeListen}); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	if err := (Plan{Ports: []Port{good}, Peers: []string{"fd00::12", "node-2", "10.1.2.3"}}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"nohostport", "h:0", "h:70000", "h:x"} {
		if _, err := NewPort(bad, "x", Public); err == nil {
			t.Fatalf("NewPort(%q) accepted", bad)
		}
	}
}

func TestIPv6PeerRichRule(t *testing.T) {
	s := strings.Join(suggest("firewalld", []Port{mustPort(t, "[::]:8444", "rpc", Cluster)}, []string{"fd00::12"}), "\n")
	if !strings.Contains(s, `rule family="ipv6" source address="fd00::12"`) {
		t.Fatal(s)
	}
	s = strings.Join(suggest("unknown", []Port{mustPort(t, "[::]:8444", "rpc", Cluster)}, nil), "\n")
	if !strings.Contains(s, "# allow TCP 8444 from the other cluster nodes only") {
		t.Fatal(s)
	}
}

func TestTextReport(t *testing.T) {
	r, _ := Check(context.Background(), nodePlan(t), Options{
		Run: (&fakeHost{out: map[string]string{"ufw status": "Status: active\n443/tcp ALLOW Anywhere\n"}}).run, Listen: freeListen, Dial: dialAll(nil),
		Now: func() time.Time { return time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC) },
	})
	txt := r.Text()
	for _, w := range []string{"2026-10-15T08:00:00Z", "Required ports", "443   tcp  public", "Host firewall: ufw",
		"Suggested commands (review before running; nothing was run)", "problem(s). This check changed nothing."} {
		if !strings.Contains(txt, w) {
			t.Fatalf("text lacks %q:\n%s", w, txt)
		}
	}
	// Public ports come first, then cluster, then local.
	if strings.Index(txt, "public") > strings.Index(txt, "cluster") || strings.Index(txt, "cluster") > strings.Index(txt, "local ") {
		t.Fatalf("ports not ordered by exposure:\n%s", txt)
	}
}

func hasFinding(r Report, check, status, detail string) bool {
	for _, f := range r.Findings {
		if f.Check == check && (status == "" || f.Status == status) && strings.Contains(f.Detail, detail) {
			return true
		}
	}
	return false
}

func hasPortStatus(r Report, port int, status string) bool {
	for _, f := range r.Findings {
		if f.Check == "firewall" && f.Port == port && f.Status == status {
			return true
		}
	}
	return false
}

func TestSuggestHostNamePeersAsComments(t *testing.T) {
	ports := []Port{mustPort(t, "0.0.0.0:7000", "store", Cluster)}
	for _, fw := range []string{"ufw", "firewalld"} {
		s := strings.Join(suggest(fw, ports, []string{"node-2.internal", "10.0.0.3"}), "\n")
		if !strings.Contains(s, "# allow TCP 7000 from node-2.internal") || !strings.Contains(s, "needs its IP address") {
			t.Fatalf("%s: host name peer not turned into a comment:\n%s", fw, s)
		}
		if strings.Contains(s, "from node-2.internal to any") || strings.Contains(s, `address="node-2.internal"`) {
			t.Fatalf("%s: host name used where an address is required:\n%s", fw, s)
		}
		if !strings.Contains(s, "10.0.0.3") {
			t.Fatalf("%s: IP peer missing:\n%s", fw, s)
		}
	}
}
