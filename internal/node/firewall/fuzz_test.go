package firewall

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"testing"
)

// Suggested commands may quote (firewalld rich rules) but hold only the
// plan's own ports and peers.
var safeCommand = regexp.MustCompile(`^[A-Za-z0-9 ./:=_'"-]+$`)

// FuzzCheck feeds arbitrary output from the read-only firewall commands to
// Check: it must not panic, must count problems consistently, and must never
// copy command output into the suggested commands an administrator might
// paste.
func FuzzCheck(f *testing.F) {
	f.Add("running", "443/tcp 9443/tcp", "https ssh", "Status: active\n443/tcp ALLOW Anywhere\n", "", "-P INPUT DROP")
	f.Add("not running", "", "", "Status: active\n9443 ALLOW 10.0.0.0/8\n; rm -rf /", "table inet f { chain input { type filter hook input priority 0; } }", "")
	f.Fuzz(func(t *testing.T, state, ports, services, ufw, nft, ipt string) {
		out := map[string]string{
			"firewall-cmd --state": state, "firewall-cmd --list-ports": ports, "firewall-cmd --list-services": services,
			"ufw status": ufw, "nft list ruleset": nft, "iptables -S INPUT": ipt,
		}
		run := func(_ context.Context, argv []string) (string, error) {
			if v, ok := out[strings.Join(argv, " ")]; ok && v != "" {
				return v, nil
			}
			return "", errors.New("not available")
		}
		plan := Plan{
			Ports: []Port{
				{Bind: "0.0.0.0:443", Port: 443, Purpose: "console", Exposure: Public},
				{Bind: "0.0.0.0:9443", Port: 9443, Purpose: "agents", Exposure: Public},
				{Bind: "0.0.0.0:7000", Port: 7000, Purpose: "store", Exposure: Cluster},
				{Bind: "127.0.0.1:8180", Port: 8180, Purpose: "status", Exposure: Local},
			},
			Peers: []string{"node-2.internal", "10.0.0.3"},
		}
		r, err := Check(context.Background(), plan, Options{
			Run:       run,
			Listen:    func(string) (net.Listener, error) { return nil, errors.New("not bound in tests") },
			SkipPeers: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		problems := 0
		for _, f := range r.Findings {
			switch f.Status {
			case StatusInUse, StatusNotLoopback, StatusBlocked, StatusTimeout:
				problems++
			}
		}
		if problems != r.Problems {
			t.Fatalf("problems %d, counted %d", r.Problems, problems)
		}
		for _, s := range r.Suggested {
			if strings.HasPrefix(s, "#") {
				continue
			}
			if !safeCommand.MatchString(s) {
				t.Fatalf("suggested command holds unexpected text: %q", s)
			}
		}
	})
}
