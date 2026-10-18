// Package firewall reports the network ports a managed node needs and
// whether the host lets them through. It never changes the firewall
// (OD-25 DEV-03): it reads, checks and suggests; the administrator acts.
//
// A report has four parts:
//
//   - Required ports, each with its exposure: public (users, Agents and
//     Gateways), cluster (the other nodes only) or local (loopback only).
//   - Local checks: whether each port this node binds is free, and whether
//     every local port is bound to loopback.
//   - The host firewall, read with a fixed list of read-only commands
//     (ReadOnlyCommands). firewalld and ufw rules are compared with the
//     required ports; nftables and iptables are detected and left for manual
//     review.
//   - Peer checks: whether the other nodes' cluster ports answer.
//
// Suggested commands are printed for the administrator, never run.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// hostRE allows host names only; they end up in suggested commands.
var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// Exposure says who must be able to reach a port.
type Exposure string

// Exposures.
const (
	Public  Exposure = "public"  // users, Agents and Gateways
	Cluster Exposure = "cluster" // the other cluster nodes only
	Local   Exposure = "local"   // this host only, on loopback
)

// Port is one port the node needs.
type Port struct {
	// Bind is the address the node binds, host:port.
	Bind     string   `json:"bind"`
	Port     int      `json:"port"`
	Purpose  string   `json:"purpose"`
	Exposure Exposure `json:"exposure"`
	// Goal is the development goal that starts using the port, for ports
	// that are planned but not used yet.
	Goal string `json:"goal,omitempty"`
}

// NewPort builds a Port from a bind address.
func NewPort(bind, purpose string, exp Exposure) (Port, error) {
	_, p, err := net.SplitHostPort(bind)
	if err != nil {
		return Port{}, fmt.Errorf("firewall: %s: %q is not host:port", purpose, bind)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return Port{}, fmt.Errorf("firewall: %s: port %q is not valid", purpose, p)
	}
	return Port{Bind: bind, Port: n, Purpose: purpose, Exposure: exp}, nil
}

// Plan is what the node needs.
type Plan struct {
	Ports []Port `json:"ports"`
	// Peers are the other cluster nodes' addresses (hosts, no ports).
	Peers []string `json:"peers,omitempty"`
}

// Validate checks the plan.
func (p Plan) Validate() error {
	seen := map[string]string{}
	for _, pt := range p.Ports {
		switch pt.Exposure {
		case Public, Cluster, Local:
		default:
			return fmt.Errorf("firewall: %s has unknown exposure %q", pt.Purpose, pt.Exposure)
		}
		if prev, dup := seen[pt.Bind]; dup {
			return fmt.Errorf("firewall: %s and %s both bind %s", prev, pt.Purpose, pt.Bind)
		}
		seen[pt.Bind] = pt.Purpose
	}
	for _, peer := range p.Peers {
		if net.ParseIP(peer) == nil && !hostRE.MatchString(peer) {
			return fmt.Errorf("firewall: peer %q must be a host name or IP address without a port", peer)
		}
	}
	return nil
}

// Status values in findings.
const (
	StatusOK          = "ok"
	StatusInUse       = "in_use"       // something already listens there
	StatusNotLoopback = "not_loopback" // a local port bound beyond loopback
	StatusAllowed     = "allowed"      // the host firewall lets it through
	StatusBlocked     = "not_allowed"  // the host firewall does not list it
	StatusUnknown     = "unknown"      // could not tell
	StatusReachable   = "reachable"    // a peer answered
	StatusRefused     = "refused"      // the peer is up, nothing listens on that port
	StatusTimeout     = "timeout"      // no answer: a firewall or the network drops it
	StatusUnreachable = "unreachable"  // no route, or the name does not resolve
	StatusPermission  = "permission_denied"
	StatusNoAddress   = "no_such_address"
	StatusBindError   = "bind_error"
	StatusInfo        = "info"
)

// IsProblem reports whether a status stops the node or a cluster link.
func IsProblem(status string) bool {
	switch status {
	case StatusInUse, StatusNotLoopback, StatusBlocked, StatusTimeout, StatusUnreachable,
		StatusPermission, StatusNoAddress, StatusBindError:
		return true
	}
	return false
}

// IsBindProblem reports whether a status means this node cannot bind one of
// its own addresses.
func IsBindProblem(status string) bool {
	switch status {
	case StatusInUse, StatusNotLoopback, StatusPermission, StatusNoAddress, StatusBindError:
		return true
	}
	return false
}

// Finding is one result.
type Finding struct {
	Check  string `json:"check"`
	Port   int    `json:"port,omitempty"`
	Target string `json:"target,omitempty"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Report is the full result.
type Report struct {
	Time       time.Time `json:"time"`
	Ports      []Port    `json:"ports"`
	Firewall   string    `json:"firewall"` // firewalld, ufw, nftables, iptables, none or unknown
	Findings   []Finding `json:"findings"`
	Suggested  []string  `json:"suggested_commands"`
	Problems   int       `json:"problems"`
	ChangedNot string    `json:"note"`
}

// Runner runs one read-only command and returns its output. The real one
// refuses anything not in ReadOnlyCommands.
type Runner func(ctx context.Context, argv []string) (string, error)

// ReadOnlyCommands is every command this package may run. Each one only
// reads the firewall's state.
var ReadOnlyCommands = [][]string{
	{"firewall-cmd", "--state"},
	{"firewall-cmd", "--list-ports"},
	{"firewall-cmd", "--list-services"},
	{"ufw", "status"},
	{"nft", "list", "ruleset"},
	{"iptables", "-S", "INPUT"},
}

// ErrNotAllowed is returned for a command outside ReadOnlyCommands.
var ErrNotAllowed = errors.New("firewall: command is not on the read-only list")

func allowed(argv []string) bool {
	for _, c := range ReadOnlyCommands {
		if strings.Join(c, "\x00") == strings.Join(argv, "\x00") {
			return true
		}
	}
	return false
}

// ExecRunner runs commands found on PATH, with a timeout and an empty
// environment apart from PATH and LANG.
func ExecRunner(ctx context.Context, argv []string) (string, error) {
	if !allowed(argv) {
		return "", ErrNotAllowed
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, argv[1:]...) // #nosec G204 -- argv passed allowed(): a fixed list of read-only firewall commands
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Options control a check.
type Options struct {
	Run Runner
	// Listen tries to bind an address; nil uses net.Listen.
	Listen func(addr string) (net.Listener, error)
	// Dial connects to an address; nil uses a net.Dialer.
	Dial        func(ctx context.Context, addr string) (net.Conn, error)
	DialTimeout time.Duration
	// SkipPeers leaves out the peer checks.
	SkipPeers bool
	// NodeRunning means this node's own processes hold their ports, so a
	// port in use is expected.
	NodeRunning bool
	Now         func() time.Time
}

// Check builds the report. It never changes anything on the host.
func Check(ctx context.Context, plan Plan, opt Options) (Report, error) {
	if err := plan.Validate(); err != nil {
		return Report{}, err
	}
	if opt.Run == nil {
		opt.Run = ExecRunner
	}
	run := func(ctx context.Context, argv []string) (string, error) {
		if !allowed(argv) {
			return "", ErrNotAllowed
		}
		return opt.Run(ctx, argv)
	}
	if opt.Listen == nil {
		opt.Listen = func(a string) (net.Listener, error) {
			var lc net.ListenConfig
			return lc.Listen(ctx, "tcp", a)
		}
	}
	if opt.DialTimeout <= 0 {
		// Long enough for Windows, which retries a refused connection for
		// about two seconds before reporting it.
		opt.DialTimeout = 5 * time.Second
	}
	if opt.Dial == nil {
		d := &net.Dialer{Timeout: opt.DialTimeout}
		opt.Dial = func(ctx context.Context, a string) (net.Conn, error) { return d.DialContext(ctx, "tcp", a) }
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	ports := append([]Port(nil), plan.Ports...)
	sort.SliceStable(ports, func(i, j int) bool {
		if ports[i].Exposure != ports[j].Exposure {
			return exposureRank(ports[i].Exposure) < exposureRank(ports[j].Exposure)
		}
		return ports[i].Port < ports[j].Port
	})
	r := Report{Time: opt.Now().UTC(), Ports: ports, ChangedNot: "This check changed nothing. Suggested commands are for the administrator to review and run."}

	// Local binding.
	for _, p := range ports {
		if p.Exposure == Local && !isLoopback(p.Bind) {
			r.add(Finding{Check: "loopback", Port: p.Port, Target: p.Bind, Status: StatusNotLoopback,
				Detail: p.Purpose + " must bind a loopback address"})
		}
		if p.Goal != "" {
			r.add(Finding{Check: "bind", Port: p.Port, Target: p.Bind, Status: StatusInfo,
				Detail: p.Purpose + " is not used yet (from " + p.Goal + "); not checked"})
			continue
		}
		ln, err := opt.Listen(p.Bind)
		switch {
		case err == nil:
			_ = ln.Close()
			r.add(Finding{Check: "bind", Port: p.Port, Target: p.Bind, Status: StatusOK, Detail: p.Purpose + ": free"})
		case opt.NodeRunning:
			r.add(Finding{Check: "bind", Port: p.Port, Target: p.Bind, Status: StatusInfo, Detail: p.Purpose + ": in use, expected while the node runs"})
		default:
			status, detail := bindStatus(err)
			r.add(Finding{Check: "bind", Port: p.Port, Target: p.Bind, Status: status, Detail: p.Purpose + ": " + detail})
		}
	}

	// Host firewall.
	r.Firewall = detect(ctx, run)
	r.checkRules(ctx, run, ports)
	r.Suggested = suggest(r.Firewall, ports, plan.Peers)

	// Peers.
	if !opt.SkipPeers {
		for _, peer := range plan.Peers {
			for _, p := range ports {
				if p.Exposure != Cluster || p.Goal != "" {
					continue
				}
				target := net.JoinHostPort(peer, strconv.Itoa(p.Port))
				dctx, cancel := context.WithTimeout(ctx, opt.DialTimeout)
				conn, err := opt.Dial(dctx, target)
				cancel()
				f := Finding{Check: "peer", Port: p.Port, Target: target}
				if err == nil {
					_ = conn.Close()
					f.Status, f.Detail = StatusReachable, p.Purpose+": answered"
				} else {
					status, detail := dialStatus(err)
					f.Status, f.Detail = status, p.Purpose+": "+detail
				}
				r.add(f)
			}
		}
	}
	return r, nil
}

func (r *Report) add(f Finding) {
	if IsProblem(f.Status) {
		r.Problems++
	}
	r.Findings = append(r.Findings, f)
}

func exposureRank(e Exposure) int {
	switch e {
	case Public:
		return 0
	case Cluster:
		return 1
	}
	return 2
}

// detect finds the active firewall manager using read-only commands.
func detect(ctx context.Context, run Runner) string {
	if out, err := run(ctx, []string{"firewall-cmd", "--state"}); err == nil && strings.TrimSpace(out) == "running" {
		return "firewalld"
	}
	// An installed but inactive ufw says "Status: inactive"; look further.
	if out, err := run(ctx, []string{"ufw", "status"}); err == nil && strings.Contains(out, "Status: active") {
		return "ufw"
	}
	if out, err := run(ctx, []string{"nft", "list", "ruleset"}); err == nil {
		if strings.Contains(out, "hook input") {
			return "nftables"
		}
	}
	if out, err := run(ctx, []string{"iptables", "-S", "INPUT"}); err == nil {
		if strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-j DROP") || strings.Contains(out, "-j REJECT") {
			return "iptables"
		}
		return "none"
	}
	return "unknown"
}

// checkRules compares firewalld or ufw rules with the public and cluster
// ports.
func (r *Report) checkRules(ctx context.Context, run Runner, ports []Port) {
	var open func(p Port) (string, string)
	switch r.Firewall {
	case "firewalld":
		out, err := run(ctx, []string{"firewall-cmd", "--list-ports"})
		if err != nil {
			r.add(Finding{Check: "firewall", Status: StatusUnknown, Detail: "firewalld is running but its ports could not be read (run the check as root)"})
			return
		}
		services, _ := run(ctx, []string{"firewall-cmd", "--list-services"})
		listed := map[string]bool{}
		for _, f := range strings.Fields(out) {
			listed[f] = true
		}
		svc := map[string]bool{}
		for _, f := range strings.Fields(services) {
			svc[f] = true
		}
		open = func(p Port) (string, string) {
			if listed[fmt.Sprintf("%d/tcp", p.Port)] || p.Port == 443 && svc["https"] {
				return StatusAllowed, "listed in firewalld's default zone"
			}
			return StatusBlocked, "not listed in firewalld's default zone"
		}
	case "ufw":
		out, err := run(ctx, []string{"ufw", "status"})
		if err != nil {
			r.add(Finding{Check: "firewall", Status: StatusUnknown, Detail: "ufw rules could not be read (run the check as root)"})
			return
		}
		open = func(p Port) (string, string) {
			for _, line := range strings.Split(out, "\n") {
				f := strings.Fields(line)
				if len(f) >= 2 && (f[0] == strconv.Itoa(p.Port) || f[0] == strconv.Itoa(p.Port)+"/tcp") && strings.EqualFold(f[1], "ALLOW") {
					return StatusAllowed, "allowed by ufw: " + strings.Join(f, " ")
				}
			}
			return StatusBlocked, "no ufw ALLOW rule for this port"
		}
	case "none":
		r.add(Finding{Check: "firewall", Status: StatusInfo, Detail: "no host firewall rules found; the network's own firewalls still apply"})
		return
	case "nftables", "iptables":
		r.add(Finding{Check: "firewall", Status: StatusUnknown, Detail: r.Firewall + " rules are active; compare them with the required ports by hand"})
		return
	default:
		r.add(Finding{Check: "firewall", Status: StatusUnknown, Detail: "the host firewall could not be read (no supported tool, or not run as root)"})
		return
	}
	for _, p := range ports {
		if p.Exposure == Local || p.Goal != "" {
			continue
		}
		st, detail := open(p)
		r.add(Finding{Check: "firewall", Port: p.Port, Status: st, Detail: p.Purpose + ": " + detail})
	}
}

// suggest returns commands that would open the ports. They are printed,
// never run.
func suggest(fw string, ports []Port, peers []string) []string {
	var out []string
	for _, p := range ports {
		if p.Exposure == Local {
			continue
		}
		port := strconv.Itoa(p.Port)
		note := ""
		if p.Goal != "" {
			note = "   # needed from " + p.Goal
		}
		switch {
		case p.Exposure == Public && fw == "ufw":
			out = append(out, "ufw allow "+port+"/tcp"+note)
		case p.Exposure == Public && fw == "firewalld":
			out = append(out, "firewall-cmd --permanent --add-port="+port+"/tcp"+note)
		case p.Exposure == Public:
			out = append(out, "# allow TCP "+port+" from users, Agents and Gateways ("+p.Purpose+")"+note)
		case len(peers) == 0:
			out = append(out, "# allow TCP "+port+" from the other cluster nodes only ("+p.Purpose+")"+note)
		default:
			for _, peer := range peers {
				ip := net.ParseIP(peer)
				switch {
				case ip == nil && (fw == "ufw" || fw == "firewalld"):
					// Both tools need an address, not a host name.
					out = append(out, "# allow TCP "+port+" from "+peer+" ("+p.Purpose+"): "+fw+" needs its IP address, not the host name"+note)
				case fw == "ufw":
					out = append(out, "ufw allow from "+peer+" to any port "+port+" proto tcp"+note)
				case fw == "firewalld":
					family := "ipv4"
					if ip.To4() == nil {
						family = "ipv6"
					}
					out = append(out, `firewall-cmd --permanent --add-rich-rule='rule family="`+family+`" source address="`+peer+`" port port="`+port+`" protocol="tcp" accept'`+note)
				default:
					out = append(out, "# allow TCP "+port+" from "+peer+" ("+p.Purpose+")"+note)
				}
			}
		}
	}
	if fw == "firewalld" && len(out) > 0 {
		out = append(out, "firewall-cmd --reload")
	}
	return out
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

// Text renders the report for a terminal.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "ObserveX node firewall check, %s\n\n", r.Time.Format(time.RFC3339))
	b.WriteString("Required ports\n")
	for _, p := range r.Ports {
		goal := ""
		if p.Goal != "" {
			goal = " (from " + p.Goal + ")"
		}
		fmt.Fprintf(&b, "  %-5d tcp  %-7s  %-22s %s%s\n", p.Port, p.Exposure, p.Bind, p.Purpose, goal)
	}
	fmt.Fprintf(&b, "\nHost firewall: %s\n\nFindings\n", r.Firewall)
	for _, f := range r.Findings {
		target := f.Target
		if target == "" && f.Port != 0 {
			target = strconv.Itoa(f.Port)
		}
		fmt.Fprintf(&b, "  %-17s %-9s %-22s %s\n", f.Status, f.Check, target, f.Detail)
	}
	if len(r.Suggested) > 0 {
		b.WriteString("\nSuggested commands (review before running; nothing was run)\n")
		for _, s := range r.Suggested {
			b.WriteString("  " + s + "\n")
		}
	}
	fmt.Fprintf(&b, "\n%d problem(s). %s\n", r.Problems, r.ChangedNot)
	return b.String()
}
