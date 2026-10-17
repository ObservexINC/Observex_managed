// Command observex-node runs a managed node: the Node Supervisor, the
// components it starts, and the node's self-monitoring (OD-25; development
// plan G01).
//
// Usage:
//
//	observex-node run      [-config path]   run the node (systemd starts this)
//	observex-node check    [-config path] [-running]
//	                                        validate the configuration, TLS files,
//	                                        NGINX and ports, then exit
//	observex-node firewall [-config path] [-json] [-skip-peers] [-running]
//	                                        report the ports the node needs and whether
//	                                        the host firewall allows them; changes nothing
//	observex-node status   [-config path]   print the supervisor's status (JSON)
//	observex-node health   [-config path]   exit 0 when the node is ready
//	observex-node render-nginx [-config path]
//	                                        print the generated NGINX configuration
//	observex-node init     -node-id id [-host name]... [-peer host]... [-group g]
//	                                        write a first configuration and TLS files;
//	                                        never overwrites existing ones
//	observex-node version
//
// The configuration path defaults to OBSERVEX_NODE_CONFIG, then
// /etc/observex/node.json.
//
// Exit codes: 0 success; 1 failure at run time, not ready, or problems
// found; 2 invalid usage, configuration or environment.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/node"
	"github.com/ObservexINC/Observex_managed/internal/node/firewall"
	"github.com/ObservexINC/Observex_managed/internal/node/frontdoor"
	"github.com/ObservexINC/Observex_managed/internal/node/pki"
	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// version is set at build time: -ldflags "-X main.version=...".
var version = "dev"

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type env struct {
	ctx    context.Context
	stdout io.Writer
	stderr io.Writer
}

func (e env) fail(code int, format string, args ...any) int {
	fmt.Fprintf(e.stderr, "observex-node: "+format+"\n", args...)
	return code
}

func defaultConfigPath() string {
	if p := os.Getenv("OBSERVEX_NODE_CONFIG"); p != "" {
		return p
	}
	return node.DefaultConfigPath
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	e := env{ctx: ctx, stdout: stdout, stderr: stderr}
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("observex-node "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath(), "node configuration file (JSON)")

	switch cmd {
	case "version":
		if err := fs.Parse(args); err != nil {
			return exitUsage
		}
		fmt.Fprintln(stdout, "observex-node", version)
		return exitOK
	case "init":
		return cmdInit(e, fs, configPath, args)
	case "run", "check", "firewall", "status", "health", "render-nginx":
	default:
		return e.fail(exitUsage, "unknown command %q (run, check, firewall, status, health, render-nginx, init, version)", cmd)
	}

	running := false
	asJSON, skipPeers := false, false
	logLevel := "info"
	switch cmd {
	case "check":
		fs.BoolVar(&running, "running", false, "the node is running, so its ports are expected to be in use")
	case "firewall":
		fs.BoolVar(&running, "running", false, "the node is running, so its ports are expected to be in use")
		fs.BoolVar(&asJSON, "json", false, "print the report as JSON")
		fs.BoolVar(&skipPeers, "skip-peers", false, "do not try to reach the other nodes")
	case "run":
		fs.StringVar(&logLevel, "log-level", "info", "debug, info, warn or error")
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		return e.fail(exitUsage, "unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	cfg, err := node.Load(*configPath)
	if err != nil {
		return e.fail(exitUsage, "%v", err)
	}
	switch cmd {
	case "run":
		return cmdRun(e, cfg, logLevel)
	case "check":
		return cmdCheck(e, cfg, running)
	case "firewall":
		return cmdFirewall(e, cfg, running, asJSON, skipPeers)
	case "status":
		return cmdStatus(e, cfg)
	case "health":
		return cmdHealth(e, cfg)
	default: // render-nginx
		f, err := frontdoor.Probe(ctx, cfg.FrontDoor.Nginx)
		if err != nil {
			return e.fail(exitUsage, "%v", err)
		}
		b, err := frontdoor.Render(cfg.FrontDoorConfig(), f)
		if err != nil {
			return e.fail(exitUsage, "%v", err)
		}
		_, _ = stdout.Write(b)
		return exitOK
	}
}

func cmdRun(e env, cfg node.Config, level string) int {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		return e.fail(exitUsage, "log level %q is not one of debug, info, warn, error", level)
	}
	logger := logging.New(e.stderr, lv).With("component", "observex-node")
	err := node.Run(e.ctx, cfg, node.Options{Logger: logger, Out: e.stdout, Version: version})
	if err != nil {
		logger.Error("node stopped with an error", "error", err.Error())
		return exitFailure
	}
	return exitOK
}

// cmdCheck validates everything the node needs to start. It prepares the
// Front Door in a temporary directory, so it never touches a running
// node's files.
func cmdCheck(e env, cfg node.Config, running bool) int {
	tmp, err := os.MkdirTemp("", "observex-node-check-")
	if err != nil {
		return e.fail(exitFailure, "%v", err)
	}
	defer os.RemoveAll(tmp)
	probe := cfg
	probe.RunDir = tmp
	if !running {
		if _, err := node.CheckPorts(e.ctx, cfg, firewall.Options{}); err != nil {
			return e.fail(exitUsage, "check failed: %v", err)
		}
	}
	prep, err := node.Prepare(e.ctx, probe)
	if err != nil {
		return e.fail(exitUsage, "check failed: %v", err)
	}
	fmt.Fprintf(e.stdout, "configuration: ok (node %s)\n", cfg.NodeID)
	fmt.Fprintf(e.stdout, "nginx: %s with %s\n", prep.Features.Version, orNone(prep.Features.TLSLibrary))
	if cfg.FrontDoor.Plaintext {
		fmt.Fprintln(e.stdout, "tls: off (plaintext)")
	} else {
		for _, l := range []string{"console", "agents"} {
			s := prep.Certificates[l]
			fmt.Fprintf(e.stdout, "tls %s: %s, valid until %s, groups %s\n", l, s.Subject, s.NotAfter.Format(time.DateOnly), strings.Join(prep.Groups[l], ":"))
		}
	}
	if running {
		fmt.Fprintln(e.stdout, "ports: not checked (-running)")
	} else {
		fmt.Fprintln(e.stdout, "ports: free")
	}
	for _, w := range prep.Warnings {
		fmt.Fprintln(e.stdout, "warning:", w)
	}
	return exitOK
}

func orNone(s string) string {
	if s == "" {
		return "no TLS library"
	}
	return s
}

func cmdFirewall(e env, cfg node.Config, running, asJSON, skipPeers bool) int {
	plan, err := cfg.FirewallPlan()
	if err != nil {
		return e.fail(exitUsage, "%v", err)
	}
	r, err := firewall.Check(e.ctx, plan, firewall.Options{NodeRunning: running, SkipPeers: skipPeers})
	if err != nil {
		return e.fail(exitUsage, "%v", err)
	}
	if asJSON {
		enc := json.NewEncoder(e.stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		fmt.Fprint(e.stdout, r.Text())
	}
	if r.Problems > 0 {
		return exitFailure
	}
	return exitOK
}

var localClient = &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}

func fetch(ctx context.Context, url string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := localClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, err
}

func cmdStatus(e env, cfg node.Config) int {
	code, body, err := fetch(e.ctx, "http://"+cfg.Supervisor.Listen+"/status")
	if err != nil {
		return e.fail(exitFailure, "the node is not running or its status endpoint %s does not answer", cfg.Supervisor.Listen)
	}
	var v struct {
		Ready bool `json:"ready"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &v) != nil {
		return e.fail(exitFailure, "unexpected answer from the status endpoint (HTTP %d)", code)
	}
	_, _ = e.stdout.Write(body)
	if !v.Ready {
		return exitFailure
	}
	return exitOK
}

func cmdHealth(e env, cfg node.Config) int {
	code, _, err := fetch(e.ctx, "http://"+cfg.Supervisor.Listen+"/health")
	if err != nil || code != http.StatusOK {
		fmt.Fprintln(e.stdout, "not ready")
		return exitFailure
	}
	fmt.Fprintln(e.stdout, "ready")
	return exitOK
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// cmdInit writes a first node configuration and the node's TLS files. It
// keeps whatever already exists.
func cmdInit(e env, fs *flag.FlagSet, configPath *string, args []string) int {
	nodeID := fs.String("node-id", "", "node ID (lower-case letters, digits, '-'); defaults to the host name")
	var hosts, peers multiFlag
	fs.Var(&hosts, "host", "host name or IP address users and Agents use to reach this node (repeatable); defaults to the host name and its addresses")
	fs.Var(&peers, "peer", "another cluster node's host name or IP address (repeatable)")
	group := fs.String("group", "", "group allowed to read the configuration and the node key (the service group)")
	tlsDir := fs.String("tls-dir", node.DefaultTLSDir, "directory for the TLS files")
	plaintext := fs.Bool("plaintext", false, "development only: no TLS, listeners on loopback")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		return e.fail(exitUsage, "unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	gid := -1
	if *group != "" {
		g, err := user.LookupGroup(*group)
		if err != nil {
			return e.fail(exitUsage, "group %q: %v", *group, err)
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	id := *nodeID
	if id == "" {
		h, err := os.Hostname()
		if err != nil {
			return e.fail(exitUsage, "no -node-id given and the host name is unknown: %v", err)
		}
		id = sanitizeID(h)
	}

	// Configuration.
	if _, err := os.Stat(*configPath); err == nil {
		fmt.Fprintf(e.stdout, "configuration: %s exists; kept\n", *configPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return e.fail(exitFailure, "%v", err)
	} else {
		doc := map[string]any{"node_id": id, "tls_dir": *tlsDir}
		if len(peers) > 0 {
			doc["peers"] = []string(peers)
		}
		if *plaintext {
			doc["front_door"] = map[string]any{"plaintext": true,
				"console": map[string]any{"listen": "127.0.0.1:8080"}, "agents": map[string]any{"listen": "127.0.0.1:8443"}}
		}
		raw, _ := json.MarshalIndent(doc, "", "  ")
		raw = append(raw, '\n')
		if _, err := node.Parse(raw); err != nil {
			return e.fail(exitUsage, "%v", err)
		}
		if err := os.MkdirAll(filepath.Dir(*configPath), 0o755); err != nil {
			return e.fail(exitFailure, "%v", err)
		}
		f, err := os.OpenFile(*configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
		if err != nil {
			return e.fail(exitFailure, "%v", err)
		}
		_, werr := f.Write(raw)
		cerr := f.Close()
		if werr != nil || cerr != nil {
			_ = os.Remove(*configPath)
			return e.fail(exitFailure, "write %s failed", *configPath)
		}
		if gid >= 0 {
			if err := os.Chown(*configPath, -1, gid); err != nil {
				return e.fail(exitFailure, "set the group of %s: %v", *configPath, err)
			}
		}
		fmt.Fprintf(e.stdout, "configuration: wrote %s (node %s)\n", *configPath, id)
	}

	if *plaintext {
		fmt.Fprintln(e.stdout, "tls: skipped (-plaintext)")
		return exitOK
	}
	if len(hosts) == 0 {
		hosts = append(hosts, defaultHosts(id)...)
	}
	files, err := pki.Init(*tlsDir, pki.Options{NodeName: id, Hosts: hosts})
	switch {
	case errors.Is(err, pki.ErrExists):
		fmt.Fprintf(e.stdout, "tls: files in %s exist; kept\n", *tlsDir)
		return exitOK
	case err != nil:
		return e.fail(exitUsage, "%v", err)
	}
	if gid >= 0 {
		for _, p := range []string{files.Dir, files.NodeKey} {
			if err := os.Chown(p, -1, gid); err != nil {
				return e.fail(exitFailure, "set the group of %s: %v", p, err)
			}
		}
	}
	fmt.Fprintf(e.stdout, "tls: wrote the cluster CA and the node certificate to %s for %s\n", *tlsDir, strings.Join(hosts, ", "))
	fmt.Fprintf(e.stdout, "tls: the CA key %s is readable by root only; keep a protected backup of it\n", files.CAKey)
	return exitOK
}

// sanitizeID turns a host name into a node ID.
func sanitizeID(h string) string {
	h = strings.ToLower(strings.SplitN(h, ".", 2)[0])
	var b strings.Builder
	for _, r := range h {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	if len(id) > 63 {
		id = strings.Trim(id[:63], "-")
	}
	if id == "" {
		id = "node"
	}
	return id
}

// defaultHosts are the names a node is usually reached by: the node ID,
// the host's full name and its non-loopback addresses.
func defaultHosts(id string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h != "" && !seen[strings.ToLower(h)] {
			seen[strings.ToLower(h)] = true
			out = append(out, h)
		}
	}
	add(id)
	if h, err := os.Hostname(); err == nil {
		add(h)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		var ips []string
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
				ips = append(ips, ipn.IP.String())
			}
		}
		sort.Strings(ips)
		for _, ip := range ips {
			add(ip)
		}
	}
	return out
}
