package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/node/firewall"
	"github.com/ObservexINC/Observex_managed/internal/node/frontdoor"
	"github.com/ObservexINC/Observex_managed/internal/node/pki"
	"github.com/ObservexINC/Observex_managed/internal/node/selfmon"
	"github.com/ObservexINC/Observex_managed/internal/node/supervisor"
)

// Prepared is what Prepare found and wrote.
type Prepared struct {
	Features frontdoor.Features `json:"nginx"`
	// Groups are the key-exchange groups each listener offers.
	Groups map[string][]string `json:"groups,omitempty"`
	// Certificates describe each listener's certificate.
	Certificates map[string]pki.Summary `json:"certificates,omitempty"`
	ConfigPath   string                 `json:"nginx_conf"`
	Warnings     []string               `json:"warnings,omitempty"`
}

// Prepare checks the TLS files, probes NGINX, writes the Front Door
// configuration and checks it with "nginx -t". It writes only inside the
// run directory.
func Prepare(ctx context.Context, c Config) (Prepared, error) {
	p := Prepared{ConfigPath: c.NginxConfPath()}
	now := time.Now()
	if !c.FrontDoor.Plaintext {
		p.Certificates = map[string]pki.Summary{}
		con := c.FrontDoor.Console
		s, err := pki.CheckPair(con.CertFile, con.KeyFile, now)
		if err != nil {
			return p, fmt.Errorf("console listener: %w", err)
		}
		p.Certificates["console"] = s
		ag := c.FrontDoor.Agents
		s, err = pki.Check(ag.CertFile, ag.KeyFile, ag.ClientCAFile, now)
		if err != nil {
			return p, fmt.Errorf("agents listener: %w", err)
		}
		p.Certificates["agents"] = s
		for _, l := range []string{"console", "agents"} {
			for _, w := range p.Certificates[l].Warnings {
				p.Warnings = append(p.Warnings, l+" listener: "+w)
			}
		}
	} else {
		p.Warnings = append(p.Warnings, "plaintext is set: the Front Door runs without TLS and cannot check client certificates; use it on a trusted development machine only")
	}

	f, err := frontdoor.Probe(ctx, c.FrontDoor.Nginx)
	if err != nil {
		return p, err
	}
	p.Features = f
	if !c.FrontDoor.Plaintext {
		p.Groups = map[string][]string{}
		for name, l := range map[string]frontdoor.Listener{"console": c.FrontDoor.Console, "agents": c.FrontDoor.Agents} {
			g, err := frontdoor.EffectiveGroups(l, f)
			if err != nil {
				return p, err
			}
			p.Groups[name] = g
		}
		if !f.HybridPQ {
			p.Warnings = append(p.Warnings, "this NGINX runs with "+f.TLSLibrary+", which cannot offer the hybrid post-quantum group "+frontdoor.GroupHybridPQ+"; it needs OpenSSL 3.5 or later")
		}
	}
	conf, err := frontdoor.Render(c.FrontDoorConfig(), f)
	if err != nil {
		return p, err
	}
	if err := os.MkdirAll(c.FrontDoorRunDir(), 0o750); err != nil {
		return p, fmt.Errorf("run directory: %w", err)
	}
	if err := writeAtomic(p.ConfigPath, conf, 0o640); err != nil {
		return p, fmt.Errorf("write the NGINX configuration: %w", err)
	}
	if err := frontdoor.Check(ctx, c.FrontDoor.Nginx, c.FrontDoorRunDir(), p.ConfigPath); err != nil {
		return p, err
	}
	if st, err := os.Stat(c.DataDir); err != nil || !st.IsDir() {
		p.Warnings = append(p.Warnings, "data_dir "+c.DataDir+" does not exist; the installer creates it")
	}
	return p, nil
}

// writeAtomic replaces a file in one step, so NGINX never reads a half
// written configuration.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// noFirewallCommands is the runner used by the start-up port check: start
// does not read the host firewall (observex-node firewall does).
func noFirewallCommands(context.Context, []string) (string, error) {
	return "", errors.New("not read at start-up")
}

// CheckPorts checks, before anything starts, that every address the node
// binds now is free and every local address is loopback. It reports by
// name, so a conflict is clear before NGINX fails on it.
func CheckPorts(ctx context.Context, c Config, opt firewall.Options) (firewall.Report, error) {
	plan, err := c.FirewallPlan()
	if err != nil {
		return firewall.Report{}, err
	}
	opt.SkipPeers = true
	if opt.Run == nil {
		opt.Run = noFirewallCommands
	}
	r, err := firewall.Check(ctx, plan, opt)
	if err != nil {
		return r, err
	}
	var bad []string
	for _, f := range r.Findings {
		if firewall.IsBindProblem(f.Status) {
			bad = append(bad, f.Detail+" ("+f.Target+")")
		}
	}
	if len(bad) > 0 {
		return r, errors.New("ports: " + strings.Join(bad, "; "))
	}
	return r, nil
}

// Registry returns the node's self-monitoring registry.
func Registry(c Config, sup *supervisor.Supervisor, prep Prepared, version string) *selfmon.Registry {
	r := &selfmon.Registry{}
	tlsMode := "on"
	if c.FrontDoor.Plaintext {
		tlsMode = "off"
	}
	r.Register(
		selfmon.Info("observex_node_info", "The node's identity and build.",
			selfmon.L("node_id", c.NodeID), selfmon.L("version", version)),
		selfmon.Info("observex_node_front_door_info", "The Front Door's NGINX, TLS library and key-exchange groups.",
			selfmon.L("nginx_version", prep.Features.Version), selfmon.L("tls_library", prep.Features.TLSLibrary),
			selfmon.L("tls", tlsMode), selfmon.L("console_groups", strings.Join(prep.Groups["console"], ":")),
			selfmon.L("agents_groups", strings.Join(prep.Groups["agents"], ":"))),
		selfmon.Supervisor{Status: sup.Status},
		selfmon.Processes{PIDs: func() map[string]int {
			m := map[string]int{}
			for _, cs := range sup.Status().Components {
				if cs.PID > 0 {
					m[cs.Name] = cs.PID
				}
			}
			return m
		}},
		selfmon.Host{},
		selfmon.Disks{Volumes: map[string]string{"data": c.DataDir, "run": c.RunDir}},
		selfmon.CollectorFunc{CollectorName: "certificates", Fn: func(b *selfmon.Batch) {
			for name, s := range prep.Certificates {
				b.Gauge("observex_node_tls_certificate_expiry_seconds", "Seconds until the listener's certificate expires.",
					time.Until(s.NotAfter).Seconds(), selfmon.L("listener", name))
			}
		}},
	)
	return r
}

// StatusHandler serves the supervisor's endpoints and /metrics.
func StatusHandler(nodeID string, sup *supervisor.Supervisor, reg *selfmon.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", reg.Handler())
	mux.Handle("/", sup.Handler(nodeID))
	return mux
}

// Options control Run.
type Options struct {
	Logger *slog.Logger
	// Out receives the components' output, one redacted line at a time.
	Out     io.Writer
	Version string
	// Firewall is used by the start-up port check (tests replace it).
	Firewall firewall.Options
	// Started is called once the status endpoint serves, with its address.
	Started func(statusAddr string, sup *supervisor.Supervisor)
}

// Run prepares the node and runs it until ctx ends, then stops the
// components in reverse order. It returns nil after a clean stop.
func Run(ctx context.Context, c Config, opt Options) error {
	logger := opt.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	logger = logger.With("node_id", c.NodeID)
	if opt.Out == nil {
		opt.Out = os.Stdout
	}
	if _, err := CheckPorts(ctx, c, opt.Firewall); err != nil {
		return err
	}
	prep, err := Prepare(ctx, c)
	if err != nil {
		return err
	}
	for _, w := range prep.Warnings {
		logger.Warn(w)
	}
	sup, err := supervisor.New(c.Specs(), c.Policy(), logger, opt.Out)
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", c.Supervisor.Listen)
	if err != nil {
		return fmt.Errorf("supervisor status address %s: %w", c.Supervisor.Listen, err)
	}
	srv := &http.Server{
		Handler:           StatusHandler(c.NodeID, sup, Registry(c, sup, prep, opt.Version)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	if opt.Started != nil {
		opt.Started(ln.Addr().String(), sup)
	}
	logger.Info("node starting",
		"version", opt.Version, "order", sup.Order(),
		"console", c.FrontDoor.Console.Listen, "agents", c.FrontDoor.Agents.Listen,
		"status", c.Supervisor.Listen, "nginx", prep.Features.Version, "tls_library", prep.Features.TLSLibrary)
	runErr := sup.Run(ctx)

	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("status endpoint stopped unexpectedly", "error", err.Error())
	}
	if runErr != nil {
		return runErr
	}
	logger.Info("node stopped cleanly")
	return nil
}
