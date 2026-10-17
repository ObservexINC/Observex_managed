// Package node assembles a managed node (OD-25; development plan G01): it
// reads the node configuration, prepares and checks the Front Door, checks
// the node's ports, and runs the Node Supervisor with self-monitoring.
//
// At G01 the supervisor runs one component, the Front Door (NGINX). The
// ObserveX Server and the Embedded Gateway join it when they exist (G03 and
// G04, integrated in G06); their loopback addresses are reserved here so
// the Front Door's routes and the firewall report are already complete.
// Until then the Front Door answers their routes with 502, and
// /node/health reports the node itself.
//
// Only the Front Door listens on a non-loopback address. Every other
// address in the configuration must be loopback.
package node

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/node/firewall"
	"github.com/ObservexINC/Observex_managed/internal/node/frontdoor"
	"github.com/ObservexINC/Observex_managed/internal/node/pki"
	"github.com/ObservexINC/Observex_managed/internal/node/supervisor"
	"github.com/ObservexINC/Observex_managed/internal/platform/config"
)

// Defaults.
const (
	DefaultConfigPath        = "/etc/observex/node.json"
	DefaultRunDir            = "/run/observex"
	DefaultDataDir           = "/var/lib/observex"
	DefaultTLSDir            = "/etc/observex/tls"
	DefaultNginx             = "/usr/sbin/nginx"
	DefaultConsoleListen     = "0.0.0.0:443"
	DefaultAgentsListen      = "0.0.0.0:9443"
	DefaultSupervisorListen  = "127.0.0.1:8180"
	DefaultProbeListen       = "127.0.0.1:8181"
	DefaultServerAddr        = "127.0.0.1:8182"
	DefaultGatewayAddr       = "127.0.0.1:8183"
	DefaultWorkerProcesses   = 2
	DefaultWorkerConnections = 4096
	DefaultMaxBodyBytes      = 16 << 20
	DefaultFrontDoorStop     = 20 * time.Second
)

// Config is the node configuration file (JSON). It holds no secrets: TLS
// keys are referenced by path.
type Config struct {
	// NodeID names the node: lower-case letters, digits and '-'.
	NodeID string `json:"node_id"`
	// RunDir holds generated files: the NGINX configuration, its pid file
	// and temporary files. It is recreated at every start.
	RunDir string `json:"run_dir,omitempty"`
	// DataDir is the node's persistent data volume.
	DataDir string `json:"data_dir,omitempty"`
	// TLSDir holds the node's certificates (see package pki); it supplies
	// the default TLS file paths of both Front Door listeners.
	TLSDir string `json:"tls_dir,omitempty"`
	// Peers are the other cluster nodes (host names or IP addresses), for
	// the firewall report.
	Peers      []string         `json:"peers,omitempty"`
	Supervisor SupervisorConfig `json:"supervisor"`
	FrontDoor  FrontDoorConfig  `json:"front_door"`
	// Upstreams are the loopback addresses of components that join the
	// node in later goals.
	Upstreams Upstreams `json:"upstreams"`
}

// SupervisorConfig configures the Node Supervisor. Zero durations take the
// supervisor's defaults.
type SupervisorConfig struct {
	// Listen is the loopback address of the status and metrics endpoint.
	Listen               string          `json:"listen,omitempty"`
	StartTimeout         config.Duration `json:"start_timeout,omitempty"`
	InitialBackoff       config.Duration `json:"initial_backoff,omitempty"`
	MaxBackoff           config.Duration `json:"max_backoff,omitempty"`
	StableAfter          config.Duration `json:"stable_after,omitempty"`
	MaxRestarts          int             `json:"max_restarts,omitempty"`
	Window               config.Duration `json:"window,omitempty"`
	ProbeInterval        config.Duration `json:"probe_interval,omitempty"`
	ProbeTimeout         config.Duration `json:"probe_timeout,omitempty"`
	RestartAfterNotReady config.Duration `json:"restart_after_not_ready,omitempty"`
}

// FrontDoorConfig configures the Front Door.
type FrontDoorConfig struct {
	// Nginx is the NGINX executable.
	Nginx       string             `json:"nginx,omitempty"`
	Console     frontdoor.Listener `json:"console"`
	Agents      frontdoor.Listener `json:"agents"`
	ProbeListen string             `json:"probe_listen,omitempty"`
	// WorkerProcesses, WorkerConnections and MaxBodyBytes have defaults.
	WorkerProcesses   int   `json:"worker_processes,omitempty"`
	WorkerConnections int   `json:"worker_connections,omitempty"`
	MaxBodyBytes      int64 `json:"max_body_bytes,omitempty"`
	// StopTimeout is how long NGINX may take to finish open requests.
	StopTimeout config.Duration `json:"stop_timeout,omitempty"`
	// Plaintext turns TLS off. For development on a trusted machine only.
	Plaintext bool `json:"plaintext,omitempty"`
}

// Upstreams are components' loopback addresses.
type Upstreams struct {
	Server  string `json:"server,omitempty"`
	Gateway string `json:"gateway,omitempty"`
}

var nodeIDRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Parse decodes a node configuration strictly (unknown fields are errors),
// fills defaults and validates it.
func Parse(data []byte) (Config, error) {
	var c Config
	if err := config.Decode(data, &c); err != nil {
		return Config{}, fmt.Errorf("node configuration: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Load reads and parses a node configuration file.
func Load(p string) (Config, error) {
	f, err := os.Open(p)
	if err != nil {
		return Config{}, fmt.Errorf("node configuration: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, config.MaxSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("node configuration: %w", err)
	}
	if len(data) > config.MaxSize {
		return Config{}, fmt.Errorf("node configuration: %w", config.ErrTooLarge)
	}
	return Parse(data)
}

func (c *Config) applyDefaults() {
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	def(&c.RunDir, DefaultRunDir)
	def(&c.DataDir, DefaultDataDir)
	def(&c.TLSDir, DefaultTLSDir)
	def(&c.Supervisor.Listen, DefaultSupervisorListen)
	def(&c.FrontDoor.Nginx, DefaultNginx)
	def(&c.FrontDoor.Console.Listen, DefaultConsoleListen)
	def(&c.FrontDoor.Agents.Listen, DefaultAgentsListen)
	def(&c.FrontDoor.ProbeListen, DefaultProbeListen)
	def(&c.Upstreams.Server, DefaultServerAddr)
	def(&c.Upstreams.Gateway, DefaultGatewayAddr)
	if c.FrontDoor.WorkerProcesses == 0 {
		c.FrontDoor.WorkerProcesses = DefaultWorkerProcesses
	}
	if c.FrontDoor.WorkerConnections == 0 {
		c.FrontDoor.WorkerConnections = DefaultWorkerConnections
	}
	if c.FrontDoor.MaxBodyBytes == 0 {
		c.FrontDoor.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if c.FrontDoor.StopTimeout == 0 {
		c.FrontDoor.StopTimeout = config.Duration(DefaultFrontDoorStop)
	}
	if !c.FrontDoor.Plaintext {
		f := pki.Paths(c.TLSDir)
		for _, l := range []*frontdoor.Listener{&c.FrontDoor.Console, &c.FrontDoor.Agents} {
			def(&l.CertFile, f.NodeCert)
			def(&l.KeyFile, f.NodeKey)
		}
		def(&c.FrontDoor.Agents.ClientCAFile, f.CACert)
	}
}

func (c Config) validate() error {
	if !nodeIDRE.MatchString(c.NodeID) {
		return errors.New("node configuration: node_id is required: lower-case letters, digits and '-', at most 63 characters")
	}
	for name, p := range map[string]string{"run_dir": c.RunDir, "data_dir": c.DataDir, "tls_dir": c.TLSDir} {
		if !path.IsAbs(p) || path.Clean(p) != p { // nodes run on Linux: slash-separated
			return fmt.Errorf("node configuration: %s must be a clean absolute path", name)
		}
	}
	if path.Clean(c.RunDir) == "/" || path.Clean(c.DataDir) == "/" {
		return errors.New("node configuration: run_dir and data_dir must not be /")
	}
	if !isLoopback(c.Supervisor.Listen) {
		return errors.New("node configuration: supervisor.listen must be a loopback address (only the Front Door is reachable from outside)")
	}
	if c.Supervisor.MaxRestarts < 0 {
		return errors.New("node configuration: supervisor.max_restarts must not be negative")
	}
	if err := c.FrontDoorConfig().Validate(); err != nil {
		return fmt.Errorf("node configuration: %w", err)
	}
	if _, err := c.FirewallPlan(); err != nil {
		return fmt.Errorf("node configuration: %w", err)
	}
	return nil
}

func isLoopback(a string) bool {
	host, _, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// Policy returns the supervisor policy; zero fields take the supervisor's
// defaults.
func (c Config) Policy() supervisor.Policy {
	s := c.Supervisor
	return supervisor.Policy{
		StartTimeout:         s.StartTimeout.D(),
		InitialBackoff:       s.InitialBackoff.D(),
		MaxBackoff:           s.MaxBackoff.D(),
		StableAfter:          s.StableAfter.D(),
		MaxRestarts:          s.MaxRestarts,
		Window:               s.Window.D(),
		ProbeInterval:        s.ProbeInterval.D(),
		ProbeTimeout:         s.ProbeTimeout.D(),
		RestartAfterNotReady: s.RestartAfterNotReady.D(),
	}
}

// FrontDoorRunDir is the Front Door's directory inside RunDir.
func (c Config) FrontDoorRunDir() string { return path.Join(c.RunDir, "frontdoor") }

// NginxConfPath is where the generated NGINX configuration is written.
func (c Config) NginxConfPath() string { return path.Join(c.FrontDoorRunDir(), "nginx.conf") }

// FrontDoorConfig returns the Front Door's configuration.
func (c Config) FrontDoorConfig() frontdoor.Config {
	return frontdoor.Config{
		Console:           c.FrontDoor.Console,
		Agents:            c.FrontDoor.Agents,
		ProbeListen:       c.FrontDoor.ProbeListen,
		ServerAddr:        c.Upstreams.Server,
		GatewayAddr:       c.Upstreams.Gateway,
		SupervisorAddr:    c.Supervisor.Listen,
		MaxBodyBytes:      c.FrontDoor.MaxBodyBytes,
		WorkerProcesses:   c.FrontDoor.WorkerProcesses,
		WorkerConnections: c.FrontDoor.WorkerConnections,
		RunDir:            c.FrontDoorRunDir(),
		Plaintext:         c.FrontDoor.Plaintext,
	}
}

// PlannedClusterPort is a port that a later goal starts using. The firewall
// report lists it early so administrators can request firewall changes
// ahead of time; it is not checked until its goal.
type PlannedClusterPort struct {
	Port    int
	Purpose string
	Goal    string
}

// PlannedClusterPorts are the engines' standard ports. Each is confirmed or
// changed by its goal's ADR.
var PlannedClusterPorts = []PlannedClusterPort{
	{2380, "ConfigurationStore peers (etcd)", "G02"},
	{7000, "MetricStore inter-node (Cassandra)", "G02"},
	{9042, "MetricStore clients (Cassandra CQL)", "G02"},
	{9200, "SearchStore clients (OpenSearch HTTP)", "G02"},
	{9300, "SearchStore inter-node (OpenSearch transport)", "G02"},
	{8190, "ObserveX Server cluster traffic", "G03"},
}

// FirewallPlan is what the firewall report checks.
func (c Config) FirewallPlan() (firewall.Plan, error) {
	type p struct {
		bind, purpose string
		exp           firewall.Exposure
		goal          string
	}
	list := []p{
		{c.FrontDoor.Console.Listen, "Console and API (Front Door)", firewall.Public, ""},
		{c.FrontDoor.Agents.Listen, "Agents and Gateways (Front Door)", firewall.Public, ""},
		{c.Supervisor.Listen, "Node Supervisor status and metrics", firewall.Local, ""},
		{c.FrontDoor.ProbeListen, "Front Door liveness probe", firewall.Local, ""},
		{c.Upstreams.Server, "ObserveX Server", firewall.Local, "G03"},
		{c.Upstreams.Gateway, "Embedded Gateway", firewall.Local, "G04"},
	}
	for _, pc := range PlannedClusterPorts {
		list = append(list, p{net.JoinHostPort("0.0.0.0", fmt.Sprint(pc.Port)), pc.Purpose, firewall.Cluster, pc.Goal})
	}
	plan := firewall.Plan{Peers: append([]string(nil), c.Peers...)}
	for _, e := range list {
		pt, err := firewall.NewPort(e.bind, e.purpose, e.exp)
		if err != nil {
			return firewall.Plan{}, err
		}
		pt.Goal = e.goal
		plan.Ports = append(plan.Ports, pt)
	}
	return plan, plan.Validate()
}

// Specs describes the node's components for the supervisor. Components get
// the minimal default environment, never the supervisor's own.
func (c Config) Specs() []supervisor.Spec {
	return []supervisor.Spec{{
		Name:        "front-door",
		Path:        c.FrontDoor.Nginx,
		Args:        frontdoor.Args(c.FrontDoorRunDir(), c.NginxConfPath()),
		Ready:       supervisor.HTTPReady("http://" + c.FrontDoor.ProbeListen + "/livez"),
		StopSignal:  gracefulStop, // NGINX finishes open requests on SIGQUIT
		StopTimeout: c.FrontDoor.StopTimeout.D(),
	}}
}
