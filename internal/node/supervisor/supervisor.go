// Package supervisor is the managed node's Node Supervisor (OD-25 policy 3;
// development plan G01).
//
// It starts a node's components as child processes in dependency order,
// waiting for each to be ready before starting the components that depend
// on it. It restarts a component that exits, with bounded exponential
// backoff, and marks a component failed when it restarts too often (a crash
// loop). On shutdown it stops the components in reverse order, each with a
// grace period and then a kill, and reports exactly which components did
// not stop cleanly.
//
// Liveness and readiness are separate. A component is alive while its
// process runs and ready while its readiness check passes. The node is ready
// only when every component is ready. A component that stays not ready for
// longer than Policy.RestartAfterNotReady is restarted; with the default of
// zero, only an exit causes a restart.
//
// Each component runs in its own process group, so a kill also reaches the
// processes it started (NGINX workers, for example). On Linux each child is
// killed by the kernel if the supervisor dies.
//
// The supervisor never logs a component's environment or arguments, and it
// passes every line a component writes through logging.RedactString.
//
// This package is ported from the M1/M2 supervisor of the earlier ObserveX
// codebase (Voxmatic/observex, internal/node/supervisor at a23009a), which
// Astra validated, with these changes: log/slog instead of zap, redacted
// child output, an explicit stop report, a minimal default environment, and
// restart of a component that stays not ready.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// ReadyFunc reports whether a component is ready.
type ReadyFunc func(ctx context.Context) error

// Spec describes one component.
type Spec struct {
	Name string
	Path string
	Args []string
	// Env is the child's whole environment. Nil gives the minimal
	// environment from DefaultEnv, never the supervisor's own, so no
	// credential in the supervisor's environment reaches a child by
	// accident.
	Env []string
	// Dir is the working directory; empty means the supervisor's.
	Dir       string
	DependsOn []string
	// Ready reports readiness. Nil means ready once the process has started.
	Ready ReadyFunc
	// StopSignal asks the process to stop gracefully: SIGTERM when nil
	// (NGINX uses SIGQUIT). On Windows a stop is always a kill.
	StopSignal os.Signal
	// StopTimeout is how long to wait after StopSignal before killing.
	StopTimeout time.Duration
}

// DefaultEnv is the environment of a component whose Spec.Env is nil.
func DefaultEnv() []string {
	return []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "TZ=UTC"}
}

// Policy controls start-up, probing and restarts.
type Policy struct {
	StartTimeout   time.Duration // how long a starting component may take to become ready
	InitialBackoff time.Duration // first restart delay
	MaxBackoff     time.Duration // longest restart delay
	StableAfter    time.Duration // a run this long resets the backoff
	MaxRestarts    int           // restarts allowed within Window before the component is failed
	Window         time.Duration
	ProbeInterval  time.Duration // readiness checks of running components
	ProbeTimeout   time.Duration // one readiness check
	StopTimeout    time.Duration // default for Spec.StopTimeout
	// RestartAfterNotReady restarts a component that was ready and has
	// been not ready for this long. Zero disables it.
	RestartAfterNotReady time.Duration
}

// DefaultPolicy is the policy used for any field left zero.
var DefaultPolicy = Policy{
	StartTimeout:   30 * time.Second,
	InitialBackoff: time.Second,
	MaxBackoff:     30 * time.Second,
	StableAfter:    60 * time.Second,
	MaxRestarts:    5,
	Window:         5 * time.Minute,
	ProbeInterval:  2 * time.Second,
	ProbeTimeout:   2 * time.Second,
	StopTimeout:    10 * time.Second,
}

// State is a component's state.
type State string

// Component states.
const (
	StatePending  State = "pending"   // waiting for its dependencies
	StateStarting State = "starting"  // process started, not yet ready
	StateReady    State = "ready"     // running and ready
	StateNotReady State = "not_ready" // running, readiness check failing
	StateBackoff  State = "backoff"   // exited; waiting to restart
	StateFailed   State = "failed"    // crash loop or cannot start; not restarted
	StateStopping State = "stopping"
	StateStopped  State = "stopped"
)

// ComponentStatus is one component's entry in a Status.
type ComponentStatus struct {
	Name      string    `json:"name"`
	State     State     `json:"state"`
	PID       int       `json:"pid,omitempty"`
	Restarts  int       `json:"restarts"`
	LastExit  string    `json:"last_exit,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	Since     time.Time `json:"since"`
}

// Status is the node's state.
type Status struct {
	Ready      bool              `json:"ready"`
	Stopping   bool              `json:"stopping"`
	Started    time.Time         `json:"started"`
	Components []ComponentStatus `json:"components"`
}

// Stop outcomes, in StopReport.
const (
	OutcomeNotRunning = "not_running" // nothing to stop
	OutcomeStopped    = "stopped"     // exited with status 0 after the stop signal
	OutcomeUnclean    = "unclean"     // exited after the stop signal, but not with status 0
	OutcomeKilled     = "killed"      // did not exit within its stop timeout and was killed
	OutcomeStuck      = "stuck"       // still running after the kill
)

// StopReport is one component's shutdown result.
type StopReport struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Exit    string `json:"exit,omitempty"`
}

// StopError is returned by Run when any component did not stop cleanly.
type StopError struct {
	Reports []StopReport
}

func (e *StopError) Error() string {
	var bad []string
	for _, r := range e.Reports {
		if r.Outcome != OutcomeStopped && r.Outcome != OutcomeNotRunning {
			bad = append(bad, r.Name+" "+r.Outcome)
		}
	}
	return "shutdown incomplete: " + strings.Join(bad, ", ")
}

type component struct {
	spec Spec

	mu         sync.Mutex
	state      State
	since      time.Time
	cmd        *exec.Cmd
	exited     chan struct{} // closed when the current process has exited
	exitErr    error         // the current process's Wait result, set before exited closes
	restarts   int
	history    []time.Time // restart times within the window
	lastExit   string
	lastError  string
	stopReport StopReport

	firstReady chan struct{} // closed the first time the component is ready
	readyOnce  sync.Once
}

// Supervisor runs a set of components.
type Supervisor struct {
	policy  Policy
	logger  *slog.Logger
	out     *lineSink
	order   []string
	comps   map[string]*component
	started time.Time

	mu       sync.Mutex
	stopping bool // set once shutdown begins; no process starts after it
	running  bool
}

var errStopping = errors.New("supervisor is stopping")

// New validates the specs (valid and unique names, an executable, known
// dependencies, no cycles) and returns a supervisor. Component output goes
// to out one line at a time, prefixed with the component's name and
// redacted.
func New(specs []Spec, policy Policy, logger *slog.Logger, out io.Writer) (*Supervisor, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if out == nil {
		out = io.Discard
	}
	policy = withDefaults(policy)
	if len(specs) == 0 {
		return nil, errors.New("supervisor: no components")
	}
	comps := map[string]*component{}
	for _, sp := range specs {
		if !validName(sp.Name) {
			return nil, fmt.Errorf("supervisor: component name %q is not valid (use a-z, 0-9 and '-', at most 32 characters)", sp.Name)
		}
		if _, dup := comps[sp.Name]; dup {
			return nil, fmt.Errorf("supervisor: component %q defined twice", sp.Name)
		}
		if sp.Path == "" {
			return nil, fmt.Errorf("supervisor: component %q has no executable", sp.Name)
		}
		if sp.StopTimeout <= 0 {
			sp.StopTimeout = policy.StopTimeout
		}
		if sp.Env == nil {
			sp.Env = DefaultEnv()
		}
		sp.Args = append([]string(nil), sp.Args...)
		sp.Env = append([]string(nil), sp.Env...)
		sp.DependsOn = append([]string(nil), sp.DependsOn...)
		comps[sp.Name] = &component{spec: sp, state: StatePending, since: time.Now(), firstReady: make(chan struct{})}
	}
	order, err := topoOrder(comps)
	if err != nil {
		return nil, err
	}
	return &Supervisor{policy: policy, logger: logger, out: &lineSink{w: out}, order: order, comps: comps}, nil
}

func withDefaults(p Policy) Policy {
	fill := func(d *time.Duration, def time.Duration) {
		if *d <= 0 {
			*d = def
		}
	}
	fill(&p.StartTimeout, DefaultPolicy.StartTimeout)
	fill(&p.InitialBackoff, DefaultPolicy.InitialBackoff)
	fill(&p.MaxBackoff, DefaultPolicy.MaxBackoff)
	fill(&p.StableAfter, DefaultPolicy.StableAfter)
	fill(&p.Window, DefaultPolicy.Window)
	fill(&p.ProbeInterval, DefaultPolicy.ProbeInterval)
	fill(&p.ProbeTimeout, DefaultPolicy.ProbeTimeout)
	fill(&p.StopTimeout, DefaultPolicy.StopTimeout)
	if p.MaxRestarts <= 0 {
		p.MaxRestarts = DefaultPolicy.MaxRestarts
	}
	if p.MaxBackoff < p.InitialBackoff {
		p.MaxBackoff = p.InitialBackoff
	}
	if p.RestartAfterNotReady < 0 {
		p.RestartAfterNotReady = 0
	}
	return p
}

func validName(n string) bool {
	if n == "" || len(n) > 32 || n[0] == '-' {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func topoOrder(comps map[string]*component) ([]string, error) {
	names := make([]string, 0, len(comps))
	for n := range comps {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, d := range comps[n].spec.DependsOn {
			if _, ok := comps[d]; !ok {
				return nil, fmt.Errorf("supervisor: component %q depends on unknown component %q", n, d)
			}
		}
	}
	state := map[string]int{} // 0 new, 1 visiting, 2 done
	var out, path []string
	var visit func(string) error
	visit = func(n string) error {
		switch state[n] {
		case 2:
			return nil
		case 1:
			i := 0
			for path[i] != n {
				i++
			}
			return fmt.Errorf("supervisor: dependency cycle: %s -> %s", strings.Join(path[i:], " -> "), n)
		}
		state[n] = 1
		path = append(path, n)
		deps := append([]string(nil), comps[n].spec.DependsOn...)
		sort.Strings(deps)
		for _, d := range deps {
			if err := visit(d); err != nil {
				return err
			}
		}
		path = path[:len(path)-1]
		state[n] = 2
		out = append(out, n)
		return nil
	}
	for _, n := range names {
		if err := visit(n); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Order returns the start order.
func (s *Supervisor) Order() []string { return append([]string(nil), s.order...) }

// Run starts the components and supervises them until ctx ends; then it
// stops them in reverse order. It returns nil when every component stopped
// cleanly and a *StopError otherwise. Run may be called once.
func (s *Supervisor) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("supervisor: Run called twice")
	}
	s.running = true
	s.started = time.Now()
	s.mu.Unlock()

	runCtx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, n := range s.order {
		c := s.comps[n]
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.manage(runCtx, c)
		}()
	}
	<-ctx.Done()
	s.logger.Info("stopping components")
	s.mu.Lock()
	s.stopping = true // no process starts after this point
	s.mu.Unlock()
	cancel()
	// manage goroutines return promptly once runCtx ends: a component in
	// backoff stops waiting, a running one stops being watched. Stopping
	// happens here, in reverse order.
	wg.Wait()
	reports := make([]StopReport, 0, len(s.order))
	clean := true
	for i := len(s.order) - 1; i >= 0; i-- {
		r := s.stop(s.comps[s.order[i]])
		reports = append(reports, r)
		if r.Outcome != OutcomeStopped && r.Outcome != OutcomeNotRunning {
			clean = false
		}
	}
	s.out.flush()
	if !clean {
		err := &StopError{Reports: reports}
		s.logger.Error("components did not all stop cleanly", "error", err.Error())
		return err
	}
	s.logger.Info("all components stopped")
	return nil
}

// StopReports returns the shutdown result of every component, in stop
// order. It is complete once Run has returned.
func (s *Supervisor) StopReports() []StopReport {
	out := make([]StopReport, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		c := s.comps[s.order[i]]
		c.mu.Lock()
		out = append(out, c.stopReport)
		c.mu.Unlock()
	}
	return out
}

// manage runs one component: wait for its dependencies, start, watch,
// restart with backoff, until ctx ends or the component fails.
func (s *Supervisor) manage(ctx context.Context, c *component) {
	for _, d := range c.spec.DependsOn {
		select {
		case <-s.comps[d].firstReady:
		case <-ctx.Done():
			return
		}
	}
	backoff := s.policy.InitialBackoff
	for {
		started := time.Now()
		exited, err := s.start(c)
		if errors.Is(err, errStopping) {
			return
		}
		if err != nil {
			s.logger.Error("component cannot start", "child", c.spec.Name, "error", err.Error())
			c.set(StateFailed, "cannot start: "+err.Error())
			return
		}
		s.watch(ctx, c, exited)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) >= s.policy.StableAfter {
			backoff = s.policy.InitialBackoff
		}
		if !c.recordRestart(time.Now(), s.policy) {
			s.logger.Error("component is restarting too often; it will not be restarted",
				"child", c.spec.Name, "max_restarts", s.policy.MaxRestarts, "window", s.policy.Window.String())
			c.set(StateFailed, fmt.Sprintf("crash loop: more than %d restarts in %s", s.policy.MaxRestarts, s.policy.Window))
			return
		}
		c.set(StateBackoff, "")
		s.logger.Warn("component exited; restarting", "child", c.spec.Name, "backoff", backoff.String())
		t := time.NewTimer(backoff)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return
		}
		backoff *= 2
		if backoff > s.policy.MaxBackoff {
			backoff = s.policy.MaxBackoff
		}
	}
}

// orphanWaitDelay is how long Wait keeps reading a dead child's output
// pipes while processes it started still hold them.
const orphanWaitDelay = time.Second

// start launches the process.
func (s *Supervisor) start(c *component) (<-chan struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return nil, errStopping
	}
	cmd := exec.Command(c.spec.Path, c.spec.Args...)
	cmd.Env = c.spec.Env
	cmd.Dir = c.spec.Dir
	w := s.out.prefixed(c.spec.Name)
	cmd.Stdout, cmd.Stderr = w, w
	setProcAttrs(cmd)
	// A child's own children (NGINX workers) inherit its output pipes. If
	// the child dies first, Wait would block until they exit too, and the
	// supervisor would never see the death. WaitDelay bounds that wait.
	cmd.WaitDelay = orphanWaitDelay
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	exited := make(chan struct{})
	c.mu.Lock()
	c.cmd = cmd
	c.exited = exited
	c.exitErr = nil
	c.state, c.since = StateStarting, time.Now()
	c.mu.Unlock()
	s.logger.Info("component started", "child", c.spec.Name, "pid", cmd.Process.Pid)
	go func() {
		err := cmd.Wait()
		// ErrWaitDelay means the process exited but something it started
		// still held its output. The exit status is what counts.
		leftovers := errors.Is(err, exec.ErrWaitDelay)
		if leftovers && cmd.ProcessState != nil && cmd.ProcessState.Success() {
			err = nil
		}
		// Whatever the child left behind in its process group (NGINX
		// workers after their master was killed) still holds its listening
		// sockets and would make the restart fail. Remove it before the
		// component counts as exited.
		killAll(cmd)
		if leftovers {
			s.logger.Warn("component exited but left processes behind; they were killed", "child", c.spec.Name)
		}
		c.mu.Lock()
		c.exitErr = err
		c.lastExit = exitText(err)
		c.mu.Unlock()
		close(exited)
	}()
	return exited, nil
}

// watch waits for readiness, then probes until the process exits or ctx
// ends.
func (s *Supervisor) watch(ctx context.Context, c *component, exited <-chan struct{}) {
	deadline := time.Now().Add(s.policy.StartTimeout)
	fastProbe := minDuration(100*time.Millisecond, s.policy.ProbeInterval)
	tick := time.NewTicker(fastProbe)
	defer tick.Stop()
	ready := false
	var lastProbe, notReadySince time.Time
	for {
		interval := s.policy.ProbeInterval
		if !ready {
			interval = fastProbe
		}
		if time.Since(lastProbe) >= interval {
			lastProbe = time.Now()
			err := s.check(ctx, c)
			switch {
			case ctx.Err() != nil:
				return
			case err == nil && !ready:
				ready = true
				c.set(StateReady, "")
				// Log before releasing the components that wait for this
				// one, so the log shows "ready" before their "started".
				s.logger.Info("component ready", "child", c.spec.Name)
				c.readyOnce.Do(func() { close(c.firstReady) })
			case err == nil:
				notReadySince = time.Time{}
				if c.get() == StateNotReady {
					c.set(StateReady, "")
					s.logger.Info("component ready again", "child", c.spec.Name)
				}
			case ready:
				if notReadySince.IsZero() {
					notReadySince = time.Now()
					s.logger.Warn("component not ready", "child", c.spec.Name, "reason", err.Error())
				}
				c.set(StateNotReady, err.Error())
				if s.policy.RestartAfterNotReady > 0 && time.Since(notReadySince) >= s.policy.RestartAfterNotReady {
					s.logger.Error("component not ready for too long; restarting it", "child", c.spec.Name,
						"not_ready_for", s.policy.RestartAfterNotReady.String())
					c.setError("not ready for " + s.policy.RestartAfterNotReady.String() + ": " + err.Error())
					s.stop(c)
					return
				}
			case time.Now().After(deadline):
				s.logger.Error("component did not become ready in time; stopping it", "child", c.spec.Name,
					"start_timeout", s.policy.StartTimeout.String())
				c.setError("not ready within " + s.policy.StartTimeout.String() + ": " + err.Error())
				s.stop(c)
				return
			}
		}
		select {
		case <-exited:
			if ctx.Err() == nil {
				c.mu.Lock()
				exit := c.lastExit
				c.mu.Unlock()
				s.logger.Warn("component exited", "child", c.spec.Name, "exit", exit)
			}
			return
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Supervisor) check(ctx context.Context, c *component) error {
	if c.spec.Ready == nil {
		return nil
	}
	pctx, cancel := context.WithTimeout(ctx, s.policy.ProbeTimeout)
	defer cancel()
	return c.spec.Ready(pctx)
}

// stop asks the component's process to stop, kills it after its stop
// timeout, and records how it went.
func (s *Supervisor) stop(c *component) StopReport {
	c.mu.Lock()
	cmd, exited := c.cmd, c.exited
	c.mu.Unlock()
	rep := StopReport{Name: c.spec.Name, Outcome: OutcomeNotRunning}
	finish := func(st State) StopReport {
		c.mu.Lock()
		c.stopReport = rep
		c.mu.Unlock()
		c.set(st, "")
		return rep
	}
	if cmd == nil || exited == nil {
		return finish(c.terminalState())
	}
	select {
	case <-exited:
		return finish(c.terminalState())
	default:
	}
	c.set(StateStopping, "")
	if err := signalStop(cmd, c.spec.StopSignal); err != nil {
		s.logger.Warn("stop signal failed; killing", "child", c.spec.Name, "error", err.Error())
	}
	t := time.NewTimer(c.spec.StopTimeout)
	defer t.Stop()
	select {
	case <-exited:
		c.mu.Lock()
		err := c.exitErr
		rep.Exit = c.lastExit
		c.mu.Unlock()
		rep.Outcome = OutcomeStopped
		if err != nil {
			rep.Outcome = OutcomeUnclean
			s.logger.Warn("component stopped uncleanly", "child", c.spec.Name, "exit", rep.Exit)
		} else {
			s.logger.Info("component stopped", "child", c.spec.Name)
		}
	case <-t.C:
		s.logger.Warn("component did not stop in time; killing", "child", c.spec.Name,
			"stop_timeout", c.spec.StopTimeout.String())
		killAll(cmd)
		k := time.NewTimer(5 * time.Second)
		defer k.Stop()
		select {
		case <-exited:
			rep.Outcome = OutcomeKilled
			c.mu.Lock()
			rep.Exit = c.lastExit
			c.mu.Unlock()
		case <-k.C:
			rep.Outcome = OutcomeStuck
			s.logger.Error("component still running after kill", "child", c.spec.Name)
			return finish(StateStopping)
		}
	}
	return finish(StateStopped)
}

// terminalState keeps "failed" visible after shutdown.
func (c *component) terminalState() State {
	if c.get() == StateFailed {
		return StateFailed
	}
	return StateStopped
}

// Status returns every component's state, in start order.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	st := Status{Ready: true, Stopping: s.stopping, Started: s.started.UTC()}
	s.mu.Unlock()
	if st.Stopping {
		st.Ready = false
	}
	for _, n := range s.order {
		c := s.comps[n]
		c.mu.Lock()
		cs := ComponentStatus{Name: n, State: c.state, Restarts: c.restarts, LastExit: c.lastExit, LastError: c.lastError, Since: c.since.UTC()}
		switch c.state {
		case StateStarting, StateReady, StateNotReady, StateStopping:
			if c.cmd != nil && c.cmd.Process != nil {
				cs.PID = c.cmd.Process.Pid
			}
		}
		c.mu.Unlock()
		if cs.State != StateReady {
			st.Ready = false
		}
		st.Components = append(st.Components, cs)
	}
	return st
}

func (c *component) set(s State, errText string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != s {
		c.state, c.since = s, time.Now()
	}
	if errText != "" {
		c.lastError = errText
	}
}

func (c *component) setError(errText string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastError = errText
}

func (c *component) get() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// recordRestart counts a restart and reports whether another is allowed.
func (c *component) recordRestart(now time.Time, p Policy) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.history[:0]
	for _, t := range c.history {
		if now.Sub(t) < p.Window {
			kept = append(kept, t)
		}
	}
	c.history = append(kept, now)
	if len(c.history) > p.MaxRestarts {
		return false
	}
	c.restarts++
	return true
}

func exitText(err error) string {
	if err == nil {
		return "exit status 0"
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ProcessState.String()
	}
	return "wait error"
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
