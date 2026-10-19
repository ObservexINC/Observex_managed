package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// The components in these tests are this test binary run again as a helper
// process. The helper's mode and address follow "--" on its command line, so
// a helper also works with the minimal default environment.

func helperArgs() (mode, addr, extra string, ok bool) {
	for i, a := range os.Args {
		if a == "--" && i+1 < len(os.Args) {
			rest := append(os.Args[i+1:], "", "", "")
			return rest[0], rest[1], rest[2], true
		}
	}
	return "", "", "", false
}

func TestHelperProcess(_ *testing.T) {
	mode, addr, extra, ok := helperArgs()
	if !ok {
		return // a normal test run, not a helper
	}
	os.Exit(runHelper(mode, addr, extra))
}

// freeAddr returns a loopback address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

func helperSpec(t *testing.T, name, mode string, deps ...string) Spec {
	t.Helper()
	addr := freeAddr(t)
	return Spec{
		Name:      name,
		Path:      os.Args[0],
		Args:      []string{"-test.run=^TestHelperProcess$", "--", mode, addr},
		Env:       helperEnv(t),
		DependsOn: deps,
		Ready:     HTTPReady("http://" + addr + "/"),
	}
}

// helperEnv is nil (the default environment) unless the tests run with
// coverage; then helpers get a coverage directory, or they would print a
// warning into the output that some tests check.
func helperEnv(t *testing.T) []string {
	if testing.CoverMode() == "" {
		return nil
	}
	return append(DefaultEnv(), "GOCOVERDIR="+t.TempDir())
}

var fast = Policy{
	StartTimeout:   5 * time.Second,
	InitialBackoff: 20 * time.Millisecond,
	MaxBackoff:     80 * time.Millisecond,
	StableAfter:    time.Minute,
	MaxRestarts:    3,
	Window:         time.Minute,
	ProbeInterval:  50 * time.Millisecond,
	ProbeTimeout:   time.Second,
	StopTimeout:    3 * time.Second,
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// recorder is a slog handler that keeps every record's message and its
// "child" attribute, in order.
type recorder struct {
	mu      sync.Mutex
	entries []entry
}

type entry struct{ msg, child string }

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *recorder) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *recorder) WithGroup(string) slog.Handler            { return r }
func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	e := entry{msg: rec.Message}
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == "child" {
			e.child = a.Value.String()
		}
		return true
	})
	r.mu.Lock()
	r.entries = append(r.entries, e)
	r.mu.Unlock()
	return nil
}

// index returns the position of the first record with msg and child, or -1.
func (r *recorder) index(msg, child string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, e := range r.entries {
		if e.msg == msg && e.child == child {
			return i
		}
	}
	return -1
}

type run struct {
	t      *testing.T
	sup    *Supervisor
	cancel context.CancelFunc
	done   chan error
	logs   *recorder
	out    *syncBuf
	once   sync.Once
	err    error
}

func start(t *testing.T, specs []Spec, p Policy) *run {
	t.Helper()
	logs := &recorder{}
	out := &syncBuf{}
	sup, err := New(specs, p, slog.New(logs), out)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &run{t: t, sup: sup, cancel: cancel, done: make(chan error, 1), logs: logs, out: out}
	go func() { r.done <- sup.Run(ctx) }()
	t.Cleanup(func() { _ = r.stop() })
	return r
}

// stop ends Run and returns its result; later calls return the same.
func (r *run) stop() error {
	r.once.Do(func() {
		r.cancel()
		select {
		case r.err = <-r.done:
		case <-time.After(20 * time.Second):
			r.err = errors.New("Run did not return within 20s")
		}
	})
	return r.err
}

// stopClean ends Run and fails the test unless every component stopped
// cleanly. On Windows a stop is always a kill, so it is never clean there.
func (r *run) stopClean() {
	r.t.Helper()
	err := r.stop()
	var se *StopError
	if err == nil || runtime.GOOS == "windows" && errors.As(err, &se) {
		return
	}
	r.t.Fatalf("Run: %v", err)
}

// waitFor polls the status until cond holds. It fails the test with the
// last status after 15 seconds.
func (r *run) waitFor(what string, cond func(Status) bool) Status {
	r.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		st := r.sup.Status()
		if cond(st) {
			return st
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("timed out waiting for %s; status %+v; output:\n%s", what, st, r.out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (r *run) component(name string) ComponentStatus {
	for _, c := range r.sup.Status().Components {
		if c.Name == name {
			return c
		}
	}
	r.t.Fatalf("no component %q", name)
	return ComponentStatus{}
}

func TestNewValidates(t *testing.T) {
	ok := Spec{Name: "a", Path: "/bin/true"}
	cases := []struct {
		name  string
		specs []Spec
		want  string
	}{
		{"none", nil, "no components"},
		{"empty name", []Spec{{Path: "/bin/true"}}, "not valid"},
		{"bad name", []Spec{{Name: "Front Door", Path: "/bin/true"}}, "not valid"},
		{"leading dash", []Spec{{Name: "-x", Path: "/bin/true"}}, "not valid"},
		{"long name", []Spec{{Name: strings.Repeat("a", 33), Path: "/bin/true"}}, "not valid"},
		{"duplicate", []Spec{ok, ok}, "defined twice"},
		{"no path", []Spec{{Name: "a"}}, "no executable"},
		{"unknown dependency", []Spec{{Name: "a", Path: "/bin/true", DependsOn: []string{"b"}}}, "unknown component"},
		{"cycle", []Spec{
			{Name: "a", Path: "/bin/true", DependsOn: []string{"b"}},
			{Name: "b", Path: "/bin/true", DependsOn: []string{"c"}},
			{Name: "c", Path: "/bin/true", DependsOn: []string{"a"}},
		}, "cycle: a -> b -> c -> a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.specs, Policy{}, nil, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestOrderFollowsDependencies(t *testing.T) {
	s, err := New([]Spec{
		{Name: "front-door", Path: "/bin/true", DependsOn: []string{"gateway"}},
		{Name: "gateway", Path: "/bin/true", DependsOn: []string{"server"}},
		{Name: "server", Path: "/bin/true"},
		{Name: "agent-proxy", Path: "/bin/true"},
	}, Policy{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(s.Order(), ",")
	if got != "agent-proxy,server,gateway,front-door" {
		t.Fatalf("order = %s", got)
	}
}

func TestPolicyDefaults(t *testing.T) {
	p := withDefaults(Policy{InitialBackoff: time.Minute, MaxBackoff: time.Second, RestartAfterNotReady: -1})
	if p.MaxBackoff != time.Minute {
		t.Fatalf("MaxBackoff = %s, want it raised to InitialBackoff", p.MaxBackoff)
	}
	if p.RestartAfterNotReady != 0 || p.MaxRestarts != DefaultPolicy.MaxRestarts || p.StopTimeout != DefaultPolicy.StopTimeout {
		t.Fatalf("defaults not applied: %+v", p)
	}
}

func TestSpecsAreCopied(t *testing.T) {
	args := []string{"x"}
	s, err := New([]Spec{{Name: "a", Path: "/bin/true", Args: args}}, Policy{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	args[0] = "changed"
	if s.comps["a"].spec.Args[0] != "x" {
		t.Fatal("New kept the caller's slice")
	}
	if got := s.comps["a"].spec.Env; strings.Join(got, ";") != strings.Join(DefaultEnv(), ";") {
		t.Fatalf("nil Env should become DefaultEnv, got %v", got)
	}
}

func TestStartsInDependencyOrderAndBecomesReady(t *testing.T) {
	r := start(t, []Spec{
		helperSpec(t, "gateway", "serve", "server"),
		helperSpec(t, "server", "serve"),
	}, fast)
	st := r.waitFor("ready", func(s Status) bool { return s.Ready })
	if len(st.Components) != 2 || st.Components[0].Name != "server" || st.Components[1].Name != "gateway" {
		t.Fatalf("components = %+v", st.Components)
	}
	for _, c := range st.Components {
		if c.PID == 0 || c.Restarts != 0 {
			t.Fatalf("component %+v", c)
		}
	}
	ready := r.logs.index("component ready", "server")
	started := r.logs.index("component started", "gateway")
	if ready < 0 || started < 0 || ready > started {
		t.Fatalf("gateway started (%d) before server was ready (%d)", started, ready)
	}
}

func TestDependentWaitsWhileDependencyIsNotReady(t *testing.T) {
	r := start(t, []Spec{
		helperSpec(t, "server", "never-ready"),
		helperSpec(t, "gateway", "serve", "server"),
	}, fast)
	r.waitFor("server running", func(s Status) bool { return s.Components[0].State == StateStarting })
	if c := r.component("gateway"); c.State != StatePending || c.PID != 0 {
		t.Fatalf("gateway = %+v, want pending", c)
	}
	if r.sup.Status().Ready {
		t.Fatal("node reported ready")
	}
}

func TestExitedComponentIsRestartedThenFailsInACrashLoop(t *testing.T) {
	sp := helperSpec(t, "crasher", "exit")
	sp.Ready = nil
	r := start(t, []Spec{sp}, fast)
	st := r.waitFor("failed", func(s Status) bool { return s.Components[0].State == StateFailed })
	c := st.Components[0]
	if c.Restarts != fast.MaxRestarts {
		t.Fatalf("restarts = %d, want %d", c.Restarts, fast.MaxRestarts)
	}
	if !strings.Contains(c.LastError, "crash loop") || c.LastExit != "exit status 3" {
		t.Fatalf("component = %+v", c)
	}
	if st.Ready {
		t.Fatal("node reported ready with a failed component")
	}
	// A failed component is not running, so shutdown is clean.
	r.stopClean()
	if got := r.component("crasher").State; got != StateFailed {
		t.Fatalf("state after shutdown = %s, want failed", got)
	}
}

func TestCannotStartIsFailedWithoutRetrying(t *testing.T) {
	r := start(t, []Spec{{Name: "missing", Path: filepath.Join(t.TempDir(), "no-such-binary")}}, fast)
	st := r.waitFor("failed", func(s Status) bool { return s.Components[0].State == StateFailed })
	if c := st.Components[0]; !strings.HasPrefix(c.LastError, "cannot start:") || c.Restarts != 0 {
		t.Fatalf("component = %+v", c)
	}
}

func TestStartTimeoutStopsAndRetries(t *testing.T) {
	p := fast
	p.StartTimeout = 300 * time.Millisecond
	r := start(t, []Spec{helperSpec(t, "slow", "never-ready")}, p)
	st := r.waitFor("restarted after start timeout", func(s Status) bool { return s.Components[0].Restarts >= 1 })
	if !strings.Contains(st.Components[0].LastError, "not ready within 300ms") {
		t.Fatalf("component = %+v", st.Components[0])
	}
}

func TestNotReadyTooLongIsRestarted(t *testing.T) {
	flag := filepath.Join(t.TempDir(), "unready")
	addr := freeAddr(t)
	sp := Spec{
		Name:  "hung",
		Path:  os.Args[0],
		Args:  []string{"-test.run=^TestHelperProcess$", "--", "flag-ready", addr, flag},
		Env:   helperEnv(t),
		Ready: HTTPReady("http://" + addr + "/"),
	}
	p := fast
	p.RestartAfterNotReady = 200 * time.Millisecond
	r := start(t, []Spec{sp}, p)
	first := r.waitFor("ready", func(s Status) bool { return s.Ready }).Components[0].PID
	if err := os.WriteFile(flag, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r.waitFor("restart", func(s Status) bool { return s.Components[0].Restarts == 1 })
	if err := os.Remove(flag); err != nil {
		t.Fatal(err)
	}
	st := r.waitFor("ready again", func(s Status) bool { return s.Ready })
	if st.Components[0].PID == first || !strings.Contains(st.Components[0].LastError, "not ready for 200ms") {
		t.Fatalf("component = %+v (first PID %d)", st.Components[0], first)
	}
}

func TestReadinessLossIsReportedWithoutRestartByDefault(t *testing.T) {
	flag := filepath.Join(t.TempDir(), "unready")
	addr := freeAddr(t)
	sp := Spec{
		Name:  "flaky",
		Path:  os.Args[0],
		Args:  []string{"-test.run=^TestHelperProcess$", "--", "flag-ready", addr, flag},
		Env:   helperEnv(t),
		Ready: HTTPReady("http://" + addr + "/"),
	}
	r := start(t, []Spec{sp}, fast)
	r.waitFor("ready", func(s Status) bool { return s.Ready })
	if err := os.WriteFile(flag, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	st := r.waitFor("not ready", func(s Status) bool { return s.Components[0].State == StateNotReady })
	if st.Ready || st.Components[0].LastError != "readiness check answered 503" {
		t.Fatalf("status = %+v", st)
	}
	if err := os.Remove(flag); err != nil {
		t.Fatal(err)
	}
	st = r.waitFor("ready again", func(s Status) bool { return s.Ready })
	if st.Components[0].Restarts != 0 {
		t.Fatalf("restarted: %+v", st.Components[0])
	}
}

func TestOutputIsPrefixedPerLineAndRedacted(t *testing.T) {
	sp := helperSpec(t, "talker", "print")
	sp.Ready = nil
	r := start(t, []Spec{sp}, fast)
	r.waitFor("output", func(Status) bool { return strings.Contains(r.out.String(), "line two") })
	r.stopClean()
	out := r.out.String()
	for _, want := range []string{"[talker] line one\n", "[talker] line two\n", "[talker] login password=[REDACTED]\n", "[talker] partial\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Hunter2") {
		t.Fatalf("secret reached the output:\n%s", out)
	}
}

func TestKeyStateEndsWithTheProcess(t *testing.T) {
	sp := helperSpec(t, "keyprinter", "print-key")
	sp.Ready = nil
	r := start(t, []Spec{sp}, fast)
	r.waitFor("a restart", func(Status) bool { return strings.Count(r.out.String(), "[keyprinter] before key\n") >= 2 })
	// The component exits by itself (status 3) again and again, so the stop
	// can meet it exiting with that status and report it as unclean. How it
	// stops is not what this test checks; its output is.
	_ = r.stop()
	out := r.out.String()
	if strings.Contains(out, bodyMarker) {
		t.Fatalf("key material reached the output:\n%s", out)
	}
	if !strings.Contains(out, "[keyprinter] [REDACTED]\n") {
		t.Fatalf("BEGIN line not shown redacted:\n%s", out)
	}
}

func TestDefaultEnvironmentHidesTheSupervisorsSecrets(t *testing.T) {
	t.Setenv("OBSERVEX_TEST_DB_PASSWORD", "not-for-children")
	sp := helperSpec(t, "env", "print-env")
	sp.Env = nil // the default environment, even under coverage
	sp.Ready = nil
	r := start(t, []Spec{sp}, fast)
	r.waitFor("env printed", func(Status) bool { return strings.Contains(r.out.String(), "env done") })
	out := r.out.String()
	if strings.Contains(out, "OBSERVEX_TEST_DB_PASSWORD") || strings.Contains(out, "not-for-children") {
		t.Fatalf("child saw the supervisor's environment:\n%s", out)
	}
	if !strings.Contains(out, "[env] TZ=UTC") {
		t.Fatalf("child did not get the default environment:\n%s", out)
	}
}

func TestStatusHandler(t *testing.T) {
	r := start(t, []Spec{helperSpec(t, "server", "serve")}, fast)
	h := r.sup.Handler("node-1")
	get := func(method, path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))
		return rec.Code, rec.Body.String()
	}
	r.waitFor("ready", func(s Status) bool { return s.Ready })
	checks := []struct {
		method, path string
		code         int
		body         string
	}{
		{"GET", "/livez", 200, `"alive"`},
		{"GET", "/readyz", 200, `"node_id":"node-1"`},
		{"GET", "/status", 200, `"name":"server"`},
		{"GET", "/health", 200, `{"status":"ready"}`},
		{"HEAD", "/health", 200, ``},
		{"POST", "/health", 405, `method not allowed`},
		{"GET", "/nope", 404, `not found`},
	}
	for _, c := range checks {
		code, body := get(c.method, c.path)
		if code != c.code || !strings.Contains(body, c.body) {
			t.Fatalf("%s %s = %d %q, want %d containing %q", c.method, c.path, code, body, c.code, c.body)
		}
	}
	if code, body := get("GET", "/health"); strings.Contains(body, "pid") || code != 200 {
		t.Fatalf("/health must carry nothing but the status: %q", body)
	}
	r.stopClean()
	if code, _ := get("GET", "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz after stop = %d", code)
	}
	if code, body := get("GET", "/status"); code != 200 || !strings.Contains(body, `"stopping":true`) {
		t.Fatalf("/status after stop = %d %q", code, body)
	}
}

func TestReadyChecks(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()
	redirect := httptest.NewServer(http.RedirectHandler(ok.URL, http.StatusFound))
	defer redirect.Close()
	ctx := context.Background()
	if err := HTTPReady(ok.URL)(ctx); err != nil {
		t.Fatal(err)
	}
	if err := HTTPReady(bad.URL)(ctx); err == nil || err.Error() != "readiness check answered 503" {
		t.Fatalf("err = %v", err)
	}
	if err := HTTPReady(redirect.URL)(ctx); err == nil {
		t.Fatal("a redirect must not count as ready")
	}
	closed := freeAddr(t)
	if err := HTTPReady("http://" + closed)(ctx); err == nil {
		t.Fatal("closed port reported ready")
	}
	if err := HTTPReady("::bad url")(ctx); err == nil {
		t.Fatal("bad URL reported ready")
	}
	if err := TCPReady(strings.TrimPrefix(ok.URL, "http://"))(ctx); err != nil {
		t.Fatal(err)
	}
	if err := TCPReady(closed)(ctx); err == nil {
		t.Fatal("closed port reported ready")
	}
	if err := AllReady(HTTPReady(ok.URL), HTTPReady(bad.URL))(ctx); err == nil {
		t.Fatal("AllReady passed with a failing check")
	}
	if err := AllReady()(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRunTwiceIsRefused(t *testing.T) {
	sp := helperSpec(t, "server", "serve")
	r := start(t, []Spec{sp}, fast)
	r.waitFor("ready", func(s Status) bool { return s.Ready })
	if err := r.sup.Run(context.Background()); err == nil {
		t.Fatal("second Run accepted")
	}
}

func TestWaitTimeout(t *testing.T) {
	r := start(t, []Spec{helperSpec(t, "server", "serve")}, fast)
	if !r.sup.WaitTimeout(func(s Status) bool { return s.Ready }, 10*time.Second, 10*time.Millisecond) {
		t.Fatal("never ready")
	}
	if r.sup.WaitTimeout(func(Status) bool { return false }, 30*time.Millisecond, 10*time.Millisecond) {
		t.Fatal("false condition reported true")
	}
}

func TestStopErrorMessage(t *testing.T) {
	err := &StopError{Reports: []StopReport{
		{Name: "front-door", Outcome: OutcomeStopped},
		{Name: "gateway", Outcome: OutcomeKilled},
		{Name: "server", Outcome: OutcomeUnclean, Exit: "exit status 1"},
		{Name: "x", Outcome: OutcomeNotRunning},
	}}
	if got := err.Error(); got != "shutdown incomplete: gateway killed, server unclean" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestExitText(t *testing.T) {
	if exitText(nil) != "exit status 0" {
		t.Fatal(exitText(nil))
	}
	if exitText(errors.New("x")) != "wait error" {
		t.Fatal(exitText(errors.New("x")))
	}
	err := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperProcess$", "--", "exit").Run()
	if got := exitText(err); got != "exit status 3" {
		t.Fatalf("exitText = %q", got)
	}
}

func TestPrefixWriter(t *testing.T) {
	var out bytes.Buffer
	sink := &lineSink{w: &out}
	w := sink.prefixed("c")
	_, _ = io.WriteString(w, "a\r\nb")
	_, _ = io.WriteString(w, "c\n")
	long := strings.Repeat("x", maxLine+10)
	_, _ = io.WriteString(w, long[:maxLine-5])
	_, _ = io.WriteString(w, long[maxLine-5:]+"\nafter\n")
	_, _ = io.WriteString(w, "tail")
	sink.flush()
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("lines = %q", lines)
	}
	if lines[0] != "[c] a" || lines[1] != "[c] bc" || lines[3] != "[c] after" || lines[4] != "[c] tail" {
		t.Fatalf("lines = %q", lines)
	}
	if !strings.HasSuffix(lines[2], truncatedMark) || len(lines[2]) != len("[c] ")+maxLine+len(truncatedMark) {
		t.Fatalf("long line not cut correctly: %d bytes", len(lines[2]))
	}
	// A line cut in one Write and ended in a later one.
	out.Reset()
	_, _ = io.WriteString(w, long)
	_, _ = io.WriteString(w, "more\nnext\n")
	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(got) != 2 || !strings.HasSuffix(got[0], truncatedMark) || got[1] != "[c] next" {
		t.Fatalf("lines = %q", got)
	}
	// A long line in one Write.
	out.Reset()
	_, _ = io.WriteString(w, long+"\n")
	if !strings.HasSuffix(strings.TrimSuffix(out.String(), "\n"), truncatedMark) {
		t.Fatal("long line in one write not marked")
	}
}

// runHelper is the helper process's behaviour for each mode.
func runHelper(mode, addr, extra string) int {
	switch mode {
	case "serve", "never-ready", "ignore-term", "unclean-exit", "flag-ready":
		onTerm(mode)
		fmt.Println("helper serving")
		_ = http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			switch {
			case mode == "never-ready":
				w.WriteHeader(http.StatusServiceUnavailable)
			case mode == "flag-ready" && fileExists(extra):
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		}))
		return 9
	case "exit":
		fmt.Println("helper exiting")
		return 3
	case "print":
		onTerm(mode)
		fmt.Print("line one\nline two\nlogin password=Hunter2-Correct-Horse\npartial")
		return sleepForever()
	case "print-key":
		// A key whose END never arrives, then the process dies.
		fmt.Print("before key\n" + beginPK + "\n" + bodyMarker + "\n" + bodyMarker + " still key\n")
		return 3
	case "print-env":
		onTerm(mode)
		for _, e := range os.Environ() {
			fmt.Println(e)
		}
		fmt.Println("env done")
		return sleepForever()
	case "spawn":
		return spawnChild(addr)
	case "supervise":
		return superviseOne(addr, extra)
	}
	return 0
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// sleepForever blocks a helper until the supervisor stops or kills it.
func sleepForever() int {
	for {
		time.Sleep(time.Hour)
	}
}
