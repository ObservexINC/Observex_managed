package selfmon

import (
	"bytes"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/node/supervisor"
)

func text(t *testing.T, r *Registry) string {
	t.Helper()
	var b bytes.Buffer
	if err := WriteText(&b, r.Gather()); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestExpositionFormat(t *testing.T) {
	r := &Registry{}
	r.Register(CollectorFunc{CollectorName: "test", Fn: func(b *Batch) {
		b.Gauge("observex_b", "Second.\nWith a newline and a \\ backslash.", 2, L("z", "1"), L("a", `quote " and \ and`+"\nnewline"))
		b.Gauge("observex_b", "ignored help", 1, L("z", "0"), L("a", "x"))
		b.Counter("observex_a_total", "First.", 3)
		b.Gauge("observex_special", "Special values.", math.NaN(), L("v", "nan"))
		b.Gauge("observex_special", "", math.Inf(1), L("v", "pinf"))
		b.Gauge("observex_special", "", math.Inf(-1), L("v", "ninf"))
		b.Gauge("observex_special", "", 0.000123, L("v", "small"))
		b.Gauge("observex_special", "", 1e21, L("v", "large"))
	}})
	got := text(t, r)
	want := `# HELP observex_a_total First.
# TYPE observex_a_total counter
observex_a_total 3
# HELP observex_b Second.\nWith a newline and a \\ backslash.
# TYPE observex_b gauge
observex_b{z="0",a="x"} 1
observex_b{z="1",a="quote \" and \\ and\nnewline"} 2
# HELP observex_selfmon_errors Problems while collecting the node's own metrics in the last scrape, by source.
# TYPE observex_selfmon_errors gauge
observex_selfmon_errors{source="test"} 0
# HELP observex_special Special values.
# TYPE observex_special gauge
observex_special{v="large"} 1e+21
observex_special{v="nan"} NaN
observex_special{v="ninf"} -Inf
observex_special{v="pinf"} +Inf
observex_special{v="small"} 0.000123
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestInvalidNamesAreCountedNotWritten(t *testing.T) {
	r := &Registry{}
	r.Register(CollectorFunc{CollectorName: "bad", Fn: func(b *Batch) {
		b.Gauge("1starts_with_digit", "", 1)
		b.Gauge("observex_ok", "", 1, L("bad-label", "x"))
		b.Gauge("observex_ok", "", 1, L("__reserved", "x"))
		b.Gauge("observex_mixed", "", 1)
		b.Counter("observex_mixed", "", 1)
		b.Errorf("source said %d", 42)
	}})
	got := text(t, r)
	if strings.Contains(got, "starts_with_digit") || strings.Contains(got, "bad-label") || strings.Contains(got, "observex_ok") {
		t.Fatalf("invalid metric written:\n%s", got)
	}
	if !strings.Contains(got, `observex_selfmon_errors{source="bad"} 5`) {
		t.Fatalf("errors not counted:\n%s", got)
	}
	if errs := r.LastErrors(); len(errs) != 5 || errs[4] != "bad: source said 42" {
		t.Fatalf("LastErrors = %q", errs)
	}
}

func TestProcessesFromRecordedProc(t *testing.T) {
	r := &Registry{}
	r.Register(Processes{Root: "testdata/proc", PageSize: 4096, PIDs: func() map[string]int {
		return map[string]int{"front-door": 4100, "server": 5200, "gateway": 9999}
	}})
	got := text(t, r)
	for _, want := range []string{
		`observex_node_component_cpu_seconds_total{component="front-door"} 2.7`,
		`observex_node_component_cpu_seconds_total{component="server"} 5`,
		`observex_node_component_resident_bytes{component="front-door"} 12312576`, // (1736+657+613) pages
		`observex_node_component_resident_bytes{component="server"} 3485696`,      // 851 pages
		`observex_node_component_processes{component="front-door"} 3`,
		`observex_node_component_threads{component="front-door"} 3`,
		`observex_node_component_open_fds{component="front-door"} 5`,
		`observex_node_component_open_fds{component="server"} 4`,
		`observex_selfmon_errors{source="processes"} 1`, // 7000/stat is garbage
	} {
		if !strings.Contains(got, want+"\n") {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, `component="gateway"`) {
		t.Fatalf("a component that is not running was reported:\n%s", got)
	}
}

func TestParseStat(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
	}{
		{"1 (init) S 0 1 1 0 -1 0 0 0 0 0 7 3 0 0 20 0 2 0 1 100 50", true},
		{"12 (a) b) c) S 0 12 12 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 1 100 9", true},
		{"no parens", false},
		{"x (bad pid) S 0 1 1 0 -1 0 0 0 0 0 7 3 0 0 20 0 2 0 1 100 50", false},
		{"1 (short) S 0 1", false},
		{"1 (nan) S 0 x 1 0 -1 0 0 0 0 0 7 3 0 0 20 0 2 0 1 100 50", false},
		// The kernel writes these numbers without a sign; FuzzParseStat found
		// "+0" read as process 0 (input 2cfbf0d5ce660a06).
		{"+1 (signed pid) S 0 1 1 0 -1 0 0 0 0 0 7 3 0 0 20 0 2 0 1 100 50", false},
		{"-0 (signed pid) S 0 0 1 0 -1 0 0 0 0 0 7 3 0 0 20 0 2 0 1 100 50", false},
		{"1 (signed pgrp) S 0 +1 1 0 -1 0 0 0 0 0 7 3 0 0 20 0 2 0 1 100 50", false},
		{"1 (signed threads) S 0 1 1 0 -1 0 0 0 0 0 7 3 0 0 20 0 +2 0 1 100 50", false},
		{"99999999999 (huge pid) S 0 1 1 0 -1 0 0 0 0 0 7 3 0 0 20 0 2 0 1 100 50", false},
	}
	for _, tc := range cases {
		ps, ok := parseStat(tc.line)
		if ok != tc.ok {
			t.Fatalf("parseStat(%q) ok = %v", tc.line, ok)
		}
		if ok && ps.pid != ps.pgrp {
			t.Fatalf("parseStat(%q) = %+v", tc.line, ps)
		}
	}
	if ps, _ := parseStat(cases[0].line); ps.utime != 7 || ps.stime != 3 || ps.threads != 2 || ps.rssPages != 50 {
		t.Fatalf("fields = %+v", ps)
	}
}

// TestProcessesIgnoreSignedNames checks that only directories named by
// digits are read as processes: "+4100" is not process 4100.
func TestProcessesIgnoreSignedNames(t *testing.T) {
	root := t.TempDir()
	stat := "4100 (nginx) S 1 4100 4100 0 -1 0 0 0 0 0 10 5 0 0 20 0 1 0 1 100 7"
	for _, name := range []string{"4100", "+4100", "-4100"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name, "stat"), []byte(stat), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := &Registry{}
	r.Register(Processes{Root: root, PageSize: 4096, PIDs: func() map[string]int { return map[string]int{"front-door": 4100} }})
	got := text(t, r)
	for _, want := range []string{
		`observex_node_component_processes{component="front-door"} 1`,
		`observex_selfmon_errors{source="processes"} 0`,
	} {
		if !strings.Contains(got, want+"\n") {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestProcessesEdgeCases(t *testing.T) {
	r := &Registry{}
	r.Register(Processes{Root: "testdata/no-such-proc", PIDs: func() map[string]int { return map[string]int{"x": 1} }})
	if got := text(t, r); !strings.Contains(got, `observex_selfmon_errors{source="processes"} 1`) {
		t.Fatalf("missing root not reported:\n%s", got)
	}
	r = &Registry{}
	r.Register(Processes{Root: "testdata/no-such-proc", PIDs: func() map[string]int { return nil }})
	if got := text(t, r); !strings.Contains(got, `observex_selfmon_errors{source="processes"} 0`) {
		t.Fatalf("no components should mean nothing to read:\n%s", got)
	}
}

func TestProcessesOnThisHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc exists only on Linux")
	}
	r := &Registry{}
	// The test process is not a group leader, so use its group's leader.
	r.Register(Processes{PIDs: func() map[string]int { return map[string]int{"self": pgrpOfSelf(t)} }})
	got := text(t, r)
	if !strings.Contains(got, `observex_node_component_processes{component="self"}`) {
		t.Fatalf("own process group not found:\n%s", got)
	}
}

func TestHostFromRecordedProc(t *testing.T) {
	r := &Registry{}
	r.Register(Host{Root: "testdata/proc"})
	got := text(t, r)
	for _, want := range []string{
		`observex_node_host_load{window="1m"} 0.2`,
		`observex_node_host_load{window="15m"} 0.07`,
		`observex_node_host_memory_total_bytes 8419655680`,
		`observex_node_host_memory_available_bytes 7884660736`,
		`observex_selfmon_errors{source="host"} 0`,
	} {
		if !strings.Contains(got, want+"\n") {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	r = &Registry{}
	r.Register(Host{Root: t.TempDir()})
	if got := text(t, r); !strings.Contains(got, `observex_selfmon_errors{source="host"} 2`) {
		t.Fatalf("missing files not reported:\n%s", got)
	}
}

func TestSupervisorCollector(t *testing.T) {
	started := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	st := supervisor.Status{Ready: false, Started: started, Components: []supervisor.ComponentStatus{
		{Name: "front-door", State: supervisor.StateReady, Restarts: 2},
		{Name: "server", State: supervisor.StateBackoff, Restarts: 5},
	}}
	r := &Registry{}
	r.Register(Supervisor{Status: func() supervisor.Status { return st }, Now: func() time.Time { return started.Add(90 * time.Second) }})
	got := text(t, r)
	for _, want := range []string{
		"observex_node_ready 0",
		"observex_node_uptime_seconds 90",
		`observex_node_component_ready{component="front-door"} 1`,
		`observex_node_component_ready{component="server"} 0`,
		`observex_node_component_restarts_total{component="server"} 5`,
		`observex_node_component_state{component="server",state="backoff"} 1`,
		`observex_node_component_state{component="server",state="ready"} 0`,
	} {
		if !strings.Contains(got, want+"\n") {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	if n := strings.Count(got, `observex_node_component_state{component="server"`); n != len(states) {
		t.Fatalf("server has %d state samples, want %d", n, len(states))
	}
	st.Started = time.Time{}
	if got := text(t, r); strings.Contains(got, "uptime") {
		t.Fatal("uptime reported before the supervisor started")
	}
}

func TestDisks(t *testing.T) {
	r := &Registry{}
	r.Register(Disks{Volumes: map[string]string{"data": t.TempDir(), "missing": "/no/such/dir"}})
	got := text(t, r)
	if runtime.GOOS == "windows" {
		if !strings.Contains(got, `observex_selfmon_errors{source="disks"} 2`) {
			t.Fatalf("Windows should report disks as unsupported:\n%s", got)
		}
		return
	}
	if !strings.Contains(got, `observex_node_disk_total_bytes{volume="data"}`) || !strings.Contains(got, `observex_node_disk_available_bytes{volume="data"}`) {
		t.Fatalf("data volume missing:\n%s", got)
	}
	if !strings.Contains(got, `observex_selfmon_errors{source="disks"} 1`) {
		t.Fatalf("missing volume not counted:\n%s", got)
	}
}

func TestInfoAndHandler(t *testing.T) {
	r := &Registry{}
	r.Register(Info("observex_node_build_info", "Build of the node software.", L("version", "0.1.0"), L("go_version", "go1.24.7")))
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()
	request := func(method string) *http.Response {
		req, err := http.NewRequestWithContext(t.Context(), method, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := request(http.MethodGet)
	defer func() { _ = resp.Body.Close() }()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	if resp.Header.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(b.String(), `observex_node_build_info{version="0.1.0",go_version="go1.24.7"} 1`) {
		t.Fatalf("body:\n%s", b.String())
	}
	post := request(http.MethodPost)
	_ = post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", post.StatusCode)
	}
}
