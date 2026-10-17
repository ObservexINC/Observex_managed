//go:build !windows

package supervisor

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Graceful stop needs signals, which Windows does not deliver to child
// processes; there the supervisor always kills (proc_windows.go).

func TestStopIsGracefulAndInReverseOrder(t *testing.T) {
	r := start(t, []Spec{
		helperSpec(t, "server", "serve"),
		helperSpec(t, "gateway", "serve", "server"),
		helperSpec(t, "front-door", "serve", "gateway"),
	}, fast)
	r.waitFor("ready", func(s Status) bool { return s.Ready })
	r.stopClean()
	out := r.out.String()
	for _, n := range []string{"server", "gateway", "front-door"} {
		if !strings.Contains(out, "["+n+"] graceful stop") {
			t.Fatalf("%s was not stopped gracefully; output:\n%s", n, out)
		}
	}
	if got := strings.Join(r.logs.children("component stopped"), ","); got != "front-door,gateway,server" {
		t.Fatalf("stop order = %s", got)
	}
	reps := r.sup.StopReports()
	if len(reps) != 3 {
		t.Fatalf("reports = %+v", reps)
	}
	for _, rep := range reps {
		if rep.Outcome != OutcomeStopped || rep.Exit != "exit status 0" {
			t.Fatalf("report = %+v", rep)
		}
	}
	for _, c := range r.sup.Status().Components {
		if c.State != StateStopped || c.PID != 0 {
			t.Fatalf("after stop: %+v", c)
		}
	}
}

func TestStopKillsAfterTimeoutAndSaysSo(t *testing.T) {
	sp := helperSpec(t, "stubborn", "ignore-term")
	sp.StopTimeout = 300 * time.Millisecond
	r := start(t, []Spec{sp}, fast)
	r.waitFor("ready", func(s Status) bool { return s.Ready })
	begin := time.Now()
	err := r.stop()
	if d := time.Since(begin); d < 300*time.Millisecond || d > 8*time.Second {
		t.Fatalf("stop took %s", d)
	}
	var se *StopError
	if !errors.As(err, &se) || se.Error() != "shutdown incomplete: stubborn killed" {
		t.Fatalf("Run = %v, want a StopError naming the killed component", err)
	}
	if rep := se.Reports[0]; rep.Outcome != OutcomeKilled || rep.Exit != "signal: killed" {
		t.Fatalf("report = %+v", rep)
	}
	if got := r.logs.children("component did not stop in time; killing"); len(got) != 1 {
		t.Fatalf("kill not logged: %v", got)
	}
}

func TestUncleanExitOnStopIsReported(t *testing.T) {
	r := start(t, []Spec{helperSpec(t, "server", "unclean-exit")}, fast)
	r.waitFor("ready", func(s Status) bool { return s.Ready })
	err := r.stop()
	var se *StopError
	if !errors.As(err, &se) || se.Reports[0].Outcome != OutcomeUnclean || se.Reports[0].Exit != "exit status 7" {
		t.Fatalf("Run = %v", err)
	}
}

func TestKilledComponentIsRestarted(t *testing.T) {
	r := start(t, []Spec{helperSpec(t, "server", "serve"), helperSpec(t, "gateway", "serve", "server")}, fast)
	r.waitFor("ready", func(s Status) bool { return s.Ready })
	pid := r.component("server").PID
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	st := r.waitFor("restarted and ready", func(s Status) bool {
		c := s.Components[0]
		return s.Ready && c.Restarts == 1 && c.PID != pid
	})
	if st.Components[0].LastExit != "signal: killed" {
		t.Fatalf("last exit %q", st.Components[0].LastExit)
	}
	if st.Components[1].Restarts != 0 {
		t.Fatalf("the dependant was restarted too: %+v", st.Components[1])
	}
	r.stopClean()
}

// Astra's M1 validation, finding 001: when an NGINX master is killed, its
// workers keep the output pipes and the listening socket. The supervisor
// must still see the death, remove the leftovers and restart the
// component, which can then bind its port again.
func TestKilledParentWithChildrenIsRestarted(t *testing.T) {
	r := start(t, []Spec{helperSpec(t, "front-door", "spawn")}, fast)
	r.waitFor("ready", func(s Status) bool { return s.Ready })
	pid := r.component("front-door").PID
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	st := r.waitFor("restarted and ready", func(s Status) bool {
		c := s.Components[0]
		return s.Ready && c.Restarts == 1 && c.PID != pid
	})
	if st.Components[0].LastExit != "signal: killed" {
		t.Fatalf("last exit %q", st.Components[0].LastExit)
	}
	r.stopClean()
}

// If the supervisor itself is killed, the kernel kills its components
// (Pdeathsig), so none is left running without supervision.
func TestComponentsDieWithTheSupervisor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Pdeathsig exists only on Linux")
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	sup := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "supervise", freeAddr(t), pidFile)
	if err := sup.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Process.Kill(); _ = sup.Wait() })
	var childPID int
	deadline := time.Now().Add(15 * time.Second)
	for childPID == 0 {
		if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 {
			childPID, _ = strconv.Atoi(string(b))
		}
		if time.Now().After(deadline) {
			t.Fatal("helper supervisor never reported its child")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := sup.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = sup.Wait()
	deadline = time.Now().Add(10 * time.Second)
	for alive(childPID) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(childPID, syscall.SIGKILL)
			t.Fatalf("component %d outlived its supervisor", childPID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// alive reports whether pid exists and is not a zombie.
func alive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// The state follows the command name in parentheses.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i < 0 || i+2 >= len(s) || s[i+2] != 'Z'
}
