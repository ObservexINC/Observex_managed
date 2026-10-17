//go:build !windows

package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// onTerm sets the helper's reaction to SIGTERM.
func onTerm(mode string) {
	switch mode {
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		return
	case "print":
		term := make(chan os.Signal, 1)
		signal.Notify(term, syscall.SIGTERM)
		go func() {
			<-term
			os.Exit(0) // quietly, so the unfinished line stays unfinished
		}()
		return
	}
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	go func() {
		<-term
		if mode == "unclean-exit" {
			fmt.Println("stopping badly")
			os.Exit(7)
		}
		fmt.Println("graceful stop")
		os.Exit(0)
	}()
}

// spawnChild behaves like an NGINX master: a child process does the serving
// and shares this process's output and process group.
func spawnChild(addr string) int {
	onTerm("serve")
	child := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "serve", addr)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		return 4
	}
	fmt.Printf("spawned %d\n", child.Process.Pid)
	return sleepForever()
}

// superviseOne runs a supervisor with one serving component and writes the
// component's PID to pidFile once it is ready.
func superviseOne(addr, pidFile string) int {
	sup, err := New([]Spec{{
		Name:  "child",
		Path:  os.Args[0],
		Args:  []string{"-test.run=^TestHelperProcess$", "--", "serve", addr},
		Ready: HTTPReady("http://" + addr + "/"),
	}}, fast, nil, os.Stdout)
	if err != nil {
		return 5
	}
	go func() { _ = sup.Run(context.Background()) }()
	if !sup.WaitTimeout(func(s Status) bool { return s.Ready }, 10*time.Second, 20*time.Millisecond) {
		return 6
	}
	pid := sup.Status().Components[0].PID
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		return 7
	}
	return sleepForever()
}
