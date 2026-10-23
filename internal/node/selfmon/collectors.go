package selfmon

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/node/supervisor"
)

// Supervisor publishes the Node Supervisor's view of the components.
type Supervisor struct {
	Status func() supervisor.Status
	Now    func() time.Time
}

// Name returns the collector's name.
func (Supervisor) Name() string { return "supervisor" }

// states are every component state, so each one gets a sample (0 or 1).
var states = []supervisor.State{
	supervisor.StatePending, supervisor.StateStarting, supervisor.StateReady, supervisor.StateNotReady,
	supervisor.StateBackoff, supervisor.StateFailed, supervisor.StateStopping, supervisor.StateStopped,
}

// Collect adds the supervisor metrics.
func (s Supervisor) Collect(b *Batch) {
	st := s.Status()
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	b.Gauge("observex_node_ready", "1 when every component of the node is ready.", boolValue(st.Ready))
	if !st.Started.IsZero() {
		b.Gauge("observex_node_uptime_seconds", "Seconds since the Node Supervisor started its components.", now().Sub(st.Started).Seconds())
	}
	for _, c := range st.Components {
		comp := L("component", c.Name)
		b.Gauge("observex_node_component_ready", "1 when the component is running and ready.", boolValue(c.State == supervisor.StateReady), comp)
		b.Counter("observex_node_component_restarts_total", "Restarts of the component by the Node Supervisor.", float64(c.Restarts), comp)
		for _, state := range states {
			b.Gauge("observex_node_component_state", "1 for the component's current state, 0 for the others.",
				boolValue(c.State == state), comp, L("state", string(state)))
		}
	}
}

func boolValue(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

// UserHZ is the unit of CPU times in /proc on Linux. The kernel fixes it at
// 100 for user space on every architecture.
const UserHZ = 100

// Processes publishes the resource use of each component's process group,
// read from /proc. Each component is the leader of its own process group
// (the supervisor starts it that way), so its children, such as NGINX
// workers, are counted with it.
type Processes struct {
	// Root is the proc file system, "/proc" when empty.
	Root string
	// PIDs maps component names to their process IDs (group leaders).
	PIDs func() map[string]int
	// PageSize is the memory page size; os.Getpagesize() when zero.
	PageSize int
}

// Name returns the collector's name.
func (Processes) Name() string { return "processes" }

type procStat struct {
	pid, pgrp, threads int
	utime, stime       uint64
	rssPages           int64
}

// procNumber parses a number the kernel writes in /proc without a sign: a
// process ID, a process group or a thread count. Only decimal digits are
// accepted; strconv.Atoi would also take "+1" and "-0".
func procNumber(s string) (int, error) {
	n, err := strconv.ParseUint(s, 10, 31)
	return int(n), err
}

// parseStat reads one /proc/<pid>/stat line. The command name is in
// parentheses and may contain spaces or parentheses, so fields are counted
// from the last ')'.
func parseStat(line string) (procStat, bool) {
	open := strings.IndexByte(line, '(')
	end := strings.LastIndexByte(line, ')')
	if open < 1 || end < open {
		return procStat{}, false
	}
	pid, err := procNumber(strings.TrimSpace(line[:open]))
	if err != nil {
		return procStat{}, false
	}
	f := strings.Fields(line[end+1:])
	// f[0] is field 3 (state); field n is f[n-3].
	if len(f) < 22 {
		return procStat{}, false
	}
	var ps procStat
	ps.pid = pid
	var e [5]error
	ps.pgrp, e[0] = procNumber(f[5-3])
	ps.utime, e[1] = strconv.ParseUint(f[14-3], 10, 64)
	ps.stime, e[2] = strconv.ParseUint(f[15-3], 10, 64)
	ps.threads, e[3] = procNumber(f[20-3])
	ps.rssPages, e[4] = strconv.ParseInt(f[24-3], 10, 64)
	for _, err := range e {
		if err != nil {
			return procStat{}, false
		}
	}
	return ps, true
}

// Collect adds per-component process metrics.
func (p Processes) Collect(b *Batch) {
	root := p.Root
	if root == "" {
		root = "/proc"
	}
	pids := p.PIDs()
	if len(pids) == 0 {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		b.Errorf("cannot read %s: %v", root, err)
		return
	}
	page := int64(p.PageSize)
	if page <= 0 {
		page = int64(os.Getpagesize())
	}
	groups := map[int][]procStat{}
	for _, e := range entries {
		if _, err := procNumber(e.Name()); err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, e.Name(), "stat")) // #nosec G304 -- /proc/<pid>/stat; the name is all digits (checked above)
		if err != nil {
			continue // the process ended between the listing and the read
		}
		ps, ok := parseStat(string(raw))
		if !ok {
			b.Errorf("cannot parse %s/%s/stat", root, e.Name())
			continue
		}
		groups[ps.pgrp] = append(groups[ps.pgrp], ps)
	}
	names := make([]string, 0, len(pids))
	for n := range pids {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		pid := pids[name]
		procs := groups[pid]
		if len(procs) == 0 {
			continue // not running right now
		}
		var cpu uint64
		var rss int64
		threads, fds := 0, 0
		for _, ps := range procs {
			cpu += ps.utime + ps.stime
			rss += ps.rssPages * page
			threads += ps.threads
			if fd, err := os.ReadDir(filepath.Join(root, strconv.Itoa(ps.pid), "fd")); err == nil {
				fds += len(fd)
			}
		}
		comp := L("component", name)
		b.Counter("observex_node_component_cpu_seconds_total", "CPU time used by the component's process group, user and system.", float64(cpu)/UserHZ, comp)
		b.Gauge("observex_node_component_resident_bytes", "Resident memory of the component's process group.", float64(rss), comp)
		b.Gauge("observex_node_component_processes", "Processes in the component's process group.", float64(len(procs)), comp)
		b.Gauge("observex_node_component_threads", "Threads in the component's process group.", float64(threads), comp)
		b.Gauge("observex_node_component_open_fds", "Open file descriptors in the component's process group (only those the node may read).", float64(fds), comp)
	}
}

// Host publishes the host's load and memory, read from /proc.
type Host struct {
	Root string
}

// Name returns the collector's name.
func (Host) Name() string { return "host" }

// Collect adds host metrics.
func (h Host) Collect(b *Batch) {
	root := h.Root
	if root == "" {
		root = "/proc"
	}
	// root is /proc; tests point it at a fixture directory.
	if raw, err := os.ReadFile(filepath.Join(root, "loadavg")); err != nil { // #nosec G304 -- see above
		b.Errorf("cannot read loadavg: %v", err)
	} else if f := strings.Fields(string(raw)); len(f) >= 3 {
		for i, w := range []string{"1m", "5m", "15m"} {
			if v, err := strconv.ParseFloat(f[i], 64); err == nil {
				b.Gauge("observex_node_host_load", "Host load average.", v, L("window", w))
			}
		}
	} else {
		b.Errorf("cannot parse loadavg")
	}
	raw, err := os.ReadFile(filepath.Join(root, "meminfo")) // #nosec G304 -- /proc, as above
	if err != nil {
		b.Errorf("cannot read meminfo: %v", err)
		return
	}
	want := map[string]string{"MemTotal:": "observex_node_host_memory_total_bytes", "MemAvailable:": "observex_node_host_memory_available_bytes"}
	help := map[string]string{"MemTotal:": "Host memory.", "MemAvailable:": "Host memory available for new work without swapping."}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			if name, ok := want[f[0]]; ok {
				kb, err := strconv.ParseFloat(f[1], 64)
				if err != nil {
					b.Errorf("cannot parse %s", f[0])
					continue
				}
				b.Gauge(name, help[f[0]], kb*1024)
				delete(want, f[0])
			}
		}
	}
	for k := range want {
		b.Errorf("meminfo has no %s", strings.TrimSuffix(k, ":"))
	}
}

// Disks publishes free and total space of the node's volumes.
type Disks struct {
	// Volumes maps a volume name ("data", "logs") to a directory on it.
	Volumes map[string]string
}

// Name returns the collector's name.
func (Disks) Name() string { return "disks" }

// Collect adds disk metrics.
func (d Disks) Collect(b *Batch) {
	names := make([]string, 0, len(d.Volumes))
	for n := range d.Volumes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		total, avail, err := diskSpace(d.Volumes[n])
		if err != nil {
			b.Errorf("volume %s: %v", n, err)
			continue
		}
		v := L("volume", n)
		b.Gauge("observex_node_disk_total_bytes", "Size of the volume.", float64(total), v)
		b.Gauge("observex_node_disk_available_bytes", "Space on the volume available to the node.", float64(avail), v)
	}
}
