package etcdstore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// threeMembers returns the configurations of a new three-member cluster.
func threeMembers(t *testing.T) []Config {
	t.Helper()
	dir := t.TempDir()
	p := freePorts(t, 6)
	names := []string{"node-1", "node-2", "node-3"}
	var cfgs []Config
	var members []Member
	for i, name := range names {
		c := memberConfig(t, dir, name, p[2*i], p[2*i+1])
		cfgs = append(cfgs, c)
		members = append(members, Member{Name: name, PeerURL: c.PeerURL})
	}
	for i := range cfgs {
		cfgs[i].Cluster = members
	}
	return cfgs
}

// startAll starts members concurrently: each waits for a quorum.
func startAll(t *testing.T, cfgs []Config) []*Node {
	t.Helper()
	nodes := make([]*Node, len(cfgs))
	errs := make([]error, len(cfgs))
	var wg sync.WaitGroup
	for i, c := range cfgs {
		wg.Add(1)
		go func(i int, c Config) {
			defer wg.Done()
			nodes[i], errs[i] = Start(startCtx(t), c)
		}(i, c)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("start %s: %v", cfgs[i].Name, err)
		}
	}
	return nodes
}

func within(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// eventually retries f until it succeeds or the deadline passes.
func eventually(t *testing.T, what string, d time.Duration, f func() error) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		err := f()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: still failing after %v: %v", what, d, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestQuorumLoss runs three members, loses two and checks that the survivor
// refuses reads and writes instead of serving stale or split data, then
// brings members back and checks that nothing committed was lost.
func TestQuorumLoss(t *testing.T) {
	cfgs := threeMembers(t)
	nodes := startAll(t, cfgs)
	defer func() {
		for _, n := range nodes {
			if n != nil {
				_ = n.Close()
			}
		}
	}()
	s1, s2, s3 := nodes[0].Store("cfg/"), nodes[1].Store("cfg/"), nodes[2].Store("cfg/")

	// All three see a write made on any member.
	rev, err := s1.Put(within(t, 10*time.Second), "rules/r1", []byte("v1"), store.MustNotExist)
	if err != nil {
		t.Fatalf("write with three members: %v", err)
	}
	for i, s := range []*Store{s2, s3} {
		kv, err := s.Get(within(t, 10*time.Second), "rules/r1")
		if err != nil || string(kv.Value) != "v1" || kv.Revision != rev {
			t.Fatalf("member %d reads %+v, %v", i+2, kv, err)
		}
	}
	for _, n := range nodes {
		if st := n.Status(); st.Members != 3 || !st.HasLeader {
			t.Fatalf("status with three members: %+v", st)
		}
	}

	// One member lost: two of three are a quorum, so work goes on.
	_ = nodes[2].Close()
	nodes[2] = nil
	rev2, err := s1.Put(within(t, 10*time.Second), "rules/r1", []byte("v2"), rev)
	if err != nil {
		t.Fatalf("write with two of three members: %v", err)
	}

	// Two members lost: the survivor must refuse, not answer from its copy.
	_ = nodes[1].Close()
	nodes[1] = nil
	start := time.Now()
	if _, err := s1.Put(within(t, 3*time.Second), "rules/r2", []byte("lost"), store.AnyRevision); err == nil {
		t.Fatal("write succeeded with one of three members")
	} else if errors.Is(err, store.ErrInvalid) || errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("write without quorum returned a contract error: %v", err)
	}
	if _, err := s1.Get(within(t, 3*time.Second), "rules/r1"); err == nil {
		t.Fatal("read succeeded with one of three members: it could be stale")
	}
	if _, err := s1.List(within(t, 3*time.Second), ""); err == nil {
		t.Fatal("list succeeded with one of three members")
	}
	t.Logf("calls without quorum failed; first failure after %v", time.Since(start).Round(time.Millisecond))
	eventually(t, "survivor reports no leader", 10*time.Second, func() error {
		if nodes[0].Status().HasLeader {
			return errors.New("still sees a leader")
		}
		return nil
	})

	// One member back: quorum again, and the committed value is there.
	n2, err := Start(startCtx(t), cfgs[1])
	if err != nil {
		t.Fatalf("restart node-2: %v", err)
	}
	nodes[1] = n2
	eventually(t, "read after quorum returns", 20*time.Second, func() error {
		kv, err := s1.Get(within(t, 2*time.Second), "rules/r1")
		if err != nil {
			return err
		}
		if string(kv.Value) != "v2" || kv.Revision != rev2 {
			t.Fatalf("after recovery rules/r1 = %+v, want v2 at %d", kv, rev2)
		}
		return nil
	})
	if _, err := s1.Put(within(t, 10*time.Second), "rules/r3", []byte("after"), store.MustNotExist); err != nil {
		t.Fatalf("write after quorum returned: %v", err)
	}

	// The third member catches up with everything it missed.
	n3, err := Start(startCtx(t), cfgs[2])
	if err != nil {
		t.Fatalf("restart node-3: %v", err)
	}
	nodes[2] = n3
	s3 = n3.Store("cfg/")
	eventually(t, "node-3 catches up", 20*time.Second, func() error {
		kv, err := s3.Get(within(t, 2*time.Second), "rules/r3")
		if err != nil {
			return err
		}
		if string(kv.Value) != "after" {
			t.Fatalf("node-3 reads %+v", kv)
		}
		return nil
	})
	kv, err := s3.Get(within(t, 5*time.Second), "rules/r1")
	if err != nil || string(kv.Value) != "v2" || kv.Revision != rev2 {
		t.Fatalf("node-3 rules/r1 = %+v, %v", kv, err)
	}
}

// TestNewClusterWaitsForQuorum checks that a member of a new three-member
// cluster does not report ready on its own.
func TestNewClusterWaitsForQuorum(t *testing.T) {
	cfgs := threeMembers(t)
	_, err := Start(within(t, 3*time.Second), cfgs[0])
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lone member of a three-member cluster: err = %v, want a deadline error", err)
	}
}
