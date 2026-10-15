// Package storetest holds the contract suites every store implementation must
// pass: the in-memory fakes today, and the Cassandra, OpenSearch, TraceStore
// and etcd adapters from G02 on. A suite takes a function that opens a fresh,
// empty store for each subtest.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Voxmatic/observe/internal/store"
)

// T0 is the fixed start time used by every suite.
var T0 = time.Date(2026, 10, 17, 2, 0, 0, 0, time.UTC)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func cancelled() context.Context {
	c, cancel := context.WithCancel(context.Background())
	cancel()
	return c
}

func wantErr(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: err = %v, want %v", what, err, target)
	}
}

func noErr(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func hour() store.TimeRange { return store.TimeRange{Start: T0, End: T0.Add(time.Hour)} }
