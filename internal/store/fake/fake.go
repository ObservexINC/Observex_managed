// Package fake provides in-memory implementations of every store contract.
// Modules use them to run and test without any database. Each fake passes the
// same contract suite (internal/store/storetest) that real adapters must pass.
package fake

import (
	"context"
	"sync"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// lifecycle tracks Close and context cancellation for every fake.
type lifecycle struct {
	mu     sync.RWMutex
	closed bool
}

func (l *lifecycle) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.closed {
		return store.ErrClosed
	}
	return nil
}

func (l *lifecycle) close() {
	l.closed = true
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
