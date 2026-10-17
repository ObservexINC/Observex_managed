package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Handler serves the supervisor's status. It is meant for the node's
// loopback address only:
//
//	GET /livez   200 while the supervisor runs
//	GET /readyz  200 when every component is ready, else 503; the body is
//	             the node ID and the full Status
//	GET /status  200 with the node ID and the full Status, ready or not
//	GET /health  200 {"status":"ready"} or 503 {"status":"not_ready"}; the
//	             only supervisor path the Front Door exposes (/node/health),
//	             so it carries nothing else
//
// Other methods get 405 and other paths 404.
func (s *Supervisor) Handler(nodeID string) http.Handler {
	mux := http.NewServeMux()
	full := func(w http.ResponseWriter, alwaysOK bool) {
		st := s.Status()
		code := http.StatusOK
		if !st.Ready && !alwaysOK {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, struct {
			NodeID string `json:"node_id"`
			Status
		}{nodeID, st})
	}
	mux.HandleFunc("/livez", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
	}))
	mux.HandleFunc("/readyz", getOnly(func(w http.ResponseWriter, _ *http.Request) { full(w, false) }))
	mux.HandleFunc("/status", getOnly(func(w http.ResponseWriter, _ *http.Request) { full(w, true) }))
	mux.HandleFunc("/health", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		if s.Status().Ready {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
	return mux
}

func getOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// probeClient never uses a proxy from the environment and never keeps
// connections, so a probe always tests a fresh connection.
var probeClient = &http.Client{
	Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// HTTPReady returns a readiness check that passes when GET url answers 200.
// The check's deadline comes from the context the supervisor passes in.
func HTTPReady(url string) ReadyFunc {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := probeClient.Do(req)
		if err != nil {
			return errors.New("readiness check got no answer")
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("readiness check answered %d", resp.StatusCode)
		}
		return nil
	}
}

// TCPReady returns a readiness check that passes when addr accepts a TCP
// connection.
func TCPReady(addr string) ReadyFunc {
	return func(ctx context.Context) error {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return errors.New("readiness check: connection refused or timed out")
		}
		_ = conn.Close()
		return nil
	}
}

// AllReady combines checks; it passes when all of them pass.
func AllReady(checks ...ReadyFunc) ReadyFunc {
	return func(ctx context.Context) error {
		for _, c := range checks {
			if err := c(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

// WaitTimeout is a helper for callers that poll Status: it reports whether
// cond became true before the timeout.
func (s *Supervisor) WaitTimeout(cond func(Status) bool, timeout, every time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond(s.Status()) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(every)
	}
}
