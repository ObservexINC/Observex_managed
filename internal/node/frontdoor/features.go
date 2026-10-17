package frontdoor

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Features describes the NGINX installed on a host, as far as the generated
// configuration depends on it.
type Features struct {
	// Version is NGINX's version, for example "1.24.0".
	Version string `json:"version"`
	// TLSLibrary is the TLS library NGINX runs with, for example
	// "OpenSSL 3.0.13".
	TLSLibrary string `json:"tls_library"`
	// HTTP2Directive is true from NGINX 1.25.1, which has "http2 on;" and
	// deprecates "listen ... http2".
	HTTP2Directive bool `json:"http2_directive"`
	// HybridPQ is true when the TLS library offers the hybrid post-quantum
	// group X25519MLKEM768 (OpenSSL 3.5 or later).
	HybridPQ bool `json:"hybrid_pq"`
}

var (
	nginxVersionRE = regexp.MustCompile(`nginx version: nginx/(\d+)\.(\d+)\.(\d+)`)
	builtWithRE    = regexp.MustCompile(`built with (OpenSSL|LibreSSL|BoringSSL) ?([0-9][0-9a-z.]*)?`)
	runningWithRE  = regexp.MustCompile(`running with (OpenSSL|LibreSSL|BoringSSL) ?([0-9][0-9a-z.]*)?`)
	openSSLVerRE   = regexp.MustCompile(`^(\d+)\.(\d+)`)
)

// ParseFeatures reads the output of "nginx -V".
func ParseFeatures(out string) (Features, error) {
	m := nginxVersionRE.FindStringSubmatch(out)
	if m == nil {
		return Features{}, errors.New("frontdoor: cannot find the NGINX version in nginx -V output")
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	f := Features{Version: m[1] + "." + m[2] + "." + m[3]}
	f.HTTP2Directive = versionAtLeast(major, minor, patch, 1, 25, 1)

	lib := runningWithRE.FindStringSubmatch(out)
	if lib == nil {
		lib = builtWithRE.FindStringSubmatch(out)
	}
	if lib == nil {
		return f, nil // no TLS library: the configuration must be plaintext
	}
	f.TLSLibrary = strings.TrimSpace(lib[1] + " " + lib[2])
	if lib[1] == "OpenSSL" {
		if v := openSSLVerRE.FindStringSubmatch(lib[2]); v != nil {
			omaj, _ := strconv.Atoi(v[1])
			omin, _ := strconv.Atoi(v[2])
			f.HybridPQ = omaj > 3 || omaj == 3 && omin >= 5
		}
	}
	return f, nil
}

func versionAtLeast(a, b, c, x, y, z int) bool {
	if a != x {
		return a > x
	}
	if b != y {
		return b > y
	}
	return c >= z
}

// Probe runs "nginx -V" and parses its output.
func Probe(ctx context.Context, nginx string) (Features, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, nginx, "-V").CombinedOutput()
	if err != nil {
		return Features{}, fmt.Errorf("frontdoor: nginx -V failed: %w", err)
	}
	return ParseFeatures(string(out))
}
