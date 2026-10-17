package frontdoor

import (
	"strings"
	"testing"
)

// FuzzParseFeatures checks that parsing any "nginx -V" output never panics
// and never claims the hybrid post-quantum group without OpenSSL.
func FuzzParseFeatures(f *testing.F) {
	for _, s := range []string{
		"nginx version: nginx/1.24.0 (Ubuntu)\nbuilt with OpenSSL 3.0.13 30 Jan 2024\nTLS SNI support enabled\n",
		"nginx version: nginx/1.29.1\nbuilt with OpenSSL 3.5.0 8 Apr 2025\nrunning with OpenSSL 3.5.2 5 Aug 2025\n",
		"nginx version: nginx/1.25.1\nbuilt with LibreSSL 3.8.2\n",
		"nginx version: nginx/1.26.0\n",
		"nginx version: nginx/99999999999999999999.1.1\nbuilt with OpenSSL 99999999999999999999.5\n",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		feat, err := ParseFeatures(out)
		if err != nil {
			return
		}
		if feat.HybridPQ && !strings.HasPrefix(feat.TLSLibrary, "OpenSSL ") {
			t.Fatalf("hybrid PQ claimed for %q", feat.TLSLibrary)
		}
		if feat.Version == "" {
			t.Fatal("accepted output without a version")
		}
	})
}
