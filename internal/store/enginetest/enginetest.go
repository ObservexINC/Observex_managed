// Package enginetest finds the real engines that store adapter tests run
// against (ADR 0011). Each engine's address comes from an environment
// variable; test/rig starts the engines in Docker or from tarballs.
//
// Without the variable a test skips and says how to run it. With
// OBSERVEX_REQUIRE_ENGINES=1 (CI and Astra's runs) a missing engine fails
// the test instead, so a skipped engine suite cannot pass as a green run.
package enginetest

import (
	"os"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
)

// Environment variables.
const (
	Require            = "OBSERVEX_REQUIRE_ENGINES"
	Cassandra          = "OBSERVEX_TEST_CASSANDRA" // host:port, comma-separated
	CassandraUsername  = "OBSERVEX_TEST_CASSANDRA_USERNAME"
	CassandraPassword  = "OBSERVEX_TEST_CASSANDRA_PASSWORD" //nolint:gosec // G101: the name of an environment variable, not a credential
	OpenSearch         = "OBSERVEX_TEST_OPENSEARCH"         // http(s)://host:port
	OpenSearchUsername = "OBSERVEX_TEST_OPENSEARCH_USERNAME"
	OpenSearchPassword = "OBSERVEX_TEST_OPENSEARCH_PASSWORD" //nolint:gosec // G101: the name of an environment variable, not a credential
	OpenSearchCA       = "OBSERVEX_TEST_OPENSEARCH_CA"       // PEM file of the CA for https
)

// Address returns the value of env, or skips (or fails, when engines are
// required) if it is not set.
func Address(t testing.TB, env string) string {
	t.Helper()
	v := os.Getenv(env)
	if v != "" {
		return v
	}
	if os.Getenv(Require) == "1" {
		t.Fatalf("%s is not set and %s=1: start the engines (test/rig) and set it", env, Require)
	}
	t.Skipf("real-engine test: set %s to a running engine (see test/rig/README.md)", env)
	return ""
}

// Credentials returns a username and password from the environment; both
// are empty when unset.
func Credentials(userEnv, passwordEnv string) (string, logging.Secret) {
	return os.Getenv(userEnv), logging.Secret(os.Getenv(passwordEnv))
}
