# G01 test manifest

Code commit: `885480f` (G01 docs), on top of `0869717`, `3eabe9d` and `298eaad`.

"Claude workspace" means Claude's cloud development workspace: a Linux
container (Ubuntu 24.04, kernel 6.18, amd64), Go 1.24.7, NGINX 1.24.0 with
OpenSSL 3.0.13, **no systemd**, run on 17 October 2026. It is not akash's
machine and not a virtual machine. Astra's runs are the acceptance evidence.

## G01 "done when"

| Criterion | Claude workspace | Still needed |
| --- | --- | --- |
| A killed process is restarted | Shown three ways with real NGINX: integration test `TestKilledFrontDoorIsRestarted` (SIGKILL to the NGINX master, restart, `/node/health` through the Front Door over TLS 1.3, no live leftovers); supervisor unit tests; live install test checks 16 to 18 (restarted and ready in 3 s) | Astra on WSL2 and on a VM |
| A node installs from a tarball on a clean VM | Shown in a disposable **container without systemd**: live install test 24 of 24 | Astra on a clean VM **with systemd** (27 checks); the CI `node-install` job once pushed |

## What ran in Claude's workspace

| Check | Command | Result |
| --- | --- | --- |
| Formatting, vet, build | `make ci-local` | Clean |
| Unit, contract, integration and fuzz-seed tests, race detector | `go test -race ./...` (twice, plus a third run of the NGINX integration tests) | PASS every run: 139 tests, 9 fuzz seed sets, 152 subtests; 0 failed, 0 skipped |
| Coverage across packages | `make cover` | 92.3% to 92.4% of statements (timing paths vary slightly) |
| Shell scripts | `make shell-check` | `sh -n` syntax only; **shellcheck not installed** |
| Fuzz, 30 s each | `make fuzz FUZZTIME=30s` | 9 of 9 PASS |
| Tarball build, twice | `make package VERSION=0.1.0-g01` | Byte-identical; SHA-256 `7e348e09e92ac6a5baa403799b84ec394e9db7329a5acb71ca1b33544b5320de` (from a fresh clone at `885480f`, Go 1.24.7) |
| Install test, layout | `packaging/linux/test-install.sh layout <tarball>` | 20 of 20 |
| Install test, live, no systemd | `packaging/linux/test-install.sh live <tarball>` (as root) | 24 of 24 |
| systemd unit | `systemd-analyze verify`, `systemd-analyze security --offline=yes` | Only "binary not installed" (expected); exposure 3.2 "OK" |
| Fresh clone of `885480f` | `git clone` then `make ci-local`, `make install-test` | PASS |
| Windows compile only | `GOOS=windows go vet ./...`, `go test -c` for every package | Compiles; **not run** on Windows |
| macOS compile only | `GOOS=darwin GOARCH=arm64 go vet ./...` | Clean; **not run** on macOS |

### Coverage by package

| Package | Coverage |
| --- | --- |
| cmd/observex-node | 81.3% |
| internal/node | 84.9% |
| internal/node/firewall | 97.6% |
| internal/node/frontdoor | 97.9% |
| internal/node/pki | 77.4% |
| internal/node/selfmon | 97.8% |
| internal/node/supervisor | 97.8% |
| internal/platform/clock | 100.0% |
| internal/platform/config | 96.7% |
| internal/platform/logging | 96.6% |
| internal/platform/tlsx | 93.1% |
| internal/platform/tlsx/tlstest | 86.0% |
| internal/store | 100.0% |
| internal/store/fake | 96.2% |
| internal/store/storetest | 88.9% |
| **total** | **92.3%** |

`internal/node/pki` is below 80%; its uncovered lines are error returns from
the random number generator and the file system that tests cannot provoke
without fault injection.

### Fuzz targets (30 s each, all PASS)

| Target | Package | Checks |
| --- | --- | --- |
| FuzzRedactString | platform/logging | No panic; idempotent |
| FuzzDecode | platform/config | No panic; validation always runs after decoding |
| FuzzVerifyToken | platform/tlsx | No panic; only the issued token verifies |
| FuzzParseTraceID | store | No panic; zero ID refused; round trip |
| FuzzParse | node | Accepted configurations keep internal addresses on loopback and render NGINX files made only of the template's own directives |
| FuzzParseFeatures | node/frontdoor | No panic; never claims post-quantum TLS without OpenSSL |
| FuzzCheck | node/firewall | No panic; consistent problem count; command output never reaches suggested commands |
| FuzzParseStat | node/selfmon | No panic on any `/proc/<pid>/stat` line |
| FuzzWriteText | node/selfmon | Escaping keeps one sample per line for any label or help text |

### Live install test (no systemd), 24 checks

1–2 tarball matches SHA256SUMS and holds its files · 3 install · 4 ready in
1 s · 5 user `observex` cannot log in · 6 `/etc/observex` root:observex 0750 ·
7 node key root:observex 0640 · 8 CA key root:root 0600 · 9
`/var/lib/observex` observex-owned · 10 `/node/health` through the Front Door
over TLS 1.3 on port 443 · 11 Front Door does not expose `/metrics` · 12
Agents listener on 9443 refuses a request without a client certificate · 13
loopback `/metrics` reports the node ready · 14 status names the NGINX master
· 15 NGINX runs as `observex`, not root · 16 NGINX killed with SIGKILL is
restarted and the node is ready again · 17 the restart is a new process · 18
health through the Front Door after the restart · 19 clean stop on SIGTERM ·
20 clean stop logged · 21 no NGINX left · 22–24 `uninstall.sh --purge --yes`
removes files and the user.

## Not run anywhere yet

| Check | Why not | Who runs it |
| --- | --- | --- |
| Install on a VM with systemd | Claude's workspace is a container without systemd | Astra (step 5); CI `node-install` job after a push |
| Native Windows test run | Workspace is Linux; first Windows run of the supervisor tests | Astra (step 3) |
| Go 1.27 | Module proxy unreachable from Claude's workspace | Astra; CI |
| golangci-lint, govulncheck, gitleaks, go-licenses, buf, shellcheck | Same | Astra (step 6); CI |
| Front Door with NGINX on OpenSSL 3.5 (post-quantum group live) | No such NGINX in the workspace; covered by golden files and unit tests only | Astra if a distribution with OpenSSL 3.5 is at hand (for example Ubuntu 25.10 or Fedora 42); otherwise later |
| GitHub Actions | Nothing pushed since G00 | CI after akash pushes |
