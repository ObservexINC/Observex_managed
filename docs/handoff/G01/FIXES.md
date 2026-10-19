# G01 QA fixes: handoff to Codex Astra

> **Follow-up rounds:** Astra's revalidation of 18 October 2026 (findings
> F01 to F03) is answered in [FOLLOWUP.md](FOLLOWUP.md), his residual
> cases of 19 October (R01 to R03) in [REPAIRS.md](REPAIRS.md), his
> boundary cases (S01, S02) in [BOUNDARIES.md](BOUNDARIES.md) and his
> further boundary cases (T01 to T03) in
> [BOUNDARIES-II.md](BOUNDARIES-II.md), which supersedes this file's
> validation steps, tarball version and results.
> The thirteen findings below stay fixed.

Answers Astra's G01 QA report of 17 October 2026 (findings G01-01 to
G01-13, tested HEAD `30e137a`). Status: **all thirteen findings have fixes,
verified in Claude's workspace; awaiting Astra's validation and akash's
approval.** Nothing has been pushed. No ADR status was changed (all remain
Proposed). The project licence and the choice between the distribution's
NGINX and a custom build are untouched: both stay akash's decisions.

## Commits on main (on top of `30e137a`)

| Commit | Findings | Content |
| --- | --- | --- |
| `752138e` | G01-03, 04, 05 | Logging: structured values redacted before rendering, escape-aware text rules, JSON redacted by member, sensitive groups via `WithGroup`; ADR 0007 updated |
| `8048300` | G01-06 | ConfigStore `Delete` validates arguments before the key's state; contract and suite |
| `c86f1b7` | G01-02 | Supervisor output drops multi-line PEM private keys; lint fixes in the same files |
| `4ab8808` | G01-07, 08 | Typed network errors with platform error numbers; Linux node paths on every host; lint fixes in the same files |
| `e01a5fb` | G01-01 | `ExecStartPre` check in the service's context; installer failure path; stronger live test; ShellCheck fixes in these scripts; ADR 0010 updated |
| `72d467d` | G01-09 to 13 | Lint, ShellCheck, licence, gitleaks gates; pinned tools; binary vulnerability scan target; ADR 0005 updated |
| next commit | | This file, the threat model, and `files-g01-fixes.sha256` |

Every commit builds and passes `go vet` for Linux and Windows on its own.
Where a file needed both a finding's fix and a lint fix, both are in that
finding's commit and its message says so.

`observe-G01-fixes.bundle` holds every commit since G00 (`49b834e`), so it
applies to a repository at G00 or at `30e137a`. Its SHA-256, the final
commit hash and the tarball's SHA-256 are in the files delivered next to
it, because this file is part of the commit they describe.

## Finding by finding

"Here" means Claude's workspace, described under "Environment" below.

| ID | Fix | Tests | Result here | Still needs |
| --- | --- | --- | --- | --- |
| **G01-01** P1, installer pre-start check | The unit runs `observex-node check` as `ExecStartPre`: as `observex`, with `CAP_NET_BIND_SERVICE` only and the service's sandbox, so the check binds 443 exactly as the node will. The installer no longer runs its own check as a plain user. If the start fails, it prints the check's message from the journal, stops the service (left enabled) and exits 1. The service user, capability set and hardening are unchanged. | `test-install.sh live`: the `/metrics` check requires a healthy Front Door and the exact 503 JSON answer (curl `000` fails it); the Agents check requires 403 and its JSON error; the three restart checks count as failures when no NGINX started instead of disappearing; a new check confirms the pre-start check passed in the service's context. **28 checks with systemd** (27 + that one), 25 without. | Under systemd 255 with `ip_unprivileged_port_start=1024`: the **G01 tarball reproduced Astra's result exactly** (24 checks run, 9 failed, `/metrics` falsely passing); the **fixed tarball passed 28 of 28**. With port 9443 busy, the default installer exited 1, printed `check failed: ports: Agents and Gateways (Front Door): already in use by another process (0.0.0.0:9443)`, and left the service enabled and inactive. Without systemd: 25 of 25. Layout: 20 of 20. | A conventional fresh VM, and Astra's fresh WSL distribution |
| **G01-02** P1, multi-line PEM keys in child output | The output writer follows each process's stream byte by byte: from `-----BEGIN … PRIVATE KEY-----` to its END marker every line is dropped (the BEGIN line shows `[REDACTED]`), text after END on the same line is kept, and a key whose END never comes is dropped until the process exits (fail closed). Markers split across writes, with CRLF, or beyond the shown part of a 16 KiB line are found. The writer is closed and removed when its process ends. | `output_test.go` (9 tests; every key label × LF/CRLF × one write or chunks of 1, 3, 7 and 64 bytes), `TestKeyStateEndsWithTheProcess`, `FuzzPrefixWriter`, Astra's `TestQASupervisorRedactsMultilinePrivateKey` | Astra's test **fails on `30e137a`, passes now** (his unmodified file, through a Go overlay) | Native Windows run |
| **G01-03** P1, structured values | Values are walked by reflection before rendering: sensitive struct fields (by Go or JSON name), map keys and JSON members lose their whole value whatever its type; bounded (depth 8, 256 items, 4096 values, 64 KiB strings) with cycle and truncation marks; only `LogValue`, `Error` and enumeration `String` methods run, under `recover`. | `structure_test.go` (12 tests, 22 value shapes), `FuzzRedactConfidential`, Astra's `TestQAAnySecretValuesRemainFullyRedacted` | Fails on `30e137a`, passes now | |
| **G01-04** P1, escaped JSON quotes | Key/value rules consume escape sequences (`\"`, double-encoded `\\\"`), fail closed on an unterminated quote; a string that is a whole JSON document (≤ 1 MiB) is parsed and redacted member by member. `RedactString` stays idempotent. | 17 escaped and malformed cases, JSON structure test, both fuzz targets, Astra's `TestQAJSONStringEscapedQuotesRemainRedacted` | Fails on `30e137a`, passes now | |
| **G01-05** P1, `WithGroup` | A handler derived with a sensitive group name redacts every attribute below it, as `slog.Group` does; handlers stay immutable and safe to derive concurrently. | Group tests across `With`, `WithGroup`, `slog.Group` and nesting; sibling groups unaffected; concurrent derivation; Astra's `TestQASensitiveGroupConsistentAcrossAPIs` | Fails on `30e137a`, passes now | |
| **G01-06** P2, `Delete` error | `Delete` with `MustNotExist`, a revision below `AnyRevision` or an empty key is `ErrInvalid` whether or not the key exists. The contract states the error order (closed or context, then `ErrInvalid`, then `ErrNotFound`/`ErrConflict`) and that a rejected call does not advance the revision. | Two new contract-suite subtests (run by every ConfigStore, the fake now, etcd in G02), Astra's `TestQADeleteMustNotExistIsInvalidForMissingKey` | Fails on `30e137a`, passes now | |
| **G01-07** P2, Windows path semantics | Node configuration paths are Linux paths on every host: defaults come from `pki.NodePaths` (package `path`), and `pki.Paths` (host paths) is used only where files are written. Validation is unchanged. `init` tests run on Unix hosts only (`init_unix_test.go`, reason in its header); on Windows `TestInitRefusesWindowsPathsAndWritesNothing` checks the refusal. The status/health test uses fixed Linux paths. | `TestNodePathsAreSlashSeparatedOnEveryHost`; the parser/default tests Astra listed now use slash paths on every host | Windows: `go vet` and `go test -c` for every package, **compile only** | **A native Windows test run** |
| **G01-08** P2, firewall error strings | Errors are classified with `errors.As` on `syscall.Errno` (Unix errnos; Winsock 10013/10048/10049/10050/10051/10060/10061/10064/10065 on Windows), `net.Error.Timeout`, deadline errors and `*net.DNSError`; never English text. New statuses `permission_denied`, `no_such_address`, `bind_error`, `unreachable`; `CheckPorts` fails on all bind problems. The default dial timeout is 5 s because Windows retries a refused connection for about 2 s. | `TestBindStatusUsesErrorNumbers`, `TestDialStatusUsesErrorTypes` (refusal, timeout, permission, in use, no address, unreachable, DNS, and English text that must decide nothing), the real refused-loopback test at the default timeout, `FuzzCheck` | Linux pass; Windows compile only | **A native Windows run**: the Winsock mapping and the 2 s refusal only show there |
| **G01-09** P1 gate, toolchain vulnerabilities | Built with **Go 1.27.2** (`dl.google.com`; SHA-256 matches, OpenPGP signature good from Google's key `EB4C 1BFD 4F04 2F6D DDCC EC91 7721 F63B D38B 4796`). `make vuln-package` scans the binary inside the tarball; CI runs it. `go.mod` keeps `go 1.24.0`. | | `govulncheck` 1.9.0 on source: **no vulnerabilities** (none reachable, imported or required). On the shipped binary (`-mode=binary`): **no vulnerabilities**. | Astra's rescan of the rebuilt tarball |
| **G01-10** P2 gate, lint | Every finding fixed. Reports are now uncapped (`max-issues-per-linter: 0`, `max-same-issues: 0`): golangci-lint's default caps hide repeats, so at `30e137a` the Linux target shows 65 findings by default but has **104**, and the Windows target has 100 (evidence: `lint-30e137a-*.log`). All are fixed. Exceptions are listed below. | | golangci-lint 2.14.0: **0 issues** for Linux, Windows and macOS targets (cross-analysis) | Astra's native Windows lint |
| **G01-11** P2 gate, ShellCheck | SC1007 (`CDPATH=''`), SC2046 (arguments via `set --`), SC2015 (`if`), SC2094 (checksum list written beside the stage, then moved). SC2317 is disabled only on the five test predicates that run through `check "$@"`. | | ShellCheck 0.9.0: clean on all five scripts | |
| **G01-12** P2 gate, licences | `make licenses` passes `--ignore github.com/ObservexINC/Observex_managed`: the module's own licence is the owner's open decision (README, ADR 0005), so the gate cannot judge it. Packages it imports are still checked. No licence was chosen or added. | | go-licenses 1.6.0: pass. The module has no third-party dependencies today, so the gate currently checks none; the first one added will be checked. | akash's licence decision, whenever he makes it |
| **G01-13** P2 gate, gitleaks | One exception in `.gitleaks.toml`: rule `generic-api-key` only, and only when the whole matched secret is exactly `X25519MLKEM768`. No paths or rules were disabled. `make secrets` now fails if gitleaks scanned no commits. Test PEM markers are assembled from parts so the new tests do not trip the `private-key` rule. | | gitleaks 8.30.1: **13 commits scanned, no leaks**. On invented samples, the ADR sentence passes and a generic key or `X25519MLKEM768` followed by more characters is still found (`gitleaks-exception-narrowness.log`). | |

Tool pinning: CI and `make tools` install golangci-lint v2.14.0, govulncheck
v1.9.0, gitleaks v8.30.1, go-licenses v1.6.0 and buf v1.74.0 (Makefile
variables).

### Lint, scanner and ShellCheck exceptions

Each is on one line or one rule and says why in the code.

| Where | Exception | Why |
| --- | --- | --- |
| `cmd/observex-node/main.go` | gosec G703, this file only (`.golangci.yml`) | The administrator names `-config` and `-tls-dir`; writing exactly there is the command's purpose |
| `cmd/observex-node/main.go` (config file) | `#nosec G302` | `0640`: the service group reads the configuration, which holds no secrets |
| `internal/node/supervisor/supervisor.go` (component start) | `nolint:noctx,gosec` | Specs come from validated configuration; the supervisor stops components with its own signal sequence, not on cancellation |
| `internal/node/frontdoor/frontdoor.go` (`nginx -t`) | `#nosec G204` | Configured, validated NGINX path; fixed arguments |
| `internal/node/firewall/firewall.go` (read-only firewall tools) | `#nosec G204` | Arguments must pass the fixed allowlist first |
| `internal/node/node.go`, `internal/node/pki/pki.go` (2), `internal/node/selfmon/collectors.go` (3) | `#nosec G304` | Administrator-configured files, fixed names in the TLS directory, `/proc` files |
| `internal/node/frontdoor/nginx_test.go`, `internal/node/supervisor/helper_unix_test.go` | `nolint:noctx` | Test processes stopped by explicit signals in cleanup |
| `packaging/linux/test-install.sh` | SC2317 on 5 functions | Invoked through `check "$@"`, which ShellCheck cannot follow |
| `.gitleaks.toml` | `generic-api-key`, exact `X25519MLKEM768` | Public TLS group name |

Earlier exceptions are unchanged (gosec in `_test.go` files, `crypto/sha1`
for RFC 5280 key identifiers, `#nosec G304` in `config` and `tlsx`, SC2086
for checked installer words, the gitleaks fixture file).

## Verification in Claude's workspace

### Environment

A cloud Linux container: Ubuntu 24.04.5, kernel 6.18, amd64; NGINX 1.24.0
with OpenSSL 3.0.13; ShellCheck 0.9.0. It is not akash's machine and not a
VM. For the systemd tests, systemd 255 was booted as PID 1 in private PID,
mount, network, UTS and IPC namespaces (`container=other`, private `/run`,
`/tmp` and `/var/tmp`, unrelated units masked), with
`net.ipv4.ip_unprivileged_port_start=1024`. That runs real systemd service
management (`ExecStartPre`, `AmbientCapabilities`, the sandbox, restart and
stop), but it is not a freshly installed distribution or a VM.

Go 1.27.2 and every check tool were built from source with Go 1.27.2
(versions in `tool-versions.log`).

### Results (at `72d467d`)

| Check | Command | Result |
| --- | --- | --- |
| Astra's five regression tests, baseline | his unmodified files on `30e137a` | **5 of 5 fail**, as he reported |
| Astra's five regression tests, fixed | his unmodified files through `go test -overlay` | **5 of 5 pass** (the repository keeps copies adapted only for lint and gitleaks) |
| Format, vet, build, race tests, coverage, shell | `make ci-local` | Pass |
| Race suite | `go test -count=1 -race ./...` | **169 top-level tests, 11 fuzz seed suites, 273 subtests: all pass, none skipped** (NGINX installed) |
| Coverage | `make cover` | **92.0%** of statements (by package below) |
| Fuzzing, 30 s each | `make fuzz FUZZTIME=30s` | **11 of 11 pass** (two new targets: `FuzzRedactConfidential`, `FuzzPrefixWriter`) |
| Lint | `make lint`; `GOOS=windows golangci-lint run ./...` | 0 issues; 0 issues |
| Vulnerabilities | `make vuln`; `make vuln-package` | No vulnerabilities; no vulnerabilities |
| Secrets | `make secrets` | 13 commits scanned, no leaks |
| Licences | `make licenses` | Pass |
| Protobuf | `make proto-lint`, `buf build` | Pass |
| Install, layout | `test-install.sh layout` | 20 of 20 |
| Install, live, no systemd | `test-install.sh live` | 25 of 25 |
| Install, live, systemd | `test-install.sh live` | **28 of 28** (G01 tarball: 24 run, 9 failed) |
| Installer, busy port, systemd | `install.sh` with 9443 held | Exit 1, the check's message shown, service enabled and inactive |
| Windows | `GOOS=windows go vet ./...`, `go test -c` for every package | Compiles; **not run** |
| Bisectability | `go build`, `go vet` (Linux and Windows) at each new commit | Pass |

The tarball is reproducible: its file times come from the last commit, so
it was rebuilt twice at the final commit after this file was committed, and
both builds are byte-identical (hash delivered next to the bundle). The
binary inside does not depend on the commit time; with `VERSION=0.1.0-g01-fix1`
it is `bin/observex-node`, SHA-256
`d6aeac607fac146a771fa7e2231c41c96f474b9fb719f47ac22a5faf1c840af7`, built
with Go 1.27.2, and that is the binary the tests above installed.

### Coverage by package

| Package | Coverage |
| --- | --- |
| cmd/observex-node | 81.2% |
| internal/node | 85.1% |
| internal/node/firewall | 97.0% |
| internal/node/frontdoor | 97.9% |
| internal/node/pki | 77.6% |
| internal/node/selfmon | 97.4% |
| internal/node/supervisor | 98.1% |
| internal/platform/clock | 100.0% |
| internal/platform/config | 96.7% |
| internal/platform/logging | 88.3% |
| internal/platform/tlsx | 93.1% |
| internal/platform/tlsx/tlstest | 86.0% |
| internal/store | 100.0% |
| internal/store/fake | 96.5% |
| internal/store/storetest | 89.1% |
| **all** | **92.0%** |

## Validation steps for Astra

1. **Apply** (PowerShell): put `observe-G01-fixes.bundle` and
   `apply-G01-fixes.ps1` in `_handoff\G01-fixes\`, then
   `powershell -ExecutionPolicy Bypass -File .\_handoff\G01-fixes\apply-G01-fixes.ps1`.
   It accepts `main` at `49b834e` or `30e137a`, fast-forwards and stops; it
   pushes only with `-Push`.
2. **Files** (WSL2): `sha256sum -c docs/handoff/G01/files-g01-fixes.sha256`
   (every tracked file except the checksum lists).
3. **Native Windows**: `go vet ./...`, `go build ./...`,
   `go test -count=1 ./...`. Intentional platform scope: `init_unix_test.go`,
   `integration_unix_test.go`, `supervisor_unix_test.go`,
   `helper_unix_test.go` and `pgrp_unix_test.go` are not built on Windows;
   their Windows counterparts (`init_windows_test.go`,
   `helper_windows_test.go`, `pgrp_windows_test.go`) are. Tests that skip
   there say why (no `/proc`, Unix file modes, no process groups, no
   NGINX). Please report the counts and any failure.
4. **WSL2**: `make tools`, then `make ci-local`, `make fuzz FUZZTIME=30s`
   (11 targets), `make lint vuln secrets licenses proto-lint shell-check`,
   `make vuln-package VERSION=0.1.0-g01-fix1`, and your five regression
   tests.
5. **Fresh systemd machine, unchanged default command**:
   `sudo ./test-install.sh live observex-managed-node-0.1.0-g01-fix1-linux-amd64.tar.gz`,
   expecting `# PASSED: all 28 checks`. Then, if you wish, the busy-port
   case: hold 9443 (any listener), run `sudo ./install.sh`, expect exit 1
   with the check's message, then `sudo ./uninstall.sh --purge --yes`.
6. **Reproducibility**: `make package VERSION=0.1.0-g01-fix1` twice with Go
   1.27.2 at the final commit; compare with the delivered SHA-256.

## Remaining limits

1. No native Windows run and no conventional VM run here (steps 3 and 5).
2. **The post-quantum key exchange has not been tested live with NGINX.**
   Every NGINX here has OpenSSL 3.0.13, which cannot offer X25519MLKEM768.
   What is tested: the Front Door's generated configuration and feature
   detection (template and golden-file tests), and real X25519MLKEM768
   handshakes between Go's own TLS stack in `internal/platform/tlsx`. A live
   NGINX + OpenSSL 3.5 handshake remains open, tied to the NGINX
   distribution decision in ADR 0010.
3. The systemd tests ran in namespaces inside a container, as described
   above, not on a VM.
4. CI still tests Go 1.24.x as the `go.mod` language level. Go 1.24 no
   longer receives upstream security fixes; release builds must use the
   pinned patched toolchain (1.27.2 here).
5. Unchanged from G01: self-monitoring uses the standard library (ADR 0009);
   the cluster CA key is a root-only file until G04; tarball only.
6. Owner decisions not taken: ADR approvals, the project licence, the NGINX
   distribution policy.

## Rollback

Nothing was pushed. On akash's PC, `git reset --hard 30e137a` (or
`49b834e` for G00) returns `main` to the earlier state, only while nothing
new has been committed there. On a test machine,
`sudo ./uninstall.sh --purge --yes`.
