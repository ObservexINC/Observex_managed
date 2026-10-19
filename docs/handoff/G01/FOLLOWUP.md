# G01 follow-up: handoff to Codex Astra

> **Repair round:** Astra's QA of 19 October 2026 (residual cases R01 to
> R03, tested HEAD `23861f6`) is answered in [REPAIRS.md](REPAIRS.md),
> and his boundary cases (S01, S02, tested HEAD `a2c1a30`) in
> [BOUNDARIES.md](BOUNDARIES.md), which supersedes this file's validation
> steps, tarball version and results. F01 to F03 stay fixed; their tests
> still pass.

Answers Astra's revalidation report of 18 October 2026 (findings F01 to
F03, tested HEAD `f6a792b`). Status: **all three findings fixed and
verified in Claude's workspace; awaiting Astra's validation and akash's
approval.** Nothing has been pushed: GitHub still has only G00
(`49b834e`). No ADR status was changed; the project licence and the NGINX
distribution policy stay akash's decisions. The thirteen original findings
are unchanged (see [FIXES.md](FIXES.md)); their tests still pass.

## Commits on main (on top of `f6a792b`)

| Commit | Findings | Content |
| --- | --- | --- |
| `7c29c4a` | F01, F02 | Sanitizer decides on the type first; keys classified on their full text; tests |
| `b323ab5` | F03 | Structural pass for JSON-like text the parser does not take; 8 MiB limit fails closed; faster key=value scan; Astra's three tests verbatim; new fuzz targets; ADR 0007 |
| `513454a` | | A supervisor test no longer depends on stop timing (it failed about 1 run in 60) |
| next commit | | This file, the threat model, `files-g01-followup.sha256` |

Every commit builds and passes `go vet` for Linux and Windows; the F01/F02
commit also passes the logging tests on its own.

`observe-G01-followup.bundle` holds every commit since G00 (`49b834e`), so
it applies to a repository at `49b834e`, `30e137a` or `f6a792b` (akash's
repository is at `f6a792b`). Its SHA-256, the final commit and the
tarball's SHA-256 are in the files delivered next to it.

## Finding by finding

| ID | Cause | Fix | Tests | Result here |
| --- | --- | --- | --- | --- |
| **F01** P1, `logging.Secret` in unexported fields | The `Secret` check ran only for values reflection lets the program read (`CanInterface`); for an unexported field the walker read the string underneath. | The type is checked first, before anything is read: a `logging.Secret` is `[REDACTED]` wherever it is, behind pointers, pointer chains, interfaces, in slices, arrays, map values and map keys, and in unexported fields. A value in an unexported field whose type defines `LogValue` cannot be asked for it there (that needs `Interface`), so it is `[REDACTED]` too instead of being walked. No unsafe access and no formatting methods are used. Ordinary unexported fields are still shown. | Astra's `TestQASecretTypeInUnexportedFields` (both subcases); `TestSecretTypeStaysOpaqueEverywhere` (19 positions); `TestOrdinaryUnexportedFieldsStayUseful`; `FuzzSensitiveShapes` shapes 0 and 1 | Astra's test **fails at `f6a792b`, passes now** (his unmodified file, through `go test -overlay`). Disabling both type checks makes 24 tests, subtests and fuzz seeds fail. |
| **F02** P2, map key truncated before classification | `mapValue` shortened the key to 64 KiB, then classified the shortened form. | Each key is classified on its full original text (and on its shown form); the decision travels with the entry, separately from the shown key. The same for JSON member names and for `slog` group keys returned by `LogValue`. Keys that look the same once shortened or redacted are shown with " #2", " #3" ..., so no entry overwrites another. The 64 KiB bound is unchanged. | Astra's `TestQALongSensitiveMapKey`; `TestLongMapKeysAreClassifiedInFull` (keys just below, at and above the bound, fragment partly and wholly cut, 3 × the bound; plain maps, nested maps and JSON members); `TestKeysWhoseShownFormLosesTheSensitiveWord` (JWT-shaped and URL-credential keys, whose shown form drops "password"); `TestCustomSensitiveKeysInMapsAndJSON`; `TestKeysThatLookEqualWhenShownKeepTheirValues`; `FuzzSensitiveShapes` shape 2 | Fails at `f6a792b`, passes now. Classifying the shown key only makes 14 tests and subtests fail. |
| **F03** P2, JSON over 1 MiB | `redactJSON` refused documents over 1 MiB and the text rules could not remove an object-valued member. | Text that is not a whole JSON document of at most 1 MiB (larger, truncated or malformed JSON, JSON inside other text, JSON written into JSON strings up to three levels) gets a **structural pass** before the text rules: the whole value of every member with a sensitive name is replaced by `"[REDACTED]"`, whatever its shape, and to the end of its text when it never closes (fail closed). Names are decoded (`\u` and other escapes) and classified on their full text. A second look finds sensitive names directly before an object or array, for text whose quoting is broken by a stray quote. The 1 MiB parse limit is unchanged; the pass is linear for each level it follows. **New explicit limit:** text over 8 MiB (`MaxRedactInput`) is not examined but replaced as a whole by `[REDACTED]` and its length. | Astra's `TestQAOversizedJSONSensitiveObject` (both sizes); `TestJSONAroundTheParseLimit` (documents of exactly 1 MiB − 1, 1 MiB, 1 MiB + 1 and + 4 KiB: no marker, ordinary members kept, still valid JSON, idempotent); `TestJSONShapesBeyondTheParseLimit` (arrays, deep nesting, objects in arrays, escaped names `cred\u0065ntials` and `api\u005fkey`, numbers, escaped strings, double, triple and `\u0022`-encoded JSON, all in one document over the limit); `TestTruncatedAndMalformedJSON` (cut inside and after the marker, before the brace, inside an array; trailing and missing commas; a stray quote; JSON in text; double-encoded JSON in text; unquoted keys with object and list values; one case over the limit); `TestEscapedCharactersInMemberNames`; `TestTextOverTheRedactionLimitIsReplaced` (exactly 8 MiB is examined, one byte more is replaced); `FuzzSensitiveShapes` shapes 3 to 7 | Fails at `f6a792b`, passes now. Disabling the structural pass makes 29 tests, subtests and fuzz seeds fail. |

### Policy changes (recorded in ADR 0007)

1. Explicit secret types are opaque by type in every position, including
   unexported fields; `LogValuer` values in unexported fields are redacted.
2. Keys are classified on their full text; colliding shown keys get a
   suffix.
3. JSON-like text the parser does not take gets the structural pass.
4. Text over 8 MiB is replaced as a whole (a work limit never lowers
   protection).
5. A quoted value keeps its quotes: `"password":"[REDACTED]"` instead of
   `"password":[REDACTED]`, so JSON-like text stays JSON-like. One existing
   test expectation changed for this.

### Speed

The key=value text rule was one regular expression with a leading
`[A-Za-z0-9_\-]*`, which the engine tries at every offset of a long word:
about 300 ms per MiB. It is now a scan from each `=` or `:` with the value
matched by an anchored expression, and rules whose literals do not occur in
the text are skipped. `FuzzPairsMatchExpression` checks that the scan gives
exactly what the old expression gave; it found one difference (the old
expression matched `[REDACTED]` case-insensitively), which was fixed and
kept as a corpus entry. A 1 MiB document now takes about 60 ms to redact.

## Verification in Claude's workspace

Environment: the same cloud Linux container as before (Ubuntu 24.04.5,
kernel 6.18, amd64), Go 1.27.2 (verified Google download), NGINX 1.24.0
with OpenSSL 3.0.13, ShellCheck 0.9.0; tools golangci-lint 2.14.0,
govulncheck 1.9.0, gitleaks 8.30.1, go-licenses 1.6.0, Buf 1.74.0, all
built with Go 1.27.2. It is not akash's machine and not a VM.

Results at `513454a` (the code commit; the next commit changes documents
only):

| Check | Command | Result |
| --- | --- | --- |
| Astra's eight regression tests, baseline | his files at `f6a792b` | 5 pass, **3 fail**, as he reported |
| Astra's eight regression tests, fixed | his unmodified files through `go test -overlay` (regenerated for this checkout) | **8 of 8 pass** |
| Format, vet, build, race, coverage, shell | `make ci-local` | Pass |
| Race suite | `go test -count=1 -race ./...` | **183 top-level tests, 13 fuzz seed suites, 363 subtests: all pass, none skipped** |
| Coverage | `make cover` | **92.2%** (logging 91.9%, was 88.3%) |
| Fuzzing, 30 s each | `make fuzz FUZZTIME=30s` | **13 of 13 pass** (two new: `FuzzSensitiveShapes`, `FuzzPairsMatchExpression`) |
| Lint | `make lint`; `GOOS=windows golangci-lint run ./...` | 0 issues; 0 issues |
| Vulnerabilities, source | `make vuln` | No vulnerabilities |
| Vulnerabilities, shipped binary | `make vuln-package VERSION=0.1.0-g01-fix2` | No vulnerabilities (binary built with Go 1.27.2) |
| Secrets | `make secrets` | Whole history scanned, no leaks (17 commits at `513454a`) |
| Licences, Buf, ShellCheck | `make licenses proto-lint shell-check` | Pass |
| Install, layout | `test-install.sh layout` | 20 of 20 |
| Install, live, no systemd | `test-install.sh live` | 25 of 25 |
| Install, live, systemd | `test-install.sh live` | **28 of 28** |
| Installer, busy port, systemd | `install.sh` with 9443 held | Exit 1 with the check's message; service enabled and inactive; purge succeeds |
| Package, two builds | fresh clones at the final commit, native Linux filesystem | Byte-identical (SHA-256 delivered next to the bundle); the binary inside is `bin/observex-node`, SHA-256 `790fa67d7144f076be8708dd43808047de05e4832f6b28073c14254e6601d0c2`, the binary the install tests above used |
| Windows | `GOOS=windows go vet ./...`, `go test -c` for every package | Compiles; **not run** (step 3 below) |

The systemd runs use systemd 255 as PID 1 in private PID, mount, network,
UTS and IPC namespaces inside the container, with private `/run`, `/tmp`
and `/var/tmp`, unrelated units masked and
`ip_unprivileged_port_start=1024`: real service management, but not a
fresh distribution and not a VM.

Coverage by package:

| Package | Coverage |
| --- | --- |
| cmd/observex-node | 81.2% |
| internal/node | 85.1% |
| internal/node/firewall | 97.0% |
| internal/node/frontdoor | 97.9% |
| internal/node/pki | 77.6% |
| internal/node/selfmon | 97.4% |
| internal/node/supervisor | 97.9% |
| internal/platform/clock | 100.0% |
| internal/platform/config | 96.7% |
| internal/platform/logging | 91.9% |
| internal/platform/tlsx | 93.1% |
| internal/platform/tlsx/tlstest | 86.0% |
| internal/store | 100.0% |
| internal/store/fake | 96.5% |
| internal/store/storetest | 89.1% |
| **all** | **92.2%** |

Fuzz executions in 30 s:

| Target | Executions |
| --- | --- |
| `FuzzRedactString` | 37,924 |
| `FuzzRedactConfidential` | 9,994 |
| `FuzzSensitiveShapes` | 694 |
| `FuzzPairsMatchExpression` | 34,349 |
| `FuzzDecode` | 66,932 |
| `FuzzVerifyToken` | 587,180 |
| `FuzzParseTraceID` | 1,689,741 |
| `FuzzParse` | 176,731 |
| `FuzzParseFeatures` | 328,969 |
| `FuzzCheck` | 757,912 |
| `FuzzParseStat` | 495,760 |
| `FuzzWriteText` | 205,737 |
| `FuzzPrefixWriter` | 7,075 |

Shape and boundary fuzzing builds documents of about 1 MiB per input, so
`FuzzSensitiveShapes` runs few inputs per second; its value is in reaching
the boundaries, not in volume.

## Validation steps for Astra

1. **Apply**: put `observe-G01-followup.bundle` and
   `apply-G01-followup.ps1` in `_handoff\G01-followup\`, then
   `powershell -ExecutionPolicy Bypass -File .\_handoff\G01-followup\apply-G01-followup.ps1`.
   It accepts `main` at `49b834e`, `30e137a` or `f6a792b`, fast-forwards and
   stops; it pushes only with `-Push`.
2. **Files**: `sha256sum -c docs/handoff/G01/files-g01-followup.sha256`.
3. **Native Windows**: `go vet ./...`, `go build ./...`,
   `go test -count=1 ./...`.
4. **Regressions**: your `repro\run-regressions.ps1 -Repository <checkout>`
   (it replaces `qa_followup_test.go`, which is your file unchanged, and
   the three earlier copies). Expected: 8 of 8 pass.
5. **WSL2 / Linux**: `make tools`, `make ci-local`,
   `make fuzz FUZZTIME=30s` (13 targets), `make lint vuln secrets licenses
   proto-lint shell-check`, `make install-test VERSION=0.1.0-g01-fix2`,
   `make vuln-package VERSION=0.1.0-g01-fix2`.
6. **Fresh systemd machine**: `sudo ./test-install.sh live
   observex-managed-node-0.1.0-g01-fix2-linux-amd64.tar.gz`, expecting
   `# PASSED: all 28 checks`.
7. **Reproducibility**: two builds on a native Linux filesystem (POSIX
   modes; a Windows mount shows 0777 modes and changes the tar hash, as you
   found), compared with the delivered SHA-256.

## Remaining limits

1. No native Windows run and no conventional VM run here.
2. **The post-quantum key exchange has not been tested live with NGINX**:
   every NGINX here has OpenSSL 3.0.13. Go-side X25519MLKEM768 handshakes
   and the Front Door's generated configuration are tested; a live NGINX +
   OpenSSL 3.5 handshake remains open, tied to the NGINX distribution
   decision in ADR 0010.
3. The systemd tests ran in namespaces inside a container, not on a VM.
4. Redaction remains a safety net; the primary rule stays: never put a
   secret into a log call. Attribute keys at the top level of a log call
   are not rewritten (they come from code), and text that is not JSON-like
   relies on the text rules.
5. Owner decisions not taken: ADR approvals, the project licence, the NGINX
   distribution policy.
