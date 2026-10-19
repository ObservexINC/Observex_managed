# G01 boundary cases S01 and S02: handoff to Codex Astra

> **Further boundary round:** Astra's QA of fix4 on 19 October 2026 (T01
> to T03, tested HEAD `11a5f04`) is answered in
> [BOUNDARIES-II.md](BOUNDARIES-II.md), which supersedes this file's
> validation steps, tarball version and results. S01 and S02 stay fixed;
> their tests still pass.

Answers Astra's QA of 19 October 2026 (tested HEAD `a2c1a30`). Status:
**both confidentiality defects (S01, S02) and one more leak of the S02
family found while repairing are fixed and verified in Claude's workspace;
awaiting Astra's validation and akash's approval.** Nothing has been
pushed: GitHub still has only G00 (`49b834e`), and akash's repository is
still at `23861f6`. No ADR status was changed; the project licence and the
NGINX distribution policy stay akash's decisions. Earlier reports stay as
they were: [FIXES.md](FIXES.md) (G01-01 to G01-13),
[FOLLOWUP.md](FOLLOWUP.md) (F01 to F03) and [REPAIRS.md](REPAIRS.md) (R01
to R03).

S01 and S02 were real disclosures of invented markers, not test-oracle
errors.

## Commits on main (on top of `a2c1a30`)

| Commit | Finding | Content |
| --- | --- | --- |
| `c3386bf` | S01 | A composite map key that a bound stops from being read in full hides its value; boundary tests; fuzz shape 9 |
| `7c8999f` | S02, and the leak found while repairing | Recovery does not take a value's end from quoting it cannot trust; strings of valid JSON holding JSON are redacted as text; Astra's `qa_repair_boundary_test.go` unchanged; combination tests; fuzz shape 10 and the input it found; ADR 0007 |
| next commit | | This file, the threat model, pointers in the earlier reports, `files-g01-boundaries.sha256` |

Each commit builds, passes `go vet` for Linux and Windows and passes the
logging tests on its own. `observe-G01-boundaries.bundle` holds every
commit since G00 and applies to a repository at `49b834e`, `30e137a`,
`f6a792b`, `23861f6` or `a2c1a30`.

## Finding by finding

| ID | Kind | Cause | Fix | Tests | Result here |
| --- | --- | --- | --- | --- | --- |
| **S01** P2 | Confidentiality defect | `keyHolds` answered "not sensitive" when the depth, item or node bound stopped it, so a secret word past a bound (the 257th element of an array key, or inside ten wrapped structs) let the map value through. It also counted interfaces as depth, unlike the sanitizer, so it stopped earlier than the bounds: at `a2c1a30` a secret word exactly at `MaxDepth` leaked too. | The walk has three answers: read in full and clean, sensitive, or stopped by a bound. Only the first shows the value. The bounds are unchanged (depth 8, 256 items, 4096 values) and counted as the sanitizer counts them. Pointer cycles in a key are read once. Opaque parts (`logging.Secret`, `slog.LogValuer`) are still never read. | Astra's `TestQACompositeKeyLimitFailsClosed` (3 subcases); `TestCompositeKeyBoundsFailClosed`: array, struct, depth and node bounds each one below, at and one above, each with three secret words in the last place read and an ordinary-key control; `TestCompositeKeyCyclesAndOpaqueParts`; `TestCompositeKeysBeyondBoundsKeepDistinctEntries`; fuzz shape 9 | Astra's test **fails at `a2c1a30` (2 of 3 subcases), passes now**. At `a2c1a30` my bound tests fail in 6 subcases: the item and depth cases show the value (a secret word at exactly `MaxDepth` included); past the node bound the value was shown as `[TRUNCATED]` by the display budget, not leaked, but not hidden by the classification either. 2 more tests fail there (a pointer chain past `MaxDepth`; two keys equal up to the item bound). Disabling the fix makes 11 tests and subtests fail. |
| **S02** P2 | Confidentiality defect | For an unquoted sensitive name after broken quoting, recovery ended the object by counting brackets, quoted ones included, so `{"pad":"]","value":"..."}` ended at the quoted `]` and the rest was shown. | Recovery no longer takes a value's end from quoting it has already found broken. A value with no quote ends where its brackets close (when they match). A value holding quotes runs to the end of the text that holds it: the whole text, or the JSON string it is written in, unless that string is valid JSON on its own. The rule covers quoted and unquoted names. A value recovery keeps to its own end in text that is not JSON gets a bare `[REDACTED]`, so a second pass reads it the same. The work stays within recovery's budget; the 1 MiB, 8 MiB and three-level limits are unchanged. | Astra's `TestQARecoveryBracketInsideQuotedValue` (3 subcases, both APIs); `TestRecoveryValueBoundaries`, 1408 combinations: 4 broken-quoting prefixes × 4 names (unquoted with `:` and `=`, quoted, quoted with an escape) × 11 values (quoted `]`, `}`, `[`, `{`, escaped quotes and backslashes, arrays, nesting, a quote-free object) × 4 forms (plain, one or two encodings in text, a JSON string literal) × whole or cut inside the marker, each through `RedactString` and the handler, with idempotence and valid-JSON checks; `TestRecoveryKeepsTextAfterASoundValue`; `TestRecoveryRunsToTheEndWhenTheValueIsNotSound`; fuzz shape 10 | Astra's test **fails at `a2c1a30` (2 of 3 subcases), passes now**. At `a2c1a30`, **512 of the 1408 combinations leak**; now none. With brackets alone deciding again, 384 leak and 6 tests fail. |
| **S02b** (found while repairing) | Confidentiality defect, same family | Valid JSON skipped recovery entirely, but a string in it can hold JSON whose own quoting is broken. When the document was a JSON string literal, or an object or array over 1 MiB, that JSON was read only by the first pass and a sensitive value in it was shown. (Smaller objects and arrays are parsed, and their strings were already redacted as text.) | Every string of valid JSON whose content holds quotes is decoded, redacted as text of its own (recovery included), down to three levels of encoding, and written back as a JSON string when it changed. The document stays valid JSON; unchanged strings keep their exact bytes. | `TestValidJSONStringsHoldingBrokenJSON` (4 contents × 5 forms: literal, literal twice, small object, over 1 MiB, over 1 MiB twice; valid-JSON and idempotence checks); `TestValidJSONStringsWithoutSecretsAreUnchanged`; form 3 of the combination test | Fails at `a2c1a30`, passes now. Without it, 176 of the 1408 combinations leak and 3 tests fail. |

**How the S02 rule was chosen.** A first version trusted a value's own end
when the text after it closed every string it opened. The shaped fuzzer
found the gap within seconds: an unescaped quote inside the value, then a
cut inside the marker, which removed the quote that would have shown the
value going on (input `62357254aec8c849`, kept in the corpus). In text
whose quoting is already broken, any quote in a sensitive value may be an
unescaped quote of its content, and a cut can always remove the evidence,
so no reading of the rest can prove where such a value ends. The final rule
does not try; trusting the quote-aware end again makes 3 tests fail,
including that input. That first version was never committed.

### Behaviour, as verified, and what it costs

Recorded in ADR 0007 and, with the costs, in the threat model:

- A composite map key that the bounds stop from being read in full hides
  its value, even when the key holds no secret. Keys read in full keep
  their values.
- In text whose quoting is broken, everything after a sensitive value that
  holds quotes is hidden, to the end of the text or of the JSON string
  holding it. Text before it is kept, and so is text after a quote-free
  value or after a value inside a JSON string that is valid JSON on its
  own. Valid JSON is unaffected and stays valid JSON.
- A string of valid JSON changed by redaction is written back with JSON's
  standard escaping, so its escapes may be written differently from the
  original. Strings that do not change keep their exact bytes.
- Redaction remains a safety net: never put a secret into a log call; use
  `logging.Secret`.

## Verification in Claude's workspace

Environment as before: a cloud Linux container (Ubuntu 24.04.5, kernel
6.18, amd64), Go 1.27.2 (verified Google download), NGINX 1.24.0 with
OpenSSL 3.0.13, ShellCheck 0.9.0, golangci-lint 2.14.0, govulncheck 1.9.0,
gitleaks 8.30.1, go-licenses 1.6.0 and Buf 1.74.0, all built with Go
1.27.2. Not akash's machine and not a VM.

Tests, fuzzing and gates ran at `7c8999f`, the last code commit (the next
commit changes documents only). The package and the first install tests
ran at `7c8999f` too. The two rebuilds at the final commit, their
comparison with the delivered tarball and a live install of the rebuilt
release under a freshly booted systemd run after this file is committed;
their results are in the evidence (`package-reproducibility.log`,
`install-live-systemd-rebuilt.log`) and in the report that comes with this
handoff, not here.

| Check | Result |
| --- | --- |
| Astra's two boundary tests at `a2c1a30` | 2 controls pass, **4 subcases fail**, as he reported |
| Astra's twelve regression tests (10 earlier + 2 boundary), his unmodified files through `go test -overlay` | **12 of 12 pass**, including the six subcases of the two boundary tests |
| Saved fuzz inputs: Astra's `1b3010105eaa5fc4`; the new `62357254aec8c849` | Both pass |
| `make ci-local` (format, vet, build, race, coverage, shell) | Pass |
| Race suite, `go test -count=1 -race ./...` | **202 top-level tests, 13 fuzz seed suites, 431 subtests and seed cases: all pass, none skipped** |
| Coverage, `make cover` | **92.2%** measured here (Astra measured 92.0% at `a2c1a30` in his environment) |
| `make fuzz FUZZTIME=30s` | **13 of 13 pass**, no failing input (executions below; `FuzzSensitiveShapes` is slow by design, each case builds 64 KiB keys or composite keys of about 4096 values) |
| `make lint`; `GOOS=windows golangci-lint run ./...` | 0 issues; 0 issues |
| `make vuln` (source) | No vulnerabilities (govulncheck 1.9.0, Go 1.27.2 standard library) |
| `make vuln-package VERSION=0.1.0-g01-fix4` (shipped binary) | No vulnerabilities in `bin/observex-node` (binary SHA-256 `125a5bf70a5c9c5ec58d577649346546c5e3c2c7bc581208b58837c5864afbf6`) |
| `make secrets` | No leaks; 25 of 25 commits scanned (whole history at `7c8999f`) |
| `make licenses proto-lint shell-check` | Pass |
| `make install-test VERSION=0.1.0-g01-fix4` (layout) | 20 of 20 |
| Live install, no systemd | 25 of 25 (container without systemd, as root; nothing left afterwards) |
| Live install, systemd 255 in namespaces | 28 of 28 (systemd 255 as PID 1 in new pid, mount, net, uts and ipc namespaces; NGINX back 3 s after SIGKILL; purge removes files and user) |
| Installer with port 9443 held | Exit 1 with the reason (`ports: Agents and Gateways (Front Door): already in use by another process (0.0.0.0:9443)`); service enabled and inactive; purge removes everything |
| Two package builds, fresh clones at the final commit, native Linux filesystem | Run after this file is committed (see above) |
| Adversarial timing, 8 MiB inputs (nine shapes) | 0.01 s to 1.4 s each, no leak; before the S02 fix 0.01 s to 1.4 s, and 2 of the 9 leaked |
| Windows | `GOOS=windows go vet ./...` and `go test -c` for every package compile; **not run natively** (step 3) |

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
| internal/platform/logging | 92.1% |
| internal/platform/tlsx | 93.1% |
| internal/platform/tlsx/tlstest | 86.0% |
| internal/store | 100.0% |
| internal/store/fake | 96.5% |
| internal/store/storetest | 89.1% |
| **all** | **92.2%** |

Fuzz executions in 30 s:

| Target | Package | Executions | Result |
| --- | --- | --- | --- |
| `FuzzRedactString` | platform/logging | 545,881 | Pass |
| `FuzzRedactConfidential` | platform/logging | 11,558 | Pass |
| `FuzzSensitiveShapes` | platform/logging | 5,538 | Pass |
| `FuzzPairsMatchExpression` | platform/logging | 38,687 | Pass |
| `FuzzDecode` | platform/config | 21,288 | Pass |
| `FuzzVerifyToken` | platform/tlsx | 403,768 | Pass |
| `FuzzParseTraceID` | store | 1,156,364 | Pass |
| `FuzzParse` | node | 134,176 | Pass |
| `FuzzParseFeatures` | node/frontdoor | 279,801 | Pass |
| `FuzzCheck` | node/firewall | 449,207 | Pass |
| `FuzzParseStat` | node/selfmon | 365,274 | Pass |
| `FuzzWriteText` | node/selfmon | 15,643 | Pass |
| `FuzzPrefixWriter` | node/supervisor | 100,077 | Pass |

## What is demonstrated and what is inferred

Demonstrated here by running it: every result in the table above, the
failures of the new tests on the code before each fix, and the mutation
checks (each part of each fix disabled in a scratch copy, with the tests
that then fail).

Inferred, not demonstrated:

- That the tests pass on native Windows. The code changed is
  platform-independent and every package compiles for Windows, but no
  Windows run was possible here (step 3).
- That the rules cover every broken-quoting shape. The combination tests
  and the shaped fuzzer cover the shapes listed; the S02 rule was chosen so
  that it does not depend on reading the rest of the text, but that is an
  argument, not a proof.
- That work stays bounded for every input. The budget bounds recovery; the
  timing covers nine adversarial shapes, measured in this container.
- A conventional VM install, and live NGINX with OpenSSL 3.5 post-quantum
  negotiation (below).

## Validation steps for Astra

1. **Apply**: put `observe-G01-boundaries.bundle` and
   `apply-G01-boundaries.ps1` in `_handoff\G01-boundaries\`, then
   `powershell -ExecutionPolicy Bypass -File .\_handoff\G01-boundaries\apply-G01-boundaries.ps1`
   (accepts `49b834e`, `30e137a`, `f6a792b`, `23861f6` or `a2c1a30` on
   `main`; fast-forwards and stops; pushes only with `-Push`). In a
   detached review checkout: `git fetch <bundle> main`, then
   `git checkout --detach FETCH_HEAD`.
2. **Files**: `sha256sum -c docs/handoff/G01/files-g01-boundaries.sha256`.
3. **Native Windows**: `go vet ./...`, `go build ./...`,
   `go test -count=1 -json ./...`.
4. **Regressions**: your `run-regressions.ps1` and
   `run-repair-boundaries.ps1` (they replace the committed copies with your
   files, unchanged). Expected: 10 of 10 and 2 of 2 (six subcases) pass.
   Saved inputs:
   `go test -count=1 -run '^FuzzSensitiveShapes/(1b3010105eaa5fc4|62357254aec8c849)$' -v ./internal/platform/logging`.
5. **Linux**: `make tools`, `make ci-local`, `make fuzz FUZZTIME=30s`,
   `make lint vuln secrets licenses proto-lint shell-check`,
   `make install-test VERSION=0.1.0-g01-fix4`,
   `make vuln-package VERSION=0.1.0-g01-fix4`.
6. **Fresh systemd machine**: `sudo ./test-install.sh live
   observex-managed-node-0.1.0-g01-fix4-linux-amd64.tar.gz`, expecting
   `# PASSED: all 28 checks`.
7. **Reproducibility**: two builds on a native Linux filesystem, compared
   with the delivered SHA-256.

## Remaining limits

1. No native Windows run and no conventional VM run here; the systemd runs
   used namespaces inside a container.
2. **Live NGINX + OpenSSL 3.5 post-quantum negotiation is untested**: every
   NGINX here links OpenSSL 3.0.13. Go-side X25519MLKEM768 handshakes and
   the generated NGINX configuration are tested.
3. Redaction remains a safety net, and its fail-closed rules hide ordinary
   text in the cases above.
4. Owner decisions not taken: G01 approval, ADR acceptance, the project
   licence and the NGINX distribution policy.
