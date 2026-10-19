# G01 residual cases R01 to R03: handoff to Codex Astra

> **Boundary round:** Astra's QA of 19 October 2026 (S01 and S02, tested
> HEAD `a2c1a30`) is answered in [BOUNDARIES.md](BOUNDARIES.md), and his
> further boundary cases (T01 to T03, tested HEAD `11a5f04`) in
> [BOUNDARIES-II.md](BOUNDARIES-II.md), which supersedes this file's
> validation steps, tarball version and results.
> R01 to R03 stay fixed; their tests still pass.

Answers Astra's QA of 19 October 2026 (tested HEAD `23861f6`). Status:
**the two confidentiality defects (R01, R02) and the fuzz-generator error
(R03) are fixed and verified in Claude's workspace; awaiting Astra's
validation and akash's approval.** Nothing has been pushed: GitHub still
has only G00 (`49b834e`). No ADR status was changed; the project licence
and the NGINX distribution policy stay akash's decisions. Earlier findings
stay fixed and their reports stay as they were: [FIXES.md](FIXES.md)
(G01-01 to G01-13) and [FOLLOWUP.md](FOLLOWUP.md) (F01 to F03).

R01 and R02 were real disclosures of invented markers. R03 was not: the
fuzz test's expectation was wrong for the key it built, and production
behaviour did not change for it.

## Commits on main (on top of `23861f6`)

| Commit | Finding | Content |
| --- | --- | --- |
| `183db0e` | R01 | Boxed and composite map keys classified on their full text; tests |
| `16076a9` | R02 | Broken-quoting recovery decodes escaped names; Astra's two tests verbatim; combination tests; ADR 0007 |
| `54bbd2f` | R03 | Shaped fuzz checks the key it builds; boxed keys and broken quoting added; Astra's saved input kept |
| `d21b097` | R02 (test) | The combination test keeps its escaped names (see the note under R02); production code unchanged |
| next commit | | This file, the threat model, pointers in the earlier reports, `files-g01-repairs.sha256` |

Each commit builds, passes `go vet` for Linux and Windows and passes the
logging tests on its own. `observe-G01-repairs.bundle` holds every commit
since G00 (`49b834e`), so it applies to a repository at `49b834e`,
`30e137a`, `f6a792b` or `23861f6` (akash's repository is at `23861f6`).

## Finding by finding

| ID | Kind | Cause | Fix | Tests | Result here |
| --- | --- | --- | --- | --- | --- |
| **R01** P2 | Confidentiality defect | A string map key boxed in an interface (`map[any]V`) reached `keyForms` as an interface value, so it was rendered (and shortened to 64 KiB) before it was classified: the trailing "password" was lost. | `keyForms` unwraps interfaces and pointers and classifies the full string. A composite key (struct, array, interface, pointer) is sensitive when any string in it is, read in full and bounded like the sanitizer. Keys of an opaque type (`logging.Secret`, `slog.LogValuer`) are never unwrapped or read. The decision travels separately from the shown key and from the " #2" collision suffixes; the 64 KiB display bound is unchanged. | Astra's `TestQAInterfaceMapKeysKeepFullClassification` (both subcases); `TestBoxedMapKeysAreClassifiedInFull` (direct, `map[any]`, nested, `map[*string]`, pointer in `any`, struct, array and unexported-field keys, each at 64 KiB − 9, − 8, − 7 and + 1 + "password"); `TestBoxedKeysWithCustomAndDisplayRemovedNames`; `TestOpaqueKeysStayOpaqueWhenBoxed`; `TestBoxedKeysThatLookEqualKeepTheirValues`; fuzz shape 2 now boxes keys | Astra's test **fails at `23861f6`, passes now**. Disabling the fix makes 19 tests and subtests fail. |
| **R02** P2 | Confidentiality defect | The second look for broken quoting used an expression for plain names of at most 128 characters; after a stray quote, an escaped name such as `cred\u0065ntials` was neither aligned for the first pass nor matched by the second, and the text rules cannot remove an object value. | The expression is gone. For text that is not valid JSON, from every `:` the quoted name before it is read backwards at the encoding level its closing quote shows (the length of the backslash run before it), skipping deeper quotes, decoded with its escapes and classified; a sensitive name's value is replaced at that level, whatever its shape, bounded by the string that holds it. A name whose opening quote is more than 64 KiB away counts as sensitive. Unquoted names before `:` or `=` with an object or array value are handled too (bare `[REDACTED]`, to the matching bracket or to the end). The pass has a work budget of about eight times the text; text it cannot finish is replaced as a whole. Valid JSON skips it, so it stays valid JSON. The 1 MiB parse limit, the 8 MiB input limit and the three-level encoding policy are unchanged. | Astra's `TestQAStrayQuoteEscapedSensitiveMember` (both subcases, `RedactString` and the handler); `TestMalformedQuotingWithEscapedNames` (840 combinations: 5 broken-quoting prefixes × 7 names, three plain and four with escapes × 4 values, object, array, string and nested × 0, 1 or 2 encodings × whole or cut inside the marker; each checked through `RedactString`, the handler and for idempotence); `TestStrayQuoteThenUnquotedKeys`; `TestValidJSONStaysValidJSON`; fuzz shape 8 | Astra's test **fails at `23861f6`, passes now**. At `23861f6`, 408 of the 840 combinations leak; now none. Disabling the recovery makes 624 leak and 10 tests and subtests fail. |
| **R03** P2 | Test-oracle error, not a leak | Fuzz shape 2 padded a sensitive word into a 64 KiB key. `"pAss"` is sensitive only as a whole key (`pass` is an exact name), so the padded key was not sensitive and the expectation was wrong. | Padding uses the word only when the padded key stays sensitive, otherwise "password"; the word is also logged unpadded as its own key, so exact names are still tested. The padded key's sensitivity is checked (`t.Fatalf` on a generator error), not assumed. The other shapes use the word unchanged as the name, which the precondition makes sensitive; that was checked shape by shape. Classifier policy is unchanged. | Astra's saved input `1b3010105eaa5fc4` kept in `testdata/fuzz/FuzzSensitiveShapes/` | The saved input **fails at `23861f6`, passes now**. The full shaped fuzz run completes (results below). |

**Correction to my own R02 test.** As first committed (`16076a9`),
`TestMalformedQuotingWithEscapedNames` wrote its escaped names as Go
interpreted strings, so Go decoded `\u0065` at compile time and those
names reached the JSON text as plain names: the escaped-name combinations
were not tested, and the figures I had measured with it were wrong (the
`16076a9` commit message says 560 leak without the recovery; with the
escapes intact it is 624). I found it while checking the fixtures before
this handoff; nothing had been delivered with it. `d21b097` makes them raw
strings and the test now fails unless four names hold an escape. Astra's
own test always kept its escape. All figures in this file come from the
corrected test.

### Behaviour, as verified

Recorded in ADR 0007, and the threat model now states the residual risk
instead of calling every input safe:

- Built-in secret words match anywhere in a key; names added with
  `WithSensitiveKeys` and the short names `pwd`, `pass`, `dsn`, `auth`,
  `jwt` and `bearer` match only the whole key. R03 is a consequence of that
  policy, which did not change.
- Redaction is a safety net. A secret in free text without a recognisable
  key word, scheme or pattern is not found. Top-level attribute keys are
  not rewritten.

## Verification in Claude's workspace

Environment as before: a cloud Linux container (Ubuntu 24.04.5, kernel
6.18, amd64), Go 1.27.2 (verified Google download), NGINX 1.24.0 with
OpenSSL 3.0.13, ShellCheck 0.9.0, golangci-lint 2.14.0, govulncheck 1.9.0,
gitleaks 8.30.1, go-licenses 1.6.0 and Buf 1.74.0, all built with Go
1.27.2. Not akash's machine and not a VM.

Tests, fuzzing and gates ran at `d21b097`, the last code-and-test commit
(the next commit changes documents only). The package and the install
tests below ran at `54bbd2f`, whose production code is identical to
`d21b097`'s (that commit changes one ordinary test). The two rebuilds at
the final commit, their comparison with the delivered tarball and a live
install of the rebuilt release under a freshly booted systemd run after
this file is committed; their results are in the evidence
(`package-reproducibility.log`, `install-live-systemd-rebuilt.log`) and in
the report that comes with this handoff, not here.

| Check | Result |
| --- | --- |
| Astra's additional tests at `23861f6` | 2 controls pass, **2 fail**, as he reported; his saved fuzz input fails |
| Corrected combination tests at `23861f6` | **408 of 840 combinations leak**; the unquoted-key test fails |
| Astra's ten regression tests (8 earlier + 2 additional), his unmodified files through `go test -overlay` | **10 of 10 pass**, including the four subcases of the two new tests |
| Saved fuzz input replay | Pass |
| `make ci-local` (format, vet, build, race, coverage, shell) | Pass |
| Race suite, `go test -count=1 -race ./...` | **192 top-level tests, 13 fuzz seed suites, 406 subtests and seed cases: all pass, none skipped** |
| Coverage, `make cover` | **92.2%** measured here (Astra measured 92.0% at `23861f6` in his environment) |
| `make fuzz FUZZTIME=30s` | **13 of 13 pass**, no failing input (executions below; `FuzzSensitiveShapes` is slow by design, each case builds 64 KiB keys); an earlier run at `54bbd2f` also passed 13 of 13 |
| `make lint`; `GOOS=windows golangci-lint run ./...` | 0 issues; 0 issues |
| `make vuln` (source) | No vulnerabilities (govulncheck 1.9.0, Go 1.27.2 standard library) |
| `make vuln-package VERSION=0.1.0-g01-fix3` (shipped binary) | No vulnerabilities in `bin/observex-node` (at `54bbd2f`; binary SHA-256 `ba4dd66b767761768bee99f7ae0149efc01197e57608452ef4b82c0ba6e767f1`) |
| `make secrets` | No leaks; 22 of 22 commits scanned (whole history at `d21b097`) |
| `make licenses proto-lint shell-check` | Pass |
| `make install-test VERSION=0.1.0-g01-fix3` (layout) | 20 of 20 |
| Live install, no systemd | 25 of 25 (container without systemd, as root; nothing left afterwards) |
| Live install, systemd 255 in namespaces | 28 of 28 (systemd 255 as PID 1 in new pid, mount, net, uts and ipc namespaces; NGINX back 3 s after SIGKILL; purge removes files and user) |
| Installer with port 9443 held | Exit 1 with the reason (`ports: Agents and Gateways (Front Door): already in use by another process (0.0.0.0:9443)`); service enabled and inactive; purge removes everything |
| Two package builds, fresh clones at the final commit, native Linux filesystem | Run after this file is committed (see above) |
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
| internal/node/supervisor | 98.1% |
| internal/platform/clock | 100.0% |
| internal/platform/config | 96.7% |
| internal/platform/logging | 91.8% |
| internal/platform/tlsx | 93.1% |
| internal/platform/tlsx/tlstest | 86.0% |
| internal/store | 100.0% |
| internal/store/fake | 96.5% |
| internal/store/storetest | 89.1% |
| **all** | **92.2%** |

Fuzz executions in 30 s:

| Target | Package | Executions | Result |
| --- | --- | --- | --- |
| `FuzzRedactString` | platform/logging | 452,223 | Pass |
| `FuzzRedactConfidential` | platform/logging | 7,456 | Pass |
| `FuzzSensitiveShapes` | platform/logging | 1,184 | Pass |
| `FuzzPairsMatchExpression` | platform/logging | 42,325 | Pass |
| `FuzzDecode` | platform/config | 223,606 | Pass |
| `FuzzVerifyToken` | platform/tlsx | 564,213 | Pass |
| `FuzzParseTraceID` | store | 1,597,239 | Pass |
| `FuzzParse` | node | 53,661 | Pass |
| `FuzzParseFeatures` | node/frontdoor | 380,958 | Pass |
| `FuzzCheck` | node/firewall | 751,316 | Pass |
| `FuzzParseStat` | node/selfmon | 471,012 | Pass |
| `FuzzWriteText` | node/selfmon | 39,757 | Pass |
| `FuzzPrefixWriter` | node/supervisor | 217,073 | Pass |

## Validation steps for Astra

1. **Apply**: put `observe-G01-repairs.bundle` and `apply-G01-repairs.ps1`
   in `_handoff\G01-repairs\`, then
   `powershell -ExecutionPolicy Bypass -File .\_handoff\G01-repairs\apply-G01-repairs.ps1`
   (accepts `49b834e`, `30e137a`, `f6a792b` or `23861f6`; fast-forwards and
   stops; pushes only with `-Push`).
2. **Files**: `sha256sum -c docs/handoff/G01/files-g01-repairs.sha256`.
3. **Native Windows**: `go vet ./...`, `go build ./...`,
   `go test -count=1 -json ./...`.
4. **Regressions**: your `run-regressions.ps1` and
   `run-additional-regressions.ps1` (they replace `qa_followup_test.go` and
   `qa_additional_followup_test.go`, your files unchanged). Expected: 8 of 8
   and 2 of 2 (four subcases) pass. Your saved input:
   `go test -count=1 -run '^FuzzSensitiveShapes/1b3010105eaa5fc4$' -v ./internal/platform/logging`.
5. **Linux**: `make tools`, `make ci-local`, `make fuzz FUZZTIME=30s`,
   `make lint vuln secrets licenses proto-lint shell-check`,
   `make install-test VERSION=0.1.0-g01-fix3`,
   `make vuln-package VERSION=0.1.0-g01-fix3`.
6. **Fresh systemd machine**: `sudo ./test-install.sh live
   observex-managed-node-0.1.0-g01-fix3-linux-amd64.tar.gz`, expecting
   `# PASSED: all 28 checks`.
7. **Reproducibility**: two builds on a native Linux filesystem, compared
   with the delivered SHA-256.

## Remaining limits

1. No native Windows run and no conventional VM run here; the systemd runs
   used namespaces inside a container.
2. **Live NGINX + OpenSSL 3.5 post-quantum negotiation is untested**: every
   NGINX here links OpenSSL 3.0.13. Go-side X25519MLKEM768 handshakes and
   the generated NGINX configuration are tested.
3. Redaction remains a safety net (see above).
4. Owner decisions not taken: G01 approval, ADR acceptance, the project
   licence and the NGINX distribution policy.
