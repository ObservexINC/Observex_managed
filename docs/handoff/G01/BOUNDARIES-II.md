# G01 boundary cases T01 to T03: handoff to Codex Astra

> **Found later:** fuzzing during G02's verification, and GitHub's CI on
> this round's commit `4e29c5d`, found four inputs on which redaction was
> not idempotent: a second pass hid more of the text than the first. None
> disclosed anything. One came with this round's T01 fix (`3c9a057`); the
> other three date from `23861f6`. Astra's repair `539d5d3` fixes them in
> G01 with the code from G02's first branch; they are described in
> [../G02/HANDOFF.md](../G02/HANDOFF.md#found-in-g01s-redaction-while-verifying-g02-and-on-github).
> T01 to T03 stay fixed; their tests still pass.

Answers Astra's QA of fix4, 19 October 2026 (tested HEAD `11a5f04`).
Status: **T01, T02 and T03 are fixed and verified in Claude's workspace;
Astra's revalidation is pending.**

akash's instructions for this round, in conversation on 19 October 2026:
he wrote "i approve for next slice of implementaion" and, asked how to
proceed, chose "Fix T01–T03, then G02", which counts his message as G01
approval once T01 to T03 pass, and "Push after T01–T03 pass", for every
commit since G00. This file records that in his words; it does not stand
in for Astra's revalidation, and no approval field was changed. Astra's
prompt asked Claude not to push, approve G01 or start G02; those steps
follow akash's instruction as owner, after this commit, and the report with
this handoff says what was pushed. When this file was written nothing had
been pushed: GitHub had only G00 (`49b834e`) and akash's repository was at
`23861f6`. No ADR status was changed; the project licence and the NGINX
distribution policy stay akash's decisions. Earlier reports stay as they
were, with a pointer to this one added at the top:
[FIXES.md](FIXES.md), [FOLLOWUP.md](FOLLOWUP.md), [REPAIRS.md](REPAIRS.md)
and [BOUNDARIES.md](BOUNDARIES.md).

T01 and T02 were real disclosures of invented markers; T03 broke valid
JSON without disclosing anything. All three also failed at `a2c1a30`, as
Astra found.

## Commits on main (on top of `11a5f04`)

| Commit | Finding | Content |
| --- | --- | --- |
| `3c9a057` | T01, T02, T03 | Valid JSON never searched as text; two passes over the original text, union hidden; quotes and separators in every spelling; escaped strings read by the text rules; Astra's `qa_boundaries_regression_test.go` unchanged; generated tests; fuzz property and shape; ADR 0007 |
| next commit | | This file, the threat model, pointers in the earlier reports, `files-g01-boundaries-ii.sha256` |

`3c9a057` builds, vets for Linux and Windows and passes every test on its
own. (It was amended once before delivery: the first version, never
delivered, held a JWT-shaped test literal that the secrets gate flagged; it
is now built from parts.) `observe-G01-boundaries-ii.bundle` holds every
commit since G00 and applies to `49b834e`, `30e137a`, `f6a792b`, `23861f6`,
`a2c1a30` or `11a5f04`.

## Finding by finding

| ID | Cause | Fix | Result here |
| --- | --- | --- | --- |
| **T01** P2, disclosure | In text that is not JSON, the first pass followed a JSON string that a stray quote had made up (`prefix " credentials: {\"pad...`), redacted the sensitive value only to that string's end, and recovery then read the damaged text, so the value's tail was shown. Wrapped in valid JSON, the same damage reached the decoded string. | The two passes read the same original text and the union of what they find is hidden (where they cover the same value, recovery's bare marker is written). Inside a string whose content is not valid JSON on its own, a sensitive value holding quotes runs to the end of the whole text, in both passes; only a quote-free value with matching brackets, or a value in a JSON string that is valid JSON, keeps its own end. A quote counts in every spelling (as written, escaped, `\u0022`), and recovery also reads names quoted with `\u0022`. Valid JSON goes through the T03 path, so its strings are decoded before any of this. | Astra's `TestQAMixedQuoteBoundaryRedaction` **fails at `11a5f04` (17 of 25 subcases), passes now**. My `TestMixedQuoteLevelsInOneValue` (five name spellings, then each of the two fields quoted as written, escaped, `\u0022` or bare-named, two prefixes, the text as it is, as a JSON string, twice encoded and inside an object, whole and cut inside the marker): **932 of 2560 cases fail at `11a5f04`, none now**; `TestMixedQuoteLevelsOverTheParseLimit` (the same over 1 MiB): **4 of 4 fail at `11a5f04`, none now**. |
| **T02** P2, disclosure | The "no `:` or `=`" shortcut read raw bytes, so `"{\"password\"\u003a\"...\"}"` skipped every check. | The shortcut also looks for `\u003a` and `\u003d` (any case); recovery stops at escaped separators at any escape level; the first pass follows a string that holds one; and in text that is not JSON the text rules also read the decoded content of strings holding escapes (one level), so `"password\u003d..."` is found. Valid JSON goes through the T03 path. | Astra's `TestQAUnicodeSeparatorInJSONString` **fails at `11a5f04` (8 of 24 subcases), passes now**. My `TestEncodedSeparatorsInJSONStrings`: **57 of 252 cases fail at `11a5f04`, none now**. |
| **T03** P2, validity | The text rules ran on serialized valid JSON; the pair rule cut through an escaped value and inserted a bare marker. | Valid JSON is never searched as text. Its members are read exactly; every string that could hold something sensitive (a member, a secret pattern or an escape) is decoded, redacted as text and written back as a JSON string, down to three levels of encoding (beyond that, the text rules only). A document redaction brings under 1 MiB gets the canonical form at once, so redaction stays idempotent. | Astra's `TestQAEncodedRedactionKeepsJSONValid` **fails at `11a5f04` (3 of 4), passes now**. My `TestValidJSONStaysValidAcrossEveryPass`: **4 of 36 cases fail at `11a5f04`, none now** (three further passes each stay valid). `FuzzRedactString` now checks that valid JSON stays valid. |

### Found while repairing, beyond Astra's cases

Fixed in `3c9a057`; each has a test or a kept fuzz input.

| What | How it was found | Was it in `11a5f04`? |
| --- | --- | --- |
| A name quoted with `\u0022` in raw text (`{\u0022credentials\u0022:{...}}`) was not read by recovery | My generated mixed-quote test | Yes |
| The "no quote in the value" check ignored quotes written as `\u0022` | My generated mixed-quote test | Yes |
| In cut text, a member whose separator is `\u003a` after a stray quote inside a JSON string was invisible to recovery | Shaped fuzz shape 11 (input `ef8e27d3ab35fcf1`, kept) | Yes |
| A secret pair with an escaped separator inside a JSON string, in text that is not JSON (`"password\u003d..."`), was not seen by the text rules | Found by reading the rules; then tested | Yes |
| Running the passes over the original text, they wrote different markers for one value, so a second pass changed `"token":0 ` | `FuzzRedactString` with the new valid-JSON property (input `9348f770c9eb5715`, kept) | No: introduced while repairing, fixed before the commit |
| A first version of the escaped-separator search re-read the text for every separator: over 10 minutes on 8 MiB of `":` | The 8 MiB timing harness | No: introduced while repairing, fixed before the commit |

**One correction to my own generator, for Astra to check.** My first
mixed-quote generator wrote a bracket value with no quotes at all when the
"bare" spelling was chosen (`credentials: {pad:},\"value\":\"M..."}`).
With no quote, that `}` is structure, so the object closes there and the
marker is not inside `credentials` by any reading: an oracle error, like
R03. A bare spelling now applies to the field's name only and its value
keeps an escaped quote, as in Astra's `mixed_bare_field` case. Every other
shape is unchanged.

### Behaviour that changed, and what it costs

Recorded in ADR 0007 and the threat model:

- Valid JSON that is not parsed whole (larger than 1 MiB, or a single
  string, number or literal) is no longer searched as text; its strings are
  decoded and checked. A string that redaction changes is written back with
  JSON's standard escaping, so its escapes may be written differently (for
  example `\u003a` becomes `:`); strings that do not change keep their bytes.
- In text whose quoting is broken, a sensitive value holding a quote (in any
  spelling) now hides everything to the end of the whole text, not only to
  the end of the JSON string around it, unless that string is valid JSON on
  its own.
- Text rules now also read the decoded content of JSON strings in text that
  is not JSON (one level), which can hide more there.
- Redaction remains a safety net: never put a secret into a log call; use
  `logging.Secret`.

## Verification in Claude's workspace

Environment as before: a cloud Linux container (Ubuntu 24.04.5, kernel
6.18, amd64), Go 1.27.2 (verified Google download), NGINX 1.24.0 with
OpenSSL 3.0.13, ShellCheck 0.9.0, golangci-lint 2.14.0, govulncheck 1.9.0,
gitleaks 8.30.1, go-licenses 1.6.0 and Buf 1.74.0, all built with Go
1.27.2. Not akash's machine, not a VM, and not native Windows.

Everything below ran at `3c9a057`, the code commit (the next commit
changes documents only). The two rebuilds at the final commit, their
comparison with the delivered tarball and a live install of the rebuilt
release under a freshly booted systemd run after this file is committed;
their results are in the evidence (`package-reproducibility.log`,
`install-live-systemd-rebuilt.log`) and the report with this handoff.

| Check | Result |
| --- | --- |
| Astra's three new tests at `11a5f04` | **28 of 53 subcases fail**, 25 pass, as he reported |
| Astra's 15 regression tests and his 2 probe tests, his unmodified files through `go test -overlay` | **15 of 15 tests and both probes pass** (12 earlier regressions and the 3 new tests, 94 subcases), none fail |
| Saved fuzz inputs `1b3010105eaa5fc4`, `62357254aec8c849`, `ef8e27d3ab35fcf1`, `9348f770c9eb5715` | All four pass |
| `make ci-local` | Pass |
| Race suite, `go test -count=1 -race ./...` | **211 top-level tests, 13 fuzz seed suites, 509 subtests and seed cases: all pass, none skipped** |
| Coverage, `make cover` | **92.1%** measured here (Astra measured 92.1% at `11a5f04`) |
| `make fuzz FUZZTIME=30s`, then the same with `-fuzzminimizetime=1s` | **13 of 13 pass in both runs**, no failing input, no new corpus file (executions below) |
| `make lint`; `GOOS=windows golangci-lint run ./...` | 0 issues; 0 issues |
| `make vuln` (source) | No vulnerabilities (govulncheck 1.9.0, Go 1.27.2 standard library) |
| `make vuln-package VERSION=0.1.0-g01-fix5` (shipped binary) | No vulnerabilities in `bin/observex-node` (binary SHA-256 `3a2e3fbf2f99f2311fe55b2711b8b2c0380b699037b6d72c8c05bc238a7bb279`) |
| `make secrets` | No leaks; 27 of 27 commits scanned (whole history at `3c9a057`) |
| `make licenses proto-lint shell-check` | Pass |
| `make install-test VERSION=0.1.0-g01-fix5` (layout) | 20 of 20 |
| Live install, no systemd | 25 of 25 (container without systemd, as root; nothing left afterwards) |
| Live install, systemd 255 in namespaces | 28 of 28 (systemd 255 as PID 1 in new pid, mount, net, uts and ipc namespaces; NGINX back 3 s after SIGKILL; purge removes files and user) |
| Installer with port 9443 held | Exit 1 with the reason (`ports: Agents and Gateways (Front Door): already in use by another process (0.0.0.0:9443)`); service enabled and inactive; purge removes everything |
| Mutation checks (each part of the fix disabled in a scratch copy) | Each of 12 parts, disabled on its own, makes tests fail (1 to 46 failing tests and subtests; up to 608 of the 2560 generated mixed-quote cases); details in `mutation-checks.log` |
| Adversarial timing, 13 inputs of 8 MiB | 0.02 s to 1.85 s each, one process per input, no leak (`timing-8mib.log`) |
| Windows | `GOOS=windows go vet ./...` and `go test -c` for every package compile; **not run natively** |

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
| internal/platform/logging | 91.6% |
| internal/platform/tlsx | 93.1% |
| internal/platform/tlsx/tlstest | 86.0% |
| internal/store | 100.0% |
| internal/store/fake | 96.5% |
| internal/store/storetest | 89.1% |
| **all** | **92.1%** |

Fuzz executions in 30 s per target (a fuzz run finds inputs; it does not
prove all inputs safe). **A correction to how earlier rounds read these
counts:** in `make fuzz`, several targets stop counting after a few seconds
(the log shows `0/sec`). Go's fuzz debug output (`GODEBUG=fuzzdebug=1`)
shows why: when a worker finds an input with new coverage it minimizes it,
and with Go's default `-fuzzminimizetime` of 60 s that takes the rest of
the 30 s while the counter stands still. The logs of the earlier rounds
show the same pattern, so their counts for those targets also reflect only
the first seconds. A second run of the same commands with
`-fuzzminimizetime=1s` (`fuzz-all-minimize1s.log`) fuzzes for the whole
30 s; both columns are below. The Makefile is unchanged in this round;
adding the flag to `make fuzz` is a small follow-up proposed for the start
of G02.

| Target | Package | `make fuzz` | With `-fuzzminimizetime=1s` | Result |
| --- | --- | --- | --- | --- |
| `FuzzRedactString` | platform/logging | 420,210 | 450,838 | Pass |
| `FuzzRedactConfidential` | platform/logging | 4,906 | 66,278 | Pass |
| `FuzzSensitiveShapes` | platform/logging | 4,160 | 7,030 | Pass |
| `FuzzPairsMatchExpression` | platform/logging | 28,177 | 324,154 | Pass |
| `FuzzDecode` | platform/config | 55,713 | 721,036 | Pass |
| `FuzzVerifyToken` | platform/tlsx | 469,550 | 472,665 | Pass |
| `FuzzParseTraceID` | store | 1,155,873 | 1,270,481 | Pass |
| `FuzzParse` | node | 177,206 | 202,535 | Pass |
| `FuzzParseFeatures` | node/frontdoor | 274,963 | 289,270 | Pass |
| `FuzzCheck` | node/firewall | 543,349 | 571,900 | Pass |
| `FuzzParseStat` | node/selfmon | 396,242 | 355,574 | Pass |
| `FuzzWriteText` | node/selfmon | 17,995 | 274,127 | Pass |
| `FuzzPrefixWriter` | node/supervisor | 108,378 | 131,898 | Pass |

## What is demonstrated and what is inferred

Demonstrated here by running it: everything in the table, the failures of
the new tests at `11a5f04`, and the mutation checks.

Inferred, not demonstrated:

- That the tests pass on native Windows: the changed code is
  platform-independent and every package compiles for Windows.
- That the rules cover every spelling of broken quoting: the generated
  tests and fuzzers cover the shapes listed, and the T01 rule does not
  depend on reading the rest of the text, but that is an argument.
- That work stays bounded for every input: the budget bounds recovery, the
  scans are linear by construction, and 13 adversarial shapes were timed in
  this container.
- A conventional VM install and live NGINX with OpenSSL 3.5 post-quantum
  negotiation (below).

## Validation steps for Astra

1. **Apply**: put `observe-G01-boundaries-ii.bundle` and
   `apply-G01-boundaries-ii.ps1` in `_handoff\G01-boundaries-ii\`, then
   `powershell -ExecutionPolicy Bypass -File .\_handoff\G01-boundaries-ii\apply-G01-boundaries-ii.ps1`.
   In a detached review checkout: `git fetch <bundle> main`, then
   `git checkout --detach FETCH_HEAD`.
2. **Files**: `sha256sum -c docs/handoff/G01/files-g01-boundaries-ii.sha256`.
3. **Native Windows**: `go vet ./...`, `go build ./...`,
   `go test -count=1 -json ./...`.
4. **Regressions**: `run-regressions.ps1`, `run-repair-boundaries.ps1` and
   `run-boundaries-regressions.ps1` with your fixtures unchanged. Expected:
   12 + 2 + 3 tests pass (53 subcases in the last). Saved inputs:
   `go test -count=1 -run '^Fuzz(SensitiveShapes|RedactString)/' -v ./internal/platform/logging`.
5. **Linux**: `make tools`, `make ci-local`, `make fuzz FUZZTIME=30s`,
   `make lint vuln secrets licenses proto-lint shell-check`,
   `make install-test VERSION=0.1.0-g01-fix5`,
   `make vuln-package VERSION=0.1.0-g01-fix5`.
6. **Fresh systemd machine**: `sudo ./test-install.sh live
   observex-managed-node-0.1.0-g01-fix5-linux-amd64.tar.gz`, expecting
   `# PASSED: all 28 checks`.
7. **Reproducibility**: two builds on a native Linux filesystem, compared
   with the delivered SHA-256.

## Remaining limits

1. No native Windows run and no conventional VM run here; the systemd runs
   used namespaces inside a container.
2. **Live NGINX + OpenSSL 3.5 post-quantum negotiation is untested**: every
   NGINX here links OpenSSL 3.0.13.
3. Redaction remains a safety net, and its fail-closed rules hide ordinary
   text in the cases above.
4. Until `make fuzz` sets `-fuzzminimizetime`, several of its targets fuzz
   for only the first seconds of each 30 s run (above).
5. Owner decisions not taken by Claude: ADR acceptance, the project licence
   and the NGINX distribution policy. G01's approval is akash's, recorded
   above in his words.
