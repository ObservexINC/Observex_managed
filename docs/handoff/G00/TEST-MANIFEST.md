# G00 test manifest

Code commit: `553a948fa91ae6402ecf79332bd55e8a67f0a4ad`

"Claude workspace" means Claude's cloud development workspace: Linux amd64,
Go 1.24.7, run on 15 October 2026. It is not akash's machine and not
validation evidence. Astra's runs are the acceptance evidence.

## What ran in Claude's workspace

| Check | Command | Result |
| --- | --- | --- |
| Formatting | `make fmt-check` (gofmt -l) | No files listed |
| Static checks | `go vet ./...` | Clean |
| Build | `go build ./...` | OK |
| Unit, contract and fuzz-seed tests with race detector | `go test -count=1 -race ./...` | PASS: 51 tests, 4 fuzz seed sets, 73 subtests, 0 failures |
| Coverage across packages | `make cover` (`-coverpkg=./...`) | 93.0% of statements (1035 of 1113) |
| Fuzz, 30 s each | `make fuzz FUZZTIME=30s` | PASS: FuzzRedactString 56,840 runs; FuzzDecode 51,415; FuzzVerifyToken 349,860; FuzzParseTraceID 954,823 |
| Fresh clone of the commit | `git clone` then `make ci-local` | PASS, 93.0% |
| Windows compile only | `GOOS=windows go build`, `go vet`, `go test -c` for every package | Compiles; **not run** on Windows |
| macOS compile only | `GOOS=darwin GOARCH=arm64 go vet ./...` | Clean; **not run** on macOS |

Coverage by package (combined profile):

| Package | Coverage |
| --- | --- |
| internal/platform/clock | 100.0% |
| internal/platform/config | 95.6% |
| internal/platform/logging | 96.6% |
| internal/platform/tlsx | 93.1% |
| internal/platform/tlsx/tlstest | 84.8% |
| internal/store | 100.0% |
| internal/store/fake | 96.2% |
| internal/store/storetest | 88.9% |

## Not run anywhere yet

| Check | Why not | Who runs it |
| --- | --- | --- |
| Go 1.27 build and tests | Workspace cannot reach proxy.golang.org to fetch the toolchain | Astra; CI |
| golangci-lint | Needs download through the module proxy | Astra (WSL2); CI |
| govulncheck | Same | Astra (WSL2); CI |
| gitleaks | Same | Astra (WSL2); CI |
| go-licenses | Same | Astra (WSL2); CI |
| buf lint and buf format | Same | Astra (WSL2); CI |
| GitHub Actions workflow | Nothing has been pushed (needs akash's approval) | CI after push |
| Native Windows run | Workspace is Linux | Astra |
| Docker | G00 has no containers or Docker tests | Not applicable |

## Tests by package

| Package | Tests |
| --- | --- |
| clock | TestRealIsUTC, TestFakeAdvanceAndSet, TestFakeConcurrentUse, TestNewStampUsesClockForRecordTime, TestValidate, TestVisibleTwoClocks, TestNegativeLagFromSkewedSource, TestViewString |
| logging | TestSecretLeak (24 log lines, 11 invented secrets, fragment check), TestSecretType, TestIsSensitiveKey, TestRedactStringCases, TestRedactStringKeepsOrdinaryText, TestNonStringValuesPassThrough, TestEnabledFollowsLevel, FuzzRedactString |
| config | TestDecodeValid, TestDecodeRejects, TestDecodeTooLarge, TestLoad, TestLoadSigned, TestVerifyRejectsShortSignature, FuzzDecode |
| tlsx | TestMutualTLSSucceeds, TestRejectsClientWithoutCertificate, TestRejectsClientFromAnotherCA, TestClientRejectsServerFromAnotherCA, TestClientRejectsWrongServerName, TestRejectsTLS12, TestClientOffersHybridPostQuantum, TestHybridOnlyServerAcceptsObserveXClient, TestBuildersCopyCurveList, TestConfigBuildersValidateInput, TestLoadCertPoolAndKeyPairErrors, TestEnrollmentTokenRoundTrip, TestEnrollmentTokenFailures, TestEnrollmentTokenNeverPrints, TestEnrollmentTokenRecordHoldsNoSecret, TestTokensAreUnique, TestNewEnrollmentTokenRejectsBadTTL, FuzzVerifyToken |
| store | TestSeriesKeyIsCanonical, TestSampleValidate, TestTimeRange, TestTraceIDParse, TestSpanValidate, TestDocumentAndBaselineAndChangeValidate, TestNormaliseLimit, FuzzParseTraceID |
| store/fake | TestMetricStoreContract, TestSearchStoreContract, TestTraceStoreContract, TestConfigStoreContract, TestHistoryStoreContract, TestBaselineStoreContract (contract suites from store/storetest) |
