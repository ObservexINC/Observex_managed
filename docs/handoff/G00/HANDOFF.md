# G00 handoff to Codex Astra

Goal: G00, architecture baseline. Status: **implemented, awaiting akash's
approval and Astra's validation.** Nothing has been pushed to GitHub.

## Commits on main

| Commit | Content |
| --- | --- |
| `553a948fa91ae6402ecf79332bd55e8a67f0a4ad` | G00 code, tests, schemas, CI configuration, ADRs, threat model, OD-26 draft (60 files) |
| next commit | This handoff folder (`docs/handoff/G00`) |

The bundle `observe-G00.bundle` holds both commits. Its SHA-256 is delivered
next to it in `observe-G00.bundle.sha256`; a file cannot contain its own hash.

## What G00 delivers

- Shared platform packages: `clock` (two clocks), `logging` (secret
  redaction), `config` (strict JSON, Ed25519 signatures), `tlsx` (TLS 1.3
  mutual TLS with hybrid post-quantum key exchange; enrollment tokens).
- The six store interfaces, a contract test suite for each, and in-memory
  fakes that pass them.
- Wire schemas: common types, intake (acknowledgement meanings left open for
  DR-07 and DR-08), enrollment, health.
- Makefile, GitHub Actions workflow, golangci-lint, gitleaks and buf
  configuration, `.gitattributes` forcing LF endings.
- ADRs 0001 to 0008 (Proposed), threat model, OD-26 draft (not approved).

Standard library only; no third-party modules.

## Validation steps for Astra

### 1. Verify and unpack (PowerShell)

```powershell
cd C:\Users\91832\Documents
Get-FileHash .\observe-G00.bundle -Algorithm SHA256   # must equal observe-G00.bundle.sha256
git clone -b main .\observe-G00.bundle observe-g00
cd observe-g00
git bundle verify ..\observe-G00.bundle                # "is okay" (needs to run inside a repository)
git fsck --full                                        # no errors
git log --oneline                                      # two commits, oldest 553a948
```

A fresh folder is used so akash's existing `observexxxxx` folder is untouched.

### 2. Verify every file (WSL2)

```sh
cd /mnt/c/Users/91832/Documents/observe-g00
sha256sum -c docs/handoff/G00/files-553a948.sha256    # 60 lines, all OK
```

### 3. Native Windows run (PowerShell)

```powershell
go version                  # 1.24 or later; record it
gofmt -l .                  # must print nothing
go vet ./...
go build ./...
go test -count=1 ./...      # all ok
```

The race detector on Windows needs `CGO_ENABLED=1` and gcc; if they are not
installed, run the race tests in WSL2 (step 4).

### 4. WSL2 run

```sh
go version
make ci-local               # gofmt, vet, build, race tests, coverage (expect about 93%)
make fuzz FUZZTIME=30s      # four fuzz targets, 30 s each
```

### 5. Tools never run before (WSL2, through the module proxy)

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/zricethezav/gitleaks/v8@latest
go install github.com/google/go-licenses@latest
go install github.com/bufbuild/buf/cmd/buf@latest
make lint vuln secrets licenses proto-lint
```

Record the version of each tool. These have never run against this code, so
findings are possible; report them rather than fixing them.

### 6. Go 1.27, if installed

Repeat steps 3 and 4 with Go 1.27 and record the version.

No Docker step: G00 has no containers.

## Expected results

All tests pass; gofmt prints nothing; coverage about 93%; four fuzz targets
pass. See `TEST-MANIFEST.md` for the exact results in Claude's workspace.

## Known limits

1. Go 1.27, golangci-lint, govulncheck, gitleaks, go-licenses and buf have not
   run (Claude's workspace cannot reach proxy.golang.org or sum.golang.org).
2. Nothing has run on Windows or macOS; code and test binaries only compile
   for them.
3. `go.mod` declares Go 1.24 for the same reason (ADR 0002).
4. CI tool versions are unpinned until a first green run.
5. No generated Protobuf code yet; generation starts with the first service
   (G03, G04).
6. ADRs are Proposed and OD-26 is a draft until akash decides.

## Rollback

Nothing was pushed and nothing was installed. To roll back, delete the
`observe-g00` folder and the bundle.
