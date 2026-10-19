# G01 handoff to Codex Astra

> **QA fix rounds:** Astra's report of 17 October 2026 is answered in
> [FIXES.md](FIXES.md) and his revalidation of 18 October in
> [FOLLOWUP.md](FOLLOWUP.md); together they supersede this file's
> validation steps, check counts (the live systemd test now has 28 checks)
> and known limits.

Goal: G01, node platform (Node Supervisor, Front Door, firewall check,
self-monitoring, installer). Status: **implemented and tested in Claude's
workspace; awaiting Astra's validation and akash's approval.** Nothing has
been pushed since G00.

## Commits on main (on top of `49b834e`, which is on GitHub)

| Commit | Content |
| --- | --- |
| `298eaad` | Module path moved to `github.com/ObservexINC/Observex_managed` (no behaviour change) |
| `3eabe9d` | Node Supervisor, Front Door, firewall check, self-monitoring |
| `0869717` | Node assembly, `observex-node` command, first-install TLS, installer, CI |
| `885480f` | ADRs 0009 and 0010, threat model, README |
| next commit | This handoff folder |

`observe-G01.bundle` holds these five commits and needs `49b834e` in the
receiving repository. Its SHA-256 and the final commit hash are in
`observe-G01.bundle.sha256` and `apply-G01.ps1`, delivered next to it.

## G01 "done when" and where it stands

| Criterion | Status |
| --- | --- |
| A killed process is restarted | Passed in Claude's workspace with real NGINX (integration test and live install test). Astra to confirm. |
| A node installs from a tarball on a clean VM | Passed in a disposable **container without systemd**. Not yet run on a VM with systemd: **step 5 below is the acceptance test.** |

## What G01 delivers

- `observex-node`: `run` (the Node Supervisor), `check`, `firewall`,
  `status`, `health`, `render-nginx`, `init`, `version`.
- The Node Supervisor runs the NGINX Front Door, restarts it with backoff,
  kills a dead component's leftover processes, and stops cleanly with a
  report. The Server and Gateway join in G03 and G04 (ADR 0010).
- Front Door: TLS 1.3 only; Console listener on 443; Agents listener on 9443
  that requires a client certificate from the cluster CA (except Enroll);
  fixed routes; X25519MLKEM768 when NGINX has OpenSSL 3.5 or later.
- Firewall report: read-only, never changes the firewall.
- Self-monitoring on loopback `http://127.0.0.1:8180/metrics`.
- First-install cluster CA and node certificate (interim until G04).
- Reproducible tarball with `install.sh`, `uninstall.sh` and a hardened
  systemd unit; the node runs as user `observex`.

## Validation steps for Astra

### 1. Apply the bundle (PowerShell)

```powershell
cd C:\Users\91832\Documents\observex_managed
powershell -ExecutionPolicy Bypass -File .\_handoff\G01\apply-G01.ps1
```

The script checks the bundle's SHA-256, that the folder is clean and at
`49b834e`, fast-forwards `main` to the G01 commits and stops. It pushes only
with `-Push`, which akash adds after approving G01.

### 2. Verify every file (WSL2)

```sh
cd /mnt/c/Users/91832/Documents/observex_managed
sha256sum -c docs/handoff/G01/files-885480f.sha256     # every line OK
```

### 3. Native Windows run (PowerShell)

```powershell
go version
gofmt -l .                  # prints nothing
go vet ./...
go build ./...
go test -count=1 ./...
```

This is the first Windows run of the supervisor tests; they have only been
compiled for Windows. Report any failure as found. The NGINX integration
tests are Linux-only and do not run on Windows.

### 4. WSL2 run (Ubuntu)

```sh
sudo apt-get install -y nginx-core      # the Front Door tests need NGINX
go version
make ci-local                           # expect about 92% coverage
go test -count=1 -v ./internal/node/... ./cmd/... | grep -c -- '--- SKIP'    # expect 0
make fuzz FUZZTIME=30s                  # nine targets
make install-test VERSION=0.1.0-g01     # 20 layout checks
```

### 5. Clean VM with systemd: the G01 acceptance test

Use a fresh VM (for example VirtualBox with Ubuntu Server 24.04) or a fresh
WSL2 distribution with systemd enabled (`[boot] systemd=true` in
`/etc/wsl.conf`). Do not use a machine that matters: the test installs,
creates a user and uninstalls.

```sh
# copy the tarball and packaging/linux/test-install.sh to the VM, then:
sha256sum -c observex-managed-node-0.1.0-g01-linux-amd64.tar.gz.sha256
sudo apt-get install -y nginx-core
sudo ./test-install.sh live observex-managed-node-0.1.0-g01-linux-amd64.tar.gz
```

Expected: `# PASSED: all 27 checks` (the systemd path adds three service
checks). Then, as an operator would, install by hand and look around:

```sh
tar -xzf observex-managed-node-0.1.0-g01-linux-amd64.tar.gz
cd observex-managed-node-0.1.0-g01-linux-amd64
sudo ./install.sh --host <vm-ip>
systemctl status observex-node
/opt/observex/bin/observex-node status
curl --cacert /etc/observex/tls/cluster-ca.crt https://<vm-ip>/node/health
sudo kill -9 "$(/opt/observex/bin/observex-node status | grep -o '"pid":[0-9]*' | cut -d: -f2)"
sleep 5; /opt/observex/bin/observex-node status       # "restarts":1, ready
sudo systemctl restart observex-node; /opt/observex/bin/observex-node health
journalctl -u observex-node --no-pager | tail -n 30
sudo ./uninstall.sh --purge --yes
```

### 6. Tools never run before (WSL2, through the module proxy)

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/zricethezav/gitleaks/v8@latest
go install github.com/google/go-licenses@latest
go install github.com/bufbuild/buf/cmd/buf@latest
sudo apt-get install -y shellcheck
make lint vuln secrets licenses proto-lint shell-check
```

Record each tool's version. Report findings rather than fixing them.

### 7. Go 1.27, if installed

Repeat steps 3 and 4 with Go 1.27.

## Known limits

1. No run on a VM with systemd yet (step 5), and no native Windows run (step 3).
2. Go 1.27, golangci-lint, govulncheck, gitleaks, go-licenses, buf and
   shellcheck have not run (the workspace cannot reach the module proxy).
3. The post-quantum key exchange is tested by unit and golden-file tests only;
   the workspace's NGINX has OpenSSL 3.0 (ADR 0010, open item 1).
4. Self-monitoring uses the standard library, not the OpenTelemetry SDK
   (ADR 0009).
5. The cluster CA key is a root-only file until G04 (ADR 0010).
6. Tarball only; DEB and RPM are proposed for G18.
7. The tarball is reproducible with Go 1.24.7; another Go version builds a
   different binary and so a different hash.

## Rollback

Nothing was pushed. On akash's PC, `git reset --hard 49b834e` in the
repository returns `main` to G00 (only while nothing new has been committed
there). On a test VM, `sudo ./uninstall.sh --purge --yes`, or delete the VM.
