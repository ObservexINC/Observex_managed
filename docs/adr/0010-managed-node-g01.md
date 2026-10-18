# ADR 0010: The managed node at G01: components, ports, TLS and installer

Status: Proposed.

## Context

G01 builds the node platform (OD-25 policies 3 and 11, DEV-02 to DEV-04):
the Node Supervisor, the Front Door, the firewall check, self-monitoring and
the installer. "Done when: a killed process is restarted; a node installs
from a tarball on a clean VM."

## Decision

### Process model

- `observex-node run` is the Node Supervisor. systemd starts it and restarts
  it if it dies; it starts, checks and restarts the node's components.
- At G01 the only component is the Front Door (NGINX). The Server and the
  Embedded Gateway join in G03 and G04 and are integrated in G06. Their
  loopback addresses are reserved now, so the Front Door's routes are fixed
  from the start and answer 503 (service unavailable) until then.
- Each component runs in its own process group; when a component dies, the
  supervisor kills what it left behind (NGINX workers holding the listening
  sockets) before restarting it. On Linux a component dies with the
  supervisor (parent-death signal).

### Ports

| Port | Exposure | Purpose |
| --- | --- | --- |
| 443 | Public | Console, API, `/node/health` (Front Door) |
| 9443 | Public | Agents and Gateways, client certificate required except Enroll (Front Door) |
| 8180 | Loopback | Supervisor status and `/metrics` |
| 8181 | Loopback | Front Door liveness probe |
| 8182, 8183 | Loopback | Server and Embedded Gateway (from G03, G04) |
| 2380, 7000, 9042, 9200, 9300, 8190 | Cluster | Planned for G02 and G03; listed in the firewall report early, confirmed by their goals' ADRs |

`observex-node firewall` reports these and the host firewall's state. It
runs only a fixed list of read-only commands and prints suggestions; it
never changes the firewall (DEV-03). Suggestions for ufw and firewalld use
IP addresses only; a peer given by host name becomes a comment.

### Front Door

- TLS 1.3 only. Key exchange: X25519MLKEM768 first when NGINX runs with
  OpenSSL 3.5 or later, then X25519 and P-256. The groups in use are logged
  and published as a metric, not chosen silently.
- Routes are fixed in code; every configurable value is validated, and a fuzz
  test checks that no value can add a directive to the generated file.
- The NGINX configuration is generated at every start into `/run/observex`,
  written atomically and checked with `nginx -t` before NGINX starts.
- NGINX's error log keeps only critical messages, because NGINX writes the
  request line, query string included, into error messages.

### Installer

- A reproducible tarball (`scripts/package.sh`) with `install.sh`,
  `uninstall.sh`, the binary and a systemd unit.
- The node runs as the system user `observex`, with `CAP_NET_BIND_SERVICE`
  as its only capability, and systemd hardening (`ProtectSystem=strict`,
  `NoNewPrivileges`, private /tmp and devices, restricted address families).
- `install.sh` never changes the firewall, never installs packages and never
  overwrites an existing configuration or key. It keeps the previous binary
  for rollback.
- Every start of the service runs `observex-node check` first
  (`ExecStartPre`), as `observex` with the service's capability and sandbox,
  so the check sees what the node will see: it can test port 443 only
  because the service holds `CAP_NET_BIND_SERVICE`. A failed check fails
  the start; the installer then prints the check's message, stops the
  service and exits non-zero.

### First-install TLS (interim)

- `observex-node init` creates a cluster CA (ECDSA P-256, path length 0, ten
  years) and the node's server certificate (397 days, the names given with
  `--host`). It never overwrites a file.
- The CA key is a root-only file (`0600`); the node never reads it. The node
  key is `root:observex 0640`.
- This lasts until G04, when the cluster CA moves into the
  ConfigurationStore, protected by the customer's KMS or HSM, and Agent
  certificates are issued through enrollment (ADR 0008). Customers may supply
  their own certificates instead.

## Consequences

- One NGINX process tree per node, owned and restarted by the supervisor,
  not by the distribution's `nginx.service`.
- A node is usable and observable (health, status, metrics, firewall report)
  before any ObserveX data service exists.

## Open for akash

1. **NGINX source.** G01 uses the distribution's NGINX. Most distributions
   ship OpenSSL 3.0 to 3.2 today, so the hybrid post-quantum key exchange is
   off on them. Shipping ObserveX's own NGINX build with OpenSSL 3.5 (as
   Dynatrace Managed ships its own NGINX) would give every customer the same
   Front Door and post-quantum TLS, at the cost of patching NGINX and
   OpenSSL ourselves. Recommendation: decide before G18; keep the
   distribution's NGINX until then.
2. **DEB and RPM packages.** The plan lists them; G01 delivers the tarball,
   which is what "done when" asks for. Proposed for G18.
