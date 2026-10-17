# ObserveX Managed threat model

Status: Proposed. G00 baseline, revised for G01 (the node: Front Door,
Node Supervisor, installer). Revised at the end of every goal that adds a
trust boundary or an entry point.

Method: STRIDE (spoofing, tampering, repudiation, information disclosure,
denial of service, elevation of privilege) per trust boundary, plus prompt
injection for the AI features. "Where" names the goal that builds the control;
"G00" means it exists in this repository now.

## Assets

1. Customer telemetry: metrics, logs, traces, sessions. It routinely contains
   personal data, and sometimes secrets that applications logged by mistake.
2. Credentials: enrollment tokens, node and agent private keys, the cluster CA
   key, the configuration signing key, user passwords and SSO secrets, store
   credentials, model endpoint keys.
3. Configuration and topology: what is monitored, how, and how it connects.
4. Evidence: problems, audit records, ProofChain records, incident capsules.
5. Availability of monitoring itself, especially during the customer's incident.
6. Control over monitored hosts through the Agent and, if enabled, remediation.

## Trust boundaries

| ID | Boundary | Crosses |
| --- | --- | --- |
| B1 | Monitored process to Agent | Process memory, files and network seen by the Agent |
| B2 | Agent to Gateway or node | Telemetry upload, configuration download, enrollment |
| B3 | Gateway to cluster node | Forwarded telemetry and configuration |
| B4 | End-user browser to beacon endpoint | Browser monitoring data from the internet |
| B5 | Person or API client to Front Door | Console and API sessions |
| B6 | Node to node | Store replication, coordination, Server-to-Server calls |
| B7 | Server to data at rest | Store files on node disks, backups |
| B8 | Server to model endpoint | Prompts and answers for AI features |
| B9 | Cluster to Mission Control (optional) | Outbound health and licence data |
| B10 | Build to customer install | Packages, images, upgrades |
| B11 | Server to customer systems (remediation, off by default) | Actions |
| B12 | Operator shell on a node | Node Supervisor, local files |

## Threats and controls

### B1 Monitored process to Agent

| STRIDE | Threat | Control | Where |
| --- | --- | --- | --- |
| I | Agent captures personal data or secrets from requests, logs or SQL | Capture rules mask at the source: query parameters, headers, SQL literals, configurable fields; logs scrubbed before upload | G05 |
| E | Agent runs privileged and becomes a foothold | Watchdog and core run with least privilege; privileged parts (eBPF) are separate modules, off unless enabled | G05, later |
| T | Local user tampers with Agent binaries or config | Signed packages, signed configuration, file permissions checked at start | G00 (signing), G05 |
| D | Agent starves the host | CPU and memory limits, bounded disk buffer, self-throttling | G05 |

### B2 Agent to Gateway or node, and B3 Gateway to node

| STRIDE | Threat | Control | Where |
| --- | --- | --- | --- |
| S | Rogue host poses as an Agent | One-time enrollment tokens, hashed at rest, single use under compare-and-set; per-agent certificate; mTLS | G00 (token, TLS), G04, G05 |
| S | Rogue server poses as the cluster | Agent pins the cluster CA received at enrollment | G05 |
| T | Telemetry or configuration altered in transit | TLS 1.3 only (Front Door enforces it from G01); configuration also signed with Ed25519 and refused unless verified | G00, G01 |
| S | A client forges the client-certificate result headers | The Front Door always sets the X-ObserveX-Client-* headers itself, overwriting anything the client sent | G01 |
| I | Traffic recorded now, decrypted later | Hybrid post-quantum key exchange X25519MLKEM768 preferred | G00 |
| R | Sender denies or replays a batch | Batch ID and per-sender sequence numbers; duplicates detected | G03 (needs DR-07, DR-08) |
| D | Flood from one Agent or a stolen identity | Per-agent and per-environment quotas, request size limits, backpressure; certificate revocation | G03, G04 |
| E | An Agent's identity used to reach admin APIs | Agent certificates authorise intake and configuration download only | G04 |

### B4 Browser to beacon endpoint

The beacon endpoint is public by design and cannot authenticate end users.

| STRIDE | Threat | Control | Where |
| --- | --- | --- | --- |
| S, T | Forged beacons poison metrics or business numbers | Application keys scoped to one application and origin; schema validation; plausibility limits; forged data is labelled by origin | G14 |
| D | Beacon flood | Rate limits per application and per client address at the Front Door; separate port and quota | G01, G14 |
| I | Session replay records what users type | Masking on by default for inputs; replay off unless enabled per application | G14 |

### B5 Person or API client to Front Door

| STRIDE | Threat | Control | Where |
| --- | --- | --- | --- |
| S | Stolen password or session | SSO (OIDC, SAML), multi-factor for local accounts, short sessions, secure cookies | G10 |
| E | User sees another team's or tenant's data | Role- and environment-scoped access checked in the Server on every query, not only in the Console | G10 |
| R | Admin denies a change | Every change written to the audit log with both clocks; ProofChain hash chain | G10, G13 |
| T | Cross-site request forgery or script injection in the Console | Same-site cookies, CSRF tokens, content security policy, output encoding | G10 |
| D | Expensive queries | Query cost limits, timeouts, per-user concurrency | G10 |
| I | Secrets leak through logs or error messages | Redacting log handler on every process; `logging.Secret` type; leak test | G00 |

### B6 Node to node, and B7 data at rest

| STRIDE | Threat | Control | Where |
| --- | --- | --- | --- |
| S, T | Host on the cluster network joins or tampers | mTLS between nodes and stores; store client authentication | G02, G07 |
| I | Disk or backup stolen | Encryption at rest through the customer's disk encryption or KMS; backups encrypted | G07, G16 |
| D | Node failure | Three identical nodes; MetricStore and SearchStore replicated; TraceStore is single-copy by design (IMP-2) | G07 |
| T | Stored evidence altered after the fact | Append-only history; ProofChain hash chain with external anchor | G13 |

### B8 Server to model endpoint, and prompt injection

Every log line, span attribute, URL and user-agent string can contain text
written by an attacker. The AI Investigator reads that text.

| Threat | Control | Where |
| --- | --- | --- |
| Telemetry text tells the model to ignore instructions, hide a problem, or call a tool | Telemetry is passed as quoted data in a separate field, never as instructions; the model's tools are read-only queries from an allowlist; no tool can change configuration or run remediation | G12 |
| Model output steers people to a harmful action | Every claim cites evidence the Console can open; suggested actions need a person to approve; remediation stays off by default (D6) | G12, G17 |
| Secrets or personal data sent to an external model | Default model runs inside the customer's network; redaction before the prompt; per-environment switch to forbid external endpoints | G12 |
| Problems decided by a model | Problems are deterministic (D7); the AI explains, it does not decide | G08 |
| AI quality drifts unnoticed | AI Scorecard replays past incidents "as known then" and includes injection test cases | G15 |

### B9 Cluster to Mission Control

| Threat | Control | Where |
| --- | --- | --- |
| Customer data leaves the premises | Outbound only, optional, off by default for air-gapped sites; content limited to health and licence data, viewable by the customer | Later |
| Mission Control becomes a dependency | The cluster runs fully without it (OD-25 policy 12) | All goals |
| Vendor remote access | Remote support off by default, time-limited, approved and audited by the customer | Later |

### B10 Build to customer install

| Threat | Control | Where |
| --- | --- | --- |
| Compromised dependency | Module proxy and checksum database always on; govulncheck; licence check; few dependencies | G00 (policy), CI |
| Tampered package | cosign signatures and SBOMs (Syft); installer verifies before install | G18 |
| Leaked secret in the repository | gitleaks in CI; one allowlisted fixture file of invented secrets | G00 |
| Bad upgrade | Staged upgrade with health checks and rollback | G16 |

### B11 Remediation

Off by default (D6). When enabled: allowlisted actions only, scoped
credentials held by the customer, approval by a person, dry run first, audit
record before and after, automatic stop on failure. Designed in G17.

### B12 Operator shell on a node, and the node service

| STRIDE | Threat | Control | Where |
| --- | --- | --- | --- |
| E | The node service is compromised and becomes root | Runs as user `observex` with `CAP_NET_BIND_SERVICE` only, `NoNewPrivileges`, `ProtectSystem=strict`, private /tmp and devices; NGINX runs as the same unprivileged user (tested) | G01 |
| I | The cluster CA key is read by the service or another user | Root-only file (`0600`); the node never reads it; `init` never overwrites it. Interim until the KMS/HSM design | G01, G04 |
| I | The node key is read by other local users | `root:observex 0640` inside a `0750` directory | G01 |
| I | A component inherits the supervisor's credentials | Components get a minimal fixed environment, never the supervisor's | G01 |
| I | Secrets reach the journal through component output | Every component line passes through the redaction filter (ADR 0007) | G01 |
| T | A configuration value injects NGINX directives | Every value validated against strict patterns; routes fixed in code; fuzz test on the generated file | G01 |
| T | The installer overwrites a key or configuration in use | `install.sh` and `init` create files only when missing (exclusive create); the previous binary is kept | G01 |
| T | Shell injection through installer arguments | Arguments checked against a strict character set before use | G01 |
| D | A crashed NGINX leaves workers holding the ports | The supervisor kills the component's whole process group before restarting it (tested with SIGKILL) | G01 |
| D | A crash loop hides an outage | Bounded backoff, then the component is marked failed; `/readyz`, `/health` and metrics report it | G01 |
| R | Firewall changes are made silently | The node never changes the firewall; it runs only a fixed list of read-only commands and prints suggestions (DEV-03) | G01 |
| I | Supervisor status or metrics are exposed to the network | Bound to loopback only (validated); the Front Door forwards `/node/health` and nothing else of the supervisor (tested) | G01 |

Admin actions taken through the shell are recorded in the audit log where
the Server can see them (G10).

## Open risks for akash

1. Acknowledgement meanings (DR-07, DR-08) are not approved, so replay and loss
   guarantees are undefined until they are.
2. The TraceStore keeps one copy; a failed node loses its share of traces.
3. The CA key's storage (file, KMS or HSM) is not chosen yet; ADR 0008 defers it
   to G04 and G05. Until then `observex-node init` keeps it as a root-only file
   on the first node (ADR 0010), which must be backed up and protected.
6. NGINX comes from the distribution (ADR 0010). Its patch level is the
   customer's responsibility, and on OpenSSL older than 3.5 the Front Door
   cannot offer post-quantum key exchange.
4. Browser monitoring data cannot be fully authenticated; it can be bounded and
   labelled only.
5. A customer that points the AI at an external model sends telemetry outside
   its premises; the switch to forbid that needs a default (proposed: forbidden).
