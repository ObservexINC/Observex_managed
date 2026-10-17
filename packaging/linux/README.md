# Installing an ObserveX Managed node

This tarball installs one node of an ObserveX Managed cluster on Linux.
At this stage (goal G01) a node runs the Node Supervisor, the NGINX Front
Door and self-monitoring. The ObserveX Server, the Embedded Gateway and the
stores join the node in later goals; until then the Front Door answers their
routes with HTTP 502.

## Requirements

| Item | Requirement |
| --- | --- |
| Operating system | Linux with systemd, x86-64 |
| NGINX | Installed from the distribution (`apt-get install nginx-core`, `dnf install nginx`). OpenSSL 3.5 or later enables the hybrid post-quantum key exchange; older OpenSSL works with X25519 and P-256. |
| Ports | 443 (Console and API) and 9443 (Agents and Gateways) reachable by users and Agents. Run `observex-node firewall` for the full list. |
| Privileges | `root` to install. The node itself runs as the unprivileged user `observex`. |

The installer never changes the firewall and never installs other packages.

## Install

```sh
tar -xzf observex-managed-node-<version>-linux-amd64.tar.gz
cd observex-managed-node-<version>-linux-amd64
sha256sum -c SHA256SUMS
sudo ./install.sh --host node1.example.com --host 10.0.0.11
```

`--host` names every DNS name and IP address that users and Agents use to
reach the node; they go into the node's certificate. Without `--host`, the
host name and its addresses are used. Other options: `--node-id`, `--peer`
(the other cluster nodes, for the firewall report), `--no-start`,
`--no-systemd`. See `./install.sh --help`.

The installer:

1. creates the system user and group `observex`;
2. installs `/opt/observex/bin/observex-node`, keeping a previous binary as
   `observex-node.previous`;
3. writes `/etc/observex/node.json` and the TLS files in `/etc/observex/tls`
   only if they do not exist;
4. installs and starts `observex-node.service`, waits until the node is
   ready, and prints the firewall report.

## Check the node

```sh
systemctl status observex-node
/opt/observex/bin/observex-node health          # "ready", exit 0
/opt/observex/bin/observex-node status          # supervisor status, JSON
/opt/observex/bin/observex-node firewall -running
curl --cacert /etc/observex/tls/cluster-ca.crt https://node1.example.com/node/health
curl -s http://127.0.0.1:8180/metrics           # self-monitoring, on the node only
journalctl -u observex-node
```

## TLS files

| File | Owner and mode | Purpose |
| --- | --- | --- |
| `cluster-ca.crt` | root, 0644 | Cluster CA certificate; Agents and browsers trust it |
| `cluster-ca.key` | root, 0600 | Cluster CA private key. **Back it up securely.** The node never reads it. |
| `node.crt` | root, 0644 | Front Door certificate |
| `node.key` | root:observex, 0640 | Front Door private key |

To use your organisation's certificates instead, put them in place before
installing, or replace `node.crt` and `node.key` and restart the service.
The CA key as a root-only file is interim: from G04 it moves into the
cluster's configuration store, protected by your KMS or HSM.

## Upgrade and roll back

Run the new tarball's `install.sh`. It keeps the configuration and TLS files
and the previous binary. To roll back:

```sh
sudo cp -p /opt/observex/bin/observex-node.previous /opt/observex/bin/observex-node
sudo systemctl restart observex-node
```

## Uninstall

```sh
sudo ./uninstall.sh                 # keeps /etc/observex and /var/lib/observex
sudo ./uninstall.sh --purge --yes   # also deletes them, the CA key and the observex user
```

## Layout

| Path | Contents |
| --- | --- |
| `/opt/observex/bin` | `observex-node` |
| `/etc/observex` | `node.json`, `tls/` (root:observex, 0750) |
| `/var/lib/observex` | Node data (observex, 0750) |
| `/run/observex` | Generated NGINX configuration, recreated at every start |
| `/etc/systemd/system/observex-node.service` | Service unit |
