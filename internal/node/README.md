# Node modules (G01)

A managed node is one `observex-node` process (the Node Supervisor) and the
components it runs. At G01 the only component is the NGINX Front Door; the
Server and the Embedded Gateway join in later goals (ADR 0010).

| Package | Module | Tests |
| --- | --- | --- |
| `supervisor` | Starts components in dependency order, waits for readiness, restarts with bounded backoff, marks crash loops failed, stops in reverse order with a report, kills a dead component's leftover processes | Unit (helper processes), Unix kill and stop tests, race detector |
| `frontdoor` | Generates the NGINX configuration: TLS 1.3, Console and Agents listeners, fixed HTTP and gRPC routes, client-certificate headers | Unit, golden files, routes checked against `proto/`, `nginx -t` on every variant, real NGINX request tests, fuzz on `nginx -V` parsing |
| `firewall` | Read-only report of required ports and the host firewall; suggestions only | Unit with fake command runners, fuzz on command output |
| `selfmon` | The node's own metrics in Prometheus text format | Unit against recorded `/proc` fixtures, fuzz on parsing and escaping |
| `pki` | First-install cluster CA and node certificate; checks pairs and chains | Unit, file modes, never-overwrite, TLS handshake |
| `node` (this directory) | Configuration, Front Door preparation, start-up port check, status and metrics endpoint, `Run` | Unit, fuzz (no value can add an NGINX directive), real NGINX integration: kill -9 and restart, metrics, mTLS refusal, clean stop |

Run them:

```sh
go test -race ./internal/node/...                  # the integration tests skip without NGINX
make install-test                                  # tarball, installed under a temporary root
sudo packaging/linux/test-install.sh live dist/<tarball>   # disposable machine only
```

Local endpoints of a running node (loopback only):

| URL | Answer |
| --- | --- |
| `http://127.0.0.1:8180/livez` | 200 while the supervisor runs |
| `http://127.0.0.1:8180/readyz` | 200 when every component is ready, else 503; full status |
| `http://127.0.0.1:8180/status` | Full status, always 200 |
| `http://127.0.0.1:8180/health` | `{"status":"ready"}` or 503; the Front Door serves this as `/node/health` |
| `http://127.0.0.1:8180/metrics` | Self-monitoring metrics |
