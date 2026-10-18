#!/bin/sh
# Install test for the node tarball (development plan G01: "a killed process
# is restarted; a node installs from a tarball on a clean VM").
#
#   packaging/linux/test-install.sh layout TARBALL
#       Any Linux machine, no root needed. Installs under a temporary root
#       and checks files, modes, re-install and argument checks.
#
#   sudo packaging/linux/test-install.sh live TARBALL
#       A disposable Linux machine (a clean VM, or a container) with NGINX
#       installed and ports 443, 9443 and 8180-8183 free. Installs for real,
#       checks the running node, kills NGINX with SIGKILL and checks the
#       restart, stops the node, then uninstalls with --purge. With systemd
#       running it uses the service; without systemd it starts the node the
#       way the service does (user observex, CAP_NET_BIND_SERVICE only).
#
# Output is TAP-like: "ok N - ..." or "not ok N - ...". Exit 0 when every
# check passed.
set -eu

MODE=${1:-}
TARBALL=${2:-}
if [ -z "$MODE" ] || [ -z "$TARBALL" ]; then
	sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
fi
[ -f "$TARBALL" ] || { echo "no such tarball: $TARBALL" >&2; exit 2; }

N=0
FAILED=0
ok() { N=$((N + 1)); echo "ok $N - $*"; }
notok() { N=$((N + 1)); FAILED=$((FAILED + 1)); echo "not ok $N - $*"; }
check() { # check "description" command...
	d=$1
	shift
	if "$@" >/dev/null 2>&1; then ok "$d"; else notok "$d"; fi
}
# The predicates below run through check ("$@"), which ShellCheck cannot
# follow; SC2317 (unreachable command) is disabled for them alone.
# shellcheck disable=SC2317
mode_is() { [ "$(stat -c '%a' "$1")" = "$2" ]; }
# shellcheck disable=SC2317
owner_is() { [ "$(stat -c '%U:%G' "$1")" = "$2" ]; }
finish() {
	echo "1..$N"
	if [ "$FAILED" -gt 0 ]; then
		echo "# FAILED: $FAILED of $N checks"
		exit 1
	fi
	echo "# PASSED: all $N checks"
	exit 0
}

WORK=$(mktemp -d)
tar -xzf "$TARBALL" -C "$WORK"
PKG=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -n 1)
check "tarball contents match SHA256SUMS" sh -c "cd '$PKG' && sha256sum -c --quiet SHA256SUMS"
check "tarball holds the binary, scripts and unit" test -x "$PKG/bin/observex-node" -a -x "$PKG/install.sh" -a -x "$PKG/uninstall.sh" -a -f "$PKG/systemd/observex-node.service"
VERSION=$(cat "$PKG/VERSION")

case "$MODE" in
layout)
	R=$WORK/root
	if "$PKG/install.sh" --root "$R" --node-id layout-test --host localhost --host 127.0.0.1 >"$WORK/install.log" 2>&1; then
		ok "install.sh --root succeeds"
	else
		notok "install.sh --root succeeds"
		sed 's/^/# /' "$WORK/install.log"
	fi
	check "binary installed, mode 0755" mode_is "$R/opt/observex/bin/observex-node" 755
	check "installed binary reports $VERSION" sh -c "'$R/opt/observex/bin/observex-node' version | grep -qx 'observex-node $VERSION'"
	check "/etc/observex is 0750" mode_is "$R/etc/observex" 750
	check "/var/lib/observex is 0750" mode_is "$R/var/lib/observex" 750
	check "node.json is 0640" mode_is "$R/etc/observex/node.json" 640
	check "node.json names the node" grep -q '"node_id": "layout-test"' "$R/etc/observex/node.json"
	check "cluster CA key is 0600" mode_is "$R/etc/observex/tls/cluster-ca.key" 600
	check "node key is 0640" mode_is "$R/etc/observex/tls/node.key" 640
	check "certificates are 0644" sh -c "[ \$(stat -c %a '$R/etc/observex/tls/node.crt') = 644 ] && [ \$(stat -c %a '$R/etc/observex/tls/cluster-ca.crt') = 644 ]"
	check "no systemd unit under --root" test ! -e "$R/etc/systemd/system/observex-node.service"
	KEY_BEFORE=$(sha256sum "$R/etc/observex/tls/cluster-ca.key" | cut -d' ' -f1)
	CONF_BEFORE=$(sha256sum "$R/etc/observex/node.json" | cut -d' ' -f1)
	"$PKG/install.sh" --root "$R" --node-id other >"$WORK/reinstall.log" 2>&1 || true
	check "re-install keeps the configuration" sh -c "[ \$(sha256sum '$R/etc/observex/node.json' | cut -d' ' -f1) = $CONF_BEFORE ]"
	check "re-install keeps the CA key" sh -c "[ \$(sha256sum '$R/etc/observex/tls/cluster-ca.key' | cut -d' ' -f1) = $KEY_BEFORE ]"
	check "re-install keeps the previous binary" test -x "$R/opt/observex/bin/observex-node.previous"
	check "install.sh refuses a host with shell characters" sh -c "! '$PKG/install.sh' --root '$WORK/r2' --host 'a;reboot'"
	check "install.sh refuses an unknown option" sh -c "! '$PKG/install.sh' --root '$WORK/r3' --frobnicate"
	check "install.sh refuses a relative --root" sh -c "! '$PKG/install.sh' --root relative/dir"
	if command -v systemd-analyze >/dev/null 2>&1; then
		# The unit names /opt/observex/bin/observex-node and user observex,
		# which exist only on an installed machine; verify reports those
		# as the only problems elsewhere.
		systemd-analyze verify "$PKG/systemd/observex-node.service" >"$WORK/verify.log" 2>&1 || true
		if grep -v -E 'observex-node|observex|Failed to create .*: Invalid argument|^$' "$WORK/verify.log" | grep -q .; then
			notok "systemd-analyze verify finds no problem in the unit"
			sed 's/^/# /' "$WORK/verify.log"
		else
			ok "systemd-analyze verify finds no problem in the unit"
		fi
	fi
	rm -rf "$WORK"
	finish
	;;
live) ;;
*)
	echo "unknown mode $MODE (layout or live)" >&2
	exit 2
	;;
esac

# ---- live ----
[ "$(id -u)" -eq 0 ] || { echo "live mode must run as root on a disposable machine" >&2; exit 2; }
if [ -e /opt/observex ] || [ -e /etc/observex ] || getent passwd observex >/dev/null 2>&1; then
	echo "this machine already has ObserveX files or the observex user; live mode needs a clean machine" >&2
	exit 2
fi
NODE=/opt/observex/bin/observex-node
export OBSERVEX_NODE_CONFIG=/etc/observex/node.json
SYSTEMD=0
[ -d /run/systemd/system ] && SYSTEMD=1
NODE_PID=""

if [ "$SYSTEMD" -eq 1 ]; then
	if "$PKG/install.sh" --node-id live-test --host localhost --host 127.0.0.1 >"$WORK/install.log" 2>&1; then
		ok "install.sh installs and starts the service (systemd)"
	else
		notok "install.sh installs and starts the service (systemd)"
		sed 's/^/# /' "$WORK/install.log"
	fi
	check "service is enabled" systemctl is-enabled --quiet observex-node.service
	check "service is active" systemctl is-active --quiet observex-node.service
	# ExecStartPre ran "observex-node check" as observex with only
	# CAP_NET_BIND_SERVICE, and it could check port 443.
	check "pre-start check passed in the service's context, ports included" sh -c \
		"journalctl -u observex-node.service --no-pager -o cat | grep -qx 'ports: free'"
else
	if "$PKG/install.sh" --no-systemd --node-id live-test --host localhost --host 127.0.0.1 >"$WORK/install.log" 2>&1; then
		ok "install.sh installs (no systemd on this machine)"
	else
		notok "install.sh installs (no systemd on this machine)"
		sed 's/^/# /' "$WORK/install.log"
	fi
	# What the unit's RuntimeDirectory=, User=, ExecStartPre= and the
	# capability settings would do.
	install -d -m 0750 -o observex -g observex /run/observex
	# as_service replaces the shell it runs in with the command, so call it
	# in a subshell or as a background job; the job's PID is then the node.
	as_service() {
		exec setpriv --reuid observex --regid observex --init-groups \
			--inh-caps +net_bind_service --ambient-caps +net_bind_service \
			--bounding-set -all,+net_bind_service --no-new-privs \
			env OBSERVEX_NODE_CONFIG=/etc/observex/node.json "$@"
	}
	if (as_service "$NODE" check) >"$WORK/check.log" 2>&1 && grep -qx 'ports: free' "$WORK/check.log"; then
		ok "pre-start check passed in the service's context, ports included"
	else
		notok "pre-start check passed in the service's context, ports included"
		sed 's/^/# /' "$WORK/check.log"
	fi
	as_service "$NODE" run >"$WORK/node.log" 2>&1 &
	NODE_PID=$!
fi

i=0
until "$NODE" health >/dev/null 2>&1 || [ $i -ge 60 ]; do i=$((i + 1)); sleep 1; done
if [ $i -lt 60 ]; then ok "node is ready (after ${i}s)"; else notok "node is ready within 60s"; fi

check "user observex exists and cannot log in" sh -c "getent passwd observex | grep -q -E 'nologin|false'"
check "/etc/observex is root:observex 0750" sh -c "[ \"\$(stat -c '%U:%G %a' /etc/observex)\" = 'root:observex 750' ]"
check "node key is root:observex 0640" sh -c "[ \"\$(stat -c '%U:%G %a' /etc/observex/tls/node.key)\" = 'root:observex 640' ]"
check "CA key is root:root 0600" sh -c "[ \"\$(stat -c '%U:%G %a' /etc/observex/tls/cluster-ca.key)\" = 'root:root 600' ]"
check "/var/lib/observex is observex:observex" owner_is /var/lib/observex observex:observex
check "health through the Front Door over TLS 1.3 (port 443)" sh -c \
	"curl -sf --tlsv1.3 --cacert /etc/observex/tls/cluster-ca.crt https://localhost/node/health | grep -q '\"ready\"'"
# answers URL BODYFILE: the HTTP status of a request that reached the Front
# Door over TLS; it fails (and prints nothing) when the transport failed, so
# an unreachable node never passes for a protected one. It and the two
# predicates after it run through check (SC2317 disabled, as above).
# shellcheck disable=SC2317
answers() {
	url=$1
	body=$2
	shift 2
	curl -s -o "$body" -w '%{http_code}' --cacert /etc/observex/tls/cluster-ca.crt "$@" "$url"
}
# shellcheck disable=SC2317
metrics_not_exposed() {
	# The node's metrics are served on loopback only. Through a healthy
	# Front Door, /metrics goes to the ObserveX Server's route, which
	# answers 503 until the Server exists (G03); it must never carry the
	# node's own metrics.
	curl -sf --cacert /etc/observex/tls/cluster-ca.crt https://localhost/node/health | grep -q '"ready"' || return 1
	code=$(answers https://localhost/metrics "$WORK/metrics.body") || return 1
	[ "$code" = 503 ] && grep -q '"service unavailable"' "$WORK/metrics.body" && ! grep -q observex_node_ "$WORK/metrics.body"
}
# shellcheck disable=SC2317
agents_need_certificate() {
	code=$(answers https://localhost:9443/v1/metrics "$WORK/agents.body" -X POST) || return 1
	[ "$code" = 403 ] && grep -q '"client certificate required"' "$WORK/agents.body"
}
check "Front Door is up and does not expose the node's /metrics (503 from the Server route)" metrics_not_exposed
check "Agents listener (9443) answers 403 to a request without a client certificate" agents_need_certificate
check "self-monitoring on loopback reports the node ready" sh -c "curl -sf http://127.0.0.1:8180/metrics | grep -qx 'observex_node_ready 1'"

STATUS=$("$NODE" status 2>/dev/null || true)
PID=$(printf '%s' "$STATUS" | grep -o '"pid":[0-9]*' | head -n 1 | cut -d: -f2)
if [ -n "$PID" ]; then ok "status names the NGINX master (pid $PID)"; else notok "status names the NGINX master"; fi
check "NGINX runs as observex, not root" sh -c "[ \"\$(ps -o user= -p '$PID' | tr -d ' ')\" = observex ]"

if [ -n "$PID" ]; then
	kill -9 "$PID"
	i=0
	until "$NODE" status 2>/dev/null | grep -q '"restarts":1' && "$NODE" health >/dev/null 2>&1 || [ $i -ge 60 ]; do
		i=$((i + 1))
		sleep 1
	done
	if [ $i -lt 60 ]; then ok "killed NGINX (SIGKILL) is restarted and the node is ready again (${i}s)"; else notok "killed NGINX is restarted within 60s"; fi
	NEWPID=$("$NODE" status 2>/dev/null | grep -o '"pid":[0-9]*' | head -n 1 | cut -d: -f2)
	check "the restarted NGINX is a new process" test -n "$NEWPID" -a "$NEWPID" != "$PID"
	check "health through the Front Door after the restart" sh -c \
		"curl -sf --cacert /etc/observex/tls/cluster-ca.crt https://localhost/node/health | grep -q '\"ready\"'"
else
	# The restart checks still count, so a node that never started cannot
	# pass with fewer checks.
	notok "killed NGINX (SIGKILL) is restarted (no NGINX to kill)"
	notok "the restarted NGINX is a new process (no NGINX to kill)"
	notok "health through the Front Door after the restart (no NGINX to kill)"
fi

if [ "$SYSTEMD" -eq 1 ]; then
	check "systemctl stop stops the node" systemctl stop observex-node.service
	check "service stopped without failure" sh -c "! systemctl is-failed --quiet observex-node.service"
	journalctl -u observex-node --no-pager -o cat >"$WORK/node.log" 2>/dev/null || true
else
	kill -TERM "$NODE_PID"
	if wait "$NODE_PID"; then ok "node stops cleanly on SIGTERM (exit 0)"; else notok "node stops cleanly on SIGTERM"; fi
fi
check "node logged a clean stop" grep -q 'node stopped cleanly' "$WORK/node.log"
check "no NGINX process left" sh -c "! pgrep -u observex nginx"

if "$PKG/uninstall.sh" --purge --yes >"$WORK/uninstall.log" 2>&1; then ok "uninstall.sh --purge --yes"; else notok "uninstall.sh --purge --yes"; fi
check "files removed" sh -c "[ ! -e /opt/observex ] && [ ! -e /etc/observex ] && [ ! -e /var/lib/observex ]"
check "user observex removed" sh -c "! getent passwd observex"
if [ "$FAILED" -gt 0 ]; then
	echo "# node log:"
	sed 's/^/# /' "$WORK/node.log" | tail -n 60
fi
rm -rf "$WORK"
finish
