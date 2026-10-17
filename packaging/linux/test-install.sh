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
[ -n "$MODE" ] && [ -n "$TARBALL" ] || { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
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
mode_is() { [ "$(stat -c '%a' "$1")" = "$2" ]; }
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
else
	if "$PKG/install.sh" --no-systemd --node-id live-test --host localhost --host 127.0.0.1 >"$WORK/install.log" 2>&1; then
		ok "install.sh installs (no systemd on this machine)"
	else
		notok "install.sh installs (no systemd on this machine)"
		sed 's/^/# /' "$WORK/install.log"
	fi
	# What the unit's RuntimeDirectory= and User= would do.
	install -d -m 0750 -o observex -g observex /run/observex
	setpriv --reuid observex --regid observex --init-groups \
		--inh-caps +net_bind_service --ambient-caps +net_bind_service \
		env OBSERVEX_NODE_CONFIG=/etc/observex/node.json "$NODE" run >"$WORK/node.log" 2>&1 &
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
check "Front Door does not expose /metrics" sh -c \
	"[ \$(curl -s -o /dev/null -w '%{http_code}' --cacert /etc/observex/tls/cluster-ca.crt https://localhost/metrics) != 200 ]"
check "Agents listener (9443) refuses a request without a client certificate" sh -c \
	"code=\$(curl -s -o /dev/null -w '%{http_code}' --cacert /etc/observex/tls/cluster-ca.crt -X POST https://localhost:9443/v1/metrics); [ \"\$code\" = 403 ] || [ \"\$code\" = 496 ]"
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
