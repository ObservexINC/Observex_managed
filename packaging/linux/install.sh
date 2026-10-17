#!/bin/sh
# Installs an ObserveX Managed node from this tarball (development plan G01).
#
#   sudo ./install.sh [options]
#
# Options:
#   --node-id ID     node ID (default: the host name)
#   --host NAME      host name or IP address users and Agents use to reach
#                    this node; repeatable (default: host name and addresses)
#   --peer HOST      another cluster node; repeatable
#   --no-start       install and enable the service, but do not start it
#   --no-systemd     do not install the systemd unit (containers, tests)
#   --root DIR       install under DIR without creating users, changing
#                    owners or touching systemd (packaging tests only)
#   --plaintext      development only: no TLS, listeners on loopback
#   -h, --help       this help
#
# What it changes:
#   creates the system user and group "observex" (if missing)
#   /opt/observex/bin/observex-node   (the previous one is kept as .previous)
#   /etc/observex/node.json and /etc/observex/tls/  (only if missing)
#   /var/lib/observex
#   /etc/systemd/system/observex-node.service
# It never changes the firewall and never installs other packages. NGINX
# must already be installed.
set -eu

PROG=install.sh
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=""
NODE_ID=""
INIT_ARGS=""
START=1
SYSTEMD=1
PLAINTEXT=0
SERVICE_USER=observex
SERVICE_GROUP=observex

die() { echo "$PROG: $*" >&2; exit 1; }
say() { echo "$PROG: $*"; }

# Values reach the init command as separate arguments; each is checked
# first so nothing can be smuggled into the command line.
check_value() {
	case "$2" in
	'' | *[!A-Za-z0-9._:-]*) die "$1 value '$2' may contain only letters, digits, '.', '_', ':' and '-'" ;;
	esac
}

while [ $# -gt 0 ]; do
	case "$1" in
	--node-id) [ $# -ge 2 ] || die "--node-id needs a value"; check_value "$1" "$2"; NODE_ID=$2; shift 2 ;;
	--host) [ $# -ge 2 ] || die "--host needs a value"; check_value "$1" "$2"; INIT_ARGS="$INIT_ARGS -host $2"; shift 2 ;;
	--peer) [ $# -ge 2 ] || die "--peer needs a value"; check_value "$1" "$2"; INIT_ARGS="$INIT_ARGS -peer $2"; shift 2 ;;
	--no-start) START=0; shift ;;
	--no-systemd) SYSTEMD=0; START=0; shift ;;
	--root) [ $# -ge 2 ] || die "--root needs a directory"; ROOT=$2; SYSTEMD=0; START=0; shift 2 ;;
	--plaintext) PLAINTEXT=1; shift ;;
	-h | --help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) die "unknown option $1 (see --help)" ;;
	esac
done

[ "$(uname -s)" = Linux ] || die "ObserveX Managed nodes run on Linux"
[ -x "$HERE/bin/observex-node" ] || die "bin/observex-node is missing next to this script"
VERSION=$(cat "$HERE/VERSION" 2>/dev/null || echo unknown)

if [ -n "$ROOT" ]; then
	case "$ROOT" in /*) ;; *) die "--root must be an absolute path" ;; esac
	[ "$ROOT" != / ] || die "--root / is not a test root; run without --root"
else
	[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./install.sh)"
fi

# Prerequisites.
NGINX=""
for c in /usr/sbin/nginx /usr/local/sbin/nginx /usr/bin/nginx; do
	if [ -x "$c" ]; then NGINX=$c; break; fi
done
if [ -z "$NGINX" ]; then
	die "NGINX is not installed. Install it first, for example:
    Debian, Ubuntu:          apt-get install nginx-core   (or nginx)
    RHEL, Rocky, Alma, Fedora: dnf install nginx
    SUSE:                    zypper install nginx
then run this installer again."
fi
if [ "$SYSTEMD" -eq 1 ] && ! command -v systemctl >/dev/null 2>&1; then
	die "systemctl not found; use --no-systemd to install without the service"
fi
say "installing ObserveX Managed node $VERSION (NGINX: $("$NGINX" -v 2>&1 | sed 's/^nginx version: //'))"

BIN_DIR=$ROOT/opt/observex/bin
ETC_DIR=$ROOT/etc/observex
DATA_DIR=$ROOT/var/lib/observex
UNIT_DIR=$ROOT/etc/systemd/system

# User and group.
if [ -z "$ROOT" ]; then
	if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
		groupadd --system "$SERVICE_GROUP"
		say "created group $SERVICE_GROUP"
	fi
	if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
		NOLOGIN=/usr/sbin/nologin
		[ -x "$NOLOGIN" ] || NOLOGIN=/sbin/nologin
		useradd --system --gid "$SERVICE_GROUP" --home-dir /var/lib/observex --no-create-home \
			--shell "$NOLOGIN" --comment "ObserveX Managed node" "$SERVICE_USER"
		say "created user $SERVICE_USER"
	fi
fi

# Directories and files.
install -d -m 0755 "$BIN_DIR"
install -d -m 0750 "$ETC_DIR" "$DATA_DIR"
if [ -z "$ROOT" ]; then
	chown root:"$SERVICE_GROUP" "$ETC_DIR"
	chown "$SERVICE_USER":"$SERVICE_GROUP" "$DATA_DIR"
fi
if [ -f "$BIN_DIR/observex-node" ]; then
	cp -p "$BIN_DIR/observex-node" "$BIN_DIR/observex-node.previous"
	say "kept the previous binary as $BIN_DIR/observex-node.previous"
fi
install -m 0755 "$HERE/bin/observex-node" "$BIN_DIR/observex-node.new"
mv -f "$BIN_DIR/observex-node.new" "$BIN_DIR/observex-node"

# First configuration and TLS files; existing ones are kept.
set -- -config "$ETC_DIR/node.json" -tls-dir "$ETC_DIR/tls"
[ -n "$NODE_ID" ] && set -- "$@" -node-id "$NODE_ID"
[ -z "$ROOT" ] && set -- "$@" -group "$SERVICE_GROUP"
[ "$PLAINTEXT" -eq 1 ] && set -- "$@" -plaintext
# shellcheck disable=SC2086 # INIT_ARGS holds checked words only
"$BIN_DIR/observex-node" init "$@" $INIT_ARGS
if [ -n "$ROOT" ]; then
	say "installed under $ROOT (no users, owners or services changed)"
	exit 0
fi
# The configuration may name a different NGINX; tell the user if the one
# found here differs from the configured default.
if [ "$NGINX" != /usr/sbin/nginx ]; then
	say "note: NGINX is at $NGINX; set front_door.nginx in $ETC_DIR/node.json if it is not /usr/sbin/nginx"
fi

if [ "$SYSTEMD" -eq 1 ]; then
	install -d -m 0755 "$UNIT_DIR"
	install -m 0644 "$HERE/systemd/observex-node.service" "$UNIT_DIR/observex-node.service"
	systemctl daemon-reload
	systemctl enable observex-node.service >/dev/null
	say "installed and enabled observex-node.service"
	if systemctl is-active --quiet nginx.service 2>/dev/null; then
		say "note: the distribution's nginx.service is running. ObserveX runs its own NGINX process;"
		say "      if nginx.service uses port 443 or 9443, stop and disable it: systemctl disable --now nginx"
	fi
fi

if [ "$START" -eq 1 ]; then
	runuser -u "$SERVICE_USER" -- env OBSERVEX_NODE_CONFIG="$ETC_DIR/node.json" "$BIN_DIR/observex-node" check \
		|| die "the pre-start check failed; fix the problem above, then: systemctl start observex-node"
	systemctl restart observex-node.service
	i=0
	while [ $i -lt 60 ]; do
		if OBSERVEX_NODE_CONFIG="$ETC_DIR/node.json" "$BIN_DIR/observex-node" health >/dev/null 2>&1; then
			say "the node is ready"
			break
		fi
		i=$((i + 1))
		sleep 1
	done
	[ $i -lt 60 ] || die "the node did not become ready within 60 s; see: journalctl -u observex-node"
fi

say "firewall report (read-only; nothing was changed):"
OBSERVEX_NODE_CONFIG="$ETC_DIR/node.json" "$BIN_DIR/observex-node" firewall -skip-peers $([ "$START" -eq 1 ] && echo -running) || true
say "done"
