#!/bin/sh
# Removes an ObserveX Managed node installed by install.sh.
#
#   sudo ./uninstall.sh            stop and remove the service and binary;
#                                  keep configuration, TLS files and data
#   sudo ./uninstall.sh --purge --yes
#                                  also delete /etc/observex (including the
#                                  cluster CA key), /var/lib/observex and the
#                                  observex user and group
set -eu

PROG=uninstall.sh
PURGE=0
YES=0
die() { echo "$PROG: $*" >&2; exit 1; }
say() { echo "$PROG: $*"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--purge) PURGE=1; shift ;;
	--yes) YES=1; shift ;;
	-h | --help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) die "unknown option $1" ;;
	esac
done
[ "$(id -u)" -eq 0 ] || die "run as root"
if [ "$PURGE" -eq 1 ] && [ "$YES" -ne 1 ]; then
	die "--purge deletes the configuration, the cluster CA key and all data; add --yes to confirm"
fi

if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/observex-node.service ]; then
	systemctl disable --now observex-node.service >/dev/null 2>&1 || true
	rm -f /etc/systemd/system/observex-node.service
	systemctl daemon-reload
	say "stopped and removed observex-node.service"
fi
rm -f /opt/observex/bin/observex-node /opt/observex/bin/observex-node.previous
rmdir /opt/observex/bin /opt/observex 2>/dev/null || true
say "removed /opt/observex"

if [ "$PURGE" -eq 1 ]; then
	rm -rf /etc/observex /var/lib/observex /run/observex
	if getent passwd observex >/dev/null 2>&1; then userdel observex; fi
	if getent group observex >/dev/null 2>&1; then groupdel observex 2>/dev/null || true; fi
	say "purged configuration, TLS files, data and the observex user"
else
	say "kept /etc/observex and /var/lib/observex (use --purge --yes to delete them)"
fi
