#!/bin/sh
# engines-tarball.sh: run the real engines for the store adapter tests from
# their release tarballs, on one Linux machine or in WSL2, loopback only.
#
#   test/rig/engines-tarball.sh fetch DIR   download and verify the tarballs
#   test/rig/engines-tarball.sh start DIR   unpack, configure and start both
#   test/rig/engines-tarball.sh env DIR     print the variables the tests read
#   test/rig/engines-tarball.sh stop DIR    stop both engines
#
# Every download is checked against the release's published checksum and
# its OpenPGP signature, using the project's own key file; nothing runs
# unless both match. Cassandra runs with PasswordAuthenticator; OpenSearch
# runs with its security plugin, HTTPS and the plugin's demo certificates.
# The OpenSearch admin password is generated here and kept in DIR, readable
# by its owner only; it is never printed. Cassandra keeps its default
# superuser (cassandra), which only loopback can reach; its password is
# written to a file in DIR too, so no password appears in the output.
#
# Needs: curl, gpg, tar, sha256sum, sha512sum, Java 17 (for Cassandra), and
# a user other than root to run OpenSearch (set OPENSEARCH_USER when this
# runs as root).

set -eu

CASSANDRA_VERSION=5.0.9
OPENSEARCH_VERSION=3.9.0
CASSANDRA_URL=https://archive.apache.org/dist/cassandra
OPENSEARCH_URL=https://artifacts.opensearch.org/releases/bundle/opensearch
OPENSEARCH_KEY_URL=https://artifacts.opensearch.org/publickeys/opensearch-release.pgp

die() {
	echo "engines-tarball.sh: $*" >&2
	exit 1
}

[ $# -eq 2 ] || die "usage: $0 fetch|start|env|stop DIR"
cmd=$1
dir=$2
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
ctar=apache-cassandra-$CASSANDRA_VERSION-bin.tar.gz
otar=opensearch-$OPENSEARCH_VERSION-linux-x64.tar.gz
chome=$dir/apache-cassandra-$CASSANDRA_VERSION
ohome=$dir/opensearch-$OPENSEARCH_VERSION

fetch() {
	cd "$dir"
	curl -fsS --retry 3 -C - -O "$CASSANDRA_URL/$CASSANDRA_VERSION/$ctar"
	curl -fsS --retry 3 -O "$CASSANDRA_URL/$CASSANDRA_VERSION/$ctar.sha256" -O "$CASSANDRA_URL/$CASSANDRA_VERSION/$ctar.asc"
	curl -fsS --retry 3 -o cassandra-KEYS "$CASSANDRA_URL/KEYS"
	curl -fsS --retry 3 -C - -O "$OPENSEARCH_URL/$OPENSEARCH_VERSION/$otar"
	curl -fsS --retry 3 -O "$OPENSEARCH_URL/$OPENSEARCH_VERSION/$otar.sha512" -O "$OPENSEARCH_URL/$OPENSEARCH_VERSION/$otar.sig"
	curl -fsS --retry 3 -o opensearch-release.pgp "$OPENSEARCH_KEY_URL"

	want=$(tr -d ' \n' <"$ctar.sha256" | cut -c1-64)
	got=$(sha256sum "$ctar" | cut -d' ' -f1)
	[ "$want" = "$got" ] || die "$ctar: SHA-256 $got, the release says $want"
	want=$(cut -d' ' -f1 <"$otar.sha512")
	got=$(sha512sum "$otar" | cut -d' ' -f1)
	[ "$want" = "$got" ] || die "$otar: SHA-512 does not match the release's"

	GNUPGHOME=$dir/gnupg
	export GNUPGHOME
	rm -rf "$GNUPGHOME"
	mkdir -m 700 "$GNUPGHOME"
	gpg --batch --quiet --import cassandra-KEYS 2>/dev/null || true
	gpg --batch --quiet --import opensearch-release.pgp 2>/dev/null || true
	gpg --batch --verify "$ctar.asc" "$ctar" 2>"$dir/cassandra-signature.txt" ||
		die "$ctar: signature check failed (see $dir/cassandra-signature.txt)"
	gpg --batch --verify "$otar.sig" "$otar" 2>"$dir/opensearch-signature.txt" ||
		die "$otar: signature check failed (see $dir/opensearch-signature.txt)"
	echo "verified: $ctar (SHA-256, signature by a key in Cassandra's KEYS)"
	echo "verified: $otar (SHA-512, OpenSearch release key)"
	grep -h "Good signature\|Primary key fingerprint" "$dir/cassandra-signature.txt" "$dir/opensearch-signature.txt"
}

java17() {
	for j in "${JAVA17_HOME:-}" /usr/lib/jvm/java-17-openjdk-amd64 /usr/lib/jvm/java-17-openjdk /usr/lib/jvm/temurin-17-jdk-amd64; do
		if [ -n "$j" ] && [ -x "$j/bin/java" ]; then
			echo "$j"
			return
		fi
	done
	die "Java 17 not found: install openjdk-17-jre-headless or set JAVA17_HOME"
}

password() {
	# 24 characters with every class OpenSearch's demo setup requires.
	umask 077
	if [ ! -s "$dir/opensearch-admin-password" ]; then
		p=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)
		printf '%saZ9!' "$p" >"$dir/opensearch-admin-password"
	fi
	[ -s "$dir/cassandra-password" ] || printf '%s' cassandra >"$dir/cassandra-password"
}

start() {
	if [ ! -f "$dir/$ctar" ] || [ ! -f "$dir/$otar" ]; then
		die "run '$0 fetch $dir' first"
	fi
	osuser=${OPENSEARCH_USER:-$(id -un)}
	[ "$osuser" != root ] || die "OpenSearch refuses to run as root: set OPENSEARCH_USER to another user"
	password

	if [ ! -d "$chome" ]; then
		tar -xzf "$dir/$ctar" -C "$dir"
		sed -i 's/^authenticator: AllowAllAuthenticator/authenticator: PasswordAuthenticator/' "$chome/conf/cassandra.yaml"
	fi
	jh=$(java17)
	(
		cd "$chome"
		unset JAVA_TOOL_OPTIONS
		JAVA_HOME=$jh PATH=$jh/bin:$PATH MAX_HEAP_SIZE=1G HEAP_NEWSIZE=256M \
			nohup bin/cassandra -f -R -p "$dir/cassandra.pid" >"$dir/cassandra.log" 2>&1 &
	)

	if [ ! -d "$ohome" ]; then
		tar -xzf "$dir/$otar" -C "$dir"
		cat >>"$ohome/config/opensearch.yml" <<'EOF'

# ObserveX test rig: one loopback node.
cluster.name: observex-test
node.name: os-1
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
node.store.allow_mmap: false
cluster.routing.allocation.disk.watermark.low: 2gb
cluster.routing.allocation.disk.watermark.high: 1gb
cluster.routing.allocation.disk.watermark.flood_stage: 500mb
EOF
		if [ "$(id -u)" = 0 ]; then
			chown -R "$osuser" "$ohome" "$dir/opensearch-admin-password"
		fi
		run_as "$osuser" "cd '$ohome' && unset JAVA_TOOL_OPTIONS JAVA_HOME OPENSEARCH_JAVA_HOME && OPENSEARCH_INITIAL_ADMIN_PASSWORD=\$(cat '$dir/opensearch-admin-password') bash plugins/opensearch-security/tools/install_demo_configuration.sh -y -i -s" >"$dir/opensearch-demo-setup.log" 2>&1
	fi
	# OpenSearch runs on the JDK its tarball bundles.
	run_as "$osuser" "cd '$ohome' && unset JAVA_TOOL_OPTIONS JAVA_HOME OPENSEARCH_JAVA_HOME && OPENSEARCH_JAVA_OPTS='-Xms1g -Xmx1g' nohup bin/opensearch -d -p '$ohome/opensearch.pid' >'$ohome/opensearch.out' 2>&1"

	echo "waiting for Cassandra on 127.0.0.1:9042 and OpenSearch on https://127.0.0.1:9200"
	n=0
	until grep -q "Startup complete" "$dir/cassandra.log" 2>/dev/null; do
		n=$((n + 1))
		[ $n -lt 180 ] || die "Cassandra did not start; see $dir/cassandra.log"
		sleep 2
	done
	n=0
	until curl -fsS --cacert "$ohome/config/root-ca.pem" -u "admin:$(cat "$dir/opensearch-admin-password")" -o /dev/null https://127.0.0.1:9200/_cluster/health 2>/dev/null; do
		n=$((n + 1))
		[ $n -lt 180 ] || die "OpenSearch did not start; see $ohome/logs/observex-test.log"
		sleep 2
	done
	echo "both engines are up"
}

run_as() {
	if [ "$(id -un)" = "$1" ]; then
		sh -c "$2"
	else
		su "$1" -s /bin/sh -c "$2"
	fi
}

envvars() {
	cat <<EOF
export OBSERVEX_TEST_CASSANDRA=127.0.0.1:9042
export OBSERVEX_TEST_CASSANDRA_USERNAME=cassandra
export OBSERVEX_TEST_CASSANDRA_PASSWORD="\$(cat $dir/cassandra-password)"
export OBSERVEX_TEST_OPENSEARCH=https://127.0.0.1:9200
export OBSERVEX_TEST_OPENSEARCH_CA=$ohome/config/root-ca.pem
export OBSERVEX_TEST_OPENSEARCH_USERNAME=admin
export OBSERVEX_TEST_OPENSEARCH_PASSWORD="\$(cat $dir/opensearch-admin-password)"
EOF
}

stop() {
	for pidfile in "$dir/cassandra.pid" "$ohome/opensearch.pid"; do
		if [ -f "$pidfile" ]; then
			kill "$(cat "$pidfile")" 2>/dev/null || true
			rm -f "$pidfile" 2>/dev/null || true
		fi
	done
	echo "stopped"
}

case $cmd in
fetch) fetch ;;
start) start ;;
env) envvars ;;
stop) stop ;;
*) die "unknown command $cmd" ;;
esac
