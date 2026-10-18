#!/bin/sh
# Builds the node tarball (development plan G01):
#
#   dist/observex-managed-node-<version>-linux-<arch>.tar.gz
#   dist/observex-managed-node-<version>-linux-<arch>.tar.gz.sha256
#
# The tarball is reproducible: file times come from the last commit, owners
# are root, files are sorted, and gzip stores no name or time.
#
#   VERSION=0.1.0 GOARCH=amd64 scripts/package.sh
set -eu

cd "$(dirname "$0")/.."
GO=${GO:-go}
GOARCH=${GOARCH:-amd64}
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
case "$VERSION" in '' | *[!A-Za-z0-9._+-]*) echo "package.sh: bad VERSION '$VERSION'" >&2; exit 1 ;; esac
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}
export SOURCE_DATE_EPOCH

NAME=observex-managed-node-$VERSION-linux-$GOARCH
OUT=dist
STAGE=$OUT/stage/$NAME
rm -rf "$OUT/stage"
mkdir -p "$STAGE/bin" "$STAGE/systemd"

CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH "$GO" build -trimpath -buildvcs=false \
	-ldflags "-s -w -X main.version=$VERSION" -o "$STAGE/bin/observex-node" ./cmd/observex-node

install -m 0755 packaging/linux/install.sh packaging/linux/uninstall.sh "$STAGE/"
install -m 0644 packaging/linux/observex-node.service "$STAGE/systemd/"
install -m 0644 packaging/linux/README.md "$STAGE/README.md"
printf '%s\n' "$VERSION" >"$STAGE/VERSION"
chmod 0644 "$STAGE/VERSION"
# The list is written next to the stage, then moved in, so the pipeline
# never reads the file it writes.
(cd "$STAGE" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | sed 's|^\./||' | xargs sha256sum) >"$OUT/stage/SHA256SUMS.tmp"
mv "$OUT/stage/SHA256SUMS.tmp" "$STAGE/SHA256SUMS"
chmod 0644 "$STAGE/SHA256SUMS"

TAR=$OUT/$NAME.tar.gz
(cd "$OUT/stage" && LC_ALL=C tar --sort=name --owner=0 --group=0 --numeric-owner \
	--mtime="@$SOURCE_DATE_EPOCH" --format=gnu -cf - "$NAME") | gzip -n -9 >"$TAR"
(cd "$OUT" && sha256sum "$NAME.tar.gz" >"$NAME.tar.gz.sha256")
rm -rf "$OUT/stage"
echo "$TAR"
cat "$TAR.sha256"
