#!/bin/sh
# Scans the whole git history for secrets with gitleaks and .gitleaks.toml.
# Fails when gitleaks finds a leak, and also when it scanned no commits: a
# missing or shallow history is not a clean result.
set -eu

cd "$(dirname "$0")/.."
log=$(mktemp)
trap 'rm -f "$log"' EXIT

commits=$(git rev-list --count HEAD)
if gitleaks detect --source . --config .gitleaks.toml --no-banner --redact >"$log" 2>&1; then
	status=0
else
	status=$?
fi
cat "$log"
[ "$status" -eq 0 ] || exit "$status"

scanned=$(grep -o '[0-9][0-9]* commits scanned' "$log" | head -n 1 | cut -d' ' -f1)
if [ -z "$scanned" ] || [ "$scanned" -eq 0 ]; then
	echo "secrets-scan.sh: gitleaks scanned no commits (the repository has $commits); fetch the full history" >&2
	exit 1
fi
echo "secrets-scan.sh: no leaks in $scanned scanned commits (git rev-list counts $commits)"
