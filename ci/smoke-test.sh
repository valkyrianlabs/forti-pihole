#!/usr/bin/env bash
# Smoke test of a built or installed `forti-pihole`, offline and without touching the caller's
# config:
#
#   ci/smoke-test.sh [PATH-TO-FORTI-VLAN-MAC]     (default: forti-pihole on PATH)
#
# Checks `forti-pihole --version` (including the engine revision it was built from) and
# `forti-pihole --help` (every subcommand is listed), that a bad option exits 2 (the ecosystem's
# usage status), and that nothing was written to the forti home (or anywhere in HOME). POSIX tools
# only: it also runs in a stock ubuntu:24.04 with nothing but the .deb installed.
set -euo pipefail

bin="${1:-forti-pihole}"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
export HOME="$scratch/home" FORTI_HOME="$scratch/forti"
mkdir -p "$HOME"

fail() {
  echo "smoke-test: $*" >&2
  exit 1
}

version="$("$bin" --version)"
echo "$version"
case "$version" in
  "forti-pihole "[0-9]*" (engine forti-cli "[0-9a-f]*", forti-api "[0-9]*")") ;;
  *) fail "unexpected --version output" ;;
esac

"$bin" --help > "$scratch/help" 2> "$scratch/stderr" || { cat "$scratch/stderr" >&2; fail "--help exited non-zero"; }
for command in report plan apply assign confirm status history; do
  grep -qw -- "$command" "$scratch/help" || { cat "$scratch/help" >&2; fail "--help does not list $command"; }
done

# Usage errors exit with 2, not a crash.
status=0
"$bin" --no-such-option > /dev/null 2>&1 || status=$?
[ "$status" -eq 2 ] || fail "an unknown option exited $status, expected 2"

# forti-piholed: next to forti-pihole when installed, under daemon/ in a build tree, else on PATH.
case "$bin" in
  */*) daemon="$(dirname "$bin")/forti-piholed"
       [ -x "$daemon" ] || daemon="$(dirname "$bin")/daemon/forti-piholed" ;;
  *) daemon="forti-piholed" ;;
esac
daemon_version="$("$daemon" --version)"
echo "$daemon_version"
case "$daemon_version" in
  "forti-piholed "[0-9]*" (engine forti-cli "[0-9a-f]*", forti-api "[0-9]*")") ;;
  *) fail "unexpected forti-piholed --version output" ;;
esac
"$daemon" --help > "$scratch/daemon-help" 2> "$scratch/stderr" || { cat "$scratch/stderr" >&2; fail "forti-piholed --help exited non-zero"; }
grep -q -- "/v1/fortigate/events" "$scratch/daemon-help" || fail "forti-piholed --help does not describe the endpoint"
status=0
"$daemon" --no-such-option > /dev/null 2>&1 || status=$?
[ "$status" -eq 2 ] || fail "forti-piholed: an unknown option exited $status, expected 2"

if [ -n "$(find "$FORTI_HOME" "$HOME" -type f 2>/dev/null)" ]; then
  fail "--version / --help wrote files"
fi
echo "smoke-test: ok"
