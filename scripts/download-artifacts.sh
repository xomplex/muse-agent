#!/usr/bin/env bash
# Idempotent downloader for the OFFICIAL zkVerify Agent Games Groth16 artifacts.
#
# These are the PLATFORM's published artifacts (see ../../SPEC.md and
# https://agentgames.zkverify.io/api/circuit-info) — NOT ours, and NOT built
# by any local ceremony. This script only fetches them and verifies sizes.
#
# Usage: bash scripts/download-artifacts.sh
# Safe to re-run: files that already exist with the expected size are skipped.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${CIRCUIT_DIR:-$REPO_ROOT/circuits/artifacts}"
BASE="https://agentgames.zkverify.io"

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# name  url  expected-bytes
download() {
  local name="$1" url="$2" expected="$3"
  if [ -f "$name" ] && [ "$(stat -c %s "$name")" = "$expected" ]; then
    echo "SKIP  $name (already present, $expected bytes)"
    return 0
  fi
  echo "GET   $url"
  curl -fSL --max-time 600 -o "$name.tmp" "$url"
  local got
  got="$(stat -c %s "$name.tmp")"
  if [ "$got" != "$expected" ]; then
    echo "ERROR $name: expected $expected bytes, got $got — keeping old file (if any), aborting" >&2
    rm -f "$name.tmp"
    exit 1
  fi
  mv "$name.tmp" "$name"
  echo "OK    $name ($got bytes)"
}

download "gatekeeper.wasm"        "$BASE/circuits/gatekeeper.wasm"         1755820
download "gatekeeper_final.zkey"  "$BASE/circuits/gatekeeper_final.zkey"   309750
download "vfy-policy.wasm"        "$BASE/circuits/vfy-policy.wasm"         2991212
download "vfy-policy_final.zkey"  "$BASE/circuits/vfy-policy_final.zkey"   810586

echo "GET   $BASE/api/circuit-info"
curl -fSL --max-time 60 -o circuit-info.json.tmp "$BASE/api/circuit-info"
mv circuit-info.json.tmp circuit-info.json
echo "OK    circuit-info.json"

sha256sum gatekeeper.wasm gatekeeper_final.zkey vfy-policy.wasm vfy-policy_final.zkey circuit-info.json > CHECKSUMS.txt
echo "OK    CHECKSUMS.txt written"
ls -la
