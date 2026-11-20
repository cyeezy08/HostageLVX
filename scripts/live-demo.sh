#!/usr/bin/env bash
set -euo pipefail

# Reproducible CLI capture. Does not query DNS or scan any internet host.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT
go build -o "$TEMP_DIR/hostage" .

echo "[hostage] offline CLI demo: release/version and built-in fingerprint catalogue"
"$TEMP_DIR/hostage" -V

if [ -t 1 ] && command -v asciinema >/dev/null 2>&1; then
  echo "[hostage] recording real CLI output to demo.cast"
  asciinema rec --overwrite --command "$TEMP_DIR/hostage -fingerprints" demo.cast
else
  echo "[hostage] asciinema unavailable; printing real CLI output"
  "$TEMP_DIR/hostage" -fingerprints
fi
