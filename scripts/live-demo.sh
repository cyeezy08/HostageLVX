#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -x "./hostage" ]; then
  echo "[hostage] building demo binary..."
  go build -o hostage .
fi

if command -v asciinema >/dev/null 2>&1; then
  echo "[hostage] launching live TUI demo via asciinema..."
  asciinema rec --command './hostage -demo' demo.cast
else
  echo "[hostage] asciinema not installed; running the live TUI demo directly..."
  exec ./hostage -demo
fi
