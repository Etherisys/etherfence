#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo build --release -p etherfence-cli --bin etherfence

if ! command -v vhs >/dev/null 2>&1; then
  echo "error: Charmbracelet VHS is required to render docs/assets/etherfence-demo.gif" >&2
  echo "install: https://github.com/charmbracelet/vhs" >&2
  exit 127
fi

mkdir -p docs/assets
PATH="$repo_root/target/release:$PATH" CI=1 vhs demo/etherfence.tape
