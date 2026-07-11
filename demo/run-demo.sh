#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# ── helpers ────────────────────────────────────────────────────────────
cleanup() {
  rm -rf "${TMPDIR:-}"
}
TMPDIR="$(mktemp -d)"
trap cleanup EXIT

missing_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: $1 is required but not found" >&2
    return 1
  fi
}

check_ttyd() {
  local raw
  raw="$(ttyd --version 2>&1)" || { echo "error: ttyd not working" >&2; exit 1; }
  # extract version with portable sed — no GNU grep -P
  local ver
  ver="$(echo "$raw" | sed -n 's/.*ttyd version \([0-9]\{1,\}\.[0-9]\{1,\}\.[0-9]\{1,\}\).*/\1/p' | head -1)"
  if [[ -z "$ver" ]]; then
    echo "error: could not detect ttyd version from: $raw" >&2
    exit 1
  fi
  local major minor patch
  major="$(echo "$ver" | cut -d. -f1)"
  minor="$(echo "$ver" | cut -d. -f2)"
  patch="$(echo "$ver" | cut -d. -f3)"
  if [[ "$major" -lt 1 ]] || { [[ "$major" -eq 1 ]] && [[ "$minor" -lt 7 ]]; } || { [[ "$major" -eq 1 ]] && [[ "$minor" -eq 7 ]] && [[ "$patch" -lt 2 ]]; }; then
    echo "error: ttyd >= 1.7.2 required (found $ver)" >&2
    exit 1
  fi
}

# ── prerequisites ──────────────────────────────────────────────────────
# Verify font (fontconfig-based; macOS ships a different toolchain)
if command -v fc-list >/dev/null 2>&1; then
  if ! fc-list 2>/dev/null > "$TMPDIR/fonts"; then
    echo "error: fc-list command failed" >&2
    exit 1
  fi
  if ! grep -qi "DejaVu.*Mono" "$TMPDIR/fonts"; then
    echo "error: DejaVu Sans Mono font is required for GIF rendering" >&2
    echo "  Install: sudo apt-get install fonts-dejavu-core" >&2
    exit 1
  fi
fi

cargo build --release -p etherfence-cli --bin etherfence

missing_tool vhs || exit 127
missing_tool ttyd || exit 127
missing_tool ffmpeg || exit 127
check_ttyd

mkdir -p docs/assets

# ── Step 1: render high-quality MP4 directly from VHS ──────────────────
echo "Rendering demo MP4 (direct source)..."
PATH="$repo_root/target/release:$PATH" vhs \
  --output docs/assets/etherfence-demo.mp4 \
  demo/etherfence.tape

# ── Step 2: generate GIF from the high-quality MP4 source ──────────────
echo "Converting MP4 to GIF with 256-color palette..."
ffmpeg -y -i docs/assets/etherfence-demo.mp4 \
  -vf "fps=10,scale=1280:-1:flags=lanczos,split[v1][v2];[v1]palettegen=max_colors=256:stats_mode=diff[pal];[v2][pal]paletteuse=dither=sierra2_4a" \
  "$TMPDIR/etherfence-demo.gif" 2>/dev/null

mv "$TMPDIR/etherfence-demo.gif" docs/assets/etherfence-demo.gif

echo "Done:"
ls -lh docs/assets/etherfence-demo.gif docs/assets/etherfence-demo.mp4
