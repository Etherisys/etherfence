#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Verify required fonts
if ! fc-list 2>/dev/null > /tmp/etherfence-fontcheck; then
  echo "error: fc-list command failed" >&2
  exit 1
fi
if ! grep -qi "DejaVu.*Mono" /tmp/etherfence-fontcheck; then
  echo "error: DejaVu Sans Mono font is required for GIF rendering" >&2
  echo "  Install: sudo apt-get install fonts-dejavu-core" >&2
  exit 1
fi
rm -f /tmp/etherfence-fontcheck

cargo build --release -p etherfence-cli --bin etherfence

missing_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: $1 is required but not found" >&2
    return 1
  fi
}

missing_tool vhs || exit 127
missing_tool ttyd || exit 127
missing_tool ffmpeg || exit 127

# Check ttyd version
ttyd_ver="$(ttyd --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)"
if [[ -z "$ttyd_ver" ]]; then
  echo "error: could not detect ttyd version" >&2
  exit 1
fi
ttyd_major="$(echo "$ttyd_ver" | cut -d. -f1)"
ttyd_minor="$(echo "$ttyd_ver" | cut -d. -f2)"
if [[ "$ttyd_major" -lt 1 ]] || { [[ "$ttyd_major" -eq 1 ]] && [[ "$ttyd_minor" -lt 7 ]]; }; then
  echo "error: ttyd >= 1.7.2 required (found $ttyd_ver)" >&2
  exit 1
fi

mkdir -p docs/assets

# Step 1: render high-quality GIF directly via VHS
echo "Rendering demo GIF..."
PATH="$repo_root/target/release:$PATH" CI=1 vhs demo/etherfence.tape

# Step 2: generate optimized GIF with ffmpeg palette pass
echo "Optimizing GIF with ffmpeg palette pass..."
ffmpeg -y -i docs/assets/etherfence-demo.gif \
  -vf "fps=10,scale=1280:-1:flags=lanczos,split[v1][v2];[v1]palettegen=max_colors=128:stats_mode=diff[pal];[v2][pal]paletteuse=dither=bayer:bayer_scale=3" \
  /tmp/etherfence-demo-opt.gif 2>/dev/null

# Replace with optimized version
mv /tmp/etherfence-demo-opt.gif docs/assets/etherfence-demo.gif

# Step 3: generate MP4 version for HD viewing
echo "Generating MP4..."
ffmpeg -y -i docs/assets/etherfence-demo.gif \
  -vf "fps=10,scale=1280:-1:flags=lanczos,pad=1280:760:(ow-iw)/2:(oh-ih)/2" \
  -c:v libx264 -preset fast -crf 23 -pix_fmt yuv420p -movflags +faststart \
  docs/assets/etherfence-demo.mp4 2>/dev/null

echo "Done:"
ls -lh docs/assets/etherfence-demo.gif docs/assets/etherfence-demo.mp4
