#!/usr/bin/env bash
# Rebuilds the DMG background (PNG 1x/2x -> HiDPI TIFF), then builds the DMG.
# Finder needs Automation permission for the window layout; do not set CI=true.
set -euo pipefail
cd "$(dirname "$0")/.."

bun run --bun scripts/render-dmg-bg.ts
(cd design/dmg && tiffutil -cathidpicheck bg.png bg@2x.png -out background.tiff)
bun run --bun tauri build --bundles dmg

dmg=$(ls -t src-tauri/target/release/bundle/dmg/NoVul_*.dmg | head -1)
echo "$PWD/$dmg"
du -h "$dmg" | cut -f1
