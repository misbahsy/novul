#!/usr/bin/env bash
# Signed + notarized release: builds NoVul.app and the DMG with the Developer ID identity
# (APPLE_SIGNING_IDENTITY), then notarizes and staples the DMG.
# One-time setup (you type the app-specific password yourself):
#   xcrun notarytool store-credentials novul --apple-id <you@example.com> --team-id CSF58GSVC8
set -euo pipefail
cd "$(dirname "$0")/.."
PROFILE="${NOTARY_PROFILE:-novul}"
export APPLE_SIGNING_IDENTITY="${APPLE_SIGNING_IDENTITY:-Developer ID Application: Menlo Park Lab Corp. (CSF58GSVC8)}"

bun run --bun tauri build --bundles app,dmg

app=src-tauri/target/release/bundle/macos/NoVul.app
dmg=$(ls -t src-tauri/target/release/bundle/dmg/NoVul_*.dmg | head -1)

# Every executable must carry the Developer ID signature with hardened runtime.
for bin in "$app"/Contents/MacOS/*; do
  codesign --verify --strict --verbose=1 "$bin"
  info=$(codesign -dv "$bin" 2>&1)
  [[ $info == *"flags="*"(runtime)"* ]] || { echo "missing hardened runtime: $bin"; exit 1; }
done
codesign --verify --deep --strict "$app"
# A signature can verify and still get the process killed at launch (gitleaks needs an entitlement).
"$app/Contents/MacOS/gitleaks" version >/dev/null
"$app/Contents/MacOS/osv-scanner" --version >/dev/null
"$app/Contents/MacOS/novul" --version >/dev/null

xcrun notarytool submit "$dmg" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$dmg"
spctl --assess --type open --context context:primary-signature --verbose "$dmg"

# The README's download button points at releases/latest/download/NoVul-arm64.dmg, so every
# release carries the DMG under that fixed name.
version=$(jq -r .version src-tauri/tauri.conf.json)
stable=src-tauri/target/release/bundle/dmg/NoVul-arm64.dmg
cp "$dmg" "$stable"

echo "$PWD/$stable ($(du -h "$stable" | cut -f1))"
echo "Publish it with:"
echo "  gh release create v$version \"$stable\" --title \"NoVul $version\" --generate-notes"
