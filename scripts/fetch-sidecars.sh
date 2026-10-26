#!/usr/bin/env bash
# Re-downloads osv-scanner and gitleaks at the pinned versions and verifies them against sidecars/SHA256SUMS.
set -euo pipefail
cd "$(dirname "$0")/.."

OSV=2.7.0
GL=8.30.1
dl=sidecars/download
out=src-tauri/binaries
mkdir -p "$dl" "$out"

expected() { grep -E "  $1\$" sidecars/SHA256SUMS | cut -d' ' -f1; }
verify() { [ "$(shasum -a 256 "$1" | cut -d' ' -f1)" = "$(expected "$2")" ] || { echo "SHA-256 mismatch: $2" >&2; exit 1; }; }

curl -fsSL -o "$dl/osv-scanner_darwin_arm64" "https://github.com/google/osv-scanner/releases/download/v$OSV/osv-scanner_darwin_arm64"
verify "$dl/osv-scanner_darwin_arm64" osv-scanner_darwin_arm64
install -m 755 "$dl/osv-scanner_darwin_arm64" "$out/osv-scanner-aarch64-apple-darwin"

tgz=gitleaks_${GL}_darwin_arm64.tar.gz
curl -fsSL -o "$dl/$tgz" "https://github.com/gitleaks/gitleaks/releases/download/v$GL/$tgz"
verify "$dl/$tgz" "$tgz"
x=$(mktemp -d)
tar -xzf "$dl/$tgz" -C "$x" gitleaks
verify "$x/gitleaks" gitleaks
install -m 755 "$x/gitleaks" "$out/gitleaks-aarch64-apple-darwin"
rm -rf "$x"

echo "ok: osv-scanner $OSV, gitleaks $GL"
