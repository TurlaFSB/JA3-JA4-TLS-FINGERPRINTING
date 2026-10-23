#!/usr/bin/env bash
# fetch_chromium.sh: download real Chromium headless-shell builds from npm.
#
# The @sparticuz/chromium package bundles a genuine Chromium build per release
# (92 to 153 at the time of writing). Each version is installed, its binary is
# decompressed, and the result is copied to <out>/chromium-<version>, so the lab
# can capture real browser ClientHellos for many versions and compare them with
# impersonation profiles of the same version.
#
# Layout: <out>/chromium-<version>/chromium plus the SwiftShader GPU libraries the
# build needs next to it (without them, releases from 116 on hang in GPU init).
#
#   dataset/lab/fetch_chromium.sh OUT_DIR VERSION [VERSION...]
#   dataset/lab/fetch_chromium.sh /opt/chromes 107.0.0 131.0.1 133.0.0
#
# Needs node, npm and network access to the npm registry. Binaries are about
# 180 MB each and are never committed; only the captures made with them are.
set -euo pipefail

out="${1:?usage: fetch_chromium.sh OUT_DIR VERSION [VERSION...]}"
shift
[ $# -gt 0 ] || { echo "give at least one version" >&2; exit 2; }
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for version in "$@"; do
    target="$out/chromium-$version/chromium"
    if [ -x "$target" ]; then
        echo "have $version"
        continue
    fi
    echo "fetching $version"
    dir="$work/v$version"
    mkdir -p "$dir"
    (
        cd "$dir"
        npm init -y >/dev/null 2>&1
        npm install --no-audit --no-fund "@sparticuz/chromium@$version" >/dev/null 2>&1
        # The package ships the browser as one brotli-compressed file; decompress it
        # directly, which works for every release (older ones only self-extract on
        # AWS Lambda).
        node -e "
          const fs = require('fs'), zlib = require('zlib');
          const src = 'node_modules/@sparticuz/chromium/bin/chromium.br';
          fs.writeFileSync('chromium', zlib.brotliDecompressSync(fs.readFileSync(src)), { mode: 0o755 });"
    )
    mkdir -p "$out/chromium-$version"
    cp "$dir/chromium" "$target"
    swift="$dir/node_modules/@sparticuz/chromium/bin/swiftshader.tar.br"
    if [ -f "$swift" ]; then
        node -e "process.stdout.write(require('zlib').brotliDecompressSync(require('fs').readFileSync('$swift')))" \
            | tar -xf - -C "$out/chromium-$version"
    fi
    # older builds refuse to run as root without --no-sandbox, even for --version
    (timeout 10 "$target" --no-sandbox --version 2>/dev/null || true) | head -n 1 | sed "s/^/  /"
    rm -rf "$dir"
done
