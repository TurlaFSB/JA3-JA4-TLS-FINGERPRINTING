#!/usr/bin/env bash
# fetch_chrome.sh: download real Chrome builds from Google's Chrome for Testing.
#
# Chrome for Testing publishes full Chrome builds (not the stripped headless
# shell) at stable URLs. Each version is downloaded, unpacked and left at
# <out>/chrome-<version>/chrome, ready for the lab to drive in new headless
# mode, which uses the same network stack as the desktop browser.
#
#   dataset/lab/fetch_chrome.sh OUT_DIR VERSION [VERSION...]
#   dataset/lab/fetch_chrome.sh /opt/chrome 131.0.6778.85 138.0.7204.49
#
# VERSION is the full four-part version (the bucket has no listing, so exact
# versions are required; https://googlechromelabs.github.io/chrome-for-testing/
# lists them). Needs curl and python3. Browsers are about 150 MB each and are
# never committed; only the captures made with them are.
set -euo pipefail

out="${1:?usage: fetch_chrome.sh OUT_DIR VERSION [VERSION...]}"
shift
[ $# -gt 0 ] || { echo "give at least one version" >&2; exit 2; }
mkdir -p "$out"
base="https://storage.googleapis.com/chrome-for-testing-public"

for version in "$@"; do
    target="$out/chrome-$version"
    if [ -x "$target/chrome" ]; then
        echo "have $version"
        continue
    fi
    echo "fetching $version"
    tmp="$(mktemp -d)"
    curl -fsSL "$base/$version/linux64/chrome-linux64.zip" -o "$tmp/chrome.zip"
    python3 - "$tmp/chrome.zip" "$tmp" <<'PY'
import os, stat, sys, zipfile
archive, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(archive) as z:
    for info in z.infolist():
        path = z.extract(info, dest)
        mode = info.external_attr >> 16
        if mode:
            os.chmod(path, mode)
PY
    rm -rf "$target"
    mv "$tmp/chrome-linux64" "$target"
    rm -rf "$tmp"
done
