#!/usr/bin/env bash
# install.sh
#
# Build and install tlsfp from this checkout and seed the intelligence database.
# Run it from a clone; it does not download or execute anything from the network
# except Rust crates via cargo.
#
#   git clone https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING
#   cd JA3-JA4-TLS-FINGERPRINTING && ./install.sh [--prefix DIR] [--live]

set -euo pipefail

PREFIX=""
DO_LIVE=0

usage() {
    cat >&2 <<'USAGE'
Usage: ./install.sh [--prefix DIR] [--live]

  --prefix DIR  install the binary to DIR/bin (default: cargo's ~/.cargo/bin)
  --live        grant cap_net_raw,cap_net_admin to the binary (uses sudo setcap)
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --live) DO_LIVE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

cd "$(dirname "$0")"
[ -f Cargo.toml ] && [ -d crates/tlsfp ] || { echo "run install.sh from a clone of the repository" >&2; exit 1; }

command -v cargo >/dev/null 2>&1 || { echo "cargo not found: install Rust from https://rustup.rs" >&2; exit 1; }
if command -v pkg-config >/dev/null 2>&1 && ! pkg-config --exists libpcap 2>/dev/null; then
    echo "libpcap development files not found (Debian/Ubuntu: apt-get install libpcap-dev)" >&2
    exit 1
fi

root_args=()
[ -n "$PREFIX" ] && root_args=(--root "$PREFIX")

echo "building and installing tlsfp" >&2
cargo install --path crates/tlsfp --locked "${root_args[@]}"

if [ -n "$PREFIX" ]; then BIN="$PREFIX/bin/tlsfp"; else BIN="${CARGO_HOME:-$HOME/.cargo}/bin/tlsfp"; fi
[ -x "$BIN" ] || { echo "installed binary not found at $BIN" >&2; exit 1; }

echo "seeding the intelligence database" >&2
"$BIN" intel seed

# The dashboard: built once and put where `tlsfp serve` looks for it, so
# serving needs no flags. Skipped, with a notice, when pnpm is not available.
WEB_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/tlsfp/web"
if command -v pnpm >/dev/null 2>&1; then
    echo "building the dashboard" >&2
    (cd frontend && pnpm install --frozen-lockfile && pnpm build) >&2
    rm -rf "$WEB_DIR" && mkdir -p "$WEB_DIR" && cp -r frontend/dist/. "$WEB_DIR"/
else
    echo "pnpm not found: the dashboard was not built (install pnpm and re-run, or use the Docker stack)" >&2
fi

if [ "$DO_LIVE" -eq 1 ]; then
    echo "granting live-capture capabilities (sudo)" >&2
    sudo setcap cap_net_raw,cap_net_admin=eip "$BIN"
fi

echo "installed: $BIN" >&2
"$BIN" --version
