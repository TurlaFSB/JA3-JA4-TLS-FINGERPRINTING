# Security and quality audit

Scope: the Rust workspace (`tlsfp-core`, `tlsfp-intel`, `tlsfp`), container and compose files, and the dependency tree. The React frontend was inspected for dependencies only. Method: build and test, `cargo fmt`, `cargo clippy -D warnings`, `cargo audit`, targeted code reading of network-facing code, and new property tests. This is a first-pass review, not a formal penetration test.

## Baseline

| Check | Result |
|---|---|
| `cargo build --workspace --all-targets` | passes (needs `libpcap-dev`) |
| `cargo test --workspace` | 204 tests passed before this audit, 216 after |
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| `cargo audit` | 2 warnings before, 0 after (see F1) |

## Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| F1 | Low | `anyhow 1.0.102` flagged unsound (RUSTSEC-2026-0190, `Error::downcast_mut`); `spin 0.9.8` yanked. | Fixed: `cargo update` to `anyhow 1.0.104`, `spin 0.9.9`; all tests still pass. |
| F2 | Low | `deny.toml` and dependency checks existed but CI never ran any advisory check. | Fixed: `audit` job added to `ci.yml`. |
| F3 | Medium (docs) | Fuzzing was claimed for the parsers, but only the TLS hello parser, the reassembler and JA4X had property tests. QUIC header/open/frame walk/assembler, the JA4H request reader, SSLv2 hello, certificate list and the full pipeline had none. | Fixed: `crates/tlsfp-core/tests/robustness.rs` (11 properties, 2048 cases each). No panics or unbounded growth found. |
| F4 | Info | The HTTP API (`/stats`, `/alerts`, `/search`, `/export`, `/stream`) has no authentication. Default bind is `127.0.0.1:8080`, which is safe, but the compose files bind `0.0.0.0` inside the container and publish the nginx port on the host. | Open, by design. Do not expose beyond localhost without a reverse proxy providing authentication. Documented here. |
| F5 | Info | SQL built with `format!` in `matcher.rs` interpolates only compile-time constants; all values are bound parameters. | No action needed. |
| F6 | Info | Container images run as non-root (`USER tlsfp`, `USER nginx`); live capture drops to two capabilities. | No action needed. |
| F7 | Info | README performance claim (about 380k to 500k fingerprints/s) is from the upstream author and was not reproduced in this audit. | Open: re-measure with `cargo bench -p tlsfp-core` on the target hardware before citing. |
| F8 | Low | `install.sh` cloned the upstream repository, not this one. | Fixed: rewritten to build from the local checkout; tested with a temporary prefix. |
| F10 | Medium | CI could never pass on a current runner: `rustup toolchain install --component clippy rustfmt` is rejected by recent rustup (each component needs its own `--component`), failing every build, test and lint job at the install step. Found from the first run on GitHub. | Fixed in `ci.yml`; Rust 1.85 and stable verified locally. |
| F9 | Low | `tlsfp pcap` reported `Broken pipe` with a backtrace when piped to `head`; the `live` path already handled it. | Fixed with a regression test (verified failing before the fix). |

## Not covered

Frontend source review, `pnpm audit`, `cargo deny` (licence and ban policy), cargo-fuzz coverage-guided fuzzing, live-capture privilege behaviour, and any evaluation of detection accuracy. Detection accuracy is the subject of the planned evaluation harness.
