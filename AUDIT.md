# Security and quality audit

Scope: the Rust workspace (`tlsfp-core`, `tlsfp-intel`, `tlsfp`), container and compose files, and the dependency tree. The React frontend was inspected for dependencies only. Method: build and test, `cargo fmt`, `cargo clippy -D warnings`, `cargo audit`, targeted code reading of network-facing code, and new property tests. This is a first-pass review, not a formal penetration test.

## Baseline

| Check | Result |
|---|---|
| `cargo build --workspace --all-targets` | passes (needs `libpcap-dev`) |
| `cargo test --workspace` | 204 tests passed before this audit, 239 after |
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
| F11 | Medium | A partial intelligence match (same sorted cipher list) to a benign entry produced a *benign* verdict, so a client sharing a known-good cipher list was vouched for. Measured on curl-impersonate profiles: unrelated clients, including a Tor-profile client, were labelled Google Chrome. | Fixed: a benign verdict requires an exact match; partial matches remain hints (verdict unknown). Tests added. |
| F12 | Medium | Scoring let near neighbours outvote an exact match; adding lookalike tool entries turned the exact, most common Chrome fingerprint suspicious. | Fixed: only the strongest match tier votes. Tests added. |
| F13 | Low | Intel labels naming an impersonation framework (`curl_cffi impersonating Chrome`) were classified as the browser they mention, which would have suppressed `ua_mismatch`. | Fixed in `signal.rs`; test added. |
| F14 | High | The bundled lab feed listed curl-impersonate browser profiles as tools. Compared with real Chromium headless-shell builds of the same era (dataset v0.4) they have the identical JA4, so the entries were a real browser stack's fingerprint and would have flagged genuine users. An earlier evaluation reported these profiles as flagged; that result was an artifact (the test set contained no real browsers) and is retracted. A later comparison with 25 full Chrome builds (v0.6) showed the profiles differ from the lab's full Chrome by configuration-dependent extensions (ECH), which is why the policy of not listing profiles stands. | Fixed: the generator never lists impersonation profiles and adds real builds as benign; `eval/fidelity.py` and CI guard it. |
| F15 | Medium | `fp_rotation` and `monoculture` raised alerts on shared addresses (NAT gateways, proxies) and on popular benign fingerprints, where many fingerprints or many addresses are normal. | Fixed: `--shared-network` skips both rules for declared networks; a fingerprint with an exact benign match is never a monoculture. Tests added. |
| F16 | Medium | `ua_mismatch` missed lying clients whose library labels were not recognised (Go, Node.js, Ruby, PHP, OpenSSL): 10 of 16 caught. | Fixed in the label classifier: 16 of 16 on the scenario dataset, no false alarms. |
| F17 | Info | No rule used the HTTP request itself to separate a browser from a tool left on its defaults. | Added `header_anomaly` (Sec-Fetch, Client Hints and h2c upgrade over cleartext to a non-loopback origin); 17 of 17 impersonation defaults caught, 0 false alarms on 10 real browsers; documented as trivially evaded. |
| F18 | Medium | A client reusing a source port while its old flow was still tracked had the new connection treated as a continuation of the old one, so its ClientHello was never fingerprinted. Found by a live-capture load test (82 to 94 percent of handshakes reported with no kernel drops); invisible on the lab captures, which never reuse a port. | Fixed: a SYN with a new initial sequence number starts a new flow; retransmitted SYNs do not. Counted as `flows_restarted`. Two regression tests; 100 percent of handshakes reported in four later runs. |
| F19 | Low | The kernel capture buffer (4 MiB) and frame channel (512) were small enough to drop 22 percent of frames under about 1,000 handshakes a second on a shared 4-core machine. The drops were counted and warned about, as designed. | Buffer 32 MiB, channel 4,096, `TLSFP_CAPTURE_BUFFER_MIB` override. |
| F9 | Low | `tlsfp pcap` reported `Broken pipe` with a backtrace when piped to `head`; the `live` path already handled it. | Fixed with a regression test (verified failing before the fix). |

## Not covered

Frontend source review, `pnpm audit`, `cargo deny` (licence and ban policy), cargo-fuzz coverage-guided fuzzing, live-capture privilege behaviour, and any evaluation of detection accuracy. Detection accuracy is the subject of the planned evaluation harness.
