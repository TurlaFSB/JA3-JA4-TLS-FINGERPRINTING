# JA3/JA4 TLS Fingerprinting

[![CI](https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING/actions/workflows/ci.yml/badge.svg)](https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-edition%202024-CE412B?logo=rust&logoColor=white)](https://www.rust-lang.org)

A passive TLS fingerprinting sensor and research platform. It reads a packet capture or a live interface, computes JA3, JA4, JA4S, JA4H, JA4X and JA4T fingerprints for every handshake (including TLS inside QUIC), matches them against a local intelligence database, and flags clients whose fingerprint disagrees with what they claim to be. It never sends a packet.

The project is a final-year research effort. It builds on an existing open-source sensor (see [Credits](#credits-and-licensing)) and extends it with a labeled dataset, a measured evaluation of the detection rules, and cross-layer impersonation and drift detection. See [Roadmap](#roadmap) for what is done and what is planned.

## Why fingerprint TLS

A client's first message, the ClientHello, is sent in the clear and describes its TLS stack: versions, cipher suites, extensions, curves. Browsers, scripting libraries, and malware assemble it differently, so a hash of those choices identifies software without decrypting anything, and survives changes of IP, domain, and certificate. JA3 (2017) hashes the fields in wire order, which broke once Chrome began shuffling extensions. JA4 (2023) sorts them first and is stable under that shuffle.

## Capabilities

**Fingerprints**
- JA3 / JA3S, kept because public malware feeds are expressed in JA3
- JA4 / JA4S, the primary fingerprint, with raw and hashed forms
- JA4H (cleartext HTTP/1.x request), JA4X (X.509, TLS 1.2 and earlier), JA4T / JA4TS (TCP SYN / SYN-ACK)
- GREASE values stripped from every list

**Capture**
- pcap and pcapng files; live capture through libpcap
- TCP reassembly tolerant of reordering, retransmission and overlap
- QUIC v1 and v2 Initial decryption and CRYPTO-frame reassembly
- Bounded memory: flow cap, idle timeout, per-stream byte limits

**Intelligence and detection**
- Bundled SQLite database (271 fingerprints) from abuse.ch SSLBL, the Salesforce JA3 list, and a curated C2 set; optional ja4db.com import
- Exact and JA4 prefix matching, scored into a verdict
- Six rules: `known_bad`, `ua_mismatch`, `os_mismatch`, `first_seen`, `fp_rotation`, `monoculture`

**Interfaces**
- CLI (`pcap`, `live`, `intel`, `serve`, `--report`) with JSON output
- Web dashboard streaming events and alerts over Server-Sent Events

## Quick start

Requirements: Rust (stable) and `libpcap-dev`.

```bash
cargo build --release
export PATH="$PWD/target/release:$PATH"

tlsfp intel seed                              # load the bundled feeds
tlsfp pcap testdata/pcap/tls-handshake.pcapng # one line per handshake
tlsfp pcap testdata/pcap/tls-handshake.pcapng --report

# live capture needs raw-socket capabilities
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tlsfp)"
tlsfp live eth0 --intel --detect

tlsfp serve 127.0.0.1:8080                     # dashboard API (default db: ~/.local/share/tlsfp/intel.db)
```

Docker: `docker compose --profile backend up` runs the dashboard with a replayed demo capture.

## Architecture

Three crates in a strict dependency line:

| Crate | Role |
|---|---|
| `tlsfp-core` | Engine. Decoding, reassembly, TLS/HTTP/QUIC parsing, fingerprint hashing. No I/O, forbids `unsafe`. |
| `tlsfp-intel` | Judgement. SQLite store, matcher, detection rules. |
| `tlsfp` | Binary. CLI, live capture, forensic report, axum web server. |

`frontend/` is the React dashboard. `testdata/pcap/` holds the vendored captures used by the tests. Design notes are in [`learn/02-ARCHITECTURE.md`](learn/02-ARCHITECTURE.md); algorithm details and the published vector each fingerprint is pinned to are in [`learn/ALGORITHMS.md`](learn/ALGORITHMS.md) and [`learn/CONFORMANCE.md`](learn/CONFORMANCE.md).

## Testing and quality

```bash
cargo test --workspace                      # 215 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo audit
```

Fingerprints are checked against published known-answer vectors (Salesforce JA3, FoxIO JA4, RFC 9001 / 9369 for QUIC). Property tests feed arbitrary and mutated bytes to the TLS, QUIC, HTTP, SSLv2, certificate and pipeline entry points and assert they never panic. The security audit and its findings are in [`AUDIT.md`](AUDIT.md).

## Roadmap

| Status | Item |
|---|---|
| Done | Import, build, test, security audit, dependency fixes, CI audit job, fuzz coverage of remaining parsers |
| Planned | Labeled handshake dataset lab (curl, curl-impersonate, requests, Go, headless browsers) with ground truth |
| Planned | Evaluation harness: precision / recall / false-positive rate of the existing rules |
| Planned | Cross-layer impersonation classifier compared against the rule baseline |
| Planned | Per-host fingerprint drift detection |
| Planned | Robustness study: Chrome extension shuffling, uTLS / curl-impersonate, Encrypted Client Hello |

Progress is tracked in [`CHANGES.md`](CHANGES.md).

## Credits and licensing

This project is derived from [ja3-ja4-tls-fingerprinting](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/ja3-ja4-tls-fingerprinting) by CarterPerez-dev (AngelaMos), AGPL-3.0, upstream commit `bf9ac5d`. The sensor core, fingerprint implementations, intelligence store and dashboard originate there. Changes in this repository are listed in [`CHANGES.md`](CHANGES.md); full provenance is in [`NOTICE.md`](NOTICE.md).

- This project is licensed under **AGPL-3.0** ([`LICENSE`](LICENSE)). Anyone who runs a modified version as a network service must offer its source.
- JA3 (Salesforce, BSD-3-Clause) and JA4 (FoxIO, BSD-3-Clause) are free to implement. JA4S, JA4H, JA4X and JA4T are under the FoxIO License 1.1 (non-commercial, academic use permitted, patent pending). See [`NOTICE.md`](NOTICE.md).
- Threat feeds: abuse.ch SSLBL, Salesforce `osx-nix`, ja4db.com (see their respective terms).
