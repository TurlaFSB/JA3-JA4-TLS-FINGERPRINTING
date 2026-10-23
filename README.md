<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

```json
████████╗██╗     ███████╗███████╗██████╗
╚══██╔══╝██║     ██╔════╝██╔════╝██╔══██╗
   ██║   ██║     ███████╗█████╗  ██████╔╝
   ██║   ██║     ╚════██║██╔══╝  ██╔═══╝
   ██║   ███████╗███████║██║     ██║
   ╚═╝   ╚══════╝╚══════╝╚═╝     ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2334-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/ja3-ja4-tls-fingerprinting)
[![Rust](https://img.shields.io/badge/Rust-edition%202024-CE412B?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![JA4+](https://img.shields.io/badge/JA4%2B-JA3%20%C2%B7%20JA4%20%C2%B7%20JA4H%20%C2%B7%20JA4X%20%C2%B7%20JA4T-4B7BEC?style=flat)](https://github.com/FoxIO-LLC/ja4)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> [!NOTE]
> **Attribution.** This repository is a fork-style derivative of the open-source project
> [`ja3-ja4-tls-fingerprinting`](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/ja3-ja4-tls-fingerprinting)
> by CarterPerez-dev (AngelaMos), part of
> [Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects).
> It is imported without the upstream commit history and remains licensed under
> **AGPL-3.0** (see `LICENSE`); third-party fingerprint licences are in `NOTICE.md`.
> Everything described below under "What Works Today" is upstream work. My additions
> (labeled dataset lab, evaluation harness, ML impersonation detection, drift detection,
> robustness experiments) are tracked in `CHANGES.md`.

---

> A passive TLS fingerprinting sensor in Rust. Point it at a capture file or a live interface and it computes the JA3, JA4, JA4S, JA4H, JA4X, and JA4T fingerprints of every handshake, matches them against a local intelligence database, and flags the things a fingerprint alone cannot hide: a TLS stack that disagrees with its own User-Agent, a brand-new fingerprint, a client that rotates its identity to evade a blocklist. It reads TCP and the TLS hidden inside QUIC initial packets, never sends a byte, and carries half a million fingerprints a second.

## Why fingerprint TLS

When a client opens a TLS connection, the very first message it sends, the ClientHello, is a detailed self-description: which TLS versions it supports, which cipher suites in which order, which extensions, which elliptic curves. A browser, a Go program, a Python script, and a piece of malware each assemble that message differently, because each is built on a different TLS library configured a different way. The ClientHello travels in the clear, before any encryption is negotiated, so a passive observer who never decrypts anything can still read it.

A fingerprint is a hash of those choices. The same software produces the same fingerprint on every connection, so a fingerprint that is on a blocklist today catches the same malware family tomorrow even if its IP, its domain, and its certificate all changed. That is the idea behind JA3, published by Salesforce in 2017, and JA4, its 2023 successor from FoxIO that fixed the one weakness that eventually killed JA3 for browser traffic: when Chrome started shuffling its extension order on every connection, JA3, which hashes extensions in wire order, produced a fresh hash every time. JA4 sorts first, so the shuffle changes nothing.

This project builds the whole sensor around that idea, in a language where a parser bug is a memory-safety bug. The fingerprinting core forbids `unsafe`, the capture path is bounded so an adversarial packet cannot exhaust memory, and every fingerprint is checked byte for byte against the reference implementations.

## What Works Today

This is not a stub. The tool fingerprints real captures, decrypts real QUIC, matches against real public threat feeds, and raises real alerts, and every capability below is exercised by a known-answer test against a published vector, an integration test against a vendored capture, and a run of the actual `tlsfp` binary.

**Fingerprints**
- **JA3 / JA3S** (MD5 of the ClientHello / ServerHello field list), kept because public malware feeds still speak JA3 and because watching it collapse next to JA4 is the clearest way to see why JA4 exists
- **JA4 / JA4S** (the FoxIO TLS client and server fingerprint, sorted cipher and extension lists), the headline fingerprint, stable under extension shuffling
- **JA4H** the HTTP client fingerprint, from a cleartext request's method, version, header order, cookies, and accept-language
- **JA4X** the X.509 fingerprint, from the issuer, subject, and extension object identifiers of a certificate, which clusters certificates minted by one toolchain
- **JA4T / JA4TS** the TCP-stack fingerprint, from the SYN's window size, options, MSS, and window scale, which catches a tool wearing a browser's TLS clothing while its OS speaks with a different TCP accent
- GREASE values stripped from every list, so the deliberate noise a modern client inserts never changes its fingerprint

**Capture**
- Reads `pcap` and `pcapng` files, and captures live from an interface through `libpcap` with the raw-socket capabilities dropped to exactly the two the kernel needs
- A reassembly layer rebuilds each direction of each TCP conversation, surviving reordering, retransmission, and overlap, so a ClientHello split across segments still fingerprints
- Bounded by construction: a flow cap, an idle timeout, and per-stream byte ceilings keep an adversarial capture from turning the flow table into a memory bomb

**QUIC**
- Decrypts QUIC Initial packets to read the ClientHello inside, deriving the client initial keys from the packet's own Destination Connection ID per RFC 9001 (QUIC v1) and RFC 9369 (QUIC v2), with no server-side secret
- Reassembles CRYPTO frames across packets, so a QUIC ClientHello spread over several initials still yields a `q`-transport JA4

**Intelligence**
- A bundled SQLite database seeded from three vendored feeds with no network call: abuse.ch SSLBL, the Salesforce `osx-nix` JA3 list, and a small curated C2 set (**271 fingerprints**)
- An optional install-time pull of ja4db.com, validated record by record on the way in
- Exact lookups plus JA4 fuzzy matching on the capability-and-cipher prefix, scored into a verdict with a threat score and a confidence

**Detection**
- Six rules that run as a capture streams: `known_bad` (a feed hit), `ua_mismatch` (the headline: a JA4 that disagrees with its own User-Agent), `os_mismatch` (a JA4T that disagrees with the OS the User-Agent claims), `first_seen`, `fp_rotation`, and `monoculture`
- A forensic `--report` mode that reads a whole capture and prints one ranked summary, folding in intelligence and detection automatically whenever the database is present
- A web dashboard that streams events and alerts over Server-Sent Events, fed by a replayed capture, a live interface, or an external sensor tailing the same database

See [`learn/CONFORMANCE.md`](learn/CONFORMANCE.md) for the exact published vector each fingerprint is pinned to, and every deliberate scope boundary.

## Quick Start

```bash
# needs Rust (stable) and libpcap-dev
cargo build --release
export PATH="$PWD/target/release:$PATH"
tlsfp intel seed
```

(`install.sh` is inherited from the upstream project and still points at the upstream repository; use the build above for this fork.) Then point it at a capture:

```bash
# Fingerprint every handshake in a capture, one line each
tlsfp pcap traffic.pcapng

# Seed the threat feeds, then match and run the detection rules
tlsfp intel seed
tlsfp pcap traffic.pcapng --report

# Watch an interface in real time, matching and detecting as it goes
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tlsfp)"
tlsfp live eth0 --intel --detect
```

A single fingerprint line looks like this, a Chrome handshake to a Google host:

```
1675707151.805 192.168.1.168:50112 -> 142.251.16.94:443 client_hello ja4=t13d1516h2_8daaf6152771_e5627efa2ab1 ja3=1c258ebef8eee2dfa3df6d8d07285af9 sni=clientservices.googleapis.com alpn=h2
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see every recipe. `just bench` runs the throughput benchmarks; `just dev-up` brings up the dockerized dashboard with hot reload.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Learn

This project ships a full teaching track. Read it in order, or jump to what you need.

| Doc | What it covers |
|-----|----------------|
| [`learn/00-OVERVIEW.md`](learn/00-OVERVIEW.md) | What TLS fingerprinting is, why it works, and a 10-minute tour |
| [`learn/01-CONCEPTS.md`](learn/01-CONCEPTS.md) | The ClientHello, JA3 vs JA4, GREASE, evasion, QUIC, passive capture, grounded in real intrusions |
| [`learn/02-ARCHITECTURE.md`](learn/02-ARCHITECTURE.md) | The three-crate split, the capture pipeline, the intelligence store, the threat model |
| [`learn/03-IMPLEMENTATION.md`](learn/03-IMPLEMENTATION.md) | A code walkthrough from a raw frame to a scored alert, and the reassembly and bounding patterns |
| [`learn/ALGORITHMS.md`](learn/ALGORITHMS.md) | How each fingerprint is computed byte by byte, and how a QUIC initial is decrypted |
| [`learn/CONFORMANCE.md`](learn/CONFORMANCE.md) | The published vector each fingerprint is pinned to, and every deliberate scope boundary |
| [`learn/04-CHALLENGES.md`](learn/04-CHALLENGES.md) | Extension ideas from beginner to expert |

## Architecture

Three crates, in a strict dependency line. The engine knows nothing about databases or networks; the intelligence store knows nothing about capture; the binary wires them together.

```
   pcap / pcapng file        live interface (libpcap)       QUIC initial
            │                         │                          │
            └─────────────┬───────────┴──────────────────────────┘
                          │  raw link-layer frames
                          ▼
   ┌────────────────────────────────────────────────────┐
   │  tlsfp-core   the engine, no I/O, forbids unsafe    │
   │  decode → flow reassembly → TLS/HTTP/QUIC → hash    │
   │  ja3 · ja4 · ja4h · ja4x · ja4t · parse · quic      │
   └───────────────────────┬────────────────────────────┘
                           │  FingerprintEvent
   ┌───────────────────────┴────────────────────────────┐
   │  tlsfp-intel   the judgement, a bundled SQLite DB   │
   │  match (exact + JA4 fuzzy) → score → detection rules │
   │  matcher · seed · import · detect · signal · schema  │
   └───────────────────────┬────────────────────────────┘
                           │  MatchReport + Alert
   ┌───────────────────────┴────────────────────────────┐
   │  tlsfp   the binary: CLI + web dashboard            │
   │  pcap · live · serve (axum + SSE) · intel · report   │
   └────────────────────────────────────────────────────┘
```

**Design decisions:** the engine forbids `unsafe` outright, so a malformed packet can never be more than a parse error. The store is deliberately synchronous, because a lookup is one indexed query and a capture is a plain loop; the async runtime lives only in the web server, where concurrent readers actually need it. JA3 uses MD5 because that is what the original definition and every public JA3 feed use, and reproducing those feed hashes is the whole point of keeping it. The QUIC decryption uses no server secret because the client initial keys are derived from a Connection ID that travels in the clear.

## Build and Test

```bash
cargo build --release            # the shipped binary → target/release/tlsfp
cargo test --workspace           # 204 unit + integration tests, 1 ignored
cargo bench -p tlsfp-core        # criterion throughput benchmarks
just clippy                      # clippy::pedantic, warnings as errors
just fmt-check                   # rustfmt
```

Every fingerprint is pinned to a published vector. The JA3 tests reproduce the original Salesforce blog vectors through MD5; the JA4 tests reproduce the FoxIO cipher, extension, and TCP section vectors; the QUIC tests derive the client initial keys and match RFC 9001 Appendix A (v1) and RFC 9369 Appendix A (v2) byte for byte. The reassembly tests rebuild a ClientHello from out-of-order and overlapping segments. The JA4X parser has a property-test fuzz harness because it walks attacker-controlled certificate DER.

The benchmarks replay vendored captures frame by frame through the whole pipeline. On a modern laptop the pipeline sustains roughly **380,000 to 500,000 fingerprints per second**, comfortably past the project target of 10,000.

## Run in Docker

No Rust toolchain on the host? The dashboard runs entirely in containers.

```bash
just up                          # production stack: built dashboard + backend
just dev-up                      # development stack: vite hot reload
```

The production image is a multi-stage build that compiles the release binary in a Rust builder and ships only the binary plus the built dashboard assets behind nginx. The development stack bind-mounts the frontend and runs `pnpm install` on startup, so an added package is always present after a restart.

## Project Structure

```
ja3-ja4-tls-fingerprinting/
├── Cargo.toml                    # the 3-crate virtual workspace
├── crates/
│   ├── tlsfp-core/               # the engine: no I/O, forbids unsafe
│   │   ├── src/
│   │   │   ├── parse/            # TLS record, ClientHello, ServerHello, certificate readers
│   │   │   ├── pipeline/         # decode → flow reassembly → TLS/HTTP → event
│   │   │   ├── ja3.rs            # JA3 / JA3S (the dead-but-still-fed MD5 fingerprint)
│   │   │   ├── ja4.rs            # JA4 / JA4S (the headline sorted fingerprint)
│   │   │   ├── ja4h.rs           # JA4H (the HTTP request fingerprint)
│   │   │   ├── ja4x.rs           # JA4X (the X.509 certificate fingerprint)
│   │   │   ├── ja4t.rs           # JA4T / JA4TS (the TCP-stack fingerprint)
│   │   │   ├── quic.rs           # QUIC initial decryption (RFC 9001 + RFC 9369)
│   │   │   ├── grease.rs         # the GREASE value table and the strip
│   │   │   ├── der.rs            # the minimal DER reader JA4X needs
│   │   │   └── registry.rs       # version codes and extension constants
│   │   ├── benches/fingerprint.rs# criterion throughput benchmarks
│   │   └── tests/                # KAT + integration: ja3, ja4, ja4x, parse, reassembly
│   ├── tlsfp-intel/              # the judgement: a bundled SQLite store
│   │   ├── src/
│   │   │   ├── schema.rs         # the migrations
│   │   │   ├── seed.rs           # the three vendored feeds, compiled in
│   │   │   ├── import.rs         # the validated ja4db.com importer
│   │   │   ├── matcher.rs        # exact + JA4 fuzzy lookup, scored into a verdict
│   │   │   ├── detect.rs         # the six detection rules
│   │   │   ├── signal.rs         # the User-Agent / OS heuristics the rules read
│   │   │   └── model.rs          # FpKind, Category, Verdict, the report types
│   │   └── seeds/                # the vendored CSV feeds
│   └── tlsfp/                    # the binary
│       └── src/
│           ├── cli.rs            # the clap command tree
│           ├── live.rs          # the libpcap capture thread and the async bridge
│           ├── report.rs        # the forensic --report builder
│           └── serve.rs          # the axum dashboard + SSE stream
├── frontend/                     # the anti-design dashboard (Vite + React 19)
├── testdata/pcap/                # vendored captures, the integration fixtures
├── install.sh                    # the one-shot curl-able installer
└── justfile                      # every recipe
```

## License

[AGPL 3.0](LICENSE). The vendored threat feeds under `crates/tlsfp-intel/seeds/` keep their original licenses, recorded per feed in [`NOTICE.md`](NOTICE.md) and in the `intel_source` table.
