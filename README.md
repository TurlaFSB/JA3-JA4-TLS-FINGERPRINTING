# tlsfp

Passive TLS fingerprinting for JA3 and the JA4+ family. Reads packet captures or a live interface, fingerprints every TLS handshake (including TLS carried in QUIC), matches fingerprints against threat intelligence, and raises alerts when a client's fingerprint contradicts what it claims to be.

[![CI](https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING/actions/workflows/ci.yml/badge.svg)](https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

`tlsfp` never transmits. It reads the cleartext part of the handshake, computes hashes of the client's and server's TLS choices, and compares them with what it knows. No decryption, no keys, no active probing.

## Contents

- [Capabilities](#capabilities)
- [Install](#install)
- [Usage](#usage)
- [Fingerprints](#fingerprints)
- [Detection](#detection)
- [Intelligence](#intelligence)
- [Output](#output)
- [Architecture](#architecture)
- [Performance](#performance)
- [Validation](#validation)
- [Deployment and security](#deployment-and-security)
- [Limitations](#limitations)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [Contributing, security reports, citation](#contributing-security-reports-citation)
- [License and acknowledgments](#license-and-acknowledgments)

## Capabilities

- **Fingerprints:** JA3, JA3S, JA4, JA4S, JA4H, JA4X, JA4T, JA4TS. GREASE values stripped; raw and hashed forms available.
- **Transports:** TCP with full stream reassembly (reordering, retransmission, overlap); QUIC v1 and v2 Initial packet decryption and CRYPTO-frame reassembly.
- **Inputs:** pcap and pcapng files; live capture through libpcap with only `CAP_NET_RAW` and `CAP_NET_ADMIN`.
- **Matching:** exact lookup and JA4 prefix matching against a local SQLite database, scored into a verdict with confidence.
- **Detection:** seven rules over fingerprint history and cleartext HTTP (known-bad, User-Agent mismatch, OS mismatch, header anomaly, first-seen, rotation, monoculture).
- **Interfaces:** CLI with text and JSON output, forensic report mode, HTTP API and web dashboard with a Server-Sent Events stream.
- **Resource bounds:** capped flow table, idle timeouts, and per-stream byte limits. The engine crate forbids `unsafe`.

## Install

Requirements: Rust 1.85 or newer and libpcap development files (`apt-get install libpcap-dev`, `brew install libpcap`).

```bash
git clone https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING.git
cd JA3-JA4-TLS-FINGERPRINTING
./install.sh                 # builds, installs to ~/.cargo/bin, seeds the intelligence database
./install.sh --live          # additionally grants cap_net_raw,cap_net_admin for live capture
```

To build without installing: `cargo build --release` (binary at `target/release/tlsfp`), then `tlsfp intel seed`.

Container: `docker compose --profile backend up` serves the dashboard (host port 11790) with a replayed demo capture. See `compose.yml`.

## Usage

```bash
tlsfp pcap capture.pcapng                    # one line per handshake
tlsfp pcap capture.pcapng --json             # one JSON object per event
tlsfp pcap capture.pcapng --intel --detect   # match and run detection rules
tlsfp pcap capture.pcapng --report           # ranked forensic summary

tlsfp live eth0 --intel --detect             # live capture
tlsfp live eth0 --filter "tcp port 443"      # narrow the kernel BPF filter

tlsfp intel seed                             # load bundled feeds
tlsfp intel import ja4db.json                # import a ja4db.com export (validated per record)
tlsfp intel lookup ja4 t13d1516h2_8daaf6152771_e5627efa2ab1
tlsfp intel alerts                           # recent alerts

tlsfp serve 127.0.0.1:8080                   # API and dashboard, tails the database
tlsfp serve --replay capture.pcapng --loop   # dashboard fed from a replayed capture
tlsfp serve --live eth0                      # dashboard fed from a live interface
tlsfp serve --location "DC-2 rack 14"        # label shown in the dashboard header (or TLSFP_SENSOR_LOCATION)
tlsfp pcap x.pcap --detect --shared-network 10.0.0.0/8   # NAT or proxy addresses (or TLSFP_SHARED_NETWORKS)
```

Live capture needs raw-socket capabilities. Grant them to the binary instead of running as root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tlsfp)"
```

The default database is `~/.local/share/tlsfp/intel.db`; override with `--db`.

## Fingerprints

| Fingerprint | Computed from | Notes |
|---|---|---|
| JA3 / JA3S | ClientHello / ServerHello fields in wire order, MD5 | Unstable for clients that randomize extension order. Kept because public malware feeds use it. |
| JA4 | ClientHello: transport, version, SNI, ALPN, sorted cipher and extension lists, SHA-256 truncated | Stable under extension shuffling. Primary fingerprint. |
| JA4S | ServerHello | Extensions in wire order. |
| JA4H | Cleartext HTTP/1.x request: method, version, header order, cookies, language | HTTP/2 and HTTPS requests are not visible to a passive observer. |
| JA4X | X.509 certificate issuer, subject and extension OIDs | Visible only where the certificate is in the clear (TLS 1.2 and earlier). |
| JA4T / JA4TS | TCP SYN / SYN-ACK: window size, options, MSS, window scale | Identifies the OS network stack beneath the TLS client. |

Anatomy of a JA4 value:

```
t13d1516h2_8daaf6152771_e5627efa2ab1
│││ │ │  │  │            └─ SHA-256 (first 12 hex) of sorted extensions + signature algorithms
│││ │ │  │  └────────────── SHA-256 (first 12 hex) of sorted cipher suites
│││ │ │  └───────────────── first ALPN value (h2)
│││ │ └──────────────────── extension count (16)
│││ └────────────────────── cipher count (15)
││└──────────────────────── SNI present (d = domain, i = IP / absent)
│└───────────────────────── TLS version (13 = 1.3)
└────────────────────────── transport (t = TCP, q = QUIC)
```

The exact published vector each fingerprint is tested against, and every deliberate scope boundary, is in [`learn/CONFORMANCE.md`](learn/CONFORMANCE.md).

## Detection

Rules read fingerprint history stored in the database, so they behave identically on a capture replayed at once and on a live link, and state survives restarts.

| Rule | Fires when |
|---|---|
| `known_bad` | A fingerprint matches malicious or suspicious intelligence. Raised once per source address, so a beacon is one alert, not one per flow. |
| `ua_mismatch` | A cleartext request presents a browser User-Agent while the same client's TLS fingerprint belongs to a script or tool. |
| `os_mismatch` | The OS implied by the User-Agent disagrees with the OS implied by the client's TCP SYN fingerprint (JA4T). |
| `first_seen` | The fingerprint has never been recorded before. Informational. |
| `fp_rotation` | One address presents more than 5 distinct fingerprints within the window (default 1 hour). |
| `monoculture` | One fingerprint appears from more than 10 distinct addresses within the window. Never raised for a fingerprint with an exact benign match. |
| `header_anomaly` | A cleartext request claiming a browser carries headers browsers never send to that origin: `Sec-Fetch-*`, `Sec-CH-*` Client Hints, or an `Upgrade: h2c` / `HTTP2-Settings` handshake. Skips loopback origins. Catches impersonation tools left on their defaults; trivially evaded. |

Thresholds and the window are configurable in `DetectConfig`. Defaults suit a quiet link; busy sensors should raise them. Rotation and monoculture are skipped for addresses declared with `--shared-network` (a NAT gateway, proxy or jump host).

## Intelligence

| Source | Records | Category | Licence |
|---|---|---|---|
| abuse.ch SSLBL | 97 | malware, C2 | CC0-1.0 |
| Salesforce `osx-nix` JA3 list | 157 | benign applications | BSD-3-Clause |
| Curated set | 21 | C2, tools, field-observed Firefox 158 | project |
| Lab-derived clients (`tlsfp lab`) | 34 | benign libraries and real Chromium builds | AGPL-3.0-only |
| ja4db.com (optional import) | variable | mixed | see ja4db.com terms |

Feeds are vendored and compiled into the binary, so seeding needs no network. Benign and malicious sources are both loaded on purpose: some hashes appear in both, and the matcher scores the disagreement.

The `tlsfp lab` feed is generated from the project's own labeled captures of real client builds (curl, Python, Go, Java, Ruby, PHP and Chromium 107 to 143); see [`dataset/README.md`](dataset/README.md). Verdict rules: a *benign* verdict needs an exact match, a partial match (same cipher list) is only a similarity hint, and only the strongest match tier votes.

## Output

Text:

```
1675707151.805 192.168.1.168:50112 -> 142.251.16.94:443 client_hello ja4=t13d1516h2_8daaf6152771_e5627efa2ab1 ja3=1c258ebef8eee2dfa3df6d8d07285af9 sni=clientservices.googleapis.com alpn=h2
    intel ja4=benign score=0.00 confidence=0.80 Google Chrome (tlsfp curated)
```

JSON (`--json`), one object per line:

```json
{"ts_nanos":1675707151805776000,"src":"192.168.1.168:50112","dst":"142.251.16.94:443","kind":"client_hello","ja3":"1c258ebef8eee2dfa3df6d8d07285af9","ja4":{"hash":"t13d1516h2_8daaf6152771_e5627efa2ab1","raw":"t13d1516h2_002f,0035,..."},"sni":"clientservices.googleapis.com","alpn":"h2"}
```

Forensic report (`--report`) summarizes a whole capture: frame and flow counts, fingerprints by kind, top client JA4 values, top server names, and per-endpoint fingerprints, verdicts and alerts.

## Dashboard

`tlsfp serve` serves a web dashboard and a JSON API from one process. The dashboard shows a live stream of fingerprinted handshakes with intelligence verdicts and alerts, a throughput trace, rule and category distributions, and a searchable, exportable view of the intelligence catalogue.

- **Opens populated:** the server keeps the last 500 events and sends them in one piece on connect, so a new page shows what has already happened; new events then stream in. A replayed capture is loaded at full speed on its first pass.
- **Profiles:** the live window grouped by client fingerprint or by destination. Each fingerprint expands to its decoded JA4, connections over time, JA3 variants, destinations and exact intelligence matches, and can be sent to the stream filter. Tick two fingerprints to compare them side by side: decoded fields, and the cipher suites, extensions and signature algorithms present in only one. Both tables export to CSV.
- **Alerts page:** every alert with severity and rule filters, search, a plain explanation of each rule and what to verify before acting, and export.
- **Themes:** dark and light, remembered per browser. `/` focuses the stream filter.
- **Live stream:** filter by event type (client, server, certificate, HTTP, TCP) or free text (IP, SNI, fingerprint); pause and resume; click any row for the full detail: every fingerprint in raw and hashed form, a field-by-field JA4 breakdown, matching intelligence and any alerts, with copy buttons.
- **Header:** backend reachability, the active feed (live interface, replayed capture, or database tail), uptime, and the operator-set `--location` label. Nothing in it is estimated from the network.
- **API:** `/api/stats`, `/api/alerts`, `/api/search`, `/api/export?format=json|csv`, `/api/meta` (sensor state, no filesystem paths), `/api/health`, and `/api/stream` (Server-Sent Events).

Build the frontend once with `cd frontend && pnpm install && pnpm build`; `tlsfp serve` serves `frontend/dist` by default (`--web` to change). The Docker setup builds it for you.

## Architecture

```
   pcap / pcapng          live interface (libpcap)          QUIC Initial
          └──────────────────────┬──────────────────────────────┘
                                 ▼  link-layer frames
   ┌──────────────────────────────────────────────────────────────┐
   │ tlsfp-core    decode → TCP reassembly → TLS / HTTP / QUIC     │
   │               → JA3 · JA4 · JA4H · JA4X · JA4T                │
   │               no I/O, no async, forbids unsafe                │
   └─────────────────────────────┬────────────────────────────────┘
                                 ▼  FingerprintEvent
   ┌──────────────────────────────────────────────────────────────┐
   │ tlsfp-intel   SQLite store · exact + JA4 prefix matching      │
   │               → scored verdict → detection rules → alerts     │
   └─────────────────────────────┬────────────────────────────────┘
                                 ▼  MatchReport, Alert
   ┌──────────────────────────────────────────────────────────────┐
   │ tlsfp         CLI · live capture · report · axum API + SSE    │
   └──────────────────────────────────────────────────────────────┘
```

Design decisions:

- **Parsers treat input as hostile.** The engine forbids `unsafe`, readers are bounds-checked, and every malformed input is an error or a counted drop.
- **Synchronous core, async only at the edge.** A lookup is one indexed query and a capture is a plain loop; the async runtime exists only in the web server.
- **QUIC needs no secret.** Client Initial keys derive from the Destination Connection ID, which is sent in the clear (RFC 9001, RFC 9369).
- **Detection state lives in the database,** not in memory, so a sensor keeps its history across restarts and external writers can share it.

## Performance

Single core: fingerprinting alone runs at about 90,000 TLS handshakes or 80,000 QUIC Initials per second; with intelligence matching and detection (SQLite) about 3,000 per second. Methodology, caveats and what has not been measured: [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md).

## Validation

| Check | Scope |
|---|---|
| Known-answer tests | JA3 (Salesforce vectors), JA4 (FoxIO vectors), QUIC key schedule (RFC 9001 and RFC 9369 appendices) |
| Integration tests | Vendored captures in `testdata/pcap/` (provenance in `testdata/pcap/PROVENANCE.md`) |
| Property tests | Arbitrary and mutated bytes into the TLS, QUIC, HTTP, SSLv2, certificate and pipeline entry points; stream reassembly under arbitrary segmentation |
| CI | `cargo test` on stable and Rust 1.85, `clippy -D warnings`, `rustfmt`, `cargo audit`, evaluation reproducibility |
| Security review | [`AUDIT.md`](AUDIT.md) |

Run locally:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo audit
cargo bench -p tlsfp-core        # throughput benchmarks
```

### Evaluation

`dataset/` holds labeled handshakes from real client builds, curl-impersonate browser profiles and real Chromium builds from version 107 to 143; `eval/` measures fingerprint stability, impersonation fidelity and what the sensor concludes about each client. Everything is reproducible and verified in CI.

| Measured result | |
|---|---|
| Known-good clients receiving a suspicious or malicious verdict | 0 of 22 (428 handshakes) |
| Known-good clients unseen by the feed that were wrongly vouched for | 0 of 5 (reported unknown) |
| Real Chromium headless-shell builds whose JA4 equals the nearest-version curl-impersonate profile | 8 of 9 |
| Real full Chrome builds (25, versions 118 to 143) whose JA4 equals it | 0 of 25: the profiles send ECH, the lab Chrome does not |
| Distinct JA4 families across 25 real full Chrome builds | 3, plus a resumption variant of each |
| Lying libraries caught by `ua_mismatch` (a library claiming Chrome or Safari) | 16 of 16, no false alarms on 8 honest libraries and 10 real browsers |
| Windows claims from a Linux host caught by `os_mismatch` | 14 of 14 |
| Impersonation tools left on defaults caught by `header_anomaly` | 17 of 17, no false alarms |
| Impersonation with defaults stripped and a Unix User-Agent | **not caught by any rule** |
| JA4 sets reproducing across two lab runs | 28 of 28 clients |
| Distinct fingerprints per client, JA3 against JA4 | 5.74 against 1.10 |

JA3 changes on every connection for any client that randomizes extension order, while JA4 collapses them. Impersonation is where the evaluation changed the most. Against Chromium headless shells the curl-impersonate profile is byte-identical (8 of 9); against full Chrome in the lab it never is (0 of 25), because the profiles send ECH, use a stale ALPS codepoint for Chrome 127 to 131 and lack the trust-anchors extension of Chrome 141 and later. Chrome's ClientHello depends on build flavour and configuration, and the lab could not make Chrome send ECH (feature flag, secure DNS and a non-loopback address all failed), so whether a profile separates from a typical desktop user is not something the lab can settle. The sensor therefore never lists impersonation profiles as tools, because the opposite error would flag real users, and it catches impersonation at other layers: curl-impersonate sends Client Hints, `Sec-Fetch-*` headers and an h2c upgrade over cleartext, which real browsers never do, so `header_anomaly` catches the default configuration. An attacker who removes those headers and claims a Unix User-Agent evades every rule here, and real-browser automation looks like a user at every measured layer. The evaluation also led to fixes in the matcher and label logic and to the `--shared-network` option for NAT gateways. Method, results and limits: [`eval/README.md`](eval/README.md); clients and threats to validity: [`dataset/README.md`](dataset/README.md).

## Deployment and security

- Run live capture with `CAP_NET_RAW` and `CAP_NET_ADMIN` only, never as root.
- The HTTP API and dashboard have **no authentication**. The default bind is `127.0.0.1`. If it must be reachable, put it behind a reverse proxy that provides authentication and TLS.
- Capture files and database contents include IP addresses and SNI values, which can be personal data. Apply your retention and access controls.
- A fingerprint identifies a TLS implementation and configuration, not a person. Treat `known_bad` as a lead, not proof.

Threat model, assumptions and responsible use: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Limitations

- Fingerprints can be spoofed (uTLS, curl-impersonate, custom ClientHello), and a spoofed ClientHello is identical to the real one. The cross-layer rules raise the cost for tools on their defaults; they do not stop a careful attacker, and nothing here detects a real browser driven by automation.
- Encrypted Client Hello hides the inner ClientHello; detection degrades to the outer one.
- JA4X needs the certificate in the clear (TLS 1.2 and earlier). JA4H covers cleartext HTTP/1.x only.
- QUIC support covers client Initial packets; no 0-RTT, Handshake packets, or connection migration.
- The bundled intelligence (309 fingerprints) is a baseline, not coverage of current malware. Its client entries come from one Linux host (plus Firefox 158 from one Windows machine) and drift as client libraries change. [`docs/INTELLIGENCE.md`](docs/INTELLIGENCE.md) explains how to import ja4db.com and add your own.
- A tool that reproduces a real browser's ClientHello cannot be separated from it by JA3 or JA4, and whether curl-impersonate does depends on browser configuration the sensor cannot see (see the fidelity results in [`eval/README.md`](eval/README.md)). Curated browser fingerprints are families, not single values: 25 real Chrome builds produced three.
- Accuracy is measured on lab captures only (see Validation); it has not been quantified on real-world traffic.

## Documentation

| Document | Contents |
|---|---|
| [`learn/02-ARCHITECTURE.md`](learn/02-ARCHITECTURE.md) | Crate structure, pipeline, intelligence store |
| [`learn/03-IMPLEMENTATION.md`](learn/03-IMPLEMENTATION.md) | Code walkthrough from frame to alert |
| [`learn/ALGORITHMS.md`](learn/ALGORITHMS.md) | Byte-level definition of each fingerprint and QUIC decryption |
| [`learn/CONFORMANCE.md`](learn/CONFORMANCE.md) | Published vectors and scope boundaries |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Threat model and responsible use |
| [`AUDIT.md`](AUDIT.md) | Security audit findings |
| [`eval/README.md`](eval/README.md) | Evaluation method and results |
| [`docs/FIELD_OBSERVATIONS.md`](docs/FIELD_OBSERVATIONS.md) | Fingerprints of real Brave, Edge and Firefox on Windows |
| [`docs/BROWSER_CAPTURE.md`](docs/BROWSER_CAPTURE.md) | Capture a real desktop browser and replay it in the dashboard |
| [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) | Measured throughput and its limits |
| [`docs/INTELLIGENCE.md`](docs/INTELLIGENCE.md) | Extending the intelligence feed; licensing |
| [`dataset/README.md`](dataset/README.md) | Dataset construction and validity |
| [`RELEASING.md`](RELEASING.md) | Release and signed-tag procedure |
| [`CHANGES.md`](CHANGES.md) | Changes relative to the upstream base |

## Roadmap

| Status | Item |
|---|---|
| Done | Security audit, CI, parser fuzz coverage, reproducible fingerprint and detection evaluation, lab-derived client intelligence |
| Next | Real Firefox, Safari and Edge captures, and a second operating system, to replace impersonation stand-ins |
| Done | Cleartext-HTTP rules (`ua_mismatch`, `os_mismatch`, `header_anomaly`) evaluated on labeled scenarios, including adaptive attackers |
| Next | Real desktop Chrome, Firefox and Safari on more than one operating system; with only one browser family a learned classifier would learn the browser, not the impersonation |
| Planned | Per-host fingerprint drift detection |
| Planned | Evasion study (uTLS, curl-impersonate) and Encrypted Client Hello impact |

## Contributing, security reports, citation

- Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Vulnerability reports: [`SECURITY.md`](SECURITY.md), via GitHub private vulnerability reporting
- Citation: [`CITATION.cff`](CITATION.cff)

## License and acknowledgments

Licensed under the GNU Affero General Public License v3.0 ([`LICENSE`](LICENSE)). A modified version run as a network service must offer its source to its users.

`tlsfp` is derived from [ja3-ja4-tls-fingerprinting](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/ja3-ja4-tls-fingerprinting) by CarterPerez-dev (AngelaMos), AGPL-3.0, upstream commit `bf9ac5d`. The sensor core, fingerprint implementations, intelligence store and dashboard originate there; copyright headers are retained. Changes are listed in [`CHANGES.md`](CHANGES.md); full provenance is in [`NOTICE.md`](NOTICE.md).

Fingerprint specifications: JA3 and JA3S by John Althouse, Jeff Atkinson and Josh Atkins (Salesforce, BSD-3-Clause); JA4 by FoxIO (BSD-3-Clause). JA4S, JA4H, JA4X and JA4T are licensed by FoxIO under the FoxIO License 1.1 (non-commercial use, patent pending); see [`NOTICE.md`](NOTICE.md) before any commercial use. Threat feeds: abuse.ch SSLBL (CC0-1.0), Salesforce `osx-nix` (BSD-3-Clause), ja4db.com.
