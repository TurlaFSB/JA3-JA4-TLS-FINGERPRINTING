# tlsfp: Complete Project Guide

A single reference for explaining this project to anyone: what it is, why it exists, how it works, what it is built with, who can use it, what it can and cannot do, and how to talk about it honestly in an interview or a talk.

Figures in this guide were taken from the repository at the time of writing. Where a number can drift (test counts, lines of code), re-check it before quoting it.

---

## 1. The project in one minute

**tlsfp** is a *passive network sensor*. It watches network traffic (live from a network card, or from a saved capture file) and computes **fingerprints** of encrypted connections without ever decrypting them or sending a packet.

A TLS fingerprint is a short hash of the *way* a program starts an encrypted conversation: which versions, ciphers and extensions it offers, in what order. Chrome, Firefox, curl, Python `requests`, Go programs and many kinds of malware each open a connection differently, so the hash says **what software** is talking, even though the content is encrypted and the program's name is never sent.

On top of that, tlsfp:

- compares fingerprints to a **threat-intelligence database** (known good, suspicious, malicious);
- runs **detection rules** that raise alerts (for example "this client claims to be Chrome but its handshake belongs to a Python script");
- shows everything in a **live web dashboard** and exports reports, logs, syslog and webhook alerts;
- also reads **SSH** (HASSH fingerprints) and **plain DNS**, so a conversation can be described as *who → whom, which name, what software, how much*.

**Elevator pitch:** "A defender's tool that answers *what software is on my network and does it look wrong?* from encrypted traffic alone, without decrypting anything, with a live dashboard, and with measured, honestly stated accuracy."

---

## 2. Provenance and honest attribution

This matters for interviews: say it first, plainly.

- The project is **derived from** CarterPerez-dev's open-source `ja3-ja4-tls-fingerprinting` (part of the Cybersecurity-Projects collection), upstream commit `bf9ac5d`, licensed **AGPL-3.0**. This repository is distributed under the same licence.
- The original provided the sensor core, the fingerprint implementations, the intelligence store, detection rules, the dashboard and the learning documents. Their `©AngelaMos` headers are kept in those files, as the licence requires.
- This repository adds substantial work on top: the evaluation harness and datasets, the capture library, live capture on Windows, custom rules, alert delivery, HTML reports, per-host history, retention, the audit and hardening pass, SSH/HASSH, passive DNS and DNS findings, the readable-conversation traffic view, the capture supervisor, configuration file, capture health, performance work and the documentation set. `CHANGES.md` lists every change, and `NOTICE.md` has the credits.

**How to say it:** "I started from an open-source AGPL sensor and extended it: I added live capture on Windows, DNS and SSH analysis, a detection and alerting pipeline, an evaluation harness against real browser builds, and a security audit. The credit for the original core is in the README and NOTICE." That is accurate and stronger than overclaiming. Do not say you wrote the original fingerprint core.

---

## 3. The problem it solves

Encryption hides content, but defenders still need to know what is on their network.

| Question | How tlsfp helps |
|---|---|
| What software is making these connections? | Fingerprint → client family (browser, curl, Python, Go, ...) |
| Is a program pretending to be something else? | Cross-layer rules: TLS fingerprint vs. User-Agent vs. TCP/OS fingerprint |
| Is there malware beaconing out? | Known-bad fingerprint matches; fingerprint rotation; many hosts with one odd fingerprint |
| Which sites and servers does this machine talk to? | SNI, DNS answers, reverse DNS, grouped by domain |
| Is DNS being abused (tunnelling, DGA)? | Six DNS pattern checks with evidence |
| Who is logging in over SSH, with what client? | HASSH / HASSHServer |
| How diverse is TLS in my environment? | Observed-fingerprint inventory and coverage |

Typical uses: threat hunting, incident response, SOC triage, bot and scraper detection, malware C2 detection, research on TLS ecosystem diversity, and teaching.

---

## 4. Who can use it

| Audience | Use |
|---|---|
| **SOC analyst / blue team** | Run the sensor on a mirror port; triage alerts; export to a SIEM through file, syslog or webhook |
| **Incident responder** | Run `tlsfp pcap` or `tlsfp html` on a capture to learn what clients and servers were involved; produce a self-contained report with the file's SHA-256 |
| **Threat hunter** | Query observed fingerprints, write custom TOML rules, import intelligence feeds |
| **Researcher** | JSON/CSV output, the labelled datasets, the evaluation scripts |
| **Student** | The `learn/` documents explain TLS, JA3/JA4 and the architecture; the synthetic capture gives a safe demo |
| **Home or small-office user** | Windows archive: double-click start script, open the dashboard |

**Not for:** tracking individuals, monitoring traffic you are not authorised to monitor, or covert profiling. The threat model document says this explicitly. Fingerprints and server names can be personal data in many jurisdictions.

---

## 5. Feature inventory

### 5.1 Fingerprints implemented
| Fingerprint | Identifies | Notes |
|---|---|---|
| **JA3 / JA3S** | TLS client / server hello (Salesforce, 2017) | Legacy; changes per connection when a client randomises extension order |
| **JA4 / JA4S** | TLS client / server hello (FoxIO, 2023) | Sorted before hashing, so randomisation does not change it |
| **JA4H** | Cleartext HTTP request | Header names and order, cookies, language |
| **JA4X** | X.509 certificate structure | Only where the certificate is visible (TLS 1.2 and earlier) |
| **JA4T / JA4TS** | TCP SYN / SYN-ACK | Implies the operating system; used by `os_mismatch` |
| **HASSH / HASSHServer** | SSH client / server key-exchange offer | Salesforce, BSD-3-Clause |
| **QUIC** | QUIC v1 and v2 Initial packets | Decrypts the Initial (keys are derived from public values per RFC 9001 / 9369), then fingerprints the embedded ClientHello |

Licensing note: the algorithms carry different licences (JA4 core is BSD-3-Clause; JA4+ members have FoxIO's own licence). `NOTICE.md` records which applies to what.

### 5.2 Capture
- **Offline:** `.pcap` / `.pcapng` files, including a capture *library* (a folder of captures) and `tlsfp identify`.
- **Live:** Linux (libpcap) and Windows (Npcap), `--live auto` picks the interface; BPF filter default `tcp or (udp and (port 443 or port 53))`.
- **Supervisor:** if the live source fails (adapter unplugged, driver reset) it reopens with back-off of 1, 2, 4 ... 30 seconds and publishes its state. Tested against fake sources; not yet exercised against a physically unplugged adapter.
- **Tunable engine:** `--max-flows`, `--idle-timeout`, `--stream-limit-kib`, `--buffer-mib` (kernel buffer).
- **Capture health:** kernel drop counts and engine counters are published, so the dashboard says what may have been missed and which flag fixes it.

### 5.3 Analysis
- **TLS reassembly** with bounded buffers; ClientHello and ServerHello parsed with readable detail (versions, ciphers, extensions, groups, signature algorithms, ALPN, GREASE).
- **Conversation naming:** each end shows a name and *how it is known* (TLS SNI, HTTP Host, DNS answer, reverse DNS (PTR), or "this computer").
- **Passive DNS:** queries, answers, failures, answer times, which servers answer. Kept in a bounded in-memory book.
- **SSH:** banner plus key-exchange lists, side decided by who opened the connection, then by port 22, else both hashes reported.

### 5.4 Intelligence and detection
- SQLite **intelligence store** (bundled SQLite), importable feeds, seeded entries, operator labels.
- **Matcher** that returns exact and inferred verdicts (known good / suspicious / malicious / unknown), with basis shown.
- **Detection rules** (all operate on stored history, so a replayed file and a live link behave the same and state survives restarts):

| Rule | Meaning |
|---|---|
| `known_bad` | Fingerprint matches malicious/suspicious intel; one alert per source address |
| `ua_mismatch` | Browser User-Agent but script/tool TLS fingerprint |
| `os_mismatch` | OS implied by User-Agent disagrees with OS implied by TCP SYN |
| `header_anomaly` | Browser-claiming request with headers browsers never send (Sec-Fetch, Client Hints, h2c upgrade) |
| `first_seen` | Never-before-seen fingerprint (informational) |
| `fp_rotation` | One address presents more than 5 fingerprints in an hour |
| `monoculture` | One fingerprint from more than 10 addresses in an hour |
| `dns_pattern` | DNS failures, generated subdomains, very long names, etc. |
| `custom` | Your own TOML rules (names, fingerprints, families, verdicts, networks, ports, TLS version, extensions) |

- **Six DNS checks:** many failures from one host, generated subdomains, very long names, steady rhythm (beaconing), changing addresses, blocked names. Each gives evidence and the innocent explanations. Thresholds are named constants with tests.

### 5.5 Output and integration
- **Dashboard** (React): pages Scope (live fingerprint stream), Traffic (readable conversations, by-domain view, capture health), DNS (plain-English summary, lookups, findings), Hosts, Alerts, Intel, Library, Sensor (interfaces, build id, preferences).
- **Exports:** JSON, CSV (formula-injection neutralised), self-contained HTML report (no script, no network, includes capture SHA-256 and the limits of the findings).
- **Alert delivery:** JSON lines file, RFC 5424 syslog over UDP/TCP, webhook (URL treated as a secret, never logged in full).
- **HTTP API** and **Prometheus `/metrics`**.
- **Configuration:** flags, environment variables, TOML config file, with precedence flag > variable > file > default; unknown keys are errors that list valid ones.
- **Retention:** deletes by age and row cap every 15 minutes.
- **Deployment:** Docker compose files, hardened systemd unit (`contrib/tlsfp.service`), Windows start script, `install.sh`.

---

## 6. Architecture

Three Rust crates and one frontend:

```
 packets (pcap file / live NIC)
        |
        v
 +--------------------------+
 | tlsfp-core  (no unsafe)  |   parse -> reassemble -> fingerprint
 |  net, parse, pipeline,   |   JA3 JA4 JA4H JA4X JA4T QUIC SSH DNS
 |  quic, ssh, dns, ...     |   emits StreamEvents
 +------------+-------------+
              |
              v
 +--------------------------+
 | tlsfp-intel              |   SQLite store, matcher, inference,
 |  schema, matcher, detect,|   detection rules, host history,
 |  rules, hosts, retention |   labels, retention
 +------------+-------------+
              |
              v
 +--------------------------+       +-----------------------+
 | tlsfp  (CLI + server)    | <---> | frontend (React SPA)  |
 |  live capture, supervisor|  HTTP |  Scope Traffic DNS    |
 |  axum API + SSE, DnsBook,|  SSE  |  Hosts Alerts Intel   |
 |  delivery, reports       |       |  Library Sensor       |
 +--------------------------+       +-----------------------+
```

Design decisions worth explaining:

1. **The engine is separate and forbids `unsafe`.** It parses attacker-controlled bytes at line rate, so memory safety is a hard requirement. Rust gives that; `#![forbid(unsafe_code)]` makes it a compile-time guarantee for the core.
2. **Everything is bounded.** Flow table, stream buffers, DNS compression-pointer walks, DNS book, event streams (capped at 64), report generation (one at a time), capture files (over 1 GiB refused). A hostile network cannot exhaust memory by design.
3. **Detection reads stored history, not in-memory state.** Same result for a replay and a live feed, and restarts do not lose state.
4. **Observation-only protocols.** SSH and DNS events never go through the fingerprint matcher (`is_fingerprinted()` guard); DNS goes to its own book, not the live stream.
5. **Passive only.** The sensor never transmits and never decrypts, which keeps its legal and operational footprint small.
6. **Honest labelling.** Every name and verdict shows its *basis* (exact, inferred, DNS-derived, from the matching client hello).

---

## 7. Technology stack and why

**Backend (Rust, edition workspace, MSRV 1.85)**

| Library | Purpose |
|---|---|
| `winnow` | Parser combinators for TLS/QUIC/HTTP/DNS binary formats |
| `etherparse`, `pcap-parser`, `pcap` | Packet decoding, capture-file reading, live capture |
| `md-5`, `sha2`, `hex` | Fingerprint hashing |
| `tokio`, `tokio-stream`, `flume`, `rustix` | Async runtime, event streams, channels |
| `axum` | HTTP API, SSE, static dashboard |
| `rusqlite` (bundled) | Intelligence store, no system SQLite needed |
| `clap` | CLI and environment/flag handling |
| `csv`, `serde`, `toml` | Import/export, configuration, rules |
| `thiserror`, `anyhow`, `tracing` | Errors and logging |
| `proptest` | Property/robustness testing |
| `criterion` | Benchmarks |

**Frontend**: React 19, TypeScript, Vite (rolldown-vite), SCSS modules, TanStack Query (polling and caching), zustand (UI state), zod (runtime validation of API responses), Vitest. Lint and format with Biome (including accessibility rules and a cognitive-complexity cap of 25) and Stylelint.

**Tooling**: GitHub Actions CI, `cargo audit`, `cargo deny`, `pnpm audit`, Docker, systemd, PowerShell start script, Python scripts for the lab, datasets and evaluation.

Why Rust: parsing hostile network input needs memory safety without a garbage-collector pause, single-binary distribution, and good async and testing ecosystems.

---

## 8. Repository map

| Path | Contents |
|---|---|
| `crates/tlsfp-core/` | Engine: parsers, fingerprints, pipeline, QUIC, SSH, DNS, benchmarks, tests |
| `crates/tlsfp-intel/` | Store, matcher, inference, detection, rules, hosts, labels, retention |
| `crates/tlsfp/` | CLI, live capture, supervisor, server, DNS book/findings, delivery, reports |
| `frontend/` | React dashboard |
| `dataset/` | Labelled handshakes from real client builds (v0.1 to v0.6) and the lab scripts |
| `eval/` | Evaluation scripts and committed, CI-verified results |
| `testdata/synthetic/` | Reproducible, clearly synthetic DNS/SSH capture |
| `docs/` | INSTALL, USAGE, DASHBOARD, DETECTION, RULES, ALERTS, DEPLOYMENT, CAPTURE_TUNING, PERFORMANCE, THREAT_MODEL, EVALUATION, INTELLIGENCE, and more |
| `learn/` | Teaching documents: concepts, architecture, algorithms, conformance |
| `contrib/` | systemd unit |
| `scripts/` | Windows start script, demo-capture generator |
| `AUDIT.md`, `SECURITY.md`, `CHANGES.md`, `NOTICE.md` | Audit findings, disclosure policy, change log, credits |

Size at time of writing: roughly 26,500 lines of Rust and 10,600 lines of TypeScript.

---

## 9. Quality and verification

**What is tested**
- Rust workspace tests (369 passing at the last full run), including known-answer tests pinned to published reference vectors for each fingerprint (`learn/CONFORMANCE.md` states exactly what is pinned and where scope is deliberately narrower).
- Property tests: arbitrary and mutated input to the QUIC, HTTP, SSLv2, certificate, DNS and SSH readers and the whole pipeline must never panic; DNS reverse names round-trip for every IPv4 and IPv6 address.
- Frontend: 60 Vitest tests, TypeScript strict type check, Biome, Stylelint.
- A live capture on loopback was run end to end (DNS ingestion, alert into the database and the alert file).

**CI gates**: rustfmt, clippy with warnings denied, tests on stable and on the minimum supported Rust (1.85), `cargo audit`, `cargo deny`, Windows build, frontend lint/types/tests/build/`pnpm audit`, and a job proving the committed evaluation results reproduce.

**Security audit**: `AUDIT.md` records findings F1 to F31 and their fixes, including a Host-header guard against DNS rebinding, capped streams, no internal detail in error responses, webhook URL never logged, retention limits, and dependency fixes.

**Performance** (single core, 2.1 GHz virtual machine, release build; orders of magnitude, not a guarantee):
- Parse one ClientHello about 143 ns; JA4 about 3.2 µs.
- Fingerprinting-only pipeline about 91,000 TLS handshakes/s; with intelligence and detection about 3,000/s.
- Memory under 50 MB in both modes.

**Dashboard performance work:** the live feed batches updates every 250 ms, rows are memoised, and shared lookups use one context. Measured under a deliberately harsh replay (about 500 events/s, CPU slowed to a quarter), long browser stalls fell from 40 totalling 6.4 s to 26 totalling 2.3 s. Better, not perfect, under that load.

---

## 10. Measured accuracy (and its limits)

Evaluation uses labelled lab captures from real client builds, including curl-impersonate and real Chromium builds from version 107 to 143. The intelligence feed is generated from an *earlier* dataset and evaluated on a *later, held-out* one, so the numbers are measurements on unseen captures.

| Measured result | |
|---|---|
| Known-good clients given a suspicious/malicious verdict | 0 of 22 (428 handshakes) |
| Known-good clients unseen by the feed that were wrongly vouched for | 0 of 5 (reported unknown) |
| Lying libraries caught by `ua_mismatch` | 16 of 16, no false alarms on 8 honest libraries and 10 real browsers |
| Windows claims from a Linux host caught by `os_mismatch` | 14 of 14 |
| Impersonation tools on defaults caught by `header_anomaly` | 17 of 17, no false alarms |
| JA4 sets reproducing across two lab runs | 28 of 28 clients |
| Distinct fingerprints per client, JA3 vs JA4 | 5.74 vs 1.10 |
| Impersonation with defaults stripped and a Unix User-Agent | **not caught by any rule** |

The last row is deliberately in the table. Stating what the tool cannot detect is what makes the other numbers credible.

**Known limits (say these before anyone asks)**
- A fingerprint identifies an implementation and configuration, not a person. Many programs share one; one program can produce several.
- A spoofed ClientHello identical to a real browser's cannot be told apart by hash. Real-browser automation looks like a user.
- Verdicts are probabilistic; `known_bad` is a lead, not proof.
- JA4X needs a visible certificate (TLS 1.2 and earlier); JA4H covers cleartext HTTP/1.x only.
- Encrypted Client Hello hides the inner hello; detection degrades to the outer one.
- DNS analysis sees only plain DNS on UDP 53, not DNS-over-HTTPS or DNS-over-TLS.
- The dashboard has no authentication; bind it to loopback or put it behind an authenticating reverse proxy.
- Accuracy figures hold only for the datasets they were measured on.
- Supervisor reconnect is tested against fake sources, not a physically unplugged adapter.

---

## 11. Security posture

- Passive: never transmits, never decrypts.
- Core forbids `unsafe`; all buffers bounded; property tests on every parser.
- Dashboard bound to `127.0.0.1` by default with a Host-header allow-list (defeats DNS rebinding); CSP allows only own scripts; React escapes every value; HTML reports escape everything and contain no script.
- Errors return fixed messages; details go to the log; webhook URLs are never logged in full.
- Retention prevents unbounded disk growth.
- Recommended live-capture privileges: only `cap_net_raw` and `cap_net_admin`, never root. The systemd unit is hardened accordingly.
- Disclosure policy in `SECURITY.md`. Full adversary table in `docs/THREAT_MODEL.md`.

---

## 12. How to run it (quick reference)

```bash
# build
cargo build --release
cd frontend && pnpm install && pnpm build && cd ..

# fingerprint a capture
./target/release/tlsfp pcap testdata/synthetic/synthetic-dns-ssh.pcap

# dashboard on a capture replay
./target/release/tlsfp serve 127.0.0.1:8080 --db tlsfp.db --replay <capture.pcap>

# dashboard on live traffic (needs capture privileges / Npcap on Windows)
./target/release/tlsfp serve 127.0.0.1:8080 --db tlsfp.db --live auto

# self-contained HTML report
./target/release/tlsfp html capture.pcap --out report.html
```

Windows: unzip the release archive, install Npcap, run `start-windows.ps1`. Full per-platform steps: `docs/INSTALL.md`.

---

## 13. Demo script (3 to 5 minutes)

1. **Say what it is** (section 1 pitch) and the attribution line (section 2).
2. Open the dashboard on the synthetic capture or live loopback.
3. **Scope page:** a live stream of handshakes; open one and show the readable detail (versions, ciphers, JA4).
4. **Traffic page:** one conversation read as *who opened it, who answered, what it was, how much*; point at the "how this name is known" label.
5. **DNS page:** the generated "what is happening" box and a finding with its evidence and innocent explanations.
6. **Alerts page:** one `ua_mismatch` or `dns_pattern` alert; show the same alert in the JSON-lines file.
7. **Close with limits:** show the row in the accuracy table that is *not* caught.

---

## 14. Interview questions and answers

**What is JA3/JA4 and why does it work?**
Every TLS client library builds its ClientHello differently: cipher order, extensions, curves. Hashing those choices gives a stable label for the software even though the traffic is encrypted. JA4 sorts the lists first so that randomised extension order (Chrome) does not change the label.

**Why JA4 over JA3?**
Chrome randomises extension order, so JA3 changes per connection. In the evaluation JA3 gave 5.74 distinct fingerprints per client against 1.10 for JA4.

**How do you handle QUIC, where the handshake is encrypted?**
QUIC Initial packets are encrypted with keys derived from the destination connection ID using public constants (RFC 9001/9369), so a passive observer can decrypt the Initial, read the ClientHello inside, and fingerprint it. Later packets stay opaque.

**How does the sensor deal with malicious input?**
The core forbids unsafe code, every buffer and table is bounded, DNS name decompression has a bounded pointer walk, and property tests feed arbitrary and mutated bytes to every parser to check nothing panics.

**How do you know your fingerprints are correct?**
Known-answer tests pinned to published reference vectors, documented in `learn/CONFORMANCE.md`, plus an evaluation on real client builds.

**How do you detect a program pretending to be Chrome?**
Not by the TLS hash alone: a perfect copy is indistinguishable. Instead the rules compare layers: TLS fingerprint vs. User-Agent (`ua_mismatch`), User-Agent OS vs. TCP SYN OS (`os_mismatch`), and headers browsers never send (`header_anomaly`). It catches tools on their defaults and misses a careful attacker, and the documentation says so.

**What are the false-positive controls?**
`known_bad` alerts once per source; monoculture is never raised for an exact benign match; NAT gateways can be declared with `--shared-network`; every DNS finding lists innocent explanations; the evaluation reports 0 false verdicts on 22 known-good clients.

**Why SQLite?**
Embedded, zero administration, durable detection state across restarts, bundled so there is no system dependency. Retention keeps it bounded.

**What would you do with more time?**
HASSH feed matching and SSH change detection, persisting DNS history, GeoIP/ASN enrichment, certificate subject names for TLS 1.2, fuzz targets, and native TLS plus authentication for the dashboard.

**What was hardest?**
Choose one honestly. Good candidates: reassembling and attributing names across protocols (a ServerHello has no name; it has to be borrowed from the matching ClientHello, a DNS answer or a PTR record, and labelled as such); keeping a live dashboard responsive under hundreds of events per second; and measuring impersonation honestly when the lab could not make real Chrome send ECH.

**What did you learn from the evaluation?**
Curl-impersonate profiles are byte-identical to Chromium headless shells (8 of 9) but never to full Chrome (0 of 25) in the lab. So the sensor never lists an impersonation profile as a tool (that would flag real users) and catches impersonation at other layers instead.

**Is this your own work?**
It is a derivative of an AGPL project. The core and the original dashboard are the upstream author's, credited in the README and NOTICE. The extensions are listed in `CHANGES.md`. Be ready to explain any part you claim, and to say which parts are upstream.

---

## 15. Glossary

| Term | Meaning |
|---|---|
| **Passive sensor** | Observes traffic; sends nothing |
| **ClientHello / ServerHello** | The first messages of a TLS handshake from client / server |
| **SNI** | Server Name Indication: the site name sent in the ClientHello |
| **GREASE** | Random reserved values clients insert to keep servers tolerant (RFC 8701); ignored in fingerprints |
| **ECH** | Encrypted Client Hello: hides the inner hello and SNI |
| **ALPN** | Negotiated application protocol (h2, http/1.1) |
| **PTR** | DNS reverse record mapping an address to a name |
| **DGA** | Domain generation algorithm used by malware |
| **C2 / beaconing** | Command-and-control; regular check-ins from malware |
| **BPF** | Berkeley Packet Filter: kernel-level capture filter |
| **SSE** | Server-Sent Events: one-way live stream to the browser |
| **Npcap** | Windows packet-capture driver |
| **NAT** | Many hosts behind one address; breaks per-address correlation |

---

## 16. Where to read more

README (overview and install), `docs/INSTALL.md`, `docs/USAGE.md`, `docs/DASHBOARD.md`, `docs/DETECTION.md`, `docs/RULES.md`, `docs/ALERTS.md`, `docs/DEPLOYMENT.md`, `docs/CAPTURE_TUNING.md`, `docs/PERFORMANCE.md`, `docs/THREAT_MODEL.md`, `docs/EVALUATION.md`, `eval/README.md`, `dataset/README.md`, `learn/` (concepts, architecture, algorithms, conformance), `AUDIT.md`, `CHANGES.md`, `NOTICE.md`.
