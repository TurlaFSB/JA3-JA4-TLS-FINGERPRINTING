# Detection and intelligence

## Detection rules

Rules read fingerprint history stored in the database, so they behave identically on a capture replayed at once and on a live link, and state survives restarts.

| Rule | Fires when |
|---|---|
| `known_bad` | A fingerprint matches malicious or suspicious intelligence. Raised once per source address, so a beacon is one alert, not one per flow. |
| `ua_mismatch` | A cleartext request presents a browser User-Agent while the same client's TLS fingerprint belongs to a script or tool. |
| `os_mismatch` | The OS implied by the User-Agent disagrees with the OS implied by the client's TCP SYN fingerprint (JA4T). |
| `header_anomaly` | A cleartext request claiming a browser carries headers browsers never send to that origin: `Sec-Fetch-*`, `Sec-CH-*` Client Hints, or an `Upgrade: h2c` / `HTTP2-Settings` handshake. Skips loopback origins. Catches impersonation tools left on their defaults; trivially evaded. |
| `first_seen` | The fingerprint has never been recorded before. Informational. |
| `fp_rotation` | One address presents more than 5 distinct fingerprints within the window (default 1 hour). |
| `monoculture` | One fingerprint appears from more than 10 distinct addresses within the window. Never raised for a fingerprint with an exact benign match. |
| `custom` | A rule from your own TOML file matched: server names, fingerprints, client families, verdicts, networks, ports, TLS version, extensions. See [`RULES.md`](RULES.md). |

Thresholds and the window are configurable in `DetectConfig`. The defaults suit a quiet link; busy sensors should raise them. Rotation and monoculture are skipped for addresses declared with `--shared-network` (a NAT gateway, proxy or jump host).

Every alert states why it fired and what to verify. A fingerprint identifies a TLS implementation and configuration, not a person: treat `known_bad` as a lead, not proof.

## Intelligence feed

| Source | Records | Category | Licence |
|---|---|---|---|
| abuse.ch SSLBL | 97 | malware, C2 | CC0-1.0 |
| Salesforce `osx-nix` JA3 list | 157 | benign applications | BSD-3-Clause |
| Curated set | 21 | C2, tools, field-observed Firefox 158 | project |
| Lab-derived clients (`tlsfp lab`) | 34 | benign libraries and real Chromium builds | AGPL-3.0-only |
| ja4db.com (optional import) | variable | mixed | see ja4db.com terms |

Feeds are vendored and compiled into the binary, so seeding needs no network. Benign and malicious sources are both loaded on purpose: some hashes appear in both, and the matcher scores the disagreement.

Matching: exact lookup, plus JA4 prefix matching. A *benign* verdict needs an exact match; a partial match (same cipher list) is only a similarity hint; only the strongest match tier votes. The `tlsfp lab` feed is generated from the project's own labelled captures of real client builds (curl, Python, Go, Java, Ruby, PHP and Chromium 107 to 143); see [`../dataset/README.md`](../dataset/README.md).

The bundled 309 fingerprints are a baseline, not coverage of current malware. Extending the feed and its licensing: [`INTELLIGENCE.md`](INTELLIGENCE.md).
