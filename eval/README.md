# Evaluation

Two scripts measure the project against labeled lab captures (`dataset/`). Both are deterministic, and CI re-runs them against the committed results, so any change to the parser, the fingerprint code, the intelligence feed or the matcher that moves a number shows up in review.

| Script | Measures |
|---|---|
| `evaluate.py` | How stable and how discriminating JA3 and JA4 are across clients |
| `detections.py` | What the sensor concludes about each client: intelligence verdicts and detection-rule alerts |
| `fidelity.py` | Whether curl-impersonate profiles reproduce a real browser's ClientHello |
| `scenarios.py` | The cleartext-HTTP rules (`ua_mismatch`, `header_anomaly`, `os_mismatch`) on client scenarios with ground truth |
| `crosslayer.py` | Whether the HTTP request fingerprint (JA4H) separates real browsers from impersonators |

```bash
cargo build --release
python3 eval/evaluate.py   --dataset dataset/v0.3 --out eval/results/v0.3
python3 eval/detections.py --dataset dataset/v0.3 --feed-dataset dataset/v0.2 --out eval/results/v0.3
# add --check to either to verify the committed results reproduce
```

## Design

**Held out.** The bundled `tlsfp lab` intelligence feed is generated from dataset v0.2 (`dataset/lab/make_intel_feed.py`). The detection evaluation runs on dataset v0.3, a separate lab run captured later that adds clients and impersonation profiles the feed never saw. Numbers are therefore a measurement on unseen captures, not a replay of the training data.

**Isolation.** Each client is evaluated against a freshly seeded database, as if it had an address of its own. A second pass puts every client behind one address to show how the correlation rules behave under NAT.

**Ground truth.** From the dataset manifest: `curl_cffi-*` clients are impersonation tools (expected: flagged as a tool, never vouched for as a browser); every other client is a known-good baseline (expected: never suspicious or malicious).

## Results

Datasets: v0.1 = 9 clients, 168 handshakes; v0.2 = 28 clients, 549 handshakes; v0.3 = 50 clients, 988 handshakes. Full tables: [`results/v0.3/results.md`](results/v0.3/results.md) and [`results/v0.3/detections.md`](results/v0.3/detections.md).

### Fingerprint stability and discrimination (v0.3, 50 clients)

| | JA3 | JA4 |
|---|---|---|
| Mean distinct fingerprints per client | 5.74 | 1.10 |
| Mean share of a client's most common fingerprint | 0.75 | 0.98 |
| Clients with a dominant fingerprint no other client shares | 33 / 50 | 24 / 50 |

- JA3 is unstable wherever extension order is randomized. Every Chromium-based profile (real Chromium and curl-impersonate Chrome 120 and later) produced a different JA3 on every connection (20 distinct in 20 handshakes). JA4 collapses them to one or two values, the second being session resumption (`pre_shared_key`).
- JA3's higher "unique" count is an artifact: a client that randomizes appears unique because its dominant value is random, not because it is identifiable.
- JA4 identifies an implementation or profile family, not a version. Chrome 120, 124 and 131 profiles share one JA4; Chrome 133 to 146 share another. Distinct software that shares a TLS library shares a fingerprint (curl with PHP cURL; httpx with aiohttp).
- Across two separate lab runs, 28 of 28 clients present in both produced identical JA4 sets.

### Impersonation fidelity (dataset v0.4): real browsers against curl-impersonate

Nine real Chromium builds (107 to 143, from npm) were captured beside sixteen curl_cffi Chrome and Edge profiles. Full table: [`results/v0.4/fidelity.md`](results/v0.4/fidelity.md).

- **8 of the 9 real builds have exactly the same JA4 as the nearest-version profile**; the exception is a one-version boundary (real 133 against the "133a" profile).
- **15 of the 16 profiles have a JA4 identical to a real build's.** The one that does not (Chrome 150) has no real counterpart newer than 143 in the dataset.
- The pattern is by era, not by version: real Chromium 107 and 110 share one JA4 with profiles 99 to 116 and Edge; 131 and 133 share one with profiles 120 to 131; 137 to 143 share one with profiles 133a to 146.

**Conclusion: no JA3 or JA4 value can separate curl-impersonate Chrome from the real browser.** That is what impersonation is for, and the measurement confirms it holds at the ClientHello level across fourteen years of Chrome releases in the sample. Any feed entry that lists such a profile as a "tool" is really listing the real browser's fingerprint.

### Detection (dataset v0.3 against the bundled feed)

Percent of client handshakes receiving each verdict; each client is judged in isolation:

| Group | Clients | Handshakes | Benign | Suspicious | Malicious | Unknown | No match |
|---|---|---|---|---|---|---|---|
| Known-good, in the feed's source runs | 17 | 328 | 100.0 | 0 | 0 | 0 | 0 |
| Known-good, **unseen** by the feed | 5 | 100 | 0 | 0 | 0 | 80.0 | 20.0 |
| Impersonation profiles | 28 | 560 | 59.3 | 0.0 | 0.0 | 8.6 | 32.1 |

- **No false positives.** No known-good client, seen or unseen, received a suspicious or malicious verdict or any alert other than the informational `first_seen`. Unseen known-good clients are not vouched for either: they come back unknown (a similar fingerprint exists, nothing exact) or no match.
- **Impersonation is not detected at the TLS layer.** Profiles of Chrome and Edge are received as benign Chromium because their fingerprint is the real browser's. Firefox, Safari and Tor profiles have no real counterpart in the lab, so they are not in the feed and come back with no verdict. Detecting impersonation needs another layer; see the cross-layer results below.
- **NAT is a false-positive mode, and now configurable.** With all 50 clients behind one address `fp_rotation` raised 30 alerts (more than 5 distinct JA4 values per address in an hour): correct for the rule, wrong for a gateway. Declared as a shared network, the same run raises none. `--shared-network <CIDR>` (or `TLSFP_SHARED_NETWORKS`) declares addresses that front many clients, and rotation and monoculture are skipped there.

### Cross-layer rules (dataset v0.5)

53 scenarios. Each client sends HTTPS and cleartext HTTP from one address to a non-secure hostname. Full table: [`results/v0.5/scenarios.md`](results/v0.5/scenarios.md). "Lies" are a non-browser claiming a browser (`ua`) or a Windows claim from a Linux host (`os`).

| Group | Scenarios | `ua_mismatch` | `header_anomaly` | either | `os_mismatch` |
|---|---|---|---|---|---|
| Library, honest User-Agent | 8 | no false alarms | no false alarms | no false alarms | no false alarms |
| Library, lying User-Agent | 16 | 16 / 16 | 0 / 16 | 16 / 16 | 8 / 8 Windows claims |
| Impersonation profile, defaults | 17 | 0 / 17 | 17 / 17 | 17 / 17 | 5 / 5 Windows claims |
| Impersonation, defaults stripped | 2 | 0 / 2 | 0 / 2 | 0 / 2 | 1 / 1 Windows claim; the macOS claim missed |
| Real browser | 10 | no false alarms | no false alarms | no false alarms | no false alarms |

- **Lying libraries are caught by `ua_mismatch`** once the label classifier knows the common client families (16 of 16, up from 10 of 16 before Go, Node.js, Ruby, PHP and OpenSSL labels were recognised). It works because the handshake of a known library names the library whatever the User-Agent says.
- **Impersonation is not caught by TLS or by `ua_mismatch`** (0 of 17), as the fidelity result predicts.
- **`header_anomaly` catches impersonation tools left on their defaults (17 of 17), with no false alarms on ten real browsers.** It rests on a protocol fact, not a fingerprint: Fetch Metadata (`Sec-Fetch-*`) and Client Hints (`Sec-CH-*`) are sent only to secure or loopback origins, and browsers never attempt a cleartext HTTP/2 upgrade, yet curl-impersonate sends all of them over plain HTTP. Against the full Chromium, the real request is `Host, Connection, Accept-Language, Upgrade-Insecure-Requests, User-Agent, Accept, Accept-Encoding`; every profile sent sixteen headers including Client Hints and Sec-Fetch, plus an `Upgrade: h2c` handshake.
- **It is trivially evaded.** An attacker who removes those headers and forces HTTP/1.1 (two scenarios) is caught by nothing except `os_mismatch`, and only when the claimed operating system disagrees with the real TCP stack. A Windows claim from a Linux host is caught; a macOS claim from a Linux host is not, because both read as Unix. **An attacker who strips the defaults and claims a Unix User-Agent evades every rule in this project.** Real-browser automation (Selenium, Playwright or Puppeteer driving an actual browser) looks like a user at every layer measured here, by construction.
- **JA4H separates the lab's real browsers from the impersonators perfectly, but that comparison is only partly valid.** Zero of 17 profiles share a JA4H with any real build, but nine of the ten real browsers are headless shells that send a leaner request than a desktop browser. The `header_anomaly` result stands on the protocol rules above, not on that comparison. See [`results/v0.5/crosslayer.md`](results/v0.5/crosslayer.md).

### What the evaluation changed in the code

1. **Partial matches no longer vouch.** A partial match (same sorted cipher list) to a benign entry used to produce a *benign* verdict, labelling unrelated clients, including a Tor-profile client, as Google Chrome. A benign verdict now requires an exact match; partial matches stay on the report as similarity hints.
2. **An exact match is no longer outvoted by neighbours.** Only the strongest tier of matches votes.
3. **Impersonation entries were removed from the feed.** An earlier version of the feed listed curl-impersonate profiles as tools, and an earlier version of this document reported that modern impersonation was therefore flagged. That result was wrong: those fingerprints are real Chrome's, so the feed would have flagged genuine Chrome users, and the test set had no real browsers to show it. Adding real Chromium builds to the lab exposed it; the generator now refuses to list any impersonation profile, and CI checks the committed feed against it.
4. **More client families recognised.** Node.js, Ruby, PHP, OpenSSL and Go labels are now classified as non-browsers, so `ua_mismatch` can use them.
5. **Shared networks and popular fingerprints.** `--shared-network` suppresses rotation and monoculture on declared addresses, and a fingerprint with an exact benign match is never a monoculture.
6. **A new rule, `header_anomaly`,** for the protocol-level tell above.

## Limits

Read the numbers with these in mind; the full list is in [`dataset/README.md`](../dataset/README.md).

- One host, one OS, one TLS server over loopback. Server-side fingerprints and TCP-stack fingerprints carry no information here.
- Real Firefox, Safari and Edge were not available. `curl_cffi` impersonation profiles stand in for them. Real Chromium is available (headless-shell builds from npm), which is what made the fidelity comparison possible; it is not desktop Chrome, and builds 116 to 123 did not run in the lab.
- "Known-good" means software run in the lab. Nothing here measures detection of real malware or real network traffic. The cleartext-HTTP rules are evaluated only in the scenario dataset, against one full browser and nine headless shells.
- Small samples: 20 handshakes per client, 50 clients. Percentages are indicative, not tight estimates.
