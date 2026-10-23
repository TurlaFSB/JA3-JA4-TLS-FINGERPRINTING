# Evaluation

Two scripts measure the project against labeled lab captures (`dataset/`). Both are deterministic, and CI re-runs them against the committed results, so any change to the parser, the fingerprint code, the intelligence feed or the matcher that moves a number shows up in review.

| Script | Measures |
|---|---|
| `evaluate.py` | How stable and how discriminating JA3 and JA4 are across clients |
| `detections.py` | What the sensor concludes about each client: intelligence verdicts and detection-rule alerts |

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
- **NAT is a false-positive mode, and now configurable.** With all 50 clients behind one address `fp_rotation` raised dozens of alerts (more than 5 distinct JA4 values per address in an hour): correct for the rule, wrong for a gateway. `--shared-network <CIDR>` (or `TLSFP_SHARED_NETWORKS`) declares addresses that front many clients, and rotation and monoculture are skipped there.

### What the evaluation changed in the code

1. **Partial matches no longer vouch.** A partial match (same sorted cipher list) to a benign entry used to produce a *benign* verdict, labelling unrelated clients, including a Tor-profile client, as Google Chrome. A benign verdict now requires an exact match; partial matches stay on the report as similarity hints.
2. **An exact match is no longer outvoted by neighbours.** Only the strongest tier of matches votes.
3. **Impersonation entries were removed from the feed.** An earlier version of the feed listed curl-impersonate profiles as tools, and an earlier version of this document reported that modern impersonation was therefore flagged. That result was wrong: those fingerprints are real Chrome's, so the feed would have flagged genuine Chrome users, and the test set had no real browsers to show it. Adding real Chromium builds to the lab exposed it; the generator now refuses to list any impersonation profile, and CI checks the committed feed against it.
4. **More client families recognised.** Node.js, Ruby, PHP, OpenSSL and Go labels are now classified as non-browsers, so `ua_mismatch` can use them.
5. **Shared networks and popular fingerprints.** `--shared-network` suppresses rotation and monoculture on declared addresses, and a fingerprint with an exact benign match is never a monoculture.

## Limits

Read the numbers with these in mind; the full list is in [`dataset/README.md`](../dataset/README.md).

- One host, one OS, one TLS server over loopback. Server-side fingerprints and TCP-stack fingerprints carry no information here.
- Real Firefox, Safari and Edge were not available. `curl_cffi` impersonation profiles stand in for them. Real Chromium is available (headless-shell builds from npm), which is what made the fidelity comparison possible; it is not desktop Chrome, and builds 116 to 123 did not run in the lab.
- "Known-good" means software run in the lab. Nothing here measures detection of real malware or real network traffic, and the `ua_mismatch` and `os_mismatch` rules, which need cleartext HTTP, are not exercised because the lab clients speak HTTPS.
- Small samples: 20 handshakes per client, 50 clients. Percentages are indicative, not tight estimates.
