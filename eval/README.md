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

### Detection (v0.3 against the feed built from v0.2)

Percent of client handshakes receiving each verdict:

| Group | Clients | Handshakes | Benign | Suspicious | Malicious | Unknown | No match |
|---|---|---|---|---|---|---|---|
| Known-good, in the feed's source run | 17 | 328 | 100.0 | 0 | 0 | 0 | 0 |
| Known-good, **unseen** by the feed | 5 | 100 | 0 | 0 | 0 | 80.0 | 20.0 |
| Impersonation profiles, in the feed's source run | 11 | 220 | 9.1 | 90.9 | 0 | 0 | 0 |
| Impersonation profiles, **unseen** by the feed | 17 | 340 | 41.2 | 58.8 | 0 | 0 | 0 |

- **No false positives.** No known-good client, seen or unseen, received a suspicious or malicious verdict or any alert other than the informational `first_seen`. Unseen benign clients are not vouched for either: they come back unknown (a similar-looking fingerprint exists, nothing exact).
- **Modern impersonation is caught, and generalizes.** Unseen Chrome 133, 136, 145 and 146, Firefox 135 and 144, Safari 184 and an Android Chrome profile were all flagged suspicious through an exact match to a sibling profile's fingerprint; Safari 170 and 260 through a partial match.
- **Old Chrome-based impersonation is not caught.** Profiles for Chrome 99 to 116, Edge 99 and 101 and Chrome Android 99 reproduce a real Chrome ClientHello exactly (their JA4 equals the known-good Chrome reference, and so would their JA3). They are received as "benign Chrome". No hash of the ClientHello can separate them from the genuine browser, so they are deliberately kept out of the feed: listing them would flag every real Chrome user. Telling them apart needs signals outside the ClientHello (TCP stack, HTTP behaviour, timing), which is what the cross-layer rules and the planned classifier address.
- **NAT is a false-positive mode.** With all 50 clients behind one address, `fp_rotation` raised 30 medium alerts (more than 5 distinct JA4 values per address in an hour). That is correct behaviour for the rule and a known false-positive source for shared egress addresses; thresholds are configurable.

### What the evaluation changed in the code

1. **Partial matches no longer vouch.** A partial match (same sorted cipher list) to a benign entry used to produce a *benign* verdict. Against curl-impersonate profiles this labelled unrelated clients, including a Tor-profile client, as Google Chrome. A benign verdict now requires an exact match; partial matches stay on the report as similarity hints and the verdict is unknown. Partial matches to malicious intelligence still count.
2. **An exact match is no longer outvoted by neighbours.** Cataloguing the lookalike tool profiles made the exact Chrome fingerprint "suspicious", because near neighbours with the same cipher list voted alongside it. Only the strongest tier of matches now votes.
3. **Impersonation labels read as non-browsers.** A label such as "curl_cffi impersonating Chrome" was classified as Chrome because it contains the word, which would have suppressed `ua_mismatch`. Labels naming an impersonation framework are now classified as the tool.
4. **Browser-identical tool profiles are excluded from the feed** by the generator, with the reason recorded in the feed file.

## Limits

Read the numbers with these in mind; the full list is in [`dataset/README.md`](../dataset/README.md).

- One host, one OS, one TLS server over loopback. Server-side fingerprints and TCP-stack fingerprints carry no information here.
- Real Firefox, Safari and Edge were not available. `curl_cffi` impersonation profiles stand in for them; they are labelled as impersonation and never presented as the browsers.
- "Known-good" means software run in the lab. Nothing here measures detection of real malware or real network traffic, and the `ua_mismatch` and `os_mismatch` rules, which need cleartext HTTP, are not exercised because the lab clients speak HTTPS.
- Small samples: 20 handshakes per client, 50 clients. Percentages are indicative, not tight estimates.
