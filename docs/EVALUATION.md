# Evaluation

[`../dataset/`](../dataset/README.md) holds labeled handshakes from real client builds, curl-impersonate browser profiles and real Chromium builds from version 107 to 143; [`../eval/`](../eval/README.md) measures fingerprint stability, impersonation fidelity and what the sensor concludes about each client. Everything is reproducible and verified in CI.

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

JA3 changes on every connection for any client that randomizes extension order, while JA4 collapses them. Impersonation is where the evaluation changed the most. Against Chromium headless shells the curl-impersonate profile is byte-identical (8 of 9); against full Chrome in the lab it never is (0 of 25), because the profiles send ECH, use a stale ALPS codepoint for Chrome 127 to 131 and lack the trust-anchors extension of Chrome 141 and later. Chrome's ClientHello depends on build flavour and configuration, and the lab could not make Chrome send ECH (feature flag, secure DNS and a non-loopback address all failed), so whether a profile separates from a typical desktop user is not something the lab can settle. The sensor therefore never lists impersonation profiles as tools, because the opposite error would flag real users, and it catches impersonation at other layers: curl-impersonate sends Client Hints, `Sec-Fetch-*` headers and an h2c upgrade over cleartext, which real browsers never do, so `header_anomaly` catches the default configuration. An attacker who removes those headers and claims a Unix User-Agent evades every rule here, and real-browser automation looks like a user at every measured layer. The evaluation also led to fixes in the matcher and label logic and to the `--shared-network` option for NAT gateways. Method, results and limits: [`../eval/README.md`](../eval/README.md); clients and threats to validity: [`../dataset/README.md`](../dataset/README.md).
