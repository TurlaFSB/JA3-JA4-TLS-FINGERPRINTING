# Threat model and responsible use

## What the tool is

A passive sensor. It reads packets and computes fingerprints of handshakes; it never transmits and never decrypts application data. Fingerprints identify a TLS client or server *implementation and configuration*, not a person or a verified identity.

## Intended use

Defensive and research use on networks and captures you own or are authorised to monitor: threat hunting, incident response, malware C2 detection, bot and scraper detection, measuring TLS stack diversity, and teaching.

Do not use it to track individuals, to monitor traffic you have no authority over, or to build covert user profiling. Fingerprints and SNI values from captures can be personal data in many jurisdictions; apply your organisation's retention and access rules.

## Assets and trust boundaries

| Asset | Risk |
|---|---|
| The sensor host | Parses attacker-controlled bytes at line rate |
| The intelligence database | Poisoned feed entries could cause false verdicts |
| The dashboard / API | Exposes observed hosts and alerts; no authentication |
| Capture files | May contain sensitive metadata (IPs, SNI, User-Agent in cleartext HTTP) |

## Adversaries and mitigations

| Adversary action | Effect | Mitigation / status |
|---|---|---|
| Malformed or hostile packets | Crash or memory exhaustion | Engine forbids `unsafe`; bounded flow table and stream buffers; property tests feed arbitrary and mutated input (`tests/robustness.rs`) |
| Fingerprint spoofing (uTLS, curl-impersonate, custom ClientHello) | Client looks like a browser | **Not preventable by fingerprint alone.** Cross-layer checks (JA4 vs JA4T vs User-Agent) raise the cost; effectiveness is measured in the evaluation, not assumed |
| Randomisation (Chrome extension shuffling) | JA3 changes every connection | JA4 sorts before hashing; JA3 kept only for legacy feeds |
| Encrypted Client Hello | Inner ClientHello hidden | Detection degrades to the outer hello; impact is a planned experiment |
| Feed poisoning | False positives or hidden malware | Importer validates records; feeds are vendored and versioned |
| Sensor fingerprinting / evasion by timing | Adversary notices detection | Out of scope: the sensor is passive |

## Known limits

- A fingerprint is a hash of client configuration. Many different programs share one fingerprint (same library defaults) and one program can produce several.
- Verdicts are probabilistic. Treat `known_bad` as a lead for investigation, not proof.
- JA4X works only where the certificate is in the clear (TLS 1.2 and earlier). JA4H covers cleartext HTTP/1.x only.
- Accuracy numbers are valid only for the dataset they were measured on; see `eval/README.md`.

## Deployment guidance

Bind the dashboard to `127.0.0.1`. If it must be reachable, put it behind a reverse proxy that provides authentication and TLS. Run live capture with only `cap_net_raw` and `cap_net_admin`, never as root.
