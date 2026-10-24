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
| The dashboard / API | Exposes observed hosts, sites and alerts; no authentication. Reachable from any web page in the same browser when bound to loopback, unless the Host header is checked |
| Alert delivery | Sends alert content off the host; a webhook URL is a secret |
| HTML reports | Contain addresses, server names and a capture's hash; built from untrusted captures |
| The capture library | Reads files from a folder an operator points it at |
| Capture files | May contain sensitive metadata (IPs, SNI, User-Agent in cleartext HTTP) |

## Adversaries and mitigations

| Adversary action | Effect | Mitigation / status |
|---|---|---|
| Malformed or hostile packets | Crash or memory exhaustion | Engine forbids `unsafe`; bounded flow table and stream buffers; property tests feed arbitrary and mutated input (`tests/robustness.rs`) |
| Fingerprint spoofing (uTLS, curl-impersonate, custom ClientHello) | Client looks like a browser | **A spoofed ClientHello that equals a real browser's cannot be told apart by hash.** Measured: curl-impersonate profiles are byte-identical to Chromium headless shells of the same era and differ from full Chrome in the lab, but Chrome's hello depends on configuration (ECH, version) the sensor cannot see, so the sensor never lists a profile as a tool. Cross-layer rules catch tools on their defaults (`header_anomaly`, `ua_mismatch` for libraries, `os_mismatch`); an attacker who strips default headers and claims a Unix User-Agent evades all of them, and a real browser under automation is indistinguishable. See `eval/README.md` |
| Randomisation (Chrome extension shuffling) | JA3 changes every connection | JA4 sorts before hashing; JA3 kept only for legacy feeds |
| Encrypted Client Hello | Inner ClientHello hidden | Detection degrades to the outer hello; impact is a planned experiment |
| Feed poisoning | False positives or hidden malware | Importer validates records; feeds are vendored and versioned |
| Sensor fingerprinting / evasion by timing | Adversary notices detection | Out of scope: the sensor is passive |
| A web page uses DNS rebinding to reach `127.0.0.1:8080` | Reads the API (who this machine talks to) as if same-origin | While bound to loopback the server answers only `localhost` and loopback Host headers; `--allowed-host` adds names. Tested through the router |
| Hostile text in a capture (SNI, User-Agent, file name) | Script injection into the dashboard or a report | React escapes every value; the CSP allows only own scripts; the HTML report escapes every value (tested with a hostile name) and contains no script |
| A client opens thousands of event streams, or requests reports in a loop | Memory or CPU exhaustion | Streams capped at 64; one report built at a time; capture files over 1 GiB are not read |
| A long-running sensor fills the disk | The observation and alert tables grow with every handshake | Retention deletes by age and by row cap, oldest first, every 15 minutes (`--keep-days`, `--keep-alert-days`, `--max-observations`) |
| A stack trace or message in an error response | Reveals paths or queries | 500 responses carry a fixed message; the detail goes to the log |
| A log line carries a webhook URL | The secret leaks into logs | Only the host is logged (tested) |

## Known limits

- A fingerprint is a hash of client configuration. Many different programs share one fingerprint (same library defaults) and one program can produce several.
- Verdicts are probabilistic. Treat `known_bad` as a lead for investigation, not proof.
- JA4X works only where the certificate is in the clear (TLS 1.2 and earlier). JA4H covers cleartext HTTP/1.x only.
- Accuracy numbers are valid only for the dataset they were measured on; see `eval/README.md`.

## Deployment guidance

Bind the dashboard to `127.0.0.1` (the default; the Host header is then checked). If it must be reachable, put it behind a reverse proxy that provides authentication and TLS. Run live capture with only `cap_net_raw` and `cap_net_admin`, never as root.
