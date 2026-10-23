# Handshake dataset

Labeled TLS ClientHello captures with ground truth, for measuring fingerprint stability and discriminability. Each capture file contains handshakes from exactly one client, so the label of every handshake is its file name.

## Versions

| Version | Clients | Handshakes | Notes |
|---|---|---|---|
| `v0.1` | 9 | 168 | curl (HTTP/1.1 and HTTP/2), wget, OpenSSL s_client, Python requests, Python urllib, Go net/http, Node https, headless Chromium |
| `v0.2` | 28 | 549 | Adds Python httpx and aiohttp, TLS 1.2-only curl and OpenSSL, Java HttpClient, Ruby Net::HTTP, PHP streams and cURL, and 11 curl_cffi impersonation profiles (Chrome 120 to 150, Edge 101, Firefox 133 and 147, Safari 26.0.1 and iOS 18.0, Tor 145). **Source of the bundled `tlsfp lab` intelligence feed.** |
| `v0.3` | 50 | 988 | A separate lab run: every v0.2 client again, plus 22 not in v0.2. Five are known-good clients the feed never saw (Java HttpsURLConnection, Go with HTTP/2, OpenSSL with ALPN h2, curl TLS 1.3 only, wget TLS 1.2 only) and 17 are further impersonation profiles. **Held out from the feed**, used for the detection evaluation. |

A released version is immutable. `manifest.json` records the SHA-256 of every capture and the exact client versions; the evaluation scripts refuse to run if a capture does not match its checksum.

## How it is produced

```bash
python3 -m venv .labvenv && .labvenv/bin/pip install requests httpx aiohttp curl_cffi
.labvenv/bin/python dataset/lab/run_lab.py --out dataset/v0.2 --repeat 20
# v0.3 adds extra impersonation profiles:
.labvenv/bin/python dataset/lab/run_lab.py --out dataset/v0.3 --repeat 20 \
    --extra-impersonate chrome145,chrome146,chrome133a,chrome136,chrome116,chrome110,chrome107,chrome104,chrome99,edge99,firefox135,firefox144,safari184,safari260,safari170,chrome131_android,chrome99_android
```

The lab starts a local TLS server (self-signed ECDSA P-256 certificate, ALPN `http/1.1`) on a random loopback port, starts `tcpdump` on `lo`, runs one client at a time against `https://localhost:<port>/`, and stops the capture. Proxy environment variables are removed so no client is diverted. It needs `tcpdump`, `openssl` and whichever clients are installed; missing clients are skipped. Repeat counts are requests, so the realised handshake counts are in `eval/results/`.

## Threats to validity

Be explicit about these when quoting results.

- **Loopback, one server.** Server-side values (ServerHello, JA4S, certificate) are identical for every client and carry no information. TCP-level JA4T on loopback does not resemble a real network path.
- **Linux only, one host.** Every client ran on the same OS build, so OS differences in client behaviour (Windows SChannel, macOS Network.framework, Android) are absent.
- **Headless Chromium, not desktop Chrome, Firefox, Safari or Edge.** Real Firefox, Safari and Edge could not be installed in the lab. `curl_cffi` (curl-impersonate, BoringSSL) profiles stand in for them. They reproduce a browser's ClientHello, are labelled as impersonation, and are not the browsers. Measured against the real Chromium of the lab they match its cipher list but differ in extensions (for example `fe0d` and `4469` against `ca34` and `44cd`), partly because the lab target is `localhost`, which changes what a real browser sends (no ECH GREASE, no QUIC).
- **Few handshakes per client** (20 requested; Chromium yields fewer because of connection reuse). Rates computed from them are indicative, not tight estimates.
- **No malware, no real traffic.** Nothing here measures detection of real threats.
- **Labels are tool names, not behaviours.** Two clients sharing a TLS library will legitimately share a fingerprint.

## Derived intelligence feed

`dataset/lab/make_intel_feed.py` turns a dataset into `crates/tlsfp-intel/seeds/lab-clients.csv`, the `tlsfp lab` source: one row per distinct JA4, and per JA3 where the client's JA3 is stable. Impersonation frameworks are category `tool`; every other client is `benign`. Rows for a profile whose ClientHello is identical to a known-good browser's are left out, with the reason written into the file, because listing them would flag every user of that browser. Regenerate after adding a dataset; CI checks the committed file matches the generator's output.

Treat labels as "consistent with this client build", not proof: fingerprints are properties of a library build and drift across versions.

## Privacy

Captures are generated locally against a local server and contain no third-party traffic.
