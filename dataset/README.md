# Handshake dataset

Labeled TLS ClientHello captures with ground truth, for measuring fingerprint stability and discriminability. Each capture file contains handshakes from exactly one client, so the label of every handshake is its file name.

## Versions

| Version | Clients | Handshakes | Notes |
|---|---|---|---|
| `v0.1` | 9 | 148 | First lab run: curl (HTTP/1.1 and HTTP/2), wget, openssl s_client, Python requests, Python urllib, Go net/http, Node https, headless Chromium |

A released version is immutable. New data goes into a new directory (`v0.2`, ...). `manifest.json` records the SHA-256 of every capture and the exact client versions; `eval/evaluate.py` refuses to run if a capture does not match its checksum.

## How it is produced

`python3 dataset/lab/run_lab.py --out dataset/v0.1 --repeat 20`

The lab starts a local TLS server (self-signed ECDSA P-256 certificate, ALPN `http/1.1`) on a random loopback port, starts `tcpdump` on `lo`, runs one client at a time against `https://localhost:<port>/`, and stops the capture. Proxy environment variables are removed so no client is diverted. It needs `tcpdump`, `openssl` and whichever clients are installed; missing clients are skipped. Repeat counts are requests, so the realised handshake counts are in `eval/results/`.

## Threats to validity

Be explicit about these when quoting results.

- **Loopback, one server.** Server-side values (ServerHello, JA4S, certificate) are identical for every client and carry no information. TCP-level JA4T on loopback does not resemble a real network path.
- **Linux only, one host.** Every client ran on the same OS build, so OS differences in client behaviour (Windows SChannel, macOS Network.framework, Android) are absent.
- **Headless Chromium, not desktop Chrome or Firefox.** Close to Chrome, not identical. Firefox and curl-impersonate are not yet included.
- **Few handshakes per client** (20 requested; Chromium yields fewer because of connection reuse). Rates computed from them are indicative, not tight estimates.
- **No malware, no real traffic.** Nothing here measures detection of real threats.
- **Labels are tool names, not behaviours.** Two clients sharing a TLS library will legitimately share a fingerprint.

## Privacy

Captures are generated locally against a local server and contain no third-party traffic.
