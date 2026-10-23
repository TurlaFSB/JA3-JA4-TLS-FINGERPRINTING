# Fingerprint evaluation: dataset v0.1

Environment: Linux-6.18.44-fc-v153-x86_64-with-glibc2.39, TLS server OpenSSL 3.0.13 30 Jan 2024, transport loopback.

## JA3

- clients: 9
- clients whose dominant fingerprint is unique: 7/9
- mean distinct fingerprints per client: 1.778
- mean share of the dominant fingerprint: 0.9028

| client | handshakes | distinct | dominant share | shares fingerprint with |
|---|---|---|---|---|
| chromium-headless | 8 | 8 | 0.125 | - |
| curl | 20 | 1 | 1.0 | curl-http2 |
| curl-http2 | 20 | 1 | 1.0 | curl |
| go-net-http | 20 | 1 | 1.0 | - |
| node-https | 20 | 1 | 1.0 | - |
| openssl-s_client | 20 | 1 | 1.0 | - |
| python-requests | 20 | 1 | 1.0 | - |
| python-urllib | 20 | 1 | 1.0 | - |
| wget | 20 | 1 | 1.0 | - |

## JA4

- clients: 9
- clients whose dominant fingerprint is unique: 9/9
- mean distinct fingerprints per client: 1.111
- mean share of the dominant fingerprint: 0.9583

| client | handshakes | distinct | dominant share | shares fingerprint with |
|---|---|---|---|---|
| chromium-headless | 8 | 2 | 0.625 | - |
| curl | 20 | 1 | 1.0 | - |
| curl-http2 | 20 | 1 | 1.0 | - |
| go-net-http | 20 | 1 | 1.0 | - |
| node-https | 20 | 1 | 1.0 | - |
| openssl-s_client | 20 | 1 | 1.0 | - |
| python-requests | 20 | 1 | 1.0 | - |
| python-urllib | 20 | 1 | 1.0 | - |
| wget | 20 | 1 | 1.0 | - |

