# Fingerprint evaluation: dataset v0.2

Environment: Linux-6.18.44-fc-v153-x86_64-with-glibc2.39, TLS server OpenSSL 3.0.13 30 Jan 2024, transport loopback.

## JA3

- clients: 28
- clients whose dominant fingerprint is unique: 23/28
- mean distinct fingerprints per client: 4.714
- mean share of the dominant fingerprint: 0.7968

| client | handshakes | distinct | dominant share | shares fingerprint with |
|---|---|---|---|---|
| chromium-headless | 9 | 9 | 0.1111 | - |
| curl | 20 | 1 | 1.0 | curl-http2, php-curl |
| curl-http2 | 20 | 1 | 1.0 | curl, php-curl |
| curl-tls12 | 20 | 1 | 1.0 | - |
| curl_cffi-chrome120 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome124 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome131 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome142 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome150 | 20 | 20 | 0.05 | - |
| curl_cffi-edge101 | 20 | 1 | 1.0 | - |
| curl_cffi-firefox133 | 20 | 1 | 1.0 | - |
| curl_cffi-firefox147 | 20 | 1 | 1.0 | - |
| curl_cffi-safari180_ios | 20 | 1 | 1.0 | - |
| curl_cffi-safari2601 | 20 | 1 | 1.0 | - |
| curl_cffi-tor145 | 20 | 1 | 1.0 | - |
| go-net-http | 20 | 1 | 1.0 | - |
| java-httpclient | 20 | 2 | 0.95 | - |
| node-https | 20 | 1 | 1.0 | - |
| openssl-s_client | 20 | 1 | 1.0 | - |
| openssl-s_client-tls12 | 20 | 1 | 1.0 | - |
| php-curl | 20 | 1 | 1.0 | curl, curl-http2 |
| php-stream | 20 | 1 | 1.0 | - |
| python-aiohttp | 20 | 1 | 1.0 | python-httpx |
| python-httpx | 20 | 1 | 1.0 | python-aiohttp |
| python-requests | 20 | 1 | 1.0 | - |
| python-urllib | 20 | 1 | 1.0 | - |
| ruby-net-http | 20 | 1 | 1.0 | - |
| wget | 20 | 1 | 1.0 | - |

## JA4

- clients: 28
- clients whose dominant fingerprint is unique: 21/28
- mean distinct fingerprints per client: 1.107
- mean share of the dominant fingerprint: 0.9788

| client | handshakes | distinct | dominant share | shares fingerprint with |
|---|---|---|---|---|
| chromium-headless | 9 | 2 | 0.5556 | - |
| curl | 20 | 1 | 1.0 | - |
| curl-http2 | 20 | 1 | 1.0 | php-curl |
| curl-tls12 | 20 | 1 | 1.0 | - |
| curl_cffi-chrome120 | 20 | 2 | 0.9 | curl_cffi-chrome124, curl_cffi-chrome131 |
| curl_cffi-chrome124 | 20 | 1 | 1.0 | curl_cffi-chrome120, curl_cffi-chrome131 |
| curl_cffi-chrome131 | 20 | 1 | 1.0 | curl_cffi-chrome120, curl_cffi-chrome124 |
| curl_cffi-chrome142 | 20 | 1 | 1.0 | - |
| curl_cffi-chrome150 | 20 | 1 | 1.0 | - |
| curl_cffi-edge101 | 20 | 1 | 1.0 | - |
| curl_cffi-firefox133 | 20 | 1 | 1.0 | - |
| curl_cffi-firefox147 | 20 | 1 | 1.0 | - |
| curl_cffi-safari180_ios | 20 | 1 | 1.0 | - |
| curl_cffi-safari2601 | 20 | 1 | 1.0 | - |
| curl_cffi-tor145 | 20 | 1 | 1.0 | - |
| go-net-http | 20 | 1 | 1.0 | - |
| java-httpclient | 20 | 2 | 0.95 | - |
| node-https | 20 | 1 | 1.0 | - |
| openssl-s_client | 20 | 1 | 1.0 | - |
| openssl-s_client-tls12 | 20 | 1 | 1.0 | - |
| php-curl | 20 | 1 | 1.0 | curl-http2 |
| php-stream | 20 | 1 | 1.0 | - |
| python-aiohttp | 20 | 1 | 1.0 | python-httpx |
| python-httpx | 20 | 1 | 1.0 | python-aiohttp |
| python-requests | 20 | 1 | 1.0 | - |
| python-urllib | 20 | 1 | 1.0 | - |
| ruby-net-http | 20 | 1 | 1.0 | - |
| wget | 20 | 1 | 1.0 | - |

