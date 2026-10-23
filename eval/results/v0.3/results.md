# Fingerprint evaluation: dataset v0.3

Environment: Linux-6.18.44-fc-v153-x86_64-with-glibc2.39, TLS server OpenSSL 3.0.13 30 Jan 2024, transport loopback.

## JA3

- clients: 50
- clients whose dominant fingerprint is unique: 33/50
- mean distinct fingerprints per client: 5.74
- mean share of the dominant fingerprint: 0.7525

| client | handshakes | distinct | dominant share | shares fingerprint with |
|---|---|---|---|---|
| chromium-headless | 8 | 8 | 0.125 | - |
| curl | 20 | 1 | 1.0 | curl-http2, php-curl |
| curl-http2 | 20 | 1 | 1.0 | curl, php-curl |
| curl-tls12 | 20 | 1 | 1.0 | - |
| curl-tls13 | 20 | 1 | 1.0 | - |
| curl_cffi-chrome104 | 20 | 1 | 1.0 | curl_cffi-chrome107, curl_cffi-chrome99, curl_cffi-chrome99_android, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome107 | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome99, curl_cffi-chrome99_android, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome110 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome116 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome120 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome124 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome131 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome131_android | 20 | 20 | 0.05 | - |
| curl_cffi-chrome133a | 20 | 20 | 0.05 | - |
| curl_cffi-chrome136 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome142 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome145 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome146 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome150 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome99 | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome99_android, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome99_android | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-edge101 | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome99, curl_cffi-chrome99_android, curl_cffi-edge99 |
| curl_cffi-edge99 | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome99, curl_cffi-chrome99_android, curl_cffi-edge101 |
| curl_cffi-firefox133 | 20 | 1 | 1.0 | - |
| curl_cffi-firefox135 | 20 | 1 | 1.0 | curl_cffi-firefox144, curl_cffi-firefox147 |
| curl_cffi-firefox144 | 20 | 1 | 1.0 | curl_cffi-firefox135, curl_cffi-firefox147 |
| curl_cffi-firefox147 | 20 | 1 | 1.0 | curl_cffi-firefox135, curl_cffi-firefox144 |
| curl_cffi-safari170 | 20 | 1 | 1.0 | curl_cffi-safari180_ios, curl_cffi-safari184 |
| curl_cffi-safari180_ios | 20 | 1 | 1.0 | curl_cffi-safari170, curl_cffi-safari184 |
| curl_cffi-safari184 | 20 | 1 | 1.0 | curl_cffi-safari170, curl_cffi-safari180_ios |
| curl_cffi-safari260 | 20 | 1 | 1.0 | - |
| curl_cffi-safari2601 | 20 | 1 | 1.0 | - |
| curl_cffi-tor145 | 20 | 1 | 1.0 | - |
| go-http2 | 20 | 1 | 1.0 | - |
| go-net-http | 20 | 1 | 1.0 | - |
| java-httpclient | 20 | 2 | 0.95 | - |
| java-urlconnection | 20 | 2 | 0.95 | - |
| node-https | 20 | 1 | 1.0 | - |
| openssl-s_client | 20 | 1 | 1.0 | - |
| openssl-s_client-alpn-h2 | 20 | 1 | 1.0 | - |
| openssl-s_client-tls12 | 20 | 1 | 1.0 | - |
| php-curl | 20 | 1 | 1.0 | curl, curl-http2 |
| php-stream | 20 | 1 | 1.0 | - |
| python-aiohttp | 20 | 1 | 1.0 | python-httpx |
| python-httpx | 20 | 1 | 1.0 | python-aiohttp |
| python-requests | 20 | 1 | 1.0 | - |
| python-urllib | 20 | 1 | 1.0 | - |
| ruby-net-http | 20 | 1 | 1.0 | - |
| wget | 20 | 1 | 1.0 | - |
| wget-tls12 | 20 | 1 | 1.0 | - |

## JA4

- clients: 50
- clients whose dominant fingerprint is unique: 24/50
- mean distinct fingerprints per client: 1.1
- mean share of the dominant fingerprint: 0.9825

| client | handshakes | distinct | dominant share | shares fingerprint with |
|---|---|---|---|---|
| chromium-headless | 8 | 2 | 0.625 | - |
| curl | 20 | 1 | 1.0 | - |
| curl-http2 | 20 | 1 | 1.0 | php-curl |
| curl-tls12 | 20 | 1 | 1.0 | - |
| curl-tls13 | 20 | 1 | 1.0 | - |
| curl_cffi-chrome104 | 20 | 1 | 1.0 | curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-chrome99_android, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome107 | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-chrome99_android, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome110 | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-chrome99_android, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome116 | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome99, curl_cffi-chrome99_android, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome120 | 20 | 2 | 0.8 | curl_cffi-chrome124, curl_cffi-chrome131, curl_cffi-chrome131_android |
| curl_cffi-chrome124 | 20 | 1 | 1.0 | curl_cffi-chrome120, curl_cffi-chrome131, curl_cffi-chrome131_android |
| curl_cffi-chrome131 | 20 | 1 | 1.0 | curl_cffi-chrome120, curl_cffi-chrome124, curl_cffi-chrome131_android |
| curl_cffi-chrome131_android | 20 | 2 | 0.8 | curl_cffi-chrome120, curl_cffi-chrome124, curl_cffi-chrome131 |
| curl_cffi-chrome133a | 20 | 1 | 1.0 | curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome145, curl_cffi-chrome146 |
| curl_cffi-chrome136 | 20 | 1 | 1.0 | curl_cffi-chrome133a, curl_cffi-chrome142, curl_cffi-chrome145, curl_cffi-chrome146 |
| curl_cffi-chrome142 | 20 | 1 | 1.0 | curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome145, curl_cffi-chrome146 |
| curl_cffi-chrome145 | 20 | 1 | 1.0 | curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome146 |
| curl_cffi-chrome146 | 20 | 1 | 1.0 | curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome145 |
| curl_cffi-chrome150 | 20 | 1 | 1.0 | - |
| curl_cffi-chrome99 | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99_android, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome99_android | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-edge101 | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-chrome99_android, curl_cffi-edge99 |
| curl_cffi-edge99 | 20 | 1 | 1.0 | curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-chrome99_android, curl_cffi-edge101 |
| curl_cffi-firefox133 | 20 | 1 | 1.0 | - |
| curl_cffi-firefox135 | 20 | 1 | 1.0 | curl_cffi-firefox144, curl_cffi-firefox147 |
| curl_cffi-firefox144 | 20 | 1 | 1.0 | curl_cffi-firefox135, curl_cffi-firefox147 |
| curl_cffi-firefox147 | 20 | 1 | 1.0 | curl_cffi-firefox135, curl_cffi-firefox144 |
| curl_cffi-safari170 | 20 | 1 | 1.0 | - |
| curl_cffi-safari180_ios | 20 | 1 | 1.0 | curl_cffi-safari184 |
| curl_cffi-safari184 | 20 | 1 | 1.0 | curl_cffi-safari180_ios |
| curl_cffi-safari260 | 20 | 1 | 1.0 | - |
| curl_cffi-safari2601 | 20 | 1 | 1.0 | - |
| curl_cffi-tor145 | 20 | 1 | 1.0 | - |
| go-http2 | 20 | 1 | 1.0 | - |
| go-net-http | 20 | 1 | 1.0 | - |
| java-httpclient | 20 | 2 | 0.95 | - |
| java-urlconnection | 20 | 2 | 0.95 | - |
| node-https | 20 | 1 | 1.0 | - |
| openssl-s_client | 20 | 1 | 1.0 | - |
| openssl-s_client-alpn-h2 | 20 | 1 | 1.0 | - |
| openssl-s_client-tls12 | 20 | 1 | 1.0 | - |
| php-curl | 20 | 1 | 1.0 | curl-http2 |
| php-stream | 20 | 1 | 1.0 | - |
| python-aiohttp | 20 | 1 | 1.0 | python-httpx |
| python-httpx | 20 | 1 | 1.0 | python-aiohttp |
| python-requests | 20 | 1 | 1.0 | - |
| python-urllib | 20 | 1 | 1.0 | - |
| ruby-net-http | 20 | 1 | 1.0 | - |
| wget | 20 | 1 | 1.0 | - |
| wget-tls12 | 20 | 1 | 1.0 | - |

