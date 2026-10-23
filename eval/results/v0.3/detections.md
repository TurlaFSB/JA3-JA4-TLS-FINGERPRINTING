# Detection evaluation: dataset v0.3

Intelligence feed built from: dataset/v0.2, dataset/v0.4.

Each client is judged in isolation against a freshly seeded database.

## Reproducibility of fingerprints across lab runs

28 of 28 clients present in both runs produced identical JA4 sets.

## Verdicts on client handshakes (percent of handshakes)

| group | clients | handshakes | benign | suspicious | malicious | unknown | no match |
|---|---|---|---|---|---|---|---|
| known-good clients, in the feed's source run | 17 | 328 | 100.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| known-good clients, not in the feed | 5 | 100 | 0.0 | 0.0 | 0.0 | 80.0 | 20.0 |
| impersonation profiles, in the feed's source run | 21 | 420 | 70.5 | 0.0 | 0.0 | 10.5 | 19.0 |
| impersonation profiles, not in the feed | 7 | 140 | 25.7 | 0.0 | 0.0 | 2.9 | 71.4 |

- known-good clients with any suspicious or malicious verdict: none
- impersonation profiles vouched for as benign: ['curl_cffi-chrome104', 'curl_cffi-chrome107', 'curl_cffi-chrome110', 'curl_cffi-chrome116', 'curl_cffi-chrome120', 'curl_cffi-chrome124', 'curl_cffi-chrome131', 'curl_cffi-chrome131_android', 'curl_cffi-chrome133a', 'curl_cffi-chrome136', 'curl_cffi-chrome142', 'curl_cffi-chrome145', 'curl_cffi-chrome146', 'curl_cffi-chrome99', 'curl_cffi-chrome99_android', 'curl_cffi-edge101', 'curl_cffi-edge99']
- known-good clients raising alerts other than first_seen (isolated): none

## Per client

| client | class | in feed source | handshakes | verdicts | best match | exact label | alerts (isolated) |
|---|---|---|---|---|---|---|---|
| chromium-headless | benign | yes | 8 | {'benign': 8} | {'exact': 8} | Chromium (headless, Playwright build) | {'first_seen': 6} |
| curl | benign | yes | 20 | {'benign': 20} | {'exact': 20} | curl (OpenSSL, HTTP/1.1) | {'first_seen': 4} |
| curl-http2 | benign | yes | 20 | {'benign': 20} | {'exact': 20} | curl (OpenSSL, HTTP/2) / PHP cURL | {'first_seen': 4} |
| curl-tls12 | benign | yes | 20 | {'benign': 20} | {'exact': 20} | curl (OpenSSL, TLS 1.2 only) | {'first_seen': 5} |
| curl-tls13 | benign | no | 20 | {'none': 20} | - | - | {'first_seen': 4} |
| curl_cffi-chrome104 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-chrome107 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-chrome110 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-chrome116 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-chrome120 | tool | yes | 20 | {'benign': 16, 'unknown': 4} | {'cipher_and_prefix': 4, 'exact': 16} | Chromium 131.0.1, 133.0.0 (headless shell) | {'first_seen': 5} |
| curl_cffi-chrome124 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Chromium 131.0.1, 133.0.0 (headless shell) | {'first_seen': 4} |
| curl_cffi-chrome131 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Chromium 131.0.1, 133.0.0 (headless shell) | {'first_seen': 4} |
| curl_cffi-chrome131_android | tool | no | 20 | {'benign': 16, 'unknown': 4} | {'cipher_and_prefix': 4, 'exact': 16} | Chromium 131.0.1, 133.0.0 (headless shell) | {'first_seen': 5} |
| curl_cffi-chrome133a | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Chromium 137.0.1, 138.0.2, 140.0.0, 141.0.0, 143.0.4 (headless shell) | {'first_seen': 4} |
| curl_cffi-chrome136 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Chromium 137.0.1, 138.0.2, 140.0.0, 141.0.0, 143.0.4 (headless shell) | {'first_seen': 4} |
| curl_cffi-chrome142 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Chromium 137.0.1, 138.0.2, 140.0.0, 141.0.0, 143.0.4 (headless shell) | {'first_seen': 4} |
| curl_cffi-chrome145 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Chromium 137.0.1, 138.0.2, 140.0.0, 141.0.0, 143.0.4 (headless shell) | {'first_seen': 4} |
| curl_cffi-chrome146 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Chromium 137.0.1, 138.0.2, 140.0.0, 141.0.0, 143.0.4 (headless shell) | {'first_seen': 4} |
| curl_cffi-chrome150 | tool | yes | 20 | {'unknown': 20} | {'cipher_and_prefix': 20} | - | {'first_seen': 4} |
| curl_cffi-chrome99 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-chrome99_android | tool | no | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-edge101 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-edge99 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-firefox133 | tool | yes | 20 | {'none': 20} | - | - | {'first_seen': 4} |
| curl_cffi-firefox135 | tool | no | 20 | {'none': 20} | - | - | {'first_seen': 4} |
| curl_cffi-firefox144 | tool | no | 20 | {'none': 20} | - | - | {'first_seen': 4} |
| curl_cffi-firefox147 | tool | yes | 20 | {'none': 20} | - | - | {'first_seen': 4} |
| curl_cffi-safari170 | tool | no | 20 | {'none': 20} | - | - | {'first_seen': 4} |
| curl_cffi-safari180_ios | tool | yes | 20 | {'none': 20} | - | - | {'first_seen': 4} |
| curl_cffi-safari184 | tool | no | 20 | {'none': 20} | - | - | {'first_seen': 4} |
| curl_cffi-safari260 | tool | no | 20 | {'none': 20} | - | - | {'first_seen': 4} |
| curl_cffi-safari2601 | tool | yes | 20 | {'none': 20} | - | - | {'first_seen': 4} |
| curl_cffi-tor145 | tool | yes | 20 | {'unknown': 20} | {'cipher_only': 20} | - | {'first_seen': 4} |
| go-http2 | benign | no | 20 | {'unknown': 20} | {'cipher_only': 20} | - | {'first_seen': 4} |
| go-net-http | benign | yes | 20 | {'benign': 20} | {'exact': 20} | Go net/http | {'first_seen': 4} |
| java-httpclient | benign | yes | 20 | {'benign': 20} | {'exact': 20} | Java HttpClient | {'first_seen': 6} |
| java-urlconnection | benign | no | 20 | {'unknown': 20} | {'cipher_only': 20} | - | {'first_seen': 6} |
| node-https | benign | yes | 20 | {'benign': 20} | {'exact': 20} | Node.js https | {'first_seen': 4} |
| openssl-s_client | benign | yes | 20 | {'benign': 20} | {'exact': 20} | OpenSSL s_client | {'first_seen': 4} |
| openssl-s_client-alpn-h2 | benign | no | 20 | {'unknown': 20} | {'cipher_only': 20} | - | {'first_seen': 4} |
| openssl-s_client-tls12 | benign | yes | 20 | {'benign': 20} | {'exact': 20} | OpenSSL s_client (TLS 1.2 only) | {'first_seen': 5} |
| php-curl | benign | yes | 20 | {'benign': 20} | {'exact': 20} | curl (OpenSSL, HTTP/2) / PHP cURL | {'first_seen': 4} |
| php-stream | benign | yes | 20 | {'benign': 20} | {'exact': 20} | PHP streams | {'first_seen': 4} |
| python-aiohttp | benign | yes | 20 | {'benign': 20} | {'exact': 20} | Python aiohttp / Python httpx | {'first_seen': 4} |
| python-httpx | benign | yes | 20 | {'benign': 20} | {'exact': 20} | Python aiohttp / Python httpx | {'first_seen': 4} |
| python-requests | benign | yes | 20 | {'benign': 20} | {'exact': 20} | Python requests (urllib3) | {'first_seen': 4} |
| python-urllib | benign | yes | 20 | {'benign': 20} | {'exact': 20} | Python urllib | {'first_seen': 4} |
| ruby-net-http | benign | yes | 20 | {'benign': 20} | {'exact': 20} | Ruby Net::HTTP | {'first_seen': 4} |
| wget | benign | yes | 20 | {'benign': 20} | {'exact': 20} | wget (OpenSSL) | {'first_seen': 4} |
| wget-tls12 | benign | no | 20 | {'unknown': 20} | {'cipher_only': 20} | - | {'first_seen': 4} |

## All clients behind one address

Every capture replayed into a single database, as a NAT gateway or shared workstation would present. The second column repeats the run with the address declared as a shared network (`--shared-network 127.0.0.1`).

| rule | severity | alerts | alerts with the address declared shared |
|---|---|---|---|
| first_seen | info | 42 | 42 |
| fp_rotation | medium | 30 | 0 |
