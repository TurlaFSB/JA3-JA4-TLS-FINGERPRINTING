# Detection evaluation: dataset v0.3

Intelligence feed built from: dataset/v0.2 (held out from this dataset's captures).

Each client is judged in isolation against a freshly seeded database.

## Reproducibility of fingerprints across lab runs

28 of 28 clients present in both runs produced identical JA4 sets.

## Verdicts on client handshakes (percent of handshakes)

| group | clients | handshakes | benign | suspicious | malicious | unknown | no match |
|---|---|---|---|---|---|---|---|
| known-good clients, in the feed's source run | 17 | 328 | 100.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| known-good clients, not in the feed | 5 | 100 | 0.0 | 0.0 | 0.0 | 80.0 | 20.0 |
| impersonation profiles, in the feed's source run | 11 | 220 | 9.1 | 90.9 | 0.0 | 0.0 | 0.0 |
| impersonation profiles, not in the feed | 17 | 340 | 41.2 | 58.8 | 0.0 | 0.0 | 0.0 |

- known-good clients with any suspicious or malicious verdict: none
- impersonation profiles vouched for as benign: ['curl_cffi-chrome104', 'curl_cffi-chrome107', 'curl_cffi-chrome110', 'curl_cffi-chrome116', 'curl_cffi-chrome99', 'curl_cffi-chrome99_android', 'curl_cffi-edge101', 'curl_cffi-edge99']
- known-good clients raising alerts other than first_seen (isolated): none

## Per client

| client | class | in feed source | handshakes | verdicts | best match | exact label | alerts (isolated) |
|---|---|---|---|---|---|---|---|
| chromium-headless | benign | yes | 8 | {'benign': 8} | {'exact': 8} | Chromium (headless, Playwright build) | {'first_seen': 6} |
| curl | benign | yes | 20 | {'benign': 20} | {'exact': 20} | curl (OpenSSL, HTTP/1.1) | {'first_seen': 4} |
| curl-http2 | benign | yes | 20 | {'benign': 20} | {'exact': 20} | curl (OpenSSL, HTTP/2) / PHP cURL | {'first_seen': 4} |
| curl-tls12 | benign | yes | 20 | {'benign': 20} | {'exact': 20} | curl (OpenSSL, TLS 1.2 only) | {'first_seen': 5} |
| curl-tls13 | benign | no | 20 | {'none': 20} | - | - | {'first_seen': 4} |
| curl_cffi-chrome104 | tool | no | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-chrome107 | tool | no | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-chrome110 | tool | no | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-chrome116 | tool | no | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-chrome120 | tool | yes | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating chrome120; curl_cffi impersonating chrome120 / curl_cffi impersonating chrome124 / curl_cffi impersonating chrome131 | {'first_seen': 5, 'known_bad': 2} |
| curl_cffi-chrome124 | tool | yes | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating chrome120 / curl_cffi impersonating chrome124 / curl_cffi impersonating chrome131 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-chrome131 | tool | yes | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating chrome120 / curl_cffi impersonating chrome124 / curl_cffi impersonating chrome131 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-chrome131_android | tool | no | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating chrome120; curl_cffi impersonating chrome120 / curl_cffi impersonating chrome124 / curl_cffi impersonating chrome131 | {'first_seen': 5, 'known_bad': 2} |
| curl_cffi-chrome133a | tool | no | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating chrome142 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-chrome136 | tool | no | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating chrome142 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-chrome142 | tool | yes | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating chrome142 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-chrome145 | tool | no | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating chrome142 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-chrome146 | tool | no | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating chrome142 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-chrome150 | tool | yes | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating chrome150 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-chrome99 | tool | no | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-chrome99_android | tool | no | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-edge101 | tool | yes | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-edge99 | tool | no | 20 | {'benign': 20} | {'exact': 20} | Google Chrome | {'first_seen': 4} |
| curl_cffi-firefox133 | tool | yes | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating firefox133 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-firefox135 | tool | no | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating firefox147 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-firefox144 | tool | no | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating firefox147 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-firefox147 | tool | yes | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating firefox147 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-safari170 | tool | no | 20 | {'suspicious': 20} | {'cipher_and_prefix': 20} | - | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-safari180_ios | tool | yes | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating safari180_ios | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-safari184 | tool | no | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating safari180_ios | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-safari260 | tool | no | 20 | {'suspicious': 20} | {'cipher_and_prefix': 20} | - | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-safari2601 | tool | yes | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating safari2601 | {'first_seen': 4, 'known_bad': 1} |
| curl_cffi-tor145 | tool | yes | 20 | {'suspicious': 20} | {'exact': 20} | curl_cffi impersonating tor145 | {'first_seen': 4, 'known_bad': 1} |
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

Every capture replayed into a single database, as a NAT gateway or shared workstation would present.

| rule | severity | alerts |
|---|---|---|
| first_seen | info | 42 |
| fp_rotation | medium | 30 |
| known_bad | medium | 11 |
