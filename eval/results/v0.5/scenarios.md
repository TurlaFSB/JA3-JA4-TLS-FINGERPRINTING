# Cross-layer rule evaluation: dataset v0.5

Each scenario is one client sending HTTPS (its TLS fingerprint) and cleartext HTTP (its claimed User-Agent) from one address, to a non-secure hostname. `ua lie` = a non-browser claiming a browser; `os lie` = a Windows claim from a Linux host. Cells read caught / lies, then false alarms / honest.

| group | scenarios | ua_mismatch | header_anomaly | either | os_mismatch |
|---|---|---|---|---|---|
| all scenarios | 53 | 16/35 caught, 0/18 false | 17/35 caught, 0/18 false | 33/35 caught, 0/18 false | 14/14 caught, 0/39 false |
| library, honest User-Agent | 8 | 0/0 caught, 0/8 false | 0/0 caught, 0/8 false | 0/0 caught, 0/8 false | 0/0 caught, 0/8 false |
| library, lying User-Agent | 16 | 16/16 caught, 0/0 false | 0/16 caught, 0/0 false | 16/16 caught, 0/0 false | 8/8 caught, 0/8 false |
| impersonation profile, defaults | 17 | 0/17 caught, 0/0 false | 17/17 caught, 0/0 false | 17/17 caught, 0/0 false | 5/5 caught, 0/12 false |
| impersonation, defaults stripped (adaptive) | 2 | 0/2 caught, 0/0 false | 0/2 caught, 0/0 false | 0/2 caught, 0/0 false | 1/1 caught, 0/1 false |
| real browser | 10 | 0/0 caught, 0/10 false | 0/0 caught, 0/10 false | 0/0 caught, 0/10 false | 0/0 caught, 0/10 false |

## Per scenario

| scenario | class | ua lie | ua_mismatch | header_anomaly | os lie | os_mismatch | user agent |
|---|---|---|---|---|---|---|---|
| chromium-107.0.0__native | browser | no | - | - | no | - | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/... |
| chromium-110.0.1__native | browser | no | - | - | no | - | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/... |
| chromium-131.0.1__native | browser | no | - | - | no | - | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/... |
| chromium-133.0.0__native | browser | no | - | - | no | - | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/... |
| chromium-137.0.1__native | browser | no | - | - | no | - | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/... |
| chromium-138.0.2__native | browser | no | - | - | no | - | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/... |
| chromium-140.0.0__native | browser | no | - | - | no | - | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/... |
| chromium-141.0.0__native | browser | no | - | - | no | - | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/... |
| chromium-143.0.4__native | browser | no | - | - | no | - | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/... |
| chromium-full__native | browser | no | - | - | no | - | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/... |
| curl__chrome-win | library | yes | ALERT | - | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| curl__native | library | no | - | - | no | - | curl/8.5.0... |
| curl__safari-mac | library | yes | ALERT | - | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-chrome107__native | impersonation | yes | - | ALERT | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| curl_cffi-chrome110__native | impersonation | yes | - | ALERT | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| curl_cffi-chrome116__native | impersonation | yes | - | ALERT | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| curl_cffi-chrome120__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-chrome124__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-chrome131__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-chrome133a__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-chrome136__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-chrome142__evasive | evasive-impersonation | yes | - | - | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| curl_cffi-chrome142__evasive-unix | evasive-impersonation | yes | - | - | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-chrome142__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-chrome145__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-chrome146__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-chrome150__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-chrome99__native | impersonation | yes | - | ALERT | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| curl_cffi-edge101__native | impersonation | yes | - | ALERT | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| curl_cffi-firefox147__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15... |
| curl_cffi-safari2601__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| curl_cffi-tor145__native | impersonation | yes | - | ALERT | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15... |
| go-net-http__chrome-win | library | yes | ALERT | - | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| go-net-http__native | library | no | - | - | no | - | Go-http-client/1.1... |
| go-net-http__safari-mac | library | yes | ALERT | - | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| node-https__chrome-win | library | yes | ALERT | - | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| node-https__native | library | no | - | - | no | - | - |
| node-https__safari-mac | library | yes | ALERT | - | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| php-curl__chrome-win | library | yes | ALERT | - | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| php-curl__native | library | no | - | - | no | - | - |
| php-curl__safari-mac | library | yes | ALERT | - | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| python-httpx__chrome-win | library | yes | ALERT | - | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| python-httpx__native | library | no | - | - | no | - | python-httpx/0.28.1... |
| python-httpx__safari-mac | library | yes | ALERT | - | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| python-requests__chrome-win | library | yes | ALERT | - | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| python-requests__native | library | no | - | - | no | - | python-requests/2.34.2... |
| python-requests__safari-mac | library | yes | ALERT | - | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| ruby-net-http__chrome-win | library | yes | ALERT | - | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| ruby-net-http__native | library | no | - | - | no | - | Ruby... |
| ruby-net-http__safari-mac | library | yes | ALERT | - | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
| wget__chrome-win | library | yes | ALERT | - | yes | ALERT | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Ap... |
| wget__native | library | no | - | - | no | - | Wget/1.21.4... |
| wget__safari-mac | library | yes | ALERT | - | no | - | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15... |
