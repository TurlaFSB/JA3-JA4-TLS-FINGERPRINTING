# HTTP-layer separation: dataset v0.5

Cleartext HTTP requests from real Chromium builds and curl-impersonate profiles, served from one plain-HTTP server under a non-secure hostname. JA4H fingerprints the request: method, version, header order, cookies, language.

- real browser builds with HTTP traffic: 10; impersonation profiles: 17
- profiles sharing a JA4H with a real build (inseparable here): 0
- profiles whose JA4H matches no real build: 17 (curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome120, curl_cffi-chrome124, curl_cffi-chrome131, curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome145, curl_cffi-chrome146, curl_cffi-chrome150, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-firefox147, curl_cffi-safari2601, curl_cffi-tor145)

## JA4H groups

| JA4H | real browsers | impersonation profiles | libraries |
|---|---|---|---|
| `ge11nn020000_1af9d02f0bf7_000000000000_000000000000` | - | - | php-curl |
| `ge11nn020000_d5c75abc5c2c_000000000000_000000000000` | - | - | node-https |
| `ge11nn030000_cd680697de12_000000000000_000000000000` | - | - | go-net-http |
| `ge11nn030000_fe444ad14866_000000000000_000000000000` | - | - | curl |
| `ge11nn040000_80c20a6e2957_000000000000_000000000000` | - | - | ruby-net-http |
| `ge11nn050000_3658ef221638_000000000000_000000000000` | - | - | wget |
| `ge11nn050000_b223a0ebb0b5_000000000000_000000000000` | - | - | python-requests |
| `ge11nn050000_be0d0b335e46_000000000000_000000000000` | - | - | python-httpx |
| `ge11nn060000_10317b2cb409_000000000000_000000000000` | chromium-131.0.1, chromium-133.0.0, chromium-137.0.1, chromium-138.0.2, chromium-140.0.0, chromium-141.0.0, chromium-143.0.4 | - | - |
| `ge11nn07enus_106dff3e66d0_000000000000_000000000000` | chromium-full | - | - |
| `ge11nn07enus_bc8d2ed93139_000000000000_000000000000` | chromium-107.0.0, chromium-110.0.1 | - | - |
| `ge11nn11enus_e0c80960df9b_000000000000_000000000000` | - | curl_cffi-safari2601 | - |
| `ge11nn15enus_8d04b9429171_000000000000_000000000000` | - | curl_cffi-firefox147 | - |
| `ge11nn16enus_b8dcc200854e_000000000000_000000000000` | - | curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome120, curl_cffi-chrome124, curl_cffi-chrome131, curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome145, curl_cffi-chrome146, curl_cffi-chrome150, curl_cffi-chrome99, curl_cffi-edge101 | - |
| `ge11nn16enus_f8d9224aba8c_000000000000_000000000000` | - | curl_cffi-tor145 | - |
| `ge11nr06enus_48fd33bb44de_000000000000_000000000000` | chromium-full | - | - |

## Header order per client

| client | class | requests | header order |
|---|---|---|---|
| chromium-107.0.0 | browser | 5 | Host,Connection,Upgrade-Insecure-Requests,User-Agent,Accept,Accept-Encoding,Accept-Language |
| chromium-110.0.1 | browser | 5 | Host,Connection,Upgrade-Insecure-Requests,User-Agent,Accept,Accept-Encoding,Accept-Language |
| chromium-131.0.1 | browser | 5 | Host,Connection,Upgrade-Insecure-Requests,User-Agent,Accept,Accept-Encoding |
| chromium-133.0.0 | browser | 5 | Host,Connection,Upgrade-Insecure-Requests,User-Agent,Accept,Accept-Encoding |
| chromium-137.0.1 | browser | 5 | Host,Connection,Upgrade-Insecure-Requests,User-Agent,Accept,Accept-Encoding |
| chromium-138.0.2 | browser | 5 | Host,Connection,Upgrade-Insecure-Requests,User-Agent,Accept,Accept-Encoding |
| chromium-140.0.0 | browser | 5 | Host,Connection,Upgrade-Insecure-Requests,User-Agent,Accept,Accept-Encoding |
| chromium-141.0.0 | browser | 5 | Host,Connection,Upgrade-Insecure-Requests,User-Agent,Accept,Accept-Encoding |
| chromium-143.0.4 | browser | 5 | Host,Connection,Upgrade-Insecure-Requests,User-Agent,Accept,Accept-Encoding |
| chromium-full | browser | 10 | Host,Connection,Accept-Language,Upgrade-Insecure-Requests,User-Agent,Accept,Accept-Encoding |
| chromium-full | browser | 10 | Host,Connection,Accept-Language,User-Agent,Accept,Accept-Encoding |
| curl | library | 10 | Host,User-Agent,Accept |
| curl_cffi-chrome107 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome110 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome116 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome120 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome124 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome131 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome133a | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome136 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome142 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome145 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome146 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome150 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-chrome99 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-edge101 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,Upgrade-Insecure-Requests,User-Agent,Accept,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-User,Sec-Fetch-Dest,Accept-Encoding,Accept-Language,Connection |
| curl_cffi-firefox147 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,User-Agent,Accept,Accept-Language,Accept-Encoding,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,Priority,Te,Connection |
| curl_cffi-safari2601 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,sec-fetch-dest,user-agent,accept,sec-fetch-site,sec-fetch-mode,accept-language,accept-encoding,Connection |
| curl_cffi-tor145 | impersonation | 10 | Host,Upgrade,HTTP2-Settings,User-Agent,Accept,Accept-Language,Accept-Encoding,Sec-GPC,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,Priority,Te,Connection |
| go-net-http | library | 10 | Host,User-Agent,Accept-Encoding |
| node-https | library | 10 | Host,Connection |
| php-curl | library | 10 | Host,Accept |
| python-httpx | library | 10 | Host,Accept,Accept-Encoding,Connection,User-Agent |
| python-requests | library | 10 | Host,User-Agent,Accept-Encoding,Accept,Connection |
| ruby-net-http | library | 10 | Accept-Encoding,Accept,User-Agent,Host |
| wget | library | 10 | Host,User-Agent,Accept,Accept-Encoding,Connection |
