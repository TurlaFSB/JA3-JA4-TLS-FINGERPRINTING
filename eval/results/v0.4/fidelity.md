# Impersonation fidelity: dataset v0.4

9 real browser builds (0 full Chrome) against 16 curl-impersonate Chrome and Edge profiles. A profile whose JA4 equals a real build's cannot be separated from it by any ClientHello hash; one that differs can, until the profile is updated.

- real builds that produced no handshake in the lab and are excluded: none
- real builds whose JA4 equals their nearest-version profile's: **8 of 9**
- profiles whose JA4 equals some real build's: **15 of 16** (chrome104, chrome107, chrome110, chrome116, chrome120, chrome124, chrome131, chrome133a, chrome136, chrome142, chrome145, chrome146, chrome99, edge101, edge99)
- profiles matching no real build: 1 (chrome150)

## Each real build against the nearest-version profile

| real build | nearest profile | identical | only in the real browser | only in the profile |
|---|---|---|---|---|
| chromium-real-107.0.0 (@sparticuz/chromium)) | chrome107 | yes | - | - |
| chromium-real-110.0.1 (@sparticuz/chromium)) | chrome110 | yes | - | - |
| chromium-real-131.0.1 (@sparticuz/chromium)) | chrome131 | yes | - | - |
| chromium-real-133.0.0 (@sparticuz/chromium)) | chrome133a | no | alps (legacy codepoint 0x4469) | alps (new codepoint 0x44cd) |
| chromium-real-137.0.1 (@sparticuz/chromium)) | chrome136 | yes | - | - |
| chromium-real-138.0.2 (@sparticuz/chromium)) | chrome136 | yes | - | - |
| chromium-real-140.0.0 (@sparticuz/chromium)) | chrome142 | yes | - | - |
| chromium-real-141.0.0 (@sparticuz/chromium)) | chrome142 | yes | - | - |
| chromium-real-143.0.4 (@sparticuz/chromium)) | chrome142 | yes | - | - |

## JA4 groups

| JA4 | real builds | profiles |
|---|---|---|
| `t13d1516h2_8daaf6152771_02713d6af862` | 131.0.1, 133.0.0 | chrome120, chrome124, chrome131 |
| `t13d1516h2_8daaf6152771_806a8c22fdea` | - | chrome150 |
| `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 137.0.1, 138.0.2, 140.0.0, 141.0.0, 143.0.4 | chrome133a, chrome136, chrome142, chrome145, chrome146 |
| `t13d1516h2_8daaf6152771_e5627efa2ab1` | 107.0.0, 110.0.1 | chrome104, chrome107, chrome110, chrome116, chrome99, edge101, edge99 |
| `t13d1517h2_8daaf6152771_b1ff8ab2d16f` | - | chrome120 |
