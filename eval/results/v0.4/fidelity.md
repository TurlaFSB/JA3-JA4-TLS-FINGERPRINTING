# Impersonation fidelity: dataset v0.4

9 real Chromium builds against 16 curl-impersonate Chrome and Edge profiles. A profile whose JA4 equals a real build's cannot be separated from that browser by any ClientHello hash.

- real builds whose JA4 equals their nearest-version profile's: **8 of 9**
- profiles whose JA4 equals some real build's: 15 of 16
- profiles with no real counterpart in this dataset: chrome150

## JA4 groups

| JA4 | real builds | profiles |
|---|---|---|
| `t13d1516h2_8daaf6152771_02713d6af862` | 131.0.1, 133.0.0 | chrome120, chrome124, chrome131 |
| `t13d1516h2_8daaf6152771_806a8c22fdea` | - | chrome150 |
| `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 137.0.1, 138.0.2, 140.0.0, 141.0.0, 143.0.4 | chrome133a, chrome136, chrome142, chrome145, chrome146 |
| `t13d1516h2_8daaf6152771_e5627efa2ab1` | 107.0.0, 110.0.1 | chrome104, chrome107, chrome110, chrome116, chrome99, edge101, edge99 |
| `t13d1517h2_8daaf6152771_b1ff8ab2d16f` | - | chrome120 |

## Real build against nearest profile

| real build | JA4 | nearest profile | identical |
|---|---|---|---|
| 107.0.0 | `t13d1516h2_8daaf6152771_e5627efa2ab1` | chrome107 | yes |
| 110.0.1 | `t13d1516h2_8daaf6152771_e5627efa2ab1` | chrome110 | yes |
| 131.0.1 | `t13d1516h2_8daaf6152771_02713d6af862` | chrome131 | yes |
| 133.0.0 | `t13d1516h2_8daaf6152771_02713d6af862` | chrome133a | no |
| 137.0.1 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | chrome136 | yes |
| 138.0.2 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | chrome136 | yes |
| 140.0.0 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | chrome142 | yes |
| 141.0.0 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | chrome142 | yes |
| 143.0.4 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | chrome142 | yes |
