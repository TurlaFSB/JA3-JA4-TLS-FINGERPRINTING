# Impersonation fidelity: dataset v0.6

25 real browser builds (25 full Chrome) against 20 curl-impersonate Chrome and Edge profiles. A profile whose JA4 equals a real build's cannot be separated from it by any ClientHello hash; one that differs can, until the profile is updated.

- real builds that produced no handshake in the lab and are excluded: chrome-real-113, chrome-real-114, chrome-real-115, chrome-real-116, chrome-real-117, chrome-real-121
- real builds whose JA4 equals their nearest-version profile's: **0 of 25**
- profiles whose JA4 equals some real build's: **0 of 20**
- profiles matching no real build: 20 (chrome100, chrome101, chrome104, chrome107, chrome110, chrome116, chrome119, chrome120, chrome123, chrome124, chrome131, chrome133a, chrome136, chrome142, chrome145, chrome146, chrome150, chrome99, edge101, edge99)

## Each real build against the nearest-version profile

| real build | nearest profile | identical | only in the real browser | only in the profile |
|---|---|---|---|---|
| chrome-real-118 (118.0.5993.70) | chrome119 | no | - | encrypted_client_hello, padding |
| chrome-real-119 (119.0.6045.105) | chrome119 | no | - | encrypted_client_hello, padding |
| chrome-real-120 (120.0.6099.109) | chrome120 | no | - | encrypted_client_hello, padding |
| chrome-real-122 (122.0.6261.69) | chrome123 | no | - | encrypted_client_hello, padding |
| chrome-real-123 (123.0.6312.58) | chrome123 | no | - | encrypted_client_hello, padding |
| chrome-real-124 (124.0.6367.60) | chrome124 | no | - | encrypted_client_hello |
| chrome-real-125 (125.0.6422.60) | chrome124 | no | - | encrypted_client_hello |
| chrome-real-126 (126.0.6478.55) | chrome124 | no | - | encrypted_client_hello |
| chrome-real-127 (127.0.6533.72) | chrome124 | no | alps (new codepoint 0x44cd) | alps (legacy codepoint 0x4469), encrypted_client_hello |
| chrome-real-128 (128.0.6613.84) | chrome131 | no | alps (new codepoint 0x44cd) | alps (legacy codepoint 0x4469), encrypted_client_hello |
| chrome-real-129 (129.0.6668.58) | chrome131 | no | alps (new codepoint 0x44cd) | alps (legacy codepoint 0x4469), encrypted_client_hello |
| chrome-real-130 (130.0.6723.58) | chrome131 | no | alps (new codepoint 0x44cd) | alps (legacy codepoint 0x4469), encrypted_client_hello |
| chrome-real-131 (131.0.6778.85) | chrome131 | no | alps (new codepoint 0x44cd) | alps (legacy codepoint 0x4469), encrypted_client_hello |
| chrome-real-132 (132.0.6834.83) | chrome133a | no | - | encrypted_client_hello |
| chrome-real-133 (133.0.6943.53) | chrome133a | no | - | encrypted_client_hello |
| chrome-real-134 (134.0.6998.35) | chrome133a | no | - | encrypted_client_hello |
| chrome-real-135 (135.0.7049.42) | chrome136 | no | - | encrypted_client_hello |
| chrome-real-136 (136.0.7103.49) | chrome136 | no | - | encrypted_client_hello |
| chrome-real-137 (137.0.7151.55) | chrome136 | no | - | encrypted_client_hello |
| chrome-real-138 (138.0.7204.49) | chrome136 | no | - | encrypted_client_hello |
| chrome-real-139 (139.0.7258.66) | chrome142 | no | - | encrypted_client_hello |
| chrome-real-140 (140.0.7339.80) | chrome142 | no | - | encrypted_client_hello |
| chrome-real-141 (141.0.7390.54) | chrome142 | no | trust_anchors | encrypted_client_hello |
| chrome-real-142 (142.0.7444.59) | chrome142 | no | trust_anchors | encrypted_client_hello |
| chrome-real-143 (143.0.7499.40) | chrome142 | no | trust_anchors | encrypted_client_hello |

## JA4 groups

| JA4 | real builds | profiles |
|---|---|---|
| `t13d1515h2_8daaf6152771_22334254f9f7` | 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140 | - |
| `t13d1515h2_8daaf6152771_f37e75b10bcc` | 118, 119, 120, 122, 123, 124, 125, 126 | - |
| `t13d1516h2_8daaf6152771_02713d6af862` | - | chrome119, chrome120, chrome123, chrome124, chrome131 |
| `t13d1516h2_8daaf6152771_806a8c22fdea` | - | chrome150 |
| `t13d1516h2_8daaf6152771_d8a2da3f94cd` | - | chrome133a, chrome136, chrome142, chrome145, chrome146 |
| `t13d1516h2_8daaf6152771_e15453cad77d` | 141, 142, 143 | - |
| `t13d1516h2_8daaf6152771_e2868af24dc0` | 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140 | - |
| `t13d1516h2_8daaf6152771_e5627efa2ab1` | - | chrome100, chrome101, chrome104, chrome107, chrome110, chrome116, chrome99, edge101, edge99 |
| `t13d1517h2_8daaf6152771_b1ff8ab2d16f` | - | chrome119, chrome120, chrome123 |
| `t13d1517h2_8daaf6152771_eacfb8afcfec` | 141, 142, 143 | - |
