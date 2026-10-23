# Fingerprint evaluation: dataset v0.4

Environment: Linux-6.18.44-fc-v153-x86_64-with-glibc2.39, TLS server OpenSSL 3.0.13 30 Jan 2024, transport loopback.

## JA3

- clients: 26
- clients whose dominant fingerprint is unique: 19/26
- mean distinct fingerprints per client: 10.462
- mean share of the dominant fingerprint: 0.3481

| client | handshakes | distinct | dominant share | shares fingerprint with |
|---|---|---|---|---|
| chromium-headless | 10 | 10 | 0.1 | - |
| chromium-real-107.0.0 | 5 | 1 | 1.0 | chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| chromium-real-110.0.1 | 5 | 1 | 1.0 | chromium-real-107.0.0, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| chromium-real-131.0.1 | 5 | 5 | 0.2 | - |
| chromium-real-133.0.0 | 5 | 5 | 0.2 | - |
| chromium-real-137.0.1 | 5 | 5 | 0.2 | - |
| chromium-real-138.0.2 | 5 | 5 | 0.2 | - |
| chromium-real-140.0.0 | 5 | 5 | 0.2 | - |
| chromium-real-141.0.0 | 5 | 5 | 0.2 | - |
| chromium-real-143.0.4 | 5 | 5 | 0.2 | - |
| curl_cffi-chrome104 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome107, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome107 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome110 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome116 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome120 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome124 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome131 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome133a | 20 | 20 | 0.05 | - |
| curl_cffi-chrome136 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome142 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome145 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome146 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome150 | 20 | 20 | 0.05 | - |
| curl_cffi-chrome99 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-edge101 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome99, curl_cffi-edge99 |
| curl_cffi-edge99 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome99, curl_cffi-edge101 |

## JA4

- clients: 26
- clients whose dominant fingerprint is unique: 2/26
- mean distinct fingerprints per client: 1.077
- mean share of the dominant fingerprint: 0.9712

| client | handshakes | distinct | dominant share | shares fingerprint with |
|---|---|---|---|---|
| chromium-headless | 10 | 2 | 0.5 | - |
| chromium-real-107.0.0 | 5 | 1 | 1.0 | chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| chromium-real-110.0.1 | 5 | 1 | 1.0 | chromium-real-107.0.0, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| chromium-real-131.0.1 | 5 | 1 | 1.0 | chromium-real-133.0.0, curl_cffi-chrome120, curl_cffi-chrome124, curl_cffi-chrome131 |
| chromium-real-133.0.0 | 5 | 1 | 1.0 | chromium-real-131.0.1, curl_cffi-chrome120, curl_cffi-chrome124, curl_cffi-chrome131 |
| chromium-real-137.0.1 | 5 | 1 | 1.0 | chromium-real-138.0.2, chromium-real-140.0.0, chromium-real-141.0.0, chromium-real-143.0.4, curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome145, curl_cffi-chrome146 |
| chromium-real-138.0.2 | 5 | 1 | 1.0 | chromium-real-137.0.1, chromium-real-140.0.0, chromium-real-141.0.0, chromium-real-143.0.4, curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome145, curl_cffi-chrome146 |
| chromium-real-140.0.0 | 5 | 1 | 1.0 | chromium-real-137.0.1, chromium-real-138.0.2, chromium-real-141.0.0, chromium-real-143.0.4, curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome145, curl_cffi-chrome146 |
| chromium-real-141.0.0 | 5 | 1 | 1.0 | chromium-real-137.0.1, chromium-real-138.0.2, chromium-real-140.0.0, chromium-real-143.0.4, curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome145, curl_cffi-chrome146 |
| chromium-real-143.0.4 | 5 | 1 | 1.0 | chromium-real-137.0.1, chromium-real-138.0.2, chromium-real-140.0.0, chromium-real-141.0.0, curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome145, curl_cffi-chrome146 |
| curl_cffi-chrome104 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome107 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome110 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome116 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome99, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-chrome120 | 20 | 2 | 0.75 | chromium-real-131.0.1, chromium-real-133.0.0, curl_cffi-chrome124, curl_cffi-chrome131 |
| curl_cffi-chrome124 | 20 | 1 | 1.0 | chromium-real-131.0.1, chromium-real-133.0.0, curl_cffi-chrome120, curl_cffi-chrome131 |
| curl_cffi-chrome131 | 20 | 1 | 1.0 | chromium-real-131.0.1, chromium-real-133.0.0, curl_cffi-chrome120, curl_cffi-chrome124 |
| curl_cffi-chrome133a | 20 | 1 | 1.0 | chromium-real-137.0.1, chromium-real-138.0.2, chromium-real-140.0.0, chromium-real-141.0.0, chromium-real-143.0.4, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome145, curl_cffi-chrome146 |
| curl_cffi-chrome136 | 20 | 1 | 1.0 | chromium-real-137.0.1, chromium-real-138.0.2, chromium-real-140.0.0, chromium-real-141.0.0, chromium-real-143.0.4, curl_cffi-chrome133a, curl_cffi-chrome142, curl_cffi-chrome145, curl_cffi-chrome146 |
| curl_cffi-chrome142 | 20 | 1 | 1.0 | chromium-real-137.0.1, chromium-real-138.0.2, chromium-real-140.0.0, chromium-real-141.0.0, chromium-real-143.0.4, curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome145, curl_cffi-chrome146 |
| curl_cffi-chrome145 | 20 | 1 | 1.0 | chromium-real-137.0.1, chromium-real-138.0.2, chromium-real-140.0.0, chromium-real-141.0.0, chromium-real-143.0.4, curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome146 |
| curl_cffi-chrome146 | 20 | 1 | 1.0 | chromium-real-137.0.1, chromium-real-138.0.2, chromium-real-140.0.0, chromium-real-141.0.0, chromium-real-143.0.4, curl_cffi-chrome133a, curl_cffi-chrome136, curl_cffi-chrome142, curl_cffi-chrome145 |
| curl_cffi-chrome150 | 20 | 1 | 1.0 | - |
| curl_cffi-chrome99 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-edge101, curl_cffi-edge99 |
| curl_cffi-edge101 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-edge99 |
| curl_cffi-edge99 | 20 | 1 | 1.0 | chromium-real-107.0.0, chromium-real-110.0.1, curl_cffi-chrome104, curl_cffi-chrome107, curl_cffi-chrome110, curl_cffi-chrome116, curl_cffi-chrome99, curl_cffi-edge101 |

