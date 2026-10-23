# Performance

Measured, single core, one machine. Treat the figures as orders of magnitude for planning, not as a guarantee: they depend on the CPU, the traffic mix and the disk.

**Machine:** Intel Xeon @ 2.1 GHz virtual machine, 4 vCPU, Linux, release build. The sensor is single threaded; the extra cores were idle.

## Hot path (criterion, `cargo bench -p tlsfp-core`)

| Operation | Time |
|---|---|
| Parse one ClientHello | 143 ns |
| JA3 of a parsed ClientHello | 1.2 µs |
| JA4 of a parsed ClientHello | 3.2 µs |
| Whole pipeline over the bundled `tls-handshake` capture | 0.84 ms (about 180,000 events/s) |
| Whole pipeline over the bundled `browsers-x509` capture | 74 µs (about 255,000 events/s) |

## End to end (`eval/throughput.py`)

Three lab captures (a real Chrome, and curl-impersonate Firefox and Chrome profiles) copied 300 times with the ephemeral ports rewritten per copy, so every copy is a new set of flows: 76.8 MB, 215,700 frames, 31,200 TLS handshakes, all TCP, all from one source address.

| Mode | Time | Frames/s | TLS handshakes/s |
|---|---|---|---|
| Fingerprinting only (`tlsfp pcap`) | 0.34 s | about 630,000 | about 91,000 |
| With intelligence and detection (`--intel --detect`) | 10.3 s | about 21,000 | about 3,000 |

Resident memory stayed under 50 MB in both.

## QUIC Initial decryption

`quic-with-several-tls-frames.pcapng` (a QUIC Initial carrying several TLS frames) copied 20,000 times with the client port rewritten per copy: 26.2 MB, 20,000 UDP datagrams, every one decrypted and fingerprinted.

| Mode | Time | Initials/s |
|---|---|---|
| Fingerprinting only | 0.24 s | about 82,000 |
| With `--intel --detect` | 4.4 s | about 4,600 |

Initial decryption (key derivation, header-protection removal, AEAD) costs roughly the same order as parsing a TLS handshake over TCP. These are 20,000 copies of the same payload from one address, so they show the cost of the cryptography and the store, not a realistic mix. A capture of a real Chrome session was also tried (`chrome-cloudflare-quic-with-secrets.pcapng`), but it holds a single Initial, so it says nothing about throughput and is not reported.

## Live capture

`tlsfp live lo --intel --detect` on the loopback interface of the same machine, with a Python client making 1,000 TLS 1.3 connections to a local server (16 threads, about 42 connections per second, limited by the Python client, not by the sensor):

- 1,000 of 1,000 client hellos and 1,000 of 1,000 server hellos were reported; 0 unfinished TLS streams; 0 dropped TCP segments.
- The kernel capture statistics, printed when the sensor stops, showed `kernel_dropped=6` out of 26,786 frames received. The sensor printed its warning that an absent fingerprint is not proof of an absent handshake. All handshakes were present anyway; the six dropped frames were not ones the sensor needed.

This shows that live capture works end to end and that the kernel loss counter is real. It is not a stress test: the offered load was a small fraction of the replay rate above.

## Reading these numbers

- **Fingerprinting is not the cost; the store is.** Matching every fingerprint against the catalogue and recording every observation and alert in SQLite is about thirty times slower than computing the fingerprints. Whether about 3,000 handshakes a second with detection on is enough depends on the new-connection rate of the link being watched, which this project has not measured on any real network. Above that rate, run fingerprinting only, sample, or shard by flow.
- **Durability setting.** The store runs SQLite in WAL mode with `synchronous = NORMAL`. A crash of the process loses nothing; a power cut can lose the last few commits but cannot corrupt the database. This roughly halved the time of the detection run (24.6 s to 10.3 s on the same input); the default `FULL` fsyncs every event.
- **Worst case for correlation.** All the traffic above comes from one address, so the rotation and monoculture rules see the maximum history per address. Traffic spread over many addresses is cheaper per event.
- **Not measured:** live capture at high packet rates (where kernel drops would appear), multi-core scaling, IPv6, packet loss and reordering, and anything on a real network. Those numbers do not exist yet and none are claimed.

## Reproduce

```
cargo build --release
python3 eval/throughput.py --pcap dataset/v0.6/pcap/chrome-real-143.pcap \
  --pcap dataset/v0.3/pcap/curl_cffi-firefox147.pcap \
  --pcap dataset/v0.3/pcap/curl_cffi-chrome142.pcap --copies 300
cargo bench -p tlsfp-core
```
