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

## Reading these numbers

- **Fingerprinting is not the cost; the store is.** Matching every fingerprint against the catalogue and recording every observation and alert in SQLite is about thirty times slower than computing the fingerprints. About 3,000 handshakes a second with detection on is far above what most links carry (a busy 1 Gbit/s edge sees hundreds of new TLS connections a second), but a 10 Gbit/s core link could exceed it. Beyond that, run fingerprinting only, sample, or shard by flow.
- **Durability setting.** The store runs SQLite in WAL mode with `synchronous = NORMAL`. A crash of the process loses nothing; a power cut can lose the last few commits but cannot corrupt the database. This roughly halved the time of the detection run (24.6 s to 10.3 s on the same input); the default `FULL` fsyncs every event.
- **Worst case for correlation.** All the traffic above comes from one address, so the rotation and monoculture rules see the maximum history per address. Traffic spread over many addresses is cheaper per event.
- **Not measured:** QUIC-heavy traffic (Initial decryption costs more per datagram than a TCP segment), live capture drop rates under load, multi-core scaling, IPv6, and packet-loss or reordering effects. Those numbers do not exist yet and none are claimed.

## Reproduce

```
cargo build --release
python3 eval/throughput.py --pcap dataset/v0.6/pcap/chrome-real-143.pcap \
  --pcap dataset/v0.3/pcap/curl_cffi-firefox147.pcap \
  --pcap dataset/v0.3/pcap/curl_cffi-chrome142.pcap --copies 300
cargo bench -p tlsfp-core
```
