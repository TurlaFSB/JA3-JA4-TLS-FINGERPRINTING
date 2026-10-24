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

`tlsfp live lo` on the loopback interface of the same 4-vCPU machine, against a TLS 1.3 server in the same process as a Go client making handshakes as fast as it can (16 workers, 10 seconds per run). The load generator, the server and the sensor all share the four cores, so these figures understate what a dedicated sensor core can do. Every run compares the number of handshakes the client completed with the number of `client_hello` events the sensor reported, and prints the kernel's own drop counter.

| Mode | Offered | Reported | Kernel drops |
|---|---|---|---|
| fingerprint only | 1,239 /s (12,395 handshakes) | 12,395 | 0 |
| fingerprint only | 1,210 /s (12,103) | 12,103 | 0 |
| `--intel --detect` | 944 /s (9,441) | 9,441 | 0 |
| `--intel --detect` | 912 /s (9,127) | 9,127 | 0 |

Every handshake the client completed was reported, in all runs, at about 900 to 1,200 new TLS connections per second. That is the ceiling of this test, set by the generator sharing the CPU, not the ceiling of the sensor: no run found the point where the sensor loses handshakes in the way the kernel drop counter would show.

Two things were found by this test and fixed:

- **Source port reuse (a sensor bug).** The first runs reported only 82 to 94 percent of the handshakes even though the kernel dropped nothing. A capture recorded with tcpdump (0 dropped) showed all of them on the wire, and `tlsfp pcap` on that capture still found only 5,398 of 6,386 connections. The cause: when a client reuses a source port (Linux does so quickly on loopback, and busy NATs do so constantly) and the old flow is still in the table, the new SYN was read as a continuation of the old connection and its ClientHello was never fingerprinted. A SYN with a new initial sequence number now starts a new flow (`flows_restarted` in the summary line counts them; 3,258 in one 12,000-connection run). Two unit tests cover it, including that a retransmitted SYN does not restart a flow.
- **Kernel buffer.** The kernel capture buffer was 4 MiB and the frame channel 512. Under the same load the sensor dropped 22 percent of frames (`kernel_dropped` in the statistics line, with the warning). The buffer is now 32 MiB, overridable with `TLSFP_CAPTURE_BUFFER_MIB` (1 to 1024). A 256 MiB buffer was tried as well and reported only 88 percent of one run's handshakes with no kernel drops counted, a result this project cannot explain, so the default is the value that was measured to work. If you tune it, check your own loss as above: count what the sender completed against what the sensor reported.

The kernel counts each loopback packet twice (`received` is double the frames the sensor processes); that is a property of the loopback interface, not a loss.

## Several cores

The sensor is single threaded. The way to use more cores is to run one process per share of the traffic (for example one per capture file or per RSS queue). Four processes reading the same 76.8 MB capture at once, median of five runs:

| Processes | Time per process | Aggregate handshakes/s |
|---|---|---|
| 1 | 0.27 s | about 117,000 |
| 2 | 0.27 s | about 234,000 |
| 3 | 0.30 s | about 312,000 |
| 4 | 0.34 s | about 366,000 |

That is 3.1 times the single-process rate on four vCPUs, fingerprinting only, from files that sit in the page cache. It shows the work parallelises; it is not a measurement of a multi-threaded sensor or of live capture on several queues.

## Reading these numbers

- **Fingerprinting is not the cost; the store is.** Matching every fingerprint against the catalogue and recording every observation and alert in SQLite is about thirty times slower than computing the fingerprints. Whether about 3,000 handshakes a second with detection on is enough depends on the new-connection rate of the link being watched, which this project has not measured on any real network. Above that rate, run fingerprinting only, sample, or shard by flow.
- **Durability setting.** The store runs SQLite in WAL mode with `synchronous = NORMAL`. A crash of the process loses nothing; a power cut can lose the last few commits but cannot corrupt the database. This roughly halved the time of the detection run (24.6 s to 10.3 s on the same input); the default `FULL` fsyncs every event.
- **Worst case for correlation.** All the traffic above comes from one address, so the rotation and monoculture rules see the maximum history per address. Traffic spread over many addresses is cheaper per event.
- **Not measured:** live capture on a dedicated core at rates above what the generator could offer, a physical NIC or a mirror port, IPv6, packet loss and reordering, and anything on a real network. Those numbers do not exist yet and none are claimed.

## Reproduce

```
cargo build --release
python3 eval/throughput.py --pcap dataset/v0.6/pcap/chrome-real-143.pcap \
  --pcap dataset/v0.3/pcap/curl_cffi-firefox147.pcap \
  --pcap dataset/v0.3/pcap/curl_cffi-chrome142.pcap --copies 300
cargo bench -p tlsfp-core
```
