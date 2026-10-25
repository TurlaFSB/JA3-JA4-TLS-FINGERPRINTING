# Capture, accuracy and tuning

What the sensor does to your network, how much of it you can ask it to read, what it can and cannot get wrong, and every knob.

## How aggressive is it?

Not at all. tlsfp is passive: it opens the interface read-only, sends no packet, answers no packet and cannot be found by a scan. It never decrypts anything. The cost it can impose is on the machine it runs on (CPU, memory, a kernel buffer), and every one of those is bounded and configurable below.

By default a live capture asks the kernel for:

- all TCP (TLS and SSH run on any port, and JA4T needs the SYNs),
- UDP port 443 (QUIC),
- UDP port 53 (plain DNS),

and drops everything else (DNS, ARP, ICMP, mDNS) inside the kernel, before it costs a context switch. Frames are never clipped (snap length 65,535), because a clipped segment would silently end fingerprinting for that stream.

## The knobs

| Flag | Environment | Default | What it does |
|---|---|---|---|
| `--filter EXPR` | | `tcp or (udp and (port 443 or port 53))` | The BPF filter applied in the kernel. Tighten on a busy link, for example `tcp port 443`, or widen it to read QUIC on another port. |
| `--no-promisc` | | promiscuous on | Capture only traffic addressed to this interface. Use it where promiscuous mode is not allowed, or when you only care about this host. |
| `--buffer-mib N` | `TLSFP_CAPTURE_BUFFER_MIB` | 32 (1 to 1024) | Kernel capture buffer. Bursts queue here; when it overflows the kernel drops frames, and the drop is counted and shown. |
| `--max-flows N` | `TLSFP_MAX_FLOWS` | 65,536 | Conversations tracked at once. When full, the stalest are shed (and counted). Raise it on a busy link. |
| `--idle-timeout SECONDS` | `TLSFP_IDLE_TIMEOUT` | 60 | How long a silent conversation is kept before it can be shed. |
| `--stream-limit-kib KIB` | `TLSFP_STREAM_LIMIT_KIB` | 256 | Bytes read from the start of each direction of a conversation. A ClientHello or certificate chain larger than this is clipped (and counted). |
| `--shared-network CIDR` | `TLSFP_SHARED_NETWORKS` | none | Addresses that front many clients (NAT, proxy); the rotation and monoculture rules skip them. |
| `--local-network CIDR` | `TLSFP_LOCAL_NETWORKS` | interface networks | What counts as "inside" for the direction of traffic. |
| `--rules FILE` | | none | Your own detection rules. |
| `--keep-days`, `--keep-alert-days`, `--max-observations` | | 90, 365, 5,000,000 | How long history is kept. |

The engine limits (`--max-flows`, `--idle-timeout`, `--stream-limit-kib`) apply to every command: `pcap`, `live`, `serve`, `html` and `identify`. Out-of-range values are refused with the allowed range.

## Knowing whether it is reading everything

A fingerprinting tool that cannot say what it missed gets its silence mistaken for absence. So the sensor counts what it fails to read and says so.

- **Dashboard.** The Traffic page has a capture health panel: `reading cleanly`, `reading with limits` or `losing frames`; frames read, handshakes read, the share that ended unread, QUIC Initials opened, kernel drops, conversations shed; the filter, kernel buffer and limits in force; and a plain sentence for anything wrong, naming the flag that fixes it.
- **API.** `GET /api/capture` returns the same, with every counter.
- **Prometheus.** `/metrics` exposes `tlsfp_frames_total`, `tlsfp_handshakes_fingerprinted_total`, `tlsfp_tls_streams_unfinished_total`, `tlsfp_flows_evicted_pressure_total`, `tlsfp_streams_capped_total`, `tlsfp_frames_malformed_total`, `tlsfp_quic_initials_total`, `tlsfp_quic_decrypted_total`, `tlsfp_kernel_received_total` and `tlsfp_kernel_dropped_total`. Alert on `rate(tlsfp_kernel_dropped_total[5m]) > 0`.

| Status | Meaning |
|---|---|
| `ok` | Nothing known to be missed. |
| `degraded` | Results are limited: streams clipped at the per-stream limit, or more than 5% of recognised TLS streams ended before a full handshake was read (needs at least 20 streams, so a quiet link does not cry wolf). |
| `lossy` | Frames or conversations were lost: the kernel dropped frames, or the conversation table filled and shed live conversations. Absence of a fingerprint is then not evidence of absence of a handshake. |

## How detailed is the output?

Every ClientHello and ServerHello event carries, besides the fingerprints, a readable account of what was offered or chosen, in wire order:

- ClientHello: legacy and offered TLS versions, every cipher suite, every extension, supported groups, signature algorithms, EC point formats, ALPN list, whether GREASE was used, and the features it signalled (ECH, session tickets, PSK resumption, OCSP stapling, certificate compression, ALPS, delegated credentials, early data and others).
- ServerHello: the negotiated version and cipher suite, extensions and selected ALPN.

Names come from a table of the values seen in practice; any other value is kept as `unknown (0xNNNN)` with its number, never dropped. It is in `tlsfp pcap --json` and `tlsfp live --json` output (`detail`), in the live stream, and in the detail drawer on the Scope page ("client offered", "server chose").

Alongside it: JA3, JA3S, JA4, JA4S, JA4H, JA4X, JA4T and JA4TS with their raw forms, the SNI, the site and client attribution, per-host history, alerts with the reason each fired, and a self-contained HTML report with the capture's SHA-256 (`tlsfp html`).

## How accurate is it?

Two different questions.

**Is the fingerprint computed correctly?** Each fingerprint is pinned to published vectors (Salesforce for JA3, FoxIO for JA4 and JA4T, the RFC appendices for QUIC key derivation), exercised against real captures of browsers, tools and servers, and fuzzed with arbitrary and mutated bytes. See [`learn/CONFORMANCE.md`](../learn/CONFORMANCE.md). What this does not prove: agreement with FoxIO's reference implementation on every possible input. Agreement is checked on the published vectors and the vendored captures, not exhaustively.

**Is "this client is Chrome" correct?** Less certain, and the sensor says so. A fingerprint names a TLS stack, not a program or a person. An exact feed match is reported as such; a guess from the shape of a handshake is reported as a family with its reasons and a caveat, never as a version. Tools that imitate browsers (curl-impersonate, uTLS) produce the same fingerprint as the browser, and nothing passive can tell them apart. Accuracy of client identification is measured on lab captures only and has not been quantified on real-world traffic; the method, results and limits are in [`eval/README.md`](../eval/README.md).

**What it cannot see.** Encrypted ClientHello hides the real server name; TLS 1.3 certificates and HTTP/2 headers are encrypted, so JA4X works on TLS 1.2 and earlier and JA4H on cleartext HTTP only; server QUIC Initials cannot be opened passively; and a capture point that sees only one direction of a flow reads only that direction. The health panel's "ended unread" and "QUIC opened" figures show how much of this is happening on your link.
