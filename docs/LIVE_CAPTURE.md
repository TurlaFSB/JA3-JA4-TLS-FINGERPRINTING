# Watching live traffic

`tlsfp serve --live INTERFACE` captures from a network interface in the same process that serves the dashboard. The Scope page then shows handshakes as they happen, and the **Traffic** page shows every conversation with the bytes and packets each way, the server name it asked for, and which client made it.

## Linux and macOS

```
cargo build --release
(cd frontend && pnpm install && pnpm build)
target/release/tlsfp interfaces                 # lists what can be captured
tlsfp intel seed
sudo setcap cap_net_raw,cap_net_admin=eip target/release/tlsfp    # Linux: run without root
target/release/tlsfp serve 127.0.0.1:8080 --live eth0 --location "my laptop"
```

Open http://127.0.0.1:8080. The server binds to loopback by default; the dashboard has no login, so put your own authentication in front of it before exposing it to a network.

`install.sh --live` does the build, the seed and the capability grant for you.

## What it shows

- **Scope:** TLS and QUIC handshakes with the intelligence verdict, plus what the sensor has seen by transport, TLS version, application protocol and server name.
- **Traffic:** conversations with direction (outbound, inbound, internal, transit), bytes and packets each way, duration, server name, client identity, and a throughput chart in bits per second. A conversation is "local to remote" when one end is a private, loopback, link-local or unique-local address; a sensor on a public segment will call everything remote.
- **`/metrics`:** Prometheus text format with byte and packet counters by direction, tracked conversations, alerts by rule and the size of the intelligence feed, for Grafana or an alerting rule.

## Limits

- It sees what the interface sees. On a switched network a laptop sees its own traffic and broadcast; watching other hosts needs a mirror port or a tap.
- Encrypted traffic is accounted by size and endpoints, not content. The server name appears only when the client sent it in the clear (Encrypted Client Hello hides it).
- It is a fingerprinting sensor, not a packet analyser: there is no per-packet view, no payload and no capture-to-file. Use Wireshark or tcpdump for that, and feed the file to `tlsfp identify`.
- Docker on Windows and macOS cannot capture the host's real network interface, and tlsfp has no native Windows capture (it would need Npcap and has not been built or tested there). On Windows, record with `scripts/capture-browser.ps1` and read the files on the Library page.
- Under the compose stack the dashboard listens on loopback only (`NGINX_BIND=0.0.0.0` changes that).
- Measured limits of the capture path are in `docs/PERFORMANCE.md`.
