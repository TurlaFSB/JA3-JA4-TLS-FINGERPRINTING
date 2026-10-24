# Watching live traffic

`tlsfp serve --live INTERFACE` captures from a network interface in the same process that serves the dashboard. The Scope page then shows handshakes as they happen, and the **Traffic** page shows every conversation with the bytes and packets each way, the server name it asked for, and which client made it.

## Linux and macOS: two commands

```
./install.sh --live        # builds tlsfp and the dashboard, seeds the feed, grants capture rights
tlsfp serve --live auto    # picks the interface you actually use; open http://127.0.0.1:8080
```

That is all. `auto` chooses the first interface that is up, has an address and is not loopback; name one (`--live wlan0`) to override, and `tlsfp interfaces` lists them. The dashboard is found without a flag: `install.sh` puts it beside the database. The server binds to loopback; the dashboard has no login, so put your own authentication in front of it before exposing it to a network.

Why a permission step exists at all: reading every packet on a network card is a privilege the operating system reserves, and no program can grant it to itself. `install.sh --live` asks once (sudo) to give the tlsfp binary that one capability, so you never run the server as root. Without it, run `sudo tlsfp serve --live auto` instead. On macOS, give your terminal access to the network devices when asked, or use sudo.

Docker on Windows or macOS cannot see the host's network card, so the Docker stack replays a capture instead; use a native install for live traffic.

## Windows

1. Install [Npcap](https://npcap.com) once (default options). It is the capture driver Wireshark uses; free for personal use, a paid licence for commercial redistribution.
2. Download the Windows release zip, extract it, and run:
   ```
   powershell -ExecutionPolicy Bypass -File .\start-windows.ps1
   ```
   It seeds the database on the first run, starts `tlsfp serve --live auto` on 127.0.0.1:8080 and opens the dashboard. It also lists captures saved in `%USERPROFILE%\tlsfp-captures` (where `capture-browser.ps1` saves). `-Interface "Wi-Fi"` picks an interface by part of its description; `tlsfp interfaces` lists them.

Without Npcap everything except live capture still works: `tlsfp pcap`, `identify`, `html`, the Library page and a replay. Live capture without Npcap stops with a message saying so.

How it was checked: CI builds the Windows binary on a Windows runner, starts it, reads a capture file and runs `interfaces` with no Npcap present, and runs the engine and store tests. **Live capture on Windows itself has not been exercised by an automated test**, because the free Npcap installer cannot run unattended; it is verified by hand on a real machine (see the checklist in `RELEASING.md`). It has been observed working on one Windows machine, on 2026-10-24: `--live auto` chose the interface, real browser conversations appeared on Scope and Traffic, and the direction bug that machine exposed (a public IPv6 address counted as remote) is fixed. The Windows and Npcap versions were not recorded; treat that as one data point, not a compatibility matrix. `auto` skips loopback and virtual adapters (VMware, Hyper-V, VPN taps) by their description.

## What counts as "inside"

The Traffic page calls a conversation outbound, inbound, internal or transit by whether each end is local. Local is: the networks of the capture interface (read from its addresses and netmasks, so a machine with a public IPv6 or IPv4 address still sees its own traffic as outbound and inbound), the private, loopback and link-local ranges, and anything you declare with `--local-network CIDR` (or `TLSFP_LOCAL_NETWORKS`). A replay of somebody else's capture has no interface, so name its inside with `--local-network`. The startup log lists the networks in use.

## Reaching the dashboard

While bound to a loopback address (the default) the dashboard accepts only `localhost`, `127.0.0.1` and `::1` as the Host. To use another name (a hosts-file alias, a reverse proxy), start with `--allowed-host NAME`. A dashboard bound to a network address skips this check; authentication and TLS are then your proxy's job.

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
