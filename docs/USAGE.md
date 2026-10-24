# Command reference

`tlsfp COMMAND [OPTIONS]`. Every command accepts `-h/--help`; `-v` and `-vv` raise log detail. Global options (`--rules`, `--alert-*`, `--max-flows`, `--idle-timeout`, `--stream-limit-kib`) go before or after the command.

## Analyse a capture file

```bash
tlsfp pcap capture.pcapng                      # one line per handshake
tlsfp pcap capture.pcapng --json               # one JSON object per event (includes handshake detail)
tlsfp pcap capture.pcapng --intel              # add the intelligence verdict to each line
tlsfp pcap capture.pcapng --intel --detect     # also run the detection rules and record observations
tlsfp pcap capture.pcapng --report             # one ranked forensic summary instead of per-event lines
tlsfp html capture.pcapng -o report.html       # self-contained HTML report with the file's SHA-256
tlsfp identify captures/                       # which client is in each capture file in a folder
```

Accepted input: pcap and pcapng with Ethernet (VLAN tags, including stacked), Linux cooked (v1 and v2), raw IP, and decrypted 802.11 data frames as Windows `pktmon` writes them. Tunnelled traffic (GRE, VXLAN) is skipped and counted, not decoded.

## Capture live

```bash
tlsfp interfaces                               # what can be captured (names and descriptions)
tlsfp live auto --intel --detect               # the interface you actually use
tlsfp live eth0 --filter "tcp port 443"        # narrow the kernel BPF filter
tlsfp live "Wi-Fi" --json                      # name an interface (Windows: part of its description works)
tlsfp live eth0 --buffer-mib 128 --max-flows 500000   # sized for a busy link
```

Stop with Ctrl+C: the first drains and prints counters, a second exits at once. Permissions: [`INSTALL.md`](INSTALL.md). All tuning flags: [`CAPTURE_TUNING.md`](CAPTURE_TUNING.md).

## Run the dashboard and API

```bash
tlsfp serve                                    # 127.0.0.1:8080, tails the database (shows alerts another process wrote)
tlsfp serve --live auto                        # captures in-process and shows it live
tlsfp serve --replay capture.pcapng --loop     # demo feed from a file, paced; no privileges needed
tlsfp serve --library ~/tlsfp-captures         # list and identify the capture files in a folder
tlsfp serve 0.0.0.0:8080 --allowed-host dash.example   # bind to a network address (put authentication in front)
```

| Option | Environment | Purpose |
|---|---|---|
| `--location TEXT` | `TLSFP_SENSOR_LOCATION` | Label shown in the dashboard header |
| `--local-network CIDR` | `TLSFP_LOCAL_NETWORKS` | Networks that count as "inside" besides the interface's own |
| `--shared-network CIDR` | `TLSFP_SHARED_NETWORKS` | NAT or proxy addresses; rotation and monoculture rules skip them |
| `--allowed-host NAME` | `TLSFP_ALLOWED_HOSTS` | Another name a loopback-bound dashboard may be reached by |
| `--library DIR` | `TLSFP_LIBRARY` | Folder of capture files to watch |
| `--web DIR` | | Dashboard files, when not found automatically |
| `--db PATH` | | Intelligence database (default in [`INSTALL.md`](INSTALL.md#5-where-things-are-stored)) |
| `--interval-ms N`, `--loop` | | Replay pacing and repetition |

## Detection and alerts

```bash
tlsfp pcap x.pcapng --detect --shared-network 10.0.0.0/8
tlsfp rules check my-rules.toml                # validate your own rules; use them with --rules FILE
tlsfp live eth0 --detect --alert-file alerts.jsonl --alert-syslog udp://siem:514 --alert-webhook "$URL"
tlsfp intel alerts                             # recent alerts
```

Rules: [`DETECTION.md`](DETECTION.md), [`RULES.md`](RULES.md). Delivery formats, retries and guarantees: [`ALERTS.md`](ALERTS.md).

## Manage intelligence

```bash
tlsfp intel seed                               # load the bundled feeds (offline)
tlsfp intel import ja4db.json                  # import a ja4db.com export (validated per record)
tlsfp intel lookup ja4 t13d1516h2_8daaf6152771_e5627efa2ab1
tlsfp intel label ja4 <value> --label "Brave on Windows"   # name a fingerprint yourself
tlsfp intel labels                             # list your labels   (unlabel removes one)
tlsfp intel prune --keep-days 30               # delete old history now
```

`serve` also prunes every 15 minutes: `--keep-days`, `--keep-alert-days` and `--max-observations` set the policy, `0` keeps everything.

## JSON output

One object per line. Fields common to all events: `ts_nanos`, `src`, `dst`, `kind`.

| `kind` | Extra fields |
|---|---|
| `client_hello` | `ja3`, `ja3_raw`, `ja4{hash,raw}`, `sni`, `alpn`, `detail` |
| `server_hello` | `ja3s`, `ja3s_raw`, `ja4s{hash,raw}`, `detail` |
| `certificate` | `ja4x` |
| `http_request` | `ja4h{hash,raw}`, `method`, `host`, `user_agent` |
| `tcp_syn` / `tcp_syn_ack` | `ja4t` / `ja4ts` |

`detail` is the readable account of the hello (versions, ciphers, extensions, groups, signature algorithms, ALPN, features); see [`CAPTURE_TUNING.md`](CAPTURE_TUNING.md#how-detailed-is-the-output).

## HTTP API

Served by `tlsfp serve` on the same port as the dashboard; no authentication (see [`THREAT_MODEL.md`](THREAT_MODEL.md)).

`/api/stats`, `/api/alerts`, `/api/search`, `/api/export`, `/api/observed`, `/api/hosts`, `/api/hosts/{ip}`, `/api/traffic`, `/api/capture`, `/api/library`, `/api/library/{id}/report`, `/api/meta`, `/api/health`, `/api/stream` (Server-Sent Events, at most 64 open) and `/metrics` (Prometheus). Errors never carry internal detail.
