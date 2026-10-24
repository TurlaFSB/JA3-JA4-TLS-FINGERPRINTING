# Dashboard

`tlsfp serve` serves a web dashboard and a JSON API from one process. Every number on it comes from the sensor or the database; nothing is estimated or invented, and a replayed capture says so in the header (backend reachability, the active feed, uptime and your `--location` label).

![Scope](images/scope.png)

| Page | What it answers |
|---|---|
| **Scope** | What is crossing the sensor now. Each handshake row names the **site** and the **client**; a server's reply borrows the site from its connection. The **By site** view lists each site with the clients and fingerprints that reached it. Click any row for a side drawer (below). Profiles group the live window by fingerprint or destination and compare two fingerprints side by side. |
| **Traffic** | A capture health panel (what may have been missed, and which flag fixes it), then every conversation with bytes and packets each way, direction, server name and client, a 15-minute throughput chart kept on the server (full when you open the page), and top remote hosts. "Local" means the capture interface's own networks, private ranges, and `--local-network`. |
| **Hosts** | One profile per machine: which client fingerprints it runs and when each first appeared, the servers it talks to, User-Agent and OS claims, and its alerts. A host that starts presenting a new client is the thing to look at. Servers that only answered are listed separately. |
| **Alerts** | Every alert with severity and rule filters, search, a plain explanation of each rule and what to verify, export, and a link to the host. |
| **Library** | Capture files found in a watched folder (`--library DIR`), each read once, named, and downloadable as an HTML report. |
| **Intel** | What this sensor has seen set against what the feed knows: the share of connections the feed can name, the fingerprints it cannot (with the shape-based guess and the exact command to name them), then the catalogue, feeds and licences. |

## The detail drawer

![Event detail](images/detail.png)

A plain sentence about the event; the connection; who the client is and why (an exact feed match or a family inferred from the handshake's shape, with its limits); every fingerprint with a one-line explanation and a copy button; what the client offered or the server chose, with registry names; the JA4 breakdown; the other events of the same connection; intelligence; alerts with what each rule means; and shortcuts to filter or open the host's history. `Esc` closes, `j`/`k` or the buttons step.

## Traffic and capture health

![Traffic](images/traffic.png)

The health panel reports `reading cleanly`, `reading with limits` or `losing frames`, with kernel drops, conversations shed and the share of handshakes that ended unread. Details: [`CAPTURE_TUNING.md`](CAPTURE_TUNING.md).

## Behaviour

- **Opens populated:** the server keeps the last 500 events and sends them in one piece on connect.
- **Themes:** dark and light. `/` focuses the stream filter.
- **Serving:** `tlsfp serve` finds the built dashboard on its own ([`INSTALL.md`](INSTALL.md#5-where-things-are-stored)). Hashed assets are cached for a year; the app shell is revalidated on every load, so an upgrade never leaves a stale page.

The screenshots above were taken from a replay of a vendored capture, `testdata/pcap/browsers-x509.pcapng`.
