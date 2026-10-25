# Sending alerts to your tools

tlsfp stores every alert in its database and shows it on the Alerts page. To get alerts into the tools you already watch, give it one or more destinations. They work with every command that runs detection (`pcap`, `live`, `serve --replay`, `serve --live`) and can be combined.

| Flag | Environment | What it does |
|---|---|---|
| `--alert-file FILE` | `TLSFP_ALERT_FILE` | Appends one JSON object per line. Point Filebeat, Vector, Fluent Bit or Splunk's forwarder at it. |
| `--alert-syslog URL` | `TLSFP_ALERT_SYSLOG` | RFC 5424 syslog to `udp://HOST:PORT` or `tcp://HOST:PORT` (TCP uses RFC 6587 octet counting). Facility local0. |
| `--alert-webhook URL` | `TLSFP_ALERT_WEBHOOK` | POSTs JSON to an `http://` or `https://` URL. |
| `--webhook-format` | | `generic` (the alert as JSON, default), `slack`, `discord`. |
| `--alert-min-severity` | `TLSFP_ALERT_MIN_SEVERITY` | `info` (default), `low`, `medium`, `high`, `critical`. Lower alerts are stored but not sent. |

```
tlsfp live eth0 --detect --alert-file /var/log/tlsfp/alerts.jsonl --alert-min-severity medium
tlsfp serve --live eth0 --detect --alert-syslog udp://10.0.0.20:514
tlsfp serve --replay cap.pcapng --detect --alert-webhook https://hooks.slack.com/services/... --webhook-format slack
```

## Alert shape

```json
{"ts_nanos":1700000000123000000,"rule":"ua_mismatch","severity":"high","ip":"10.0.0.5",
 "fp_value":"t13d1516h2_...","title":"...","detail":"...","time":"2023-11-14T22:13:20.123Z","sensor":"tlsfp"}
```

Syslog carries the same facts: the rule is the message id, and the structured data `[tlsfp@32473 rule="" severity="" src="" fp=""]` holds the fields a SIEM can index. Severity maps critical to 2, high to 3, medium to 4, low to 5, info to 6. UDP messages are cut at 1,200 bytes.

## Behaviour you should know

- Delivery never slows packet processing. Alerts go through a queue of 1,024 to one background thread. If a destination is slower than the alert rate and the queue fills, new alerts are dropped for delivery (they are still in the database) and counted.
- A webhook gets three attempts with 1 s and 2 s pauses, a 5 s timeout, and no redirects. A 4xx answer other than 429 is not retried.
- A one-shot command waits up to ten seconds at exit for the queue to empty.
- `/metrics` reports `tlsfp_alert_delivery_total{outcome="delivered|failed|dropped"}`. Failures are also logged.
- Delivery is at most once. There is no spool to disk and no replay after a crash; the database is the record. If you need guaranteed delivery, tail the database with `tlsfp intel alerts --json` or use the file output with a shipper that tracks its position.
- A webhook URL often contains a secret. Prefer the environment variable to the flag so it stays out of the process list, and it is never logged.
- Alerts raised by a separate sensor writing the same database are delivered by that sensor, not by a `serve` that only tails the database.

## DNS pattern alerts

Alongside fingerprint alerts, the sensor raises `dns_pattern` alerts (severity low) when plain DNS traffic shows a host with many "no such name" answers, many random-looking subdomains under one domain, or very long names. Each is raised once per host or domain until the sensor restarts, is stored and shown like any other alert, and goes to every configured destination (file, syslog, webhook). The detail names the evidence and what else could explain it; the thresholds are in `crates/tlsfp/src/dnsfind.rs`. Informational DNS findings (steady rhythm, changing addresses, blocked names) appear on the DNS page but do not alert.
