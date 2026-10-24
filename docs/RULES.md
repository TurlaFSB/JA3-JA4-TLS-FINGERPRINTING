# Writing detection rules

The built-in rules look for what the project's author thought worth catching. Your own rules say what matters on your network. They live in a TOML file:

```
tlsfp rules check my-rules.toml                              # validate and list
tlsfp pcap capture.pcapng --detect --rules my-rules.toml     # one capture
tlsfp serve --live eth0 --rules my-rules.toml                # the dashboard, live
```

`--rules` (or `TLSFP_RULES`) works on every command that detects. `examples/rules.example.toml` is a starting point.

## A rule

```toml
[[rule]]
name = "dynamic-dns"                       # required, unique; becomes the alert title
description = "TLS to a dynamic DNS provider"
severity = "medium"                        # info | low | medium (default) | high | critical
once_per = "address"                       # how often one source may trigger it

[rule.when]                                # all conditions here must hold
event = ["client_hello"]
sni_glob = ["*.duckdns.org", "*.ddns.net"]

[rule.unless]                              # optional; same fields; any match vetoes
src_network = ["10.9.0.0/16"]
```

Within one condition the list means **any of**; across conditions, **all of**. A rule with nothing under `[rule.when]` is refused, since it would match every event. Unknown keys, unknown values (a misspelt family, a bad network) and duplicate names are errors that name the rule: a typo never becomes a rule that silently never fires.

## Conditions

| Field | Matches when |
|---|---|
| `event` | the event is one of `client_hello`, `server_hello`, `certificate`, `http_request`, `tcp_syn`, `tcp_syn_ack` |
| `sni_glob` | a client hello's server name matches a pattern (`*` is the only wildcard; case-insensitive) |
| `sni_present` | `true` or `false`: whether the client hello carried a server name |
| `host_glob`, `user_agent_contains` | an HTTP request's `Host` or `User-Agent` (cleartext HTTP only) |
| `ja3`, `ja4`, `ja3s`, `ja4s`, `ja4h`, `ja4x`, `ja4t`, `ja4ts` | the event's fingerprint of that kind equals one of the listed values |
| `ja4_prefix` | the client JA4 starts with one of the listed strings |
| `family` | the family read from the ClientHello: `chromium`, `firefox`, `safari_like`, `open_ssl`, `library`, `unknown` (see below) |
| `verdict` | the intelligence verdict for the event's fingerprints: `malicious`, `suspicious`, `benign`, `unknown` |
| `alpn` | the first application protocol the client offered (`h2`, `h3`, `http/1.1`) |
| `transport` | `tcp`, `quic`, `dtls` |
| `tls_version` | the JA4 version field: `13`, `12`, `11`, `10` |
| `has_extension`, `lacks_extension` | the ClientHello does (not) offer an extension, by hex code as JA4 writes it (`fe0d` ECH, `44cd` ALPS) |
| `src_network`, `dst_network` | the source or destination address is inside a CIDR network (`10.0.0.0/8`, `2001:db8::/32`, or a bare address) |
| `dst_port` | the destination port is in the list |

`family` is the same inference `tlsfp identify` uses. It is a heuristic with a stated blind spot: a tool that copies a browser's ClientHello carries the browser's markers (`docs/FIELD_OBSERVATIONS.md`).

## `once_per`

A beacon makes a connection every few seconds; one alert is useful, a thousand are not. `once_per` keeps a rule from repeating:

| Value | One alert per |
|---|---|
| `event` | matching event (every one) |
| `address` | rule and source address |
| `fingerprint` | rule and fingerprint |
| `address_and_fingerprint` (default) | rule, source address and fingerprint |
| `rule` | rule, for the whole run |

The memory is per process: a restart forgets which rules have fired.

## What an alert looks like

The alert has the rule `custom`, the severity you chose, the rule name as its title, and a detail line with your description and exactly what matched:

```
google-from-chromium | demo [matched: event=client_hello, sni=www.google.com, family=chromium]
```

It is stored with the other alerts, shows on the Alerts page, and goes wherever alerts are delivered.
