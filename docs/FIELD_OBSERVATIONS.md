# Field observations: real desktop browsers

Fingerprints of real browsers recorded on a Windows 10 laptop over Wi-Fi with `scripts/capture-browser.ps1` (pktmon, then `tlsfp pcap`). The captures themselves are not published: they hold every connection the machine made while recording. Only fingerprint hashes appear here.

Each browser opened the same five sites (example.com, wikipedia.org, github.com, cloudflare.com, mozilla.org) for 45 seconds, 2026-10-23. One machine, one network, one run per browser: this is an observation, not a survey.

| browser | version | handshakes | QUIC Initials decrypted |
|---|---|---|---|
| Brave | 1.98.60 | 74 | 18 of 18 |
| Microsoft Edge | 155.0.4283.62 | 182 | 66 of 66 |
| Firefox | 158.0.1 | 244 | 56 of 56 |

## Result

Both browsers send the **same TCP ClientHello JA4** for a fresh HTTPS connection:

| JA4 | what it is |
|---|---|
| `t13d1516h2_8daaf6152771_806a8c22fdea` | fresh connection, HTTP/2 (Brave and Edge) |
| `t13d1517h2_8daaf6152771_a87ad97598a9` | the same hello resuming a session (adds `pre_shared_key`) |
| `t13d1515h1_8daaf6152771_e4c2b8c727f2` | the same hello offering only HTTP/1.1 |
| `q13d0311h3_55b375c5d22e_653d80c3fe9d` | QUIC Initial, HTTP/3 (Brave and Edge) |

Edge additionally produced QUIC variants `q13d0312h3_…_5a06198afb93` and `q13d0313h3_…_226f3f127bbe`. Brave's run showed only the first.

The raw JA4 of the fresh hello lists, besides the usual extensions, `44cd` (ALPS, new codepoint) and `fe0d` (Encrypted Client Hello). Both desktop browsers do send ECH.

## What this changes

- `806a8c22fdea` is also the JA4 of the curl-impersonate `chrome150` profile in dataset v0.6. A current curl-impersonate Chrome profile therefore cannot be told apart from a current Brave or Edge by JA4. JA3 cannot be compared, because Chromium shuffles extension order on every connection.
- The ClientHellos of the lab's own Chrome builds lacked ECH. That was a limit of the headless Linux lab, not a property of desktop Chromium.
- The bundled intelligence feed does not list this hash, because the same bytes are also what an impersonation tool sends. A sensor shown it reports `unknown`, not `benign`. Vouching for it would vouch for the tool as well.

## Firefox

Firefox 158.0.1 (a different TLS library, NSS) fingerprints differently from the Chromium browsers:

| JA4 | what it is |
|---|---|
| `t13d1517h2_8daaf6152771_3cbfd9057e0d` | HTTP/2 connection; the JA3 was `9d42e90b0225e779f03141ddcd699df2` on every one of them |
| `t13d1516h1_8daaf6152771_e6d2851837fd` | HTTP/1.1 only (push service WebSocket) |
| `q13d0315h3_55b375c5d22e_dc5437974b47` | QUIC Initial, HTTP/3 |
| `t12d1211h2_d34a8e72043a_810e2f290f6f` | TLS 1.2 only, 12 extensions: Firefox's own background requests (update checks, Remote Settings, add-on version checks) |

- Firefox does not shuffle extensions, so its JA3 is stable (one value across 100+ connections), unlike Chromium's. A JA3 allow-list works for Firefox and cannot work for Chromium.
- A handful of connections to ad and tag hosts used rarer variants (`…_0c27189014cf`, `…_e6dcd7ae0a9e`); the cause was not investigated.
- The curl-impersonate Firefox profiles in datasets v0.2 and v0.3 (versions 133 to 147) have `t13d1717h2_5b57614c22b0_3cbfd9057e0d`: the same signature-algorithm hash, but 17 cipher suites instead of 15 and a different cipher hash. So for this Firefox version the profiles are separable by JA4. This compares a 158 browser with profiles captured for 147 and earlier; it shows the profiles had fallen behind this release, not that they cannot be updated.

## Other clients seen in the same captures

Not browsers, but visible in the recordings and useful for recognising background traffic on a Windows host:

| JA4 | seen with |
|---|---|
| `t13d2013h2_2b729b4bf6f3_e24568c0d440` | Windows system components (`login.live.com`, `play.googleapis.com`) |
| `t12d1809h2_4b22cbed5bed_7af1ed941c26` | TLS 1.2 client to `login.live.com` |
| `t13d201300_2b729b4bf6f3_1ea369dc5faa` | no ALPN: Office and Spotify endpoints |

## Reproducing

```
.\scripts\capture-browser.ps1 -Browser edge
```

See `docs/BROWSER_CAPTURE.md`. Wi-Fi recordings are decoded since commit 35946c9: pktmon writes raw 802.11 frames under an Ethernet label, and the decoder falls back to the 802.11 layout when Ethernet parsing finds no IP packet.
