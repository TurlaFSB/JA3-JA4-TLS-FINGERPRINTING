# Capturing a real desktop browser

The lab runs on Linux with automated browsers, which leaves one question open: what do real desktop browsers send? This procedure records the TLS handshakes of the browsers installed on a Windows computer and fingerprints them with `tlsfp`.

It uses `pktmon`, the packet recorder built into Windows 10 (version 2004 or later) and Windows 11. Nothing needs installing except Docker, which the project already uses.

## One-time setup

1. Install Docker Desktop and start it.
2. In the repository folder, build the analysis image once:

```
docker build -f infra/docker/tlsfp.prod -t tlsfp:local .
```

## Capture

For each browser you want to measure (Chrome, Edge, Firefox, Brave):

1. Open **PowerShell as Administrator** and `cd` to the repository folder.
2. Allow the script for this window only: `Set-ExecutionPolicy -Scope Process Bypass`
3. Run `.\scripts\capture-browser.ps1 -Browser chrome` (or `edge`, `firefox`, `brave`).
4. When it asks, close every window of that browser and any other program that uses the internet, then press Enter.
5. The browser opens five public test sites. Leave it alone for 45 seconds.

The script saves `<browser>.pcapng` and `<browser>.txt` (version and OS) in `%USERPROFILE%\tlsfp-captures`, and prints the `client_hello` lines with their `ja4`, `ja3`, `sni` and `alpn`.

## Manual version (no script)

```
pktmon filter remove
pktmon filter add -p 443
pktmon start --capture --comp nics --pkt-size 0 --file-name chrome.etl
```

Open the browser, visit a few sites, then:

```
pktmon stop
pktmon etl2pcap chrome.etl --out chrome.pcapng
docker run --rm -v "%CD%:/cap" --entrypoint tlsfp tlsfp:local pcap /cap/chrome.pcapng
```

## What to look for

- **ECH:** whether the real browser sends the `encrypted_client_hello` extension. Run with `--json` and search the `ja4.raw` field for `fe0d`.
- **JA4:** compare with the curl-impersonate profiles in `eval/results/v0.6/fidelity.md`.
- **Variants:** a browser often shows two JA4 values (a full handshake and a resumed one with `pre_shared_key`).

## Privacy

The recording contains the IP addresses and server names of everything the computer connected to on port 443 while it ran. Close other programs first, keep the run short, and read the output before sharing anything. Share the printed fingerprint lines, not the `.pcapng`. Do not commit captures to the repository.

## Seeing your captures in the dashboard

Put capture files in `tlsfp-captures` in your user folder (the Windows script saves there already) and start the dashboard:

```
docker compose --profile backend up --build -d
```

Open http://localhost:11790 and choose **Library**. Every `.pcap` and `.pcapng` in the folder is read once and listed with the client it contains: an exact match from the intelligence feed when there is one ("Firefox 158 (Windows 10; HTTP/2)"), otherwise a family guess read from the ClientHello ("Chromium family"), with the evidence and the caveat that an impersonation tool can look the same. Drop in a new file and it appears within about twenty seconds.

Docker can only see folders it is given, so the library is the one folder above, mounted read-only. To use a different folder, set `CAPTURE_DIR` first:

```
$env:CAPTURE_DIR = "D:\captures"        # PowerShell
CAPTURE_DIR=/data/captures docker compose --profile backend up -d    # Linux, macOS
```

Without Docker: `tlsfp serve --library ~/tlsfp-captures` (repeat the flag for more folders), or from a terminal `tlsfp identify ~/tlsfp-captures`.

The Scope page shows live traffic and, by default, replays the bundled demo. To loop one of your files there instead, set `REPLAY_PCAP=/captures/<file>` before starting.

The library reads files for analysis only. It does not raise alerts or write to the database, never follows symbolic links out of the folder, and shows file names relative to the folder, never full paths. Captures hold everything the machine connected to while recording; keep them private.
