# Running it for real

How to run `tlsfp` as a long-lived sensor: a service that starts at boot, a configuration file instead of a long command line, a safe way to let others see the dashboard, and how to watch and back it up.

## 1. Put the options in a file

```bash
tlsfp config example > tlsfp.toml      # a commented template
tlsfp --config tlsfp.toml serve        # or: TLSFP_CONFIG=tlsfp.toml tlsfp serve
tlsfp config path                      # where it is read from automatically
```

Precedence, strongest first: a flag, an environment variable, the file, the built-in default. Keys are the flag names without the dashes (`max-flows`, `alert-file`). Options every command accepts go at the top; a command's own options go in a table named after it (`[serve]`, `[live]`). A misspelt or unknown key is an error that lists the valid ones, and values go through the same validation as flags (a `max-flows` below its minimum is refused).

```toml
alert-file = "/var/log/tlsfp/alerts.jsonl"
alert-syslog = "udp://siem.example:514"
max-flows = 200000

[serve]
live = "auto"
bind = "127.0.0.1:8080"
location = "DC-2 rack 14"
buffer-mib = 64
keep-days = 90
```

## 2. Linux: run it under systemd

[`contrib/tlsfp.service`](../contrib/tlsfp.service) runs the sensor as an unprivileged `tlsfp` user holding only `CAP_NET_RAW` and `CAP_NET_ADMIN`, with a private `/tmp`, read-only system, no home directory, and a short list of allowed address families. The install steps are in the file's header. After installing:

```bash
systemctl status tlsfp
journalctl -u tlsfp -f
systemd-analyze security tlsfp         # what the service can still do
```

The unit is a starting point: it follows systemd's documented options but has not been exercised on every distribution, so check it against your own policy.

If the capture's interface disappears (a USB adapter unplugged, a VM NIC reset), the program reopens it itself with growing pauses (1, 2, 4, up to 30 seconds), and the dashboard's header and capture health panel say `capture reconnecting` and why. systemd restarts the process only if it dies.

## 3. Windows: start at logon

Task Scheduler can start the sensor when you sign in. In PowerShell (adjust the folder):

```powershell
$dir = "C:\tlsfp\tlsfp-0.2.0-windows-x86_64"
$action  = New-ScheduledTaskAction -Execute "$dir\tlsfp.exe" -Argument "--config $dir\tlsfp.toml serve" -WorkingDirectory $dir
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "tlsfp" -Action $action -Trigger $trigger -RunLevel Highest
```

This has not been tested on a Windows machine by the maintainer. Npcap must be installed. `-RunLevel Highest` is needed only if Npcap was installed in Administrators-only mode.

## 4. Letting other people see the dashboard

The dashboard has no login. Keep `bind` on `127.0.0.1` and put a reverse proxy in front that provides TLS and authentication. A minimal nginx server block:

```nginx
server {
    listen 443 ssl;
    server_name tlsfp.example.org;
    ssl_certificate     /etc/ssl/tlsfp.example.org.pem;
    ssl_certificate_key /etc/ssl/tlsfp.example.org.key;

    auth_basic           "tlsfp";
    auth_basic_user_file /etc/nginx/tlsfp.htpasswd;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host $host;
        proxy_buffering    off;            # the live stream is Server-Sent Events
        proxy_read_timeout 1h;
    }
}
```

Add `allowed-host = ["tlsfp.example.org"]` under `[serve]` so the Host check accepts the proxy's name. Do not expose the port directly.

## 5. Watching it

- **Prometheus:** scrape `http://127.0.0.1:8080/metrics`. Useful alerts: `rate(tlsfp_kernel_dropped_total[5m]) > 0` (frames are being lost: raise `buffer-mib`), `increase(tlsfp_flows_evicted_pressure_total[10m]) > 0` (the conversation table is full: raise `max-flows`), and a rising `tlsfp_tls_streams_unfinished_total` against `tlsfp_handshakes_fingerprinted_total`.
- **Health:** `GET /api/health` answers while the server is up. `GET /api/capture` reports whether the capture is running, reconnecting or stopped, and what has been missed.
- **Alerts:** send them where your team looks: `alert-file` (for a log shipper), `alert-syslog`, or `alert-webhook` ([`ALERTS.md`](ALERTS.md)).

## 6. Sizing

Reading and fingerprinting is cheap (tens of thousands of handshakes a second on one core); recording and detecting into SQLite is the slower path (about three thousand a second). The bounded things are the conversation table (`max-flows`, a few KiB each), the kernel capture buffer (`buffer-mib`, owned by the kernel) and the retention window (`keep-days`, `max-observations`). The capture health panel tells you when a limit is being hit; raise that limit then, not before. Figures and what has not been measured: [`PERFORMANCE.md`](PERFORMANCE.md).

## 7. Backups and upgrades

- The state is one SQLite file (`intel.db`, with `-wal` and `-shm` beside it while running). Back it up while the sensor runs with SQLite's own tool, which gives a consistent copy: `sqlite3 /var/lib/tlsfp/intel.db ".backup '/backup/intel.db'"`.
- Upgrade by replacing the binary (and the `web` folder) and restarting. The database migrates itself on first use. On Linux, a binary run with file capabilities needs `setcap` again; the systemd unit does not.
- The DNS summary is held in memory and starts empty after a restart; fingerprints, alerts, labels and host history persist.
