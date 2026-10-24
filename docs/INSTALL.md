# Installation guide

Three ways to get `tlsfp`, from least to most effort. Pick one, then run the [verification](#4-verify-the-installation).

| | Prebuilt archive | Build from source | Docker |
|---|---|---|---|
| Effort | Download, extract | Install a toolchain, one command | `docker compose up` |
| Linux x86-64 | Yes | Yes | Yes |
| Windows x86-64 | Yes | Yes | Replay only |
| macOS | No archive | Yes (see [support status](#platform-support)) | Replay only |
| Live capture | Yes | Yes | No (a container cannot see the host's network card on Windows or macOS) |
| Dashboard included | Yes | Yes, if pnpm is installed | Yes |

## Platform support

| Platform | Status |
|---|---|
| Linux x86-64 | Built and tested in CI on every commit; released as an archive. Live capture exercised in tests and by hand. |
| Windows 10/11 x86-64 | Built in CI on every commit and released as a zip. Reading captures needs nothing else. Live capture needs [Npcap](https://npcap.com); it has been observed working on one machine (2026-10-24) but is not covered by an automated test, because Npcap cannot be installed unattended in CI. |
| macOS | Uses the same code path as Linux (libpcap). **Not built or tested in CI and not tested by the maintainer.** Expect it to work; report problems. |
| Linux ARM64, BSD | Not built or tested. |

---

## 1. Prebuilt archive (recommended)

Each [release](https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING/releases) contains:

| File | Contents |
|---|---|
| `tlsfp-VERSION-linux-x86_64.tar.gz` | `tlsfp` binary, the dashboard (`web/`), licence files |
| `tlsfp-VERSION-windows-x86_64.zip` | `tlsfp.exe`, the dashboard (`web\`), `start-windows.ps1`, licence files |
| `*.sha256` | SHA-256 of the archive beside it |

Every archive carries a build provenance attestation: GitHub signs a statement that this exact file was built from this repository, at this commit, by the release workflow.

### Linux

```bash
# 1. Download the archive and its checksum from the release page, then:
sha256sum -c tlsfp-0.2.0-linux-x86_64.tar.gz.sha256        # must print: OK

# 2. (Optional, recommended) verify the provenance. Needs the GitHub CLI.
gh attestation verify tlsfp-0.2.0-linux-x86_64.tar.gz --repo TurlaFSB/JA3-JA4-TLS-FINGERPRINTING

# 3. Extract and enter
tar -xzf tlsfp-0.2.0-linux-x86_64.tar.gz
cd tlsfp-0.2.0-linux-x86_64

# 4. Runtime dependency: libpcap (Debian/Ubuntu shown)
sudo apt-get install -y libpcap0.8

# 5. Load the bundled intelligence feed (once, no network needed)
./tlsfp intel seed
```

To run it from anywhere, copy the binary and the `web` folder:

```bash
sudo install -m 0755 tlsfp /usr/local/bin/tlsfp
mkdir -p ~/.local/share/tlsfp && cp -r web ~/.local/share/tlsfp/web   # where `tlsfp serve` looks for the dashboard
```

For live capture without running as root, grant the binary the two capabilities it needs (once, and again after replacing the binary):

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tlsfp)"
```

### Windows

1. Download `tlsfp-0.2.0-windows-x86_64.zip` and its `.sha256` from the release page.
2. Verify the checksum in PowerShell. The two values must be identical:
   ```powershell
   (Get-FileHash .\tlsfp-0.2.0-windows-x86_64.zip -Algorithm SHA256).Hash.ToLower()
   Get-Content .\tlsfp-0.2.0-windows-x86_64.zip.sha256
   ```
3. Extract the zip (right-click, Extract All, or `Expand-Archive`).
4. **For live capture only:** install [Npcap](https://npcap.com) once, with the default options (about 1 MB; free for personal use, a licence is required to redistribute it commercially). Reading capture files, the Library page and reports work without it.
5. Open PowerShell in the extracted folder and run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start-windows.ps1
   ```
   It seeds the feed on the first run, starts the sensor on `http://127.0.0.1:8080` with `--live auto`, and opens the dashboard. Pick an adapter with `-Interface "Wi-Fi"`; `.\tlsfp.exe interfaces` lists them.

Windows SmartScreen may warn about an unsigned download. The checksum and attestation are how you confirm the file is the one the release workflow built; the binary is not Authenticode-signed.

---

## 2. Build from source

### Requirements

| Needed | Version | Why |
|---|---|---|
| Rust toolchain | 1.85 or newer | Compiles the sensor ([rustup.rs](https://rustup.rs)) |
| libpcap headers | any recent | Live capture (Linux: `libpcap-dev`; macOS: included with the OS; Windows: the Npcap SDK) |
| Node.js | 22 | Builds the dashboard |
| pnpm | 10 | Builds the dashboard (`corepack enable` provides it) |
| A C linker | | Linux: `build-essential`; macOS: Xcode command line tools; Windows: MSVC Build Tools |

The dashboard is optional: without Node and pnpm the sensor still builds and every command except the web UI works.

### Linux and macOS

```bash
# Debian / Ubuntu
sudo apt-get install -y build-essential pkg-config libpcap-dev
# Fedora / RHEL:  sudo dnf install -y gcc pkgconf-pkg-config libpcap-devel
# macOS:          xcode-select --install

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh     # skip if Rust is installed
corepack enable                                                     # provides pnpm (needs Node 22)

git clone https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING.git
cd JA3-JA4-TLS-FINGERPRINTING
./install.sh --live
```

`install.sh` builds and installs `tlsfp` (to `~/.cargo/bin`, or `--prefix DIR`), loads the intelligence feed, builds the dashboard into `~/.local/share/tlsfp/web`, and with `--live` grants the capture capabilities (asks for sudo once; Linux only). Everything it does is printed. Add `~/.cargo/bin` to your `PATH` if `tlsfp` is not found afterwards.

Without the script: `cargo build --release`, then `target/release/tlsfp intel seed`; the dashboard is `cd frontend && pnpm install --frozen-lockfile && pnpm build`.

On macOS, live capture opens the BPF devices, which typically needs `sudo` unless your account already has access to `/dev/bpf*`.

### Windows

1. Install Rust with the MSVC toolchain and the Visual Studio Build Tools ("Desktop development with C++").
2. Download the [Npcap SDK](https://npcap.com/#download) (the SDK zip, not the installer), extract it, and set `LIB` to its `Lib\x64` folder:
   ```powershell
   $env:LIB = "C:\npcap-sdk\Lib\x64"
   ```
3. Build:
   ```powershell
   git clone https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING.git
   cd JA3-JA4-TLS-FINGERPRINTING
   cargo build --release
   .\target\release\tlsfp.exe intel seed
   ```
4. The dashboard: install Node 22, run `corepack enable`, then `cd frontend; pnpm install --frozen-lockfile; pnpm build`. `tlsfp serve` finds `frontend\dist`.

The SDK is needed only to link. At run time the program loads Npcap on demand, so the same binary reads capture files on a machine without it.

---

## 3. Docker (demo or replay)

```bash
git clone https://github.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING.git
cd JA3-JA4-TLS-FINGERPRINTING
docker compose --profile backend up --build
```

Open `http://127.0.0.1:11790`. The stack replays a bundled capture in a loop so the dashboard is populated immediately. Mount your own captures into the Library with `TLSFP_LIBRARY` (see `compose.yml`). The dashboard listens on loopback only; `NGINX_BIND=0.0.0.0` exposes it, and it has no login, so put authentication in front of it first.

A container on Windows or macOS cannot see the host's network card, so this is for demonstration and for analysing capture files, not for live monitoring. On a Linux host, run the native install for live capture.

---

## 4. Verify the installation

Run these in the folder holding `tlsfp`. The sample capture is in the repository (`testdata/pcap/`); without a clone, download it:

```bash
curl -LO https://raw.githubusercontent.com/TurlaFSB/JA3-JA4-TLS-FINGERPRINTING/main/testdata/pcap/browsers-x509.pcapng
```

```bash
tlsfp --version                                      # tlsfp 0.2.0
tlsfp intel seed                                     # feeds: abuse.ch, salesforce, curated, lab; prints counts
tlsfp pcap browsers-x509.pcapng --intel
```

The last command prints one line per handshake, including a `client_hello` with
`ja4=t13d1516h2_8daaf6152771_e5627efa2ab1` and an `intel` line naming Chromium. That value is the published FoxIO reference fingerprint; seeing it confirms the engine computes what the specification says.

Then the dashboard:

```bash
tlsfp serve --replay browsers-x509.pcapng --loop
```

Open `http://127.0.0.1:8080`. The header reads `REPLAY ...`, and Scope fills within a few seconds.

Finally, live capture (needs the capture permission above, or Npcap on Windows):

```bash
tlsfp interfaces              # lists what can be captured
tlsfp serve --live auto       # open http://127.0.0.1:8080 and browse the web in another window
```

The header should read `LIVE ...` and conversations should appear on Traffic.

## 5. Where things are stored

| What | Linux / macOS | Windows |
|---|---|---|
| Intelligence database (observations, alerts, labels) | `~/.local/share/tlsfp/intel.db` | `%LOCALAPPDATA%\tlsfp\intel.db` |
| Dashboard (where `serve` looks, after `./web` beside the program and `frontend/dist`) | `~/.local/share/tlsfp/web` | `web\` beside `tlsfp.exe` |

Override the database with `--db PATH`. History is pruned automatically (90 days of observations, 365 of alerts, 5,000,000 rows by default); see [`CAPTURE_TUNING.md`](CAPTURE_TUNING.md).

## 6. Upgrade and uninstall

- **Upgrade:** install the new archive or re-run `./install.sh`. The database migrates itself on first use. Re-apply `setcap` on Linux after replacing the binary.
- **Uninstall:** delete the binary, and `~/.local/share/tlsfp` (or `%LOCALAPPDATA%\tlsfp`) to remove the database and dashboard. `cargo uninstall tlsfp` removes a source install.

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `libpcap development files not found` | Install `libpcap-dev` (Debian/Ubuntu) or `libpcap-devel` (Fedora) and re-run. |
| `error while loading shared libraries: libpcap.so.0.8` | Install `libpcap0.8` (the runtime library) when using the prebuilt Linux archive. |
| `permission denied` or `you don't have permission to capture` on Linux | Run `sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tlsfp)"`, or run with `sudo`. The grant is lost whenever the binary is replaced. |
| Windows: "Npcap is not installed" | Install Npcap with default options from npcap.com, then start again. Everything except live capture works without it. |
| Windows: "cannot open capture" although Npcap is installed | Npcap can be installed in an Administrators-only mode. Either reinstall it without that option or run the terminal as Administrator. |
| Windows: no traffic appears | Run `tlsfp interfaces` and pass the right adapter with `--live "Wi-Fi"`. `auto` skips VPN, VMware and Hyper-V adapters; if you use one of those, name it. |
| Log says `no dashboard files found`, or `:8080` shows no page (the API still works) | Build it (`cd frontend && pnpm install && pnpm build`) or pass `--web DIR`. The release archives already contain it. |
| `421 Misdirected Request` | You reached the dashboard under a name it does not trust. Use `localhost`/`127.0.0.1`, or add `--allowed-host NAME`. |
| Browser shows an error after an upgrade | A stale cached page. Reload; the dashboard reloads itself once automatically. |
| Handshakes seem to be missing | See the capture health panel on Traffic, and [`CAPTURE_TUNING.md`](CAPTURE_TUNING.md). |
| `cargo` build fails with `rustc 1.xx is too old` | `rustup update stable`. Rust 1.85 or newer is required. |
