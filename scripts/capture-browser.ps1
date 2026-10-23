# capture-browser.ps1
#
# Records the TLS handshakes of a real desktop browser on Windows and, when Docker
# is available, prints their fingerprints with tlsfp. It uses pktmon, the packet
# recorder built into Windows 10 (version 2004) and Windows 11, so nothing needs
# installing.
#
#   1. Open PowerShell as Administrator.
#   2. cd to the repository folder.
#   3. .\scripts\capture-browser.ps1 -Browser chrome      (also: edge, firefox, brave)
#
# The recording holds the addresses and server names of EVERYTHING this computer
# connects to on port 443 while it runs. Close other programs first, keep the run
# short, and look at the output before sharing it. See docs\BROWSER_CAPTURE.md.

param(
    [Parameter(Mandatory = $true)][ValidateSet('chrome', 'edge', 'firefox', 'brave')][string]$Browser,
    [string]$OutDir = (Join-Path $env:USERPROFILE 'tlsfp-captures'),
    [string]$ExePath,
    [int]$Seconds = 45,
    [string]$Image = 'tlsfp:local'
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this from PowerShell opened as Administrator (pktmon needs it).' }
if (-not (Get-Command pktmon -ErrorAction SilentlyContinue)) { throw 'pktmon was not found; it needs Windows 10 version 2004 or later.' }

$candidates = @{
    chrome  = @('C:\Program Files\Google\Chrome\Application\chrome.exe',
                'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
                (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe'))
    edge    = @('C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
                'C:\Program Files\Microsoft\Edge\Application\msedge.exe')
    firefox = @('C:\Program Files\Mozilla Firefox\firefox.exe',
                'C:\Program Files (x86)\Mozilla Firefox\firefox.exe',
                (Join-Path $env:LOCALAPPDATA 'Mozilla Firefox\firefox.exe'))
    brave   = @('C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe',
                'C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe',
                (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\Application\brave.exe'))
}
$exe = @($ExePath) + $candidates[$Browser] | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
$name = @{ chrome = 'chrome.exe'; edge = 'msedge.exe'; firefox = 'firefox.exe'; brave = 'brave.exe' }[$Browser]
if (-not $exe) {
    # Installed somewhere unusual: ask Windows where the program registered itself.
    foreach ($hive in 'HKLM', 'HKCU') {
        $key = "${hive}:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$name"
        $found = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).'(default)'
        if ($found -and (Test-Path $found)) { $exe = $found; break }
    }
}
if (-not $exe) {
    $exe = (Get-Command $name -ErrorAction SilentlyContinue).Source
}
if (-not $exe) { throw "Could not find $Browser. Run it again with -ExePath <full path to the .exe>." }
$version = (Get-Item $exe).VersionInfo.ProductVersion

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$etl = Join-Path $OutDir "$Browser.etl"
$pcap = Join-Path $OutDir "$Browser.pcapng"
$meta = Join-Path $OutDir "$Browser.txt"
Remove-Item $etl, $pcap, $meta -ErrorAction SilentlyContinue

$urls = @('https://example.com', 'https://www.wikipedia.org', 'https://github.com',
          'https://www.cloudflare.com', 'https://www.mozilla.org')

Write-Host "Browser:  $Browser $version"
Write-Host "Recording to $OutDir for $Seconds seconds."
Read-Host "Close EVERY window of $Browser and any other program that uses the internet, then press Enter"

try {
    pktmon filter remove | Out-Null
    pktmon filter add -p 443 | Out-Null
    # nics only: recording at every layer of the stack would duplicate each packet
    pktmon start --capture --comp nics --pkt-size 0 --file-name $etl | Out-Null
    Start-Process -FilePath $exe -ArgumentList $urls
    Write-Host 'Browser started. Leave it alone until the timer ends...'
    Start-Sleep -Seconds $Seconds
}
finally {
    pktmon stop | Out-Null
}

pktmon etl2pcap $etl --out $pcap | Out-Null
if (-not (Test-Path $pcap)) { throw 'The conversion to pcapng failed; check that the recording was not empty.' }

@(
    "browser: $Browser",
    "version: $version",
    "os: $([System.Environment]::OSVersion.VersionString)",
    "captured: $(Get-Date -Format s)",
    "sites: $($urls -join ' ')"
) | Set-Content $meta

Write-Host ''
Write-Host "Saved: $pcap"
Write-Host "Notes: $meta"

if (Get-Command docker -ErrorAction SilentlyContinue) {
    docker image inspect $Image *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Building the tlsfp image ($Image); this takes a few minutes the first time..."
        docker build -f infra/docker/tlsfp.prod -t $Image .
    }
    Write-Host ''
    Write-Host 'Fingerprints of the handshakes (ja4 and ja3 identify the browser):'
    docker run --rm -v "${OutDir}:/cap" --entrypoint tlsfp $Image pcap "/cap/$Browser.pcapng" |
        Select-String -Pattern 'client_hello'
}
else {
    Write-Host 'Docker was not found. Analyse the file later with:'
    Write-Host "  docker run --rm -v `"${OutDir}:/cap`" --entrypoint tlsfp $Image pcap /cap/$Browser.pcapng"
}
