# © Pranav Verma | 2026
# start-windows.ps1
#
# Starts tlsfp with live capture on Windows and opens the dashboard.
# Run it from the folder you extracted the release into:
#   powershell -ExecutionPolicy Bypass -File .\start-windows.ps1 [-Interface "Wi-Fi"] [-Port 8080]
# Live capture needs Npcap (https://npcap.com). Reading capture files does not.

param(
    [string]$Interface = "auto",
    [int]$Port = 8080,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $here "tlsfp.exe"
if (-not (Test-Path $exe)) { throw "tlsfp.exe not found next to this script ($here)" }

$npcap = (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll") -or (Test-Path "$env:SystemRoot\System32\wpcap.dll")
if (-not $npcap) {
    Write-Host "Npcap is not installed. Live capture needs it." -ForegroundColor Yellow
    Write-Host "Opening https://npcap.com/#download - install it with the default options, then run this script again."
    Start-Process "https://npcap.com/#download"
    exit 1
}

$db = Join-Path $env:LOCALAPPDATA "tlsfp\intel.db"
if (-not (Test-Path $db)) {
    Write-Host "Seeding the intelligence database (first run)..."
    & $exe intel seed
    if ($LASTEXITCODE -ne 0) { throw "seeding failed" }
}

$captures = Join-Path $env:USERPROFILE "tlsfp-captures"
$args = @("serve", "127.0.0.1:$Port", "--live", $Interface)
if (Test-Path $captures) { $args += @("--library", $captures) }

Write-Host "Dashboard: http://127.0.0.1:$Port  (Ctrl+C to stop)"
if (-not $NoBrowser) { Start-Process "http://127.0.0.1:$Port" }
& $exe @args
