# Castiel Install Script for Windows
# Run as Administrator in PowerShell
#
# Usage:
#   .\windows_build\install.ps1

$ErrorActionPreference = "Stop"

# Paths
$InstallDir = "C:\Program Files\Castiel"
$ConfigDir  = $InstallDir
$LogDir     = "$InstallDir\logs"
$DataDir    = "$InstallDir\data"
$ServiceName = "Castiel"

$ScriptDir = Split-Path -Parent $PSScriptRoot
$WindowsDir = "$ScriptDir\windows_build"

Write-Host "=== Castiel - Windows Installation ===" -ForegroundColor Green
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Error: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "  Right-click PowerShell -> Run as Administrator"
    exit 1
}

# 1. Build the Go binary (cross-compile if on non-Windows, or use pre-built)
Write-Host "[1/7] Building Castiel daemon..." -ForegroundColor Green
if (Test-Path "$WindowsDir\castiel.exe") {
    Write-Host "  Using pre-built binary: $WindowsDir\castiel.exe"
} elseif (Get-Command go -ErrorAction SilentlyContinue) {
    Push-Location $ScriptDir
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
    & go build -ldflags="-s -w" -o "$WindowsDir\castiel.exe" .
    Pop-Location
    Write-Host "  Built $WindowsDir\castiel.exe"
} else {
    Write-Host "Error: Go not installed and no pre-built binary found." -ForegroundColor Red
    Write-Host "  Install Go from https://go.dev/dl/"
    exit 1
}

# 2. Create directories
Write-Host "[2/7] Creating directories..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
Write-Host "  OK"

# 3. Install binary + config + data
Write-Host "[3/7] Installing files..." -ForegroundColor Green
Copy-Item "$WindowsDir\castiel.exe" $InstallDir -Force
Copy-Item "$WindowsDir\config.yaml" $ConfigDir -Force

# Copy data files
$dataSource = "$ScriptDir\data"
if (Test-Path $dataSource) {
    Copy-Item "$dataSource\*" $DataDir -Recurse -Force
}

# Patch config paths for Windows
$config = Get-Content "$ConfigDir\config.yaml" -Raw
$config = $config -replace 'data/', ($DataDir -replace '\\', '\\')
$config = $config -replace '/usr/local/var/log/castiel', ($LogDir -replace '\\', '\\')
$config | Set-Content "$ConfigDir\config.yaml" -NoNewline

Write-Host "  Binary: $InstallDir\castiel.exe"
Write-Host "  Config: $ConfigDir\config.yaml"
Write-Host "  Data:   $DataDir"

# 4. Install kill switch script
Write-Host "[4/7] Installing kill switch..." -ForegroundColor Green
Copy-Item "$WindowsDir\doh-killswitch.ps1" $InstallDir -Force
Write-Host "  OK: $InstallDir\doh-killswitch.ps1"

# 5. Install Windows Service
Write-Host "[5/7] Installing Windows Service..." -ForegroundColor Green
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

$binPath = "`"$InstallDir\castiel.exe`" -config `"$ConfigDir\config.yaml`""
sc.exe create $ServiceName binPath= $binPath start= auto | Out-Null
sc.exe description $ServiceName "Castiel DNS Defense Daemon - DGA detection, tunneling prevention, DNSSEC validation"
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
Write-Host "  Service installed: $ServiceName"

# 6. Configure DNS redirect
Write-Host "[6/7] Configuring DNS redirect..." -ForegroundColor Green
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "127.0.0.1"
    Write-Host "  DNS set to 127.0.0.1 on: $($adapter.Name)"
}

# 7. Start service
Write-Host "[7/7] Starting service..." -ForegroundColor Green
sc.exe start $ServiceName | Out-Null
Start-Sleep -Seconds 2

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "  Castiel is running" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Castiel failed to start - check: sc.exe query Castiel" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Installation Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "  Binary:   $InstallDir\castiel.exe"
Write-Host "  Config:   $ConfigDir\config.yaml"
Write-Host "  Data:     $DataDir"
Write-Host "  Logs:     $LogDir"
Write-Host "  Service:  $ServiceName"
Write-Host ""
Write-Host "Commands:"
Write-Host "  sc.exe query Castiel                    # Check service status"
Write-Host "  sc.exe stop Castiel                     # Stop daemon"
Write-Host "  sc.exe start Castiel                    # Start daemon"
Write-Host "  .\doh-killswitch.ps1 status             # Check DoH status"
Write-Host "  .\doh-killswitch.ps1 off                # Emergency disable DoH"
Write-Host "  .\doh-killswitch.ps1 restore            # Restore DNS (emergency)"
