# Castiel Uninstall Script for Windows
# Run as Administrator in PowerShell
#
# Usage:
#   .\windows_build\uninstall.ps1

$ErrorActionPreference = "Stop"

$InstallDir = "C:\Program Files\Castiel"
$ServiceName = "Castiel"

Write-Host "=== Castiel - Windows Uninstallation ===" -ForegroundColor Green
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Error: This script must be run as Administrator" -ForegroundColor Red
    exit 1
}

# 1. Stop the service
Write-Host "[1/5] Stopping Castiel service..." -ForegroundColor Green
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "  Service stopped"
} else {
    Write-Host "  Service not found"
}

# 2. Remove DNS redirect
Write-Host "[2/5] Restoring DNS settings..." -ForegroundColor Green
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
}
# Remove portproxy rules
netsh interface portproxy delete v4tov4 listenport=53 protocol=tcp 2>$null
netsh interface portproxy delete v4tov4 listenport=53 protocol=udp 2>$null
Write-Host "  DNS restored to DHCP"

# 3. Remove Windows Service
Write-Host "[3/5] Removing Windows Service..." -ForegroundColor Green
if ($svc) {
    sc.exe delete $ServiceName | Out-Null
    Write-Host "  Service removed"
}

# 4. Remove files
Write-Host "[4/5] Removing files..." -ForegroundColor Green
if (Test-Path $InstallDir) {
    $confirm = Read-Host "  This will remove all Castiel files at $InstallDir. Continue? (y/N)"
    if ($confirm -eq "y" -or $confirm -eq "Y") {
        Remove-Item $InstallDir -Recurse -Force
        Write-Host "  Files removed"
    } else {
        Write-Host "  Skipped file removal"
    }
}

# 5. Verify
Write-Host "[5/5] Verifying..." -ForegroundColor Green
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "  Service: removed" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Service still exists" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Uninstallation Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "  Castiel has been fully removed from this system."
