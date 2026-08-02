# Castiel DoH Kill Switch for Windows
#
# Usage:
#   .\doh-killswitch.ps1              # Toggle DoH on/off
#   .\doh-killswitch.ps1 off          # Emergency disable DoH
#   .\doh-killswitch.ps1 on           # Re-enable DoH
#   .\doh-killswitch.ps1 status       # Check Castiel status
#   .\doh-killswitch.ps1 stop         # Stop Castiel + restore DNS
#   .\doh-killswitch.ps1 restore      # Restore DNS to DHCP (emergency)

param(
    [Parameter(Position=0)]
    [ValidateSet("toggle","off","on","status","stop","restore")]
    [string]$Action = "toggle"
)

$ServiceName = "Castiel"
$InstallDir = "C:\Program Files\Castiel"

function Send-CastielSignal {
    param([string]$SignalType)
    # On Windows, we use sc.exe to send service controls
    # For DoH toggle, we restart the service with a special env var
    # or use a named pipe (future enhancement)
    # For now, we restart the service which re-reads config
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "Castiel service not found." -ForegroundColor Red
        return
    }

    # TODO: Implement named pipe IPC for DoH toggle without restart
    # For now, toggle by restarting the service with modified config
    Write-Host "Note: DoH toggle on Windows currently requires service restart."
    Write-Host "Future versions will use named pipe IPC for live toggle."
    Write-Host ""

    switch ($SignalType) {
        "toggle" {
            # Read config, toggle use_doh, restart
            $configPath = "$InstallDir\config.yaml"
            if (Test-Path $configPath) {
                $config = Get-Content $configPath -Raw
                if ($config -match 'use_doh:\s*true') {
                    $config = $config -replace 'use_doh:\s*true', 'use_doh: false'
                    Write-Host "Disabling DoH..."
                } else {
                    $config = $config -replace 'use_doh:\s*false', 'use_doh: true'
                    Write-Host "Enabling DoH..."
                }
                $config | Set-Content $configPath -NoNewline
                Restart-Service -Name $ServiceName -Force
                Write-Host "DoH toggled. Service restarted."
            }
        }
        "off" {
            $configPath = "$InstallDir\config.yaml"
            if (Test-Path $configPath) {
                $config = Get-Content $configPath -Raw
                $config = $config -replace 'use_doh:\s*true', 'use_doh: false'
                $config | Set-Content $configPath -NoNewline
                Restart-Service -Name $ServiceName -Force
                Write-Host "DoH disabled. Service restarted."
            }
        }
        "on" {
            $configPath = "$InstallDir\config.yaml"
            if (Test-Path $configPath) {
                $config = Get-Content $configPath -Raw
                $config = $config -replace 'use_doh:\s*false', 'use_doh: true'
                $config | Set-Content $configPath -NoNewline
                Restart-Service -Name $ServiceName -Force
                Write-Host "DoH enabled. Service restarted."
            }
        }
    }
}

function Restore-DNS {
    Write-Host "Restoring DNS to DHCP defaults..."
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($adapter in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
    }

    # Remove portproxy rules
    netsh interface portproxy delete v4tov4 listenport=53 protocol=tcp 2>$null
    netsh interface portproxy delete v4tov4 listenport=53 protocol=udp 2>$null

    Write-Host "DNS restored to DHCP defaults."

    # Verify
    Write-Host ""
    Write-Host "Verifying DNS connectivity..."
    try {
        $result = Resolve-DnsName -Name google.com -Server 1.1.1.1 -ErrorAction Stop
        Write-Host "OK: DNS is working (query to 1.1.1.1 succeeded)" -ForegroundColor Green
    } catch {
        Write-Host "WARNING: DNS may still be broken - try: ipconfig /flushdns" -ForegroundColor Yellow
    }
}

switch ($Action) {
    "toggle"  { Send-CastielSignal "toggle" }
    "off"     { Send-CastielSignal "off" }
    "on"      { Send-CastielSignal "on" }
    "status"  {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "Castiel service: $($svc.Status)"
        } else {
            Write-Host "Castiel service not found."
        }
        Write-Host ""
        Write-Host "DNS Configuration:"
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
            if ($dns) {
                Write-Host "  $($adapter.Name): $($dns.ServerAddresses -join ', ')"
            }
        }
        Write-Host ""
        Write-Host "Portproxy rules:"
        netsh interface portproxy show all
    }
    "stop"    {
        Write-Host "Stopping Castiel..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Write-Host "Service stopped."
        Restore-DNS
    }
    "restore" { Restore-DNS }
    default   {
        Write-Host "Castiel DoH Kill Switch (Windows)"
        Write-Host ""
        Write-Host "Usage: .\doh-killswitch.ps1 {toggle|off|on|status|stop|restore}"
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  toggle   - Toggle DoH on/off (restarts service)"
        Write-Host "  off      - Emergency disable DoH (restarts service)"
        Write-Host "  on       - Re-enable DoH (restarts service)"
        Write-Host "  status   - Check Castiel status and DNS configuration"
        Write-Host "  stop     - Stop Castiel entirely + restore DNS"
        Write-Host "  restore  - Restore DNS to DHCP defaults (emergency)"
        Write-Host ""
        Write-Host "If your internet is broken:"
        Write-Host "  1. .\doh-killswitch.ps1 off       # Try disabling DoH first"
        Write-Host "  2. .\doh-killswitch.ps1 stop       # If still broken, stop Castiel"
        Write-Host "  3. .\doh-killswitch.ps1 restore    # Last resort: restore DNS"
    }
}
