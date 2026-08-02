# Castiel — Windows Build Specification

## Overview

Castiel on Windows replaces macOS-specific subsystems with Windows equivalents:

| Component             | macOS (current)              | Windows (proposed)                          |
|-----------------------|------------------------------|---------------------------------------------|
| DNS traffic redirect  | PF firewall (`pfctl`)        | WinDivert (user-space packet capture)       |
| System service        | LaunchDaemon (`launchctl`)   | Windows Service (SCM / `sc.exe`)            |
| Desktop GUI app       | SwiftUI (macOS only)         | WPF / WinUI 3 (C#) or Go + Walk/Lorca       |
| Desktop notifications | `osascript` (Notification Center) | Windows Toast Notifications (WinRT)    |
| DNS settings restore  | `networksetup`               | `netsh interface ip set dnsservers`         |
| App bundle            | `.app` bundle + `Info.plist` | MSI installer / NSIS / portable `.exe`      |
| Kill switch           | `doh-killswitch.sh` (bash)   | `doh-killswitch.ps1` (PowerShell)           |
| Signal handling       | `kill -HUP` / SIGUSR1/USR2   | Windows Service controls + named pipe       |

## Architecture

```
windows_build/
├── README.md                    # This file
├── install.ps1                  # PowerShell install script
├── uninstall.ps1                # PowerShell uninstall script
├── castiel-service.go           # Windows Service wrapper (golang.org/x/sys/windows/svc)
├── doh-killswitch.ps1           # PowerShell kill switch
├── config.yaml                  # Windows-specific config
├── castiel.ico                  # Windows app icon
├── wfp/
│   └── castiel-rules.ps1        # Windows Filtering Platform rules (optional alt to WinDivert)
├── installer/
│   ├── castiel.nsi              # NSIS installer script
│   └── castiel-msi.wxs          # WiX MSI definition (alternative)
└── gui/                         # Windows GUI app (optional)
    ├── main.go                  # Walk/Lorca entry point
    ├── go.mod
    └── README.md
```

## 1. DNS Traffic Interception — WinDivert

### Approach

Windows doesn't have a built-in user-space NAT redirect like PF or nftables. Two options:

### Option A: WinDivert (Recommended)

[WinDivert](https://reqrypt.org/windivert.html) is a user-space packet capture/modify library that can intercept DNS packets and redirect them to the local proxy.

```go
//go:build windows
package windivert

import (
    "github.com/AdiPratama15/windivert-go"  // or raw syscall wrapper
)

type Manager struct {
    cfg        config.WinDivertConfig
    handle     windivert.Handle
    redirectPort int
}

func NewManager(cfg config.WinDivertConfig) (*Manager, error) {
    // Open WinDivert handle with filter: "udp.DstPort == 53 or tcp.DstPort == 53"
    // Requires Administrator privileges
    handle, err := windivert.Open("udp.DstPort == 53 or tcp.DstPort == 53",
        windivert.LayerNetwork, 0, 0)
    if err != nil {
        return nil, fmt.Errorf("WinDivert open failed: %w", err)
    }
    return &Manager{cfg: cfg, handle: handle}, nil
}

func (m *Manager) InstallRedirect() error {
    // Start a goroutine that:
    // 1. Reads packets from WinDivert
    // 2. Modifies destination port from 53 to 5300
    // 3. Recalculates checksums
    // 4. Re-injects the modified packet
    // 5. Captures the response, reverses the port change, re-injects
    go m.redirectLoop()
    return nil
}

func (m *Manager) redirectLoop() {
    buf := make([]byte, 65535)
    for {
        n, addr, err := m.handle.Recv(buf)
        if err != nil {
            return
        }
        packet := buf[:n]
        // Parse IP + UDP/TCP headers
        // Change dst port 53 -> m.cfg.RedirectPort
        // Fix checksums
        // Re-inject
        m.handle.Send(packet, addr)
    }
}

func (m *Manager) Cleanup() {
    m.handle.Close()
}
```

**Pros:** Works on all Windows versions, no kernel driver needed (uses signed WinDivert driver)
**Cons:** Requires bundling WinDivert driver (`WinDivert64.sys`), higher overhead than kernel NAT

### Option B: Windows Filtering Platform (WFP)

WFP is the native Windows kernel-level packet filtering framework. It requires a kernel-mode callout driver (C/C++) or the `netsh` interface.

```powershell
# netsh-based port redirect (simpler but less flexible)
netsh interface portproxy add v4tov4 listenport=53 connectaddress=127.0.0.1 connectport=5300 protocol=udp
netsh interface portproxy add v4tov4 listenport=53 connectaddress=127.0.0.1 connectport=5300 protocol=tcp
```

**Pros:** No third-party driver, built into Windows
**Cons:** `netsh portproxy` only works for TCP by default; UDP requires WFP callout driver

### Option C: DNS Proxy via System Settings

Simply set the system DNS to `127.0.0.1` — Castiel listens on port 53 directly:

```powershell
# Set DNS to localhost (Castiel listens on :53)
netsh interface ip set dns "Ethernet" static 127.0.0.1
netsh interface ip set dns "Wi-Fi" static 127.0.0.1
```

**Pros:** Simplest approach, no packet interception needed
**Cons:** Only catches DNS from apps that respect system DNS (not hardcoded resolvers), requires Castiel to bind to port 53

### Recommended: Option C (system DNS) + Option B (portproxy for TCP)

Most pragmatic for Windows — set system DNS to 127.0.0.1, use `netsh portproxy` for TCP fallback.

### Config

```yaml
# Windows-specific config (replaces pf: section)
dns_redirect:
  enabled: true
  method: "system_dns"        # "system_dns", "portproxy", or "windivert"
  redirect_port: 5300
  interface: ""               # empty = all interfaces
  bind_port_53: true          # Castiel binds directly to :53
```

## 2. System Service — Windows Service Control Manager

### Go Service Wrapper

Use `golang.org/x/sys/windows/svc` to run Castiel as a Windows Service:

```go
//go:build windows
package main

import (
    "golang.org/x/sys/windows/svc"
    "golang.org/x/sys/windows/svc/mgr"
)

func main() {
    isIntSess, err := svc.IsWindowsService()
    if err != nil {
        log.Fatalf("failed to determine service context: %v", err)
    }

    if !isIntSess {
        // Running in terminal — start in foreground
        runDaemon()
        return
    }

    // Running as Windows Service
    if err := svc.Run("Castiel", &castielService{}); err != nil {
        log.Fatalf("failed to run service: %v", err)
    }
}

type castielService struct{}

func (s *castielService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
    changes <- svc.Status{State: svc.StartPending}

    // Start Castiel daemon in goroutine
    ctx, cancel := context.WithCancel(context.Background())
    go runDaemon(ctx)

    changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreshutdown}

    for {
        c := <-r
        switch c.Cmd {
        case svc.Interrogate:
            changes <- c.CurrentStatus
        case svc.Stop, svc.Shutdown:
            changes <- svc.Status{State: svc.StopPending}
            cancel()
            time.Sleep(2 * time.Second)
            changes <- svc.Status{State: svc.Stopped}
            return
        case svc.Preshutdown:
            // Graceful shutdown
            changes <- svc.Status{State: svc.StopPending}
            cancel()
            time.Sleep(2 * time.Second)
            changes <- svc.Status{State: svc.Stopped}
            return
        }
    }
}
```

### Service Installation

```powershell
# Install as Windows Service
sc.exe create Castiel binPath= "C:\Program Files\Castiel\castiel.exe -config C:\Program Files\Castiel\config.yaml" start= auto
sc.exe description Castiel "Castiel DNS Defense Daemon — DGA detection, tunneling prevention, DNSSEC validation"
sc.exe failure Castiel reset= 86400 actions= restart/5000/restart/10000/restart/30000

# Start
sc.exe start Castiel

# Stop
sc.exe stop Castiel

# Query status
sc.exe query Castiel
```

### DoH Kill Switch via Service Controls

Instead of Unix signals, use Windows Service custom controls or a named pipe:

```go
// Named pipe for IPC (kill switch commands)
// \\.\pipe\castiel-control
pipe, _ := winio.ListenPipe(`\\.\pipe\castiel-control`, nil)
go func() {
    for {
        conn, err := pipe.Accept()
        if err != nil { continue }
        handleControlCommand(conn)  // reads "doh_off", "doh_on", "doh_toggle"
    }
}()
```

PowerShell kill switch sends commands via the named pipe:

```powershell
# doh-killswitch.ps1
function Send-CastielCommand {
    param([string]$Command)
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "castiel-control", [System.IO.Pipes.PipeDirection]::InOut)
    $pipe.Connect(5000)
    $writer = New-Object System.IO.StreamWriter($pipe)
    $writer.WriteLine($Command)
    $writer.Flush()
    $pipe.Close()
}

Send-CastielCommand "doh_toggle"
```

## 3. Desktop GUI — WPF / WinUI 3 or Go + Walk

### Option A: Go + Walk (Pure Go)

[Walk](https://github.com/lxn/walk) is a Windows GUI toolkit for Go:

```go
//go:build windows
package main

import (
    "github.com/lxn/walk"
    . "github.com/lxn/walk/declarative"
)

func main() {
    MainWindow{
        Title:   "Castiel DNS Defense",
        MinSize: Size{400, 300},
        Layout:  VBox{},
        Children: []Widget{
            Label{Text: "Status: Running", Font: Font{Bold: true, Size: 14}},
            Composite{
                Layout: Grid{Columns: 2},
                Children: []Widget{
                    Label{Text: "Total Queries:"}, Label{Text: "1,234,567"},
                    Label{Text: "Blocked:"}, Label{Text: "45,678 (3.7%)"},
                    Label{Text: "DoH:"}, Label{Text: "Enabled"},
                },
            },
            PushButton{Text: "Toggle DoH", OnClicked: func() { /* ... */ }},
            PushButton{Text: "Kill Switch", OnClicked: func() { /* ... */ }},
        },
    }.Run()
}
```

### Option B: Go + Lorca (Chrome-based UI)

[Lorca](https://github.com/zserge/lorca) opens a Chrome window with an HTML UI:

```go
ui, _ := lorca.New("http://127.0.0.1:9090/dashboard", "", 800, 600)
// Reuse the existing web dashboard / metrics endpoint
```

### Option C: WPF / WinUI 3 (C#)

Separate C# project that reads from the metrics endpoint:
- Native Windows look and feel
- System tray icon with context menu
- Toast notifications via WinRT

### Recommended: Option B (Lorca)

Reuses the existing Prometheus metrics endpoint, minimal new code, cross-platform HTML UI.

## 4. Desktop Notifications — Windows Toast

```go
//go:build windows
func (m *Manager) sendDesktopNotification(a Alert) {
    title := fmt.Sprintf("Castiel — %s", a.Severity)
    body := a.Message
    if a.Domain != "" {
        body = fmt.Sprintf("%s — Domain: %s", a.Message, a.Domain)
    }
    // Use PowerShell to show toast notification
    psScript := fmt.Sprintf(
        `[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime] | Out-Null;`+
        `$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);`+
        `$text = $template.GetElementsByTagName("text");`+
        `$text.Item(0).AppendChild($template.CreateTextNode("%s")) | Out-Null;`+
        `$text.Item(1).AppendChild($template.CreateTextNode("%s")) | Out-Null;`+
        `[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Castiel").Show($template)`,
        title, body)
    exec.Command("powershell", "-NoProfile", "-Command", psScript).Run()
}
```

## 5. Kill Switch — `doh-killswitch.ps1`

```powershell
# Castiel DoH Kill Switch for Windows
param(
    [Parameter(Position=0)]
    [ValidateSet("toggle","off","on","status","stop","restore")]
    [string]$Action = "toggle"
)

$ServiceName = "Castiel"
$PipeName = "castiel-control"

function Send-CastielCommand {
    param([string]$Command)
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
            ".", $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
        $pipe.Connect(5000)
        $writer = New-Object System.IO.StreamWriter($pipe)
        $writer.WriteLine($Command)
        $writer.Flush()
        $pipe.Close()
        Write-Host "Sent command: $Command"
    } catch {
        Write-Host "Error: Could not connect to Castiel. Is the service running?"
    }
}

function Restore-DNS {
    # Reset DNS to DHCP
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($adapter in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses
    }

    # Remove portproxy rules
    netsh interface portproxy delete v4tov4 listenport=53 protocol=udp 2>$null
    netsh interface portproxy delete v4tov4 listenport=53 protocol=tcp 2>$null

    Write-Host "DNS restored to DHCP defaults."
}

switch ($Action) {
    "toggle"  { Send-CastielCommand "doh_toggle" }
    "off"     { Send-CastielCommand "doh_off" }
    "on"      { Send-CastielCommand "doh_on" }
    "status"  {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "Castiel service: $($svc.Status)"
        } else {
            Write-Host "Castiel service not found."
        }
    }
    "stop"    {
        Stop-Service -Name $ServiceName -Force
        Restore-DNS
    }
    "restore" { Restore-DNS }
}
```

## 6. Install Script — `install.ps1`

```powershell
# Castiel Windows Install Script
# Run as Administrator

$ErrorActionPreference = "Stop"
$InstallDir = "C:\Program Files\Castiel"
$ConfigDir  = "$InstallDir"
$LogDir     = "$InstallDir\logs"
$DataDir    = "$InstallDir\data"

Write-Host "=== Castiel Installation ===" -ForegroundColor Green

# Check admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Error: Must run as Administrator" -ForegroundColor Red
    exit 1
}

# 1. Build Go daemon
Write-Host "[1/6] Building Go daemon..." -ForegroundColor Green
go build -ldflags="-s -w" -o castiel.exe .

# 2. Create directories
Write-Host "[2/6] Creating directories..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path $InstallDir, $LogDir, $DataDir | Out-Null

# 3. Install binary + config + data
Write-Host "[3/6] Installing files..." -ForegroundColor Green
Copy-Item castiel.exe $InstallDir\
Copy-Item config.yaml $ConfigDir\
Copy-Item data\* $DataDir\ -Recurse

# Patch config paths
$config = Get-Content "$ConfigDir\config.yaml" -Raw
$config = $config -replace 'data/', "$DataDir\".Replace('\','\\')
$config | Set-Content "$ConfigDir\config.yaml"

# 4. Install kill switch
Copy-Item doh-killswitch.ps1 $InstallDir\

# 5. Install Windows Service
Write-Host "[4/6] Installing Windows Service..." -ForegroundColor Green
if (Get-Service -Name Castiel -ErrorAction SilentlyContinue) {
    sc.exe delete Castiel
}
sc.exe create Castiel binPath= "`"$InstallDir\castiel.exe`" -config `"$ConfigDir\config.yaml`"" start= auto
sc.exe description Castiel "Castiel DNS Defense Daemon"
sc.exe failure Castiel reset= 86400 actions= restart/5000/restart/10000/restart/30000

# 6. Configure DNS redirect
Write-Host "[5/6] Configuring DNS redirect..." -ForegroundColor Green
# Set system DNS to localhost
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "127.0.0.1"
}

# 7. Start service
Write-Host "[6/6] Starting service..." -ForegroundColor Green
sc.exe start Castiel

Write-Host ""
Write-Host "=== Installation Complete ===" -ForegroundColor Green
Write-Host "  Service:  sc.exe query Castiel"
Write-Host "  Logs:     $LogDir"
Write-Host "  Config:   $ConfigDir\config.yaml"
Write-Host ""
Write-Host "Commands:"
Write-Host "  sc.exe stop Castiel              # Stop daemon"
Write-Host "  sc.exe start Castiel             # Start daemon"
Write-Host "  .\doh-killswitch.ps1 status      # Check status"
Write-Host "  .\doh-killswitch.ps1 off         # Emergency disable DoH"
Write-Host "  .\doh-killswitch.ps1 restore     # Restore DNS (emergency)"
```

## 7. Config — `config.yaml` (Windows)

```yaml
server:
  listen_addr: "127.0.0.1"
  listen_port: 53          # Bind directly to :53 on Windows
  upstream: ["1.1.1.1:53", "9.9.9.9:53"]
  use_doh: true
  doh_upstream: "https://cloudflare-dns.com/dns-query"

# Windows-specific (replaces pf: section)
dns_redirect:
  enabled: true
  method: "system_dns"    # Set system DNS to 127.0.0.1
  # method: "portproxy"   # Use netsh portproxy (TCP only)
  # method: "windivert"   # Use WinDivert packet capture
  redirect_port: 53
  interface: ""

alerts:
  enabled: true
  log_file: "C:\\Program Files\\Castiel\\logs\\castiel_alerts.jsonl"
  syslog_enabled: false    # No syslog on Windows; use Windows Event Log
  desktop_notification: true  # Uses Windows Toast
  event_log: true          # Write to Windows Event Log
  min_severity: "warn"
```

## 8. Windows Event Log Integration

```go
//go:build windows
package alerts

import (
    "golang.org/x/sys/windows/elog"
)

type EventLogger struct {
    log *elog.Log
}

func NewEventLogger() (*EventLogger, error) {
    log, err := elog.Open("Castiel")
    if err != nil {
        return nil, err
    }
    return &EventLogger{log: log}, nil
}

func (e *EventLogger) Log(severity string, message string) {
    switch severity {
    case "critical":
        e.log.Error(1, message)
    case "warn":
        e.log.Warning(2, message)
    default:
        e.log.Info(3, message)
    }
}
```

Requires registering event source:
```powershell
eventvwr.msc → Applications and Services Logs → Castiel
# Or via registry:
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Castiel"
```

## 9. NSIS Installer — `installer/castiel.nsi`

```nsis
!define APPNAME "Castiel"
!define VERSION "0.1.0"
!define INSTALLDIR "C:\Program Files\Castiel"

Name "${APPNAME}"
OutFile "castiel-${VERSION}-setup.exe"
InstallDir "${INSTALLDIR}"
RequestExecutionLevel admin

Page directory
Page instfiles

Section "Install"
    SetOutPath "$INSTDIR"
    File castiel.exe
    File config.yaml
    File /r data
    File doh-killswitch.ps1

    # Install service
    nsExec::Exec 'sc.exe create Castiel binPath= "$INSTDIR\castiel.exe -config $INSTDIR\config.yaml" start= auto'
    nsExec::Exec 'sc.exe start Castiel'

    # Create Start Menu shortcut
    CreateDirectory "$SMPROGRAMS\Castiel"
    CreateShortcut "$SMPROGRAMS\Castiel\Castiel.lnk" "$INSTDIR\castiel.exe"
    CreateShortcut "$SMPROGRAMS\Castiel\Uninstall.lnk" "$INSTDIR\uninstall.exe"

    WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
    nsExec::Exec 'sc.exe stop Castiel'
    nsExec::Exec 'sc.exe delete Castiel'
    Delete "$INSTDIR\*"
    RMDir "$INSTDIR"
    Delete "$SMPROGRAMS\Castiel\*"
    RMDir "$SMPROGRAMS\Castiel"
SectionEnd
```

## 10. Build Tags Strategy

```
internal/
├── pf/               # //go:build darwin
├── nft/              # //go:build linux
├── windivert/        # //go:build windows
├── alerts/
│   ├── manager.go           # shared logic
│   ├── notify_darwin.go     # //go:build darwin
│   ├── notify_linux.go      # //go:build linux
│   └── notify_windows.go    # //go:build windows
├── service/
│   ├── service_darwin.go    # //go:build darwin (launchd helpers)
│   ├── service_linux.go     # //go:build linux (systemd helpers)
│   └── service_windows.go   # //go:build windows (SCM wrapper)
├── config/
│   └── config.go            # add WinDivertConfig, DnsRedirectConfig
```

## 11. Cross-Platform Firewall Interface

```go
// internal/firewall/firewall.go
package firewall

type Manager interface {
    InstallRedirect() error
    Cleanup()
}

// internal/pf/pf.go        — //go:build darwin
// internal/nft/nft.go      — //go:build linux
// internal/windivert/wd.go — //go:build windows

// main.go (shared)
func newFirewallManager(cfg *config.Config) (firewall.Manager, error) {
    switch runtime.GOOS {
    case "darwin":
        return pf.NewManager(cfg.PF)
    case "linux":
        return nft.NewManager(cfg.Nft)
    case "windows":
        return windivert.NewManager(cfg.DnsRedirect)
    default:
        return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
    }
}
```

## 12. Dependencies

### Build Dependencies
- Go 1.21+ (with `GOOS=windows`)
- (Optional) NSIS for installer creation
- (Optional) WiX Toolset for MSI
- (Optional) Go + Walk for native GUI

### Runtime Dependencies
- Windows 10/11 (x64) or Windows Server 2016+
- Administrator privileges (for service + DNS redirect)
- (If WinDivert) WinDivert64.sys driver (bundled)

### Go Module Dependencies (Windows-only)
```
golang.org/x/sys/windows/svc       # Windows Service wrapper
golang.org/x/sys/windows/svc/mgr   # Service manager
golang.org/x/sys/windows/elog      # Event Log
github.com/lxn/walk                # (optional) Windows GUI
github.com/zserge/lorca            # (optional) Chrome-based UI
```

## 13. Testing

### Unit Tests
- `internal/windivert/wd_test.go` — test packet parsing logic (no admin needed)
- Build-tag gated: `//go:build windows`
- Cross-compile from macOS: `GOOS=windows go test ./internal/windivert/`

### Integration Tests
- `test-castiel.sh` → port to `test-castiel.ps1` (PowerShell)
- Replace `pgrep` with `Get-Process`
- Replace `curl` with `Invoke-WebRequest`
- Replace `pfctl` with `sc.exe query`

## 14. Build Commands

```bash
# Cross-compile from macOS/Linux
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o castiel.exe .

# Or native on Windows
go build -ldflags="-s -w" -o castiel.exe .

# Build GUI (optional, Windows-only)
cd gui && go build -ldflags="-H windowsgui" -o castiel-gui.exe .
```

## 15. Security Considerations

- **UAC elevation**: Install script and service require Administrator
- **Windows Defender**: WinDivert driver may trigger SmartScreen; sign with code signing certificate
- **Firewall rules**: Windows Firewall may block Castiel's outbound DNS; add inbound rule for port 5300
- **DNS over HTTPS**: System DNS setting doesn't affect apps using DoH directly (Chrome, Firefox) — WinDivert approach would be needed for full coverage
- **Service account**: Run as `LocalSystem` (has admin privileges) or `NetworkService` with specific rights
