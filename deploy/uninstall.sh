#!/bin/bash
#
# Castiel Uninstall Script
#
# Stops and removes the Castiel DNS defense daemon, config, and app.
# Must be run with sudo.
#
# Usage:
#   sudo ./deploy/uninstall.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PREFIX="/usr/local"
BIN_DIR="${PREFIX}/bin"
ETC_DIR="${PREFIX}/etc/castiel"
VAR_DIR="${PREFIX}/var/log/castiel"
LAUNCH_DAEMON_DIR="/Library/LaunchDaemons"
LAUNCH_AGENT_DIR="${HOME}/Library/LaunchAgents"
APP_DIR="/Applications"

echo -e "${GREEN}=== Castiel — Uninstallation ===${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run with sudo.${NC}"
    echo "  sudo $0"
    exit 1
fi

# 1. Stop and unload the daemon
echo -e "${GREEN}[1/5] Stopping daemon...${NC}"
launchctl unload "$LAUNCH_DAEMON_DIR/com.castiel.daemon.plist" 2>/dev/null || true
echo "  ✓ Daemon stopped and unloaded"

# 2. Remove PF rules
echo -e "${GREEN}[2/5] Removing PF rules...${NC}"
pfctl -a castiel -r 2>/dev/null || true
echo "  ✓ PF anchor cleared"

# 3. Restore DNS settings
echo -e "${GREEN}[3/5] Restoring DNS to DHCP defaults...${NC}"
NETWORK_SERVICE=$(networksetup -listallnetworkservices 2>/dev/null | grep -E "Wi-Fi|Ethernet" | head -1)
if [ -n "$NETWORK_SERVICE" ]; then
    networksetup -setdnsservers "$NETWORK_SERVICE" empty 2>/dev/null || true
    echo "  ✓ DNS restored on: $NETWORK_SERVICE"
else
    echo -e "${YELLOW}  ⚠ Could not detect network service — restore DNS manually${NC}"
fi

# 4. Remove files
echo -e "${GREEN}[4/5] Removing files...${NC}"

# Remove LaunchDaemon
rm -f "$LAUNCH_DAEMON_DIR/com.castiel.daemon.plist"
echo "  ✓ Removed LaunchDaemon plist"

# Remove LaunchAgent
rm -f "$LAUNCH_AGENT_DIR/com.castiel.app.plist"
echo "  ✓ Removed LaunchAgent plist"

# Remove binary
rm -f "$BIN_DIR/castiel" "$BIN_DIR/doh-killswitch.sh"
echo "  ✓ Removed binaries"

# Remove app
rm -rf "$APP_DIR/Castiel.app"
echo "  ✓ Removed macOS app"

# Backup and remove config/data
if [ -d "$ETC_DIR" ]; then
    cp -r "$ETC_DIR" "${ETC_DIR}.bak.$(date +%s)" 2>/dev/null || true
    rm -rf "$ETC_DIR"
    echo "  ✓ Removed config (backup at ${ETC_DIR}.bak.*)"
fi

# Remove logs
if [ -d "$VAR_DIR" ]; then
    rm -rf "$VAR_DIR"
    echo "  ✓ Removed logs"
fi

# 5. Verify
echo -e "${GREEN}[5/5] Verifying...${NC}"
if launchctl list | grep -q "castiel"; then
    echo -e "${YELLOW}  ⚠ Daemon still in launchctl list — may need reboot${NC}"
else
    echo "  ✓ Daemon fully removed"
fi

# Test DNS
if nslookup google.com 1.1.1.1 >/dev/null 2>&1; then
    echo "  ✓ DNS is working (query to 1.1.1.1 succeeded)"
else
    echo -e "${YELLOW}  ⚠ DNS may still be broken — try: sudo networksetup -setdnsservers Wi-Fi empty${NC}"
fi

echo ""
echo -e "${GREEN}=== Uninstallation Complete ===${NC}"
echo ""
echo "All Castiel components have been removed. DNS has been restored to DHCP defaults."
