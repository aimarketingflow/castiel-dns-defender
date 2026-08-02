#!/bin/bash
#
# Castiel Uninstall Script for Linux
#
# Removes all Castiel components.
# Must be run with sudo.
#
# Usage:
#   sudo ./linux_build/uninstall.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PREFIX="/usr/local"
BIN_DIR="${PREFIX}/bin"
ETC_DIR="${PREFIX}/etc/castiel"
VAR_DIR="${PREFIX}/var/log/castiel"
SYSTEMD_DIR="/etc/systemd/system"
APP_DIR="/usr/share/applications"

echo -e "${GREEN}=== Castiel — Linux Uninstallation ===${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run with sudo.${NC}"
    exit 1
fi

# 1. Stop the service
echo -e "${GREEN}[1/5] Stopping Castiel service...${NC}"
systemctl stop castiel 2>/dev/null || true
systemctl disable castiel 2>/dev/null || true
echo "  ✓ Service stopped"

# 2. Remove nftables rules
echo -e "${GREEN}[2/5] Removing nftables/iptables rules...${NC}"
nft delete table ip castiel 2>/dev/null || true
nft delete table ip6 castiel 2>/dev/null || true
iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5300 2>/dev/null || true
iptables -t nat -D OUTPUT -p tcp --dport 53 -j REDIRECT --to-port 5300 2>/dev/null || true
ip6tables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5300 2>/dev/null || true
ip6tables -t nat -D OUTPUT -p tcp --dport 53 -j REDIRECT --to-port 5300 2>/dev/null || true
echo "  ✓ Firewall rules removed"

# 3. Remove systemd service
echo -e "${GREEN}[3/5] Removing systemd service...${NC}"
rm -f "$SYSTEMD_DIR/castiel.service"
systemctl daemon-reload
echo "  ✓ Service file removed"

# 4. Remove binary and scripts
echo -e "${GREEN}[4/5] Removing binary and scripts...${NC}"
rm -f "$BIN_DIR/castiel"
rm -f "$BIN_DIR/doh-killswitch.sh"
echo "  ✓ Binary removed"

# 5. Remove config, data, and logs
echo -e "${GREEN}[5/5] Removing config and data...${NC}"
echo -e "${YELLOW}  ⚠ This will remove all Castiel config and logs.${NC}"
echo -e "${YELLOW}  Press Ctrl+C to cancel, or Enter to continue...${NC}"
read -r

rm -rf "$ETC_DIR"
rm -rf "$VAR_DIR"
rm -f "$APP_DIR/castiel.desktop"
echo "  ✓ Config and data removed"

echo ""
echo -e "${GREEN}=== Uninstallation Complete ===${NC}"
echo ""
echo "  Castiel has been fully removed from this system."
