#!/bin/bash
#
# Castiel Install Script for Linux
#
# Installs the Castiel DNS defense daemon, config, and systemd service.
# Must be run with sudo.
#
# Usage:
#   sudo ./linux_build/install.sh
#
# Supports: Ubuntu/Debian, RHEL/Fedora, Arch Linux

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Paths
PREFIX="/usr/local"
BIN_DIR="${PREFIX}/bin"
ETC_DIR="${PREFIX}/etc/castiel"
VAR_DIR="${PREFIX}/var/log/castiel"
DATA_DIR="${ETC_DIR}/data"
SYSTEMD_DIR="/etc/systemd/system"
APP_DIR="/usr/share/applications"
ICON_DIR="/usr/share/icons/hicolor"

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LINUX_DIR="$SCRIPT_DIR/linux_build"

echo -e "${GREEN}=== Castiel — Linux Installation ===${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run with sudo.${NC}"
    echo "  sudo $0"
    exit 1
fi

# Detect distro
if command -v apt-get >/dev/null 2>&1; then
    DISTRO="debian"
elif command -v dnf >/dev/null 2>&1; then
    DISTRO="fedora"
elif command -v pacman >/dev/null 2>&1; then
    DISTRO="arch"
else
    DISTRO="unknown"
fi

echo -e "${GREEN}Detected distro: ${DISTRO}${NC}"
echo ""

# 1. Install dependencies
echo -e "${GREEN}[1/7] Installing dependencies...${NC}"
case $DISTRO in
    debian)
        apt-get update -qq
        apt-get install -y -qq nftables libnotify4 2>/dev/null || true
        ;;
    fedora)
        dnf install -y -q nftables libnotify 2>/dev/null || true
        ;;
    arch)
        pacman -S --noconfirm --quiet nftables libnotify 2>/dev/null || true
        ;;
    *)
        echo -e "${YELLOW}  ⚠ Unknown distro — skipping dependency installation${NC}"
        echo "  Please install: nftables (or iptables), libnotify4"
        ;;
esac
echo "  ✓ Dependencies installed"

# 2. Build the Go binary (cross-compile if on non-Linux)
echo -e "${GREEN}[2/7] Building Castiel daemon...${NC}"
if [ -f "$LINUX_DIR/castiel" ]; then
    echo "  ✓ Using pre-built binary: $LINUX_DIR/castiel"
else
    cd "$SCRIPT_DIR"
    if command -v go >/dev/null 2>&1; then
        GOOS=linux GOARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') go build -ldflags="-s -w" -o "$LINUX_DIR/castiel" .
    else
        echo -e "${RED}Error: Go not installed and no pre-built binary found.${NC}"
        echo "  Install Go from https://go.dev/dl/ or run: sudo apt install golang"
        exit 1
    fi
fi
echo "  ✓ Built $LINUX_DIR/castiel"

# 3. Install binary
echo -e "${GREEN}[3/7] Installing binary to ${BIN_DIR}...${NC}"
mkdir -p "$BIN_DIR"
cp "$LINUX_DIR/castiel" "$BIN_DIR/castiel"
chmod 755 "$BIN_DIR/castiel"
echo "  ✓ Installed: $BIN_DIR/castiel"

# 4. Install config and data files
echo -e "${GREEN}[4/7] Installing config and data to ${ETC_DIR}...${NC}"
mkdir -p "$ETC_DIR" "$DATA_DIR" "$VAR_DIR"

# Don't overwrite existing config
if [ -f "$ETC_DIR/config.yaml" ]; then
    echo -e "${YELLOW}  ⚠ Config already exists at $ETC_DIR/config.yaml — backing up${NC}"
    cp "$ETC_DIR/config.yaml" "$ETC_DIR/config.yaml.bak.$(date +%s)"
fi
cp "$LINUX_DIR/config.yaml" "$ETC_DIR/config.yaml"

# Copy data files
cp "$SCRIPT_DIR/data/root-trust-anchor.txt" "$DATA_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/data/legitimate-domains.txt" "$DATA_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/data/custom_block.txt" "$DATA_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/data/custom_allow.txt" "$DATA_DIR/" 2>/dev/null || true

# Update config paths to installed locations
sed -i "s|data/root-trust-anchor.txt|${DATA_DIR}/root-trust-anchor.txt|g" "$ETC_DIR/config.yaml"
sed -i "s|data/legitimate-domains.txt|${DATA_DIR}/legitimate-domains.txt|g" "$ETC_DIR/config.yaml"
sed -i "s|data/custom_block.txt|${DATA_DIR}/custom_block.txt|g" "$ETC_DIR/config.yaml"
sed -i "s|data/custom_allow.txt|${DATA_DIR}/custom_allow.txt|g" "$ETC_DIR/config.yaml"

echo "  ✓ Config installed: $ETC_DIR/config.yaml"
echo "  ✓ Data installed: $DATA_DIR/"

# 5. Install kill switch script
echo -e "${GREEN}[5/7] Installing kill switch script...${NC}"
cp "$LINUX_DIR/doh-killswitch.sh" "$BIN_DIR/doh-killswitch.sh"
chmod 755 "$BIN_DIR/doh-killswitch.sh"
echo "  ✓ Installed: $BIN_DIR/doh-killswitch.sh"

# 6. Install systemd service
echo -e "${GREEN}[6/7] Installing systemd service...${NC}"
cp "$LINUX_DIR/castiel.service" "$SYSTEMD_DIR/castiel.service"
chmod 644 "$SYSTEMD_DIR/castiel.service"
systemctl daemon-reload
echo "  ✓ Installed: $SYSTEMD_DIR/castiel.service"

# 7. Install desktop entry (optional)
echo -e "${GREEN}[7/7] Installing desktop entry...${NC}"
if [ -f "$LINUX_DIR/castiel.desktop" ]; then
    mkdir -p "$APP_DIR"
    cp "$LINUX_DIR/castiel.desktop" "$APP_DIR/castiel.desktop"
    chmod 644 "$APP_DIR/castiel.desktop"
    echo "  ✓ Installed: $APP_DIR/castiel.desktop"
else
    echo "  ⚠ Desktop entry not found — skipping"
fi

# Start the service
echo ""
echo -e "${GREEN}Starting Castiel service...${NC}"
systemctl enable castiel
systemctl start castiel
sleep 1
if systemctl is-active --quiet castiel; then
    echo -e "${GREEN}  ✓ Castiel is running${NC}"
else
    echo -e "${YELLOW}  ⚠ Castiel failed to start — check: journalctl -u castiel -e${NC}"
fi

echo ""
echo -e "${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "  Daemon:     $BIN_DIR/castiel"
echo "  Config:     $ETC_DIR/config.yaml"
echo "  Data:       $DATA_DIR/"
echo "  Logs:       $VAR_DIR/"
echo "  Service:    $SYSTEMD_DIR/castiel.service"
echo ""
echo "Commands:"
echo "  systemctl status castiel          # Check daemon status"
echo "  sudo systemctl stop castiel       # Stop daemon"
echo "  sudo systemctl start castiel      # Start daemon"
echo "  sudo journalctl -u castiel -f     # View live logs"
echo "  doh-killswitch.sh status          # Check DoH status"
echo "  doh-killswitch.sh off             # Emergency disable DoH"
echo "  doh-killswitch.sh restore         # Restore DNS (emergency)"
echo ""
echo -e "${YELLOW}Note: nftables redirect requires CAP_NET_ADMIN (service runs with capabilities).${NC}"
