#!/bin/bash
#
# Castiel Install Script
#
# Installs the Castiel DNS defense daemon, config, and macOS app.
# Must be run with sudo.
#
# Usage:
#   sudo ./deploy/install.sh
#

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
DATA_DIR="${PREFIX}/etc/castiel/data"
LAUNCH_DAEMON_DIR="/Library/LaunchDaemons"
LAUNCH_AGENT_DIR="${HOME}/Library/LaunchAgents"
APP_DIR="/Applications"

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo -e "${GREEN}=== Castiel — Installation ===${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run with sudo.${NC}"
    echo "  sudo $0"
    exit 1
fi

# 1. Build the Go binary
echo -e "${GREEN}[1/8] Building Go daemon...${NC}"
cd "$SCRIPT_DIR"
go build -o castiel .
echo "  ✓ Built $(pwd)/castiel"

# 2. Build the macOS app
echo -e "${GREEN}[2/8] Building macOS app...${NC}"
cd "$SCRIPT_DIR/macos-app"
swift build -c release
echo "  ✓ Built macOS app (release)"

# 3. Install binary
echo -e "${GREEN}[3/8] Installing binary to ${BIN_DIR}...${NC}"
mkdir -p "$BIN_DIR"
cp "$SCRIPT_DIR/castiel" "$BIN_DIR/castiel"
chmod 755 "$BIN_DIR/castiel"
echo "  ✓ Installed: $BIN_DIR/castiel"

# 4. Install config and data files
echo -e "${GREEN}[4/8] Installing config and data to ${ETC_DIR}...${NC}"
mkdir -p "$ETC_DIR" "$DATA_DIR" "$VAR_DIR"

# Don't overwrite existing config
if [ -f "$ETC_DIR/config.yaml" ]; then
    echo -e "${YELLOW}  ⚠ Config already exists at $ETC_DIR/config.yaml — backing up${NC}"
    cp "$ETC_DIR/config.yaml" "$ETC_DIR/config.yaml.bak.$(date +%s)"
fi
cp "$SCRIPT_DIR/config.yaml" "$ETC_DIR/config.yaml"

# Copy data files
cp "$SCRIPT_DIR/data/root-trust-anchor.txt" "$DATA_DIR/"
cp "$SCRIPT_DIR/data/legitimate-domains.txt" "$DATA_DIR/"
cp "$SCRIPT_DIR/data/custom_block.txt" "$DATA_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/data/custom_allow.txt" "$DATA_DIR/" 2>/dev/null || true

# Update config paths to installed locations
sed -i '' "s|data/root-trust-anchor.txt|${DATA_DIR}/root-trust-anchor.txt|g" "$ETC_DIR/config.yaml"
sed -i '' "s|data/legitimate-domains.txt|${DATA_DIR}/legitimate-domains.txt|g" "$ETC_DIR/config.yaml"
sed -i '' "s|data/custom_block.txt|${DATA_DIR}/custom_block.txt|g" "$ETC_DIR/config.yaml"
sed -i '' "s|data/custom_allow.txt|${DATA_DIR}/custom_allow.txt|g" "$ETC_DIR/config.yaml"

echo "  ✓ Config installed: $ETC_DIR/config.yaml"
echo "  ✓ Data installed: $DATA_DIR/"

# 5. Install kill switch script
echo -e "${GREEN}[5/8] Installing kill switch script...${NC}"
cp "$SCRIPT_DIR/doh-killswitch.sh" "$BIN_DIR/doh-killswitch.sh"
chmod 755 "$BIN_DIR/doh-killswitch.sh"
echo "  ✓ Installed: $BIN_DIR/doh-killswitch.sh"

# 6. Install LaunchDaemon plist
echo -e "${GREEN}[6/8] Installing LaunchDaemon...${NC}"
cp "$SCRIPT_DIR/deploy/com.castiel.daemon.plist" "$LAUNCH_DAEMON_DIR/"
chown root:wheel "$LAUNCH_DAEMON_DIR/com.castiel.daemon.plist"
chmod 644 "$LAUNCH_DAEMON_DIR/com.castiel.daemon.plist"
echo "  ✓ Installed: $LAUNCH_DAEMON_DIR/com.castiel.daemon.plist"

# 7. Install macOS app
echo -e "${GREEN}[7/8] Installing macOS app to /Applications...${NC}"
APP_BUILD="$SCRIPT_DIR/macos-app/.build/release/Castiel"
if [ -d "$APP_DIR/Castiel.app" ]; then
    rm -rf "$APP_DIR/Castiel.app"
fi
# Create .app bundle structure
mkdir -p "$APP_DIR/Castiel.app/Contents/MacOS"
mkdir -p "$APP_DIR/Castiel.app/Contents/Resources"
cp "$APP_BUILD" "$APP_DIR/Castiel.app/Contents/MacOS/Castiel"
chmod 755 "$APP_DIR/Castiel.app/Contents/MacOS/Castiel"

# Copy app icon
cp "$SCRIPT_DIR/deploy/Castiel.icns" "$APP_DIR/Castiel.app/Contents/Resources/Castiel.icns"
echo "  ✓ Icon installed"

# Create Info.plist for the app bundle
cat > "$APP_DIR/Castiel.app/Contents/Info.plist" << 'INFOPLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Castiel</string>
    <key>CFBundleIdentifier</key>
    <string>com.castiel.app</string>
    <key>CFBundleVersion</key>
    <string>0.1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleExecutable</key>
    <string>Castiel</string>
    <key>CFBundleIconFile</key>
    <string>Castiel</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSUIElement</key>
    <false/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
INFOPLIST

echo "  ✓ Installed: $APP_DIR/Castiel.app"

# Install LaunchAgent for the app (per-user)
mkdir -p "$LAUNCH_AGENT_DIR"
cp "$SCRIPT_DIR/deploy/com.castiel.app.plist" "$LAUNCH_AGENT_DIR/"
echo "  ✓ LaunchAgent installed: $LAUNCH_AGENT_DIR/com.castiel.app.plist"

# 8. Load the daemon
echo -e "${GREEN}[8/8] Loading LaunchDaemon...${NC}"
launchctl unload "$LAUNCH_DAEMON_DIR/com.castiel.daemon.plist" 2>/dev/null || true
launchctl load -w "$LAUNCH_DAEMON_DIR/com.castiel.daemon.plist"
echo "  ✓ Daemon loaded and started"

echo ""
echo -e "${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "  Daemon:     $BIN_DIR/castiel"
echo "  Config:     $ETC_DIR/config.yaml"
echo "  Data:       $DATA_DIR/"
echo "  Logs:       $VAR_DIR/"
echo "  App:        $APP_DIR/Castiel.app"
echo ""
echo "Commands:"
echo "  launchctl list | grep castiel          # Check daemon status"
echo "  sudo launchctl stop com.castiel.daemon   # Stop daemon"
echo "  sudo launchctl start com.castiel.daemon  # Start daemon"
echo "  doh-killswitch.sh status          # Check DoH status"
echo "  doh-killswitch.sh off             # Emergency disable DoH"
echo "  doh-killswitch.sh restore         # Restore DNS (emergency)"
echo ""
echo -e "${YELLOW}Note: PF firewall redirect requires reboot or manual pfctl reload.${NC}"
echo -e "${YELLOW}      The daemon runs as root for PF access.${NC}"
