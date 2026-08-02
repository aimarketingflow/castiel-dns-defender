#!/bin/bash
#
# Castiel DoH Kill Switch
#
# Usage:
#   ./doh-killswitch.sh           # Toggle DoH on/off
#   ./doh-killswitch.sh off       # Emergency disable DoH
#   ./doh-killswitch.sh on        # Re-enable DoH
#   ./doh-killswitch.sh status    # Check if Castiel is running
#   ./doh-killswitch.sh stop      # Stop Castiel entirely + restore DNS
#   ./doh-killswitch.sh restore   # Restore DNS to DHCP defaults (emergency)
#

set -e

CASTIEL_PROCESS="castiel"
ORIGINAL_DNS_FILE="/etc/resolv.conf.castiel-backup"
NETWORK_SERVICE=$(networksetup -listallnetworkservices 2>/dev/null | grep -E "Wi-Fi|Ethernet" | head -1)

case "${1:-toggle}" in
    toggle)
        PID=$(pgrep -x "$CASTIEL_PROCESS" 2>/dev/null || true)
        if [ -z "$PID" ]; then
            echo "Castiel is not running — nothing to toggle."
            exit 1
        fi
        echo "Toggling DoH for Castiel (PID $PID)..."
        kill -HUP "$PID"
        echo "Sent SIGHUP — DoH toggled. Check Castiel logs for status."
        ;;

    off)
        PID=$(pgrep -x "$CASTIEL_PROCESS" 2>/dev/null || true)
        if [ -z "$PID" ]; then
            echo "Castiel is not running."
            exit 1
        fi
        echo "Emergency disabling DoH for Castiel (PID $PID)..."
        kill -USR1 "$PID"
        echo "Sent SIGUSR1 — DoH disabled. Castiel will use plain DNS upstream."
        ;;

    on)
        PID=$(pgrep -x "$CASTIEL_PROCESS" 2>/dev/null || true)
        if [ -z "$PID" ]; then
            echo "Castiel is not running."
            exit 1
        fi
        echo "Re-enabling DoH for Castiel (PID $PID)..."
        kill -USR2 "$PID"
        echo "Sent SIGUSR2 — DoH re-enabled."
        ;;

    status)
        PID=$(pgrep -x "$CASTIEL_PROCESS" 2>/dev/null || true)
        if [ -z "$PID" ]; then
            echo "Castiel is NOT running."
        else
            echo "Castiel is running (PID $PID)."
        fi
        echo ""
        echo "Current DNS servers:"
        if [ -n "$NETWORK_SERVICE" ]; then
            networksetup -getdnsservers "$NETWORK_SERVICE" 2>/dev/null || echo "  (could not query)"
        fi
        echo ""
        echo "PF anchors:"
        pfctl -a castiel -sr 2>/dev/null || echo "  (no Castiel anchor or pfctl not available)"
        ;;

    stop)
        echo "Stopping Castiel..."
        PID=$(pgrep -x "$CASTIEL_PROCESS" 2>/dev/null || true)
        if [ -n "$PID" ]; then
            kill -TERM "$PID"
            echo "Sent SIGTERM to Castiel (PID $PID). Waiting for shutdown..."
            sleep 2
        else
            echo "Castiel is not running."
        fi
        # Remove PF anchor if still present
        pfctl -a castiel -r 2>/dev/null || true
        echo "PF anchor removed."
        # Restore DNS
        $0 restore
        ;;

    restore)
        echo "Restoring DNS to DHCP defaults..."
        if [ -n "$NETWORK_SERVICE" ]; then
            echo "Clearing custom DNS on: $NETWORK_SERVICE"
            networksetup -setdnsservers "$NETWORK_SERVICE" empty 2>/dev/null || true
            echo "DNS restored to DHCP-provided servers."
        else
            echo "Could not determine network service. Manual restore needed:"
            echo "  System Settings → Network → Wi-Fi → Details → DNS → Clear"
        fi
        # Also remove PF anchor
        pfctl -a castiel -r 2>/dev/null || true
        echo ""
        echo "Verifying DNS connectivity..."
        # Test with a direct DNS query (bypassing any local proxy)
        if nslookup google.com 1.1.1.1 >/dev/null 2>&1; then
            echo "✓ DNS is working (query to 1.1.1.1 succeeded)"
        else
            echo "✗ DNS may still be broken — try: sudo networksetup -setdnsservers Wi-Fi empty"
        fi
        ;;

    *)
        echo "Castiel DoH Kill Switch"
        echo ""
        echo "Usage: $0 {toggle|off|on|status|stop|restore}"
        echo ""
        echo "Commands:"
        echo "  toggle   - Toggle DoH on/off (default)"
        echo "  off      - Emergency disable DoH (fall back to plain DNS)"
        echo "  on       - Re-enable DoH"
        echo "  status   - Check Castiel status and DNS configuration"
        echo "  stop     - Stop Castiel entirely + remove PF redirect + restore DNS"
        echo "  restore  - Restore DNS to DHCP defaults (emergency — use if internet is broken)"
        echo ""
        echo "If your internet is broken:"
        echo "  1. $0 off          # Try disabling DoH first"
        echo "  2. $0 stop          # If still broken, stop Castiel entirely"
        echo "  3. $0 restore       # Last resort: restore DNS to DHCP defaults"
        ;;
esac
