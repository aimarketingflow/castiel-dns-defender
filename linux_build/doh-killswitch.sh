#!/bin/bash
#
# Castiel DoH Kill Switch for Linux
#
# Usage:
#   ./doh-killswitch.sh           # Toggle DoH on/off
#   ./doh-killswitch.sh off       # Emergency disable DoH
#   ./doh-killswitch.sh on        # Re-enable DoH
#   ./doh-killswitch.sh status    # Check if Castiel is running
#   ./doh-killswitch.sh stop      # Stop Castiel entirely + restore DNS
#   ./doh-killswitch.sh restore   # Restore DNS to DHCP defaults (emergency)

set -e

CASTIEL_PROCESS="castiel"

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
        echo "Service status:"
        systemctl status castiel 2>/dev/null | head -5 || echo "  (systemctl not available)"
        echo ""
        echo "nftables rules:"
        nft list table ip castiel 2>/dev/null || echo "  (no castiel nftables table)"
        echo ""
        echo "DNS configuration:"
        if command -v resolvectl >/dev/null 2>&1; then
            resolvectl status 2>/dev/null | head -10 || echo "  (could not query)"
        elif [ -f /etc/resolv.conf ]; then
            cat /etc/resolv.conf
        fi
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
        # Also try systemd
        systemctl stop castiel 2>/dev/null || true
        # Remove nftables rules
        nft delete table ip castiel 2>/dev/null || true
        nft delete table ip6 castiel 2>/dev/null || true
        echo "nftables rules removed."
        # Restore DNS
        $0 restore
        ;;

    restore)
        echo "Restoring DNS to DHCP defaults..."
        # Restore systemd-resolved if available
        if command -v resolvectl >/dev/null 2>&1; then
            # Reset DNS to DHCP defaults
            for link in $(resolvectl list-links 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]+$'); do
                resolvectl revert "$link" 2>/dev/null || true
            done
            echo "DNS restored via resolvectl."
        elif [ -f /etc/resolv.conf.castiel-backup ]; then
            cp /etc/resolv.conf.castiel-backup /etc/resolv.conf
            echo "DNS restored from backup."
        else
            echo "Could not automatically restore DNS. Manual restore needed:"
            echo "  sudo rm /etc/resolv.conf && ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf"
            echo "  # Or: sudo systemctl restart systemd-resolved"
        fi
        # Remove nftables rules
        nft delete table ip castiel 2>/dev/null || true
        nft delete table ip6 castiel 2>/dev/null || true
        # Remove iptables rules (fallback)
        iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-port 5300 2>/dev/null || true
        iptables -t nat -D OUTPUT -p tcp --dport 53 -j REDIRECT --to-port 5300 2>/dev/null || true
        echo ""
        echo "Verifying DNS connectivity..."
        if command -v dig >/dev/null 2>&1; then
            if dig +short google.com @1.1.1.1 >/dev/null 2>&1; then
                echo "✓ DNS is working (query to 1.1.1.1 succeeded)"
            else
                echo "✗ DNS may still be broken — try: sudo systemctl restart systemd-resolved"
            fi
        elif command -v nslookup >/dev/null 2>&1; then
            if nslookup google.com 1.1.1.1 >/dev/null 2>&1; then
                echo "✓ DNS is working (query to 1.1.1.1 succeeded)"
            else
                echo "✗ DNS may still be broken — try: sudo systemctl restart systemd-resolved"
            fi
        else
            echo "Cannot verify DNS — install dig or nslookup"
        fi
        ;;

    *)
        echo "Castiel DoH Kill Switch (Linux)"
        echo ""
        echo "Usage: $0 {toggle|off|on|status|stop|restore}"
        echo ""
        echo "Commands:"
        echo "  toggle   - Toggle DoH on/off (default)"
        echo "  off      - Emergency disable DoH (fall back to plain DNS)"
        echo "  on       - Re-enable DoH"
        echo "  status   - Check Castiel status and DNS configuration"
        echo "  stop     - Stop Castiel entirely + remove nftables rules + restore DNS"
        echo "  restore  - Restore DNS to DHCP defaults (emergency — use if internet is broken)"
        echo ""
        echo "If your internet is broken:"
        echo "  1. $0 off          # Try disabling DoH first"
        echo "  2. $0 stop          # If still broken, stop Castiel entirely"
        echo "  3. $0 restore       # Last resort: restore DNS to DHCP defaults"
        ;;
esac
