#!/usr/bin/env bash
# ============================================================
# Castiel DNS Poisoning Monitor
# Continuously probes the local network resolver (Mac B) and
# Castiel for DNS poisoning / blocking indicators.
# ============================================================
set -uo pipefail

# --- Configuration ---
BRIDGE_RESOLVER="192.168.2.1"
CASTIEL_ADDR="127.0.0.1"
CASTIEL_PORT="5300"
INTERVAL=5                          # seconds between sweeps
ALERT_LOG="/usr/local/var/log/castiel/poison_monitor.jsonl"
CASTIEL_ALERT_LOG="/usr/local/var/log/castiel/castiel_alerts.jsonl"

TEST_DOMAINS=(
  "ocsp.apple.com"
  "google.com"
  "cloudflare.com"
  "github.com"
  "microsoft.com"
  "amazon.com"
)

# RFC-1918 / link-local patterns that should never resolve for public domains
PRIVATE_RE="^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|127\.|0\.0\.0\.0|192\.168\.0\.0)"

# --- Helpers ---
ts()   { date "+%Y-%m-%d %H:%M:%S"; }
bold() { printf "\033[1m%s\033[0m" "$1"; }
red()  { printf "\033[1;31m%s\033[0m" "$1"; }
grn()  { printf "\033[1;32m%s\033[0m" "$1"; }
ylw()  { printf "\033[1;33m%s\033[0m" "$1"; }
cyn()  { printf "\033[1;36m%s\033[0m" "$1"; }
dim()  { printf "\033[2m%s\033[0m" "$1"; }

poison_count=0
clean_count=0
sweep_num=0
castiel_up="unknown"

log_alert() {
  local domain="$1" resolver="$2" ip="$3" kind="$4"
  local json="{\"ts\":\"$(ts)\",\"domain\":\"${domain}\",\"resolver\":\"${resolver}\",\"resolved_ip\":\"${ip}\",\"type\":\"${kind}\"}"
  echo "$json" >> "$ALERT_LOG" 2>/dev/null || true
}

check_castiel_status() {
  if dig @"${CASTIEL_ADDR}" -p "${CASTIEL_PORT}" +short +time=1 +tries=1 version.bind CH TXT >/dev/null 2>&1 ||
     dig @"${CASTIEL_ADDR}" -p "${CASTIEL_PORT}" +short +time=1 +tries=1 google.com A >/dev/null 2>&1; then
    castiel_up="UP"
  else
    castiel_up="DOWN"
  fi
}

print_header() {
  clear
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║        $(bold 'Castiel DNS Poisoning Monitor')                       ║"
  echo "╠══════════════════════════════════════════════════════════════╣"
  printf "║  Bridge resolver : %-40s ║\n" "$BRIDGE_RESOLVER"
  printf "║  Castiel         : %-40s ║\n" "${CASTIEL_ADDR}:${CASTIEL_PORT}"
  printf "║  Sweep interval  : %-40s ║\n" "${INTERVAL}s"
  printf "║  Alert log       : %-40s ║\n" "$ALERT_LOG"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
}

# --- Trap ---
trap 'echo ""; echo "[$(ts)] Monitor stopped. Sweeps: $sweep_num | Poisoned: $poison_count | Clean: $clean_count"; exit 0' INT TERM

# --- Main loop ---
print_header
echo "[$(ts)] $(cyn 'Starting monitor...') Press Ctrl+C to stop."
echo ""

while true; do
  sweep_num=$((sweep_num + 1))
  total=${#TEST_DOMAINS[@]}
  done_count=0

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[$(ts)] Sweep #${sweep_num}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # Check Castiel status
  check_castiel_status
  if [ "$castiel_up" = "UP" ]; then
    printf "  Castiel status : %s\n" "$(grn 'RUNNING')"
  else
    printf "  Castiel status : %s\n" "$(red 'DOWN')"
  fi

  # Check bridge reachability
  if ping -c 1 -W 1 "$BRIDGE_RESOLVER" >/dev/null 2>&1; then
    printf "  Bridge link    : %s\n" "$(grn 'REACHABLE')"
  else
    printf "  Bridge link    : %s\n" "$(red 'UNREACHABLE')"
  fi
  echo ""

  for domain in "${TEST_DOMAINS[@]}"; do
    done_count=$((done_count + 1))
    pct=$(( (done_count * 100) / total ))

    # --- Query bridge resolver (Mac B) ---
    bridge_raw=$(dig @"${BRIDGE_RESOLVER}" +short +time=2 +tries=1 "$domain" A 2>&1)
    bridge_ip=$(echo "$bridge_raw" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    bridge_ip="${bridge_ip:-TIMEOUT}"

    # --- Query Castiel ---
    castiel_ip=""
    if [ "$castiel_up" = "UP" ]; then
      castiel_raw=$(dig @"${CASTIEL_ADDR}" -p "${CASTIEL_PORT}" +short +time=2 +tries=1 "$domain" A 2>&1)
      castiel_ip=$(echo "$castiel_raw" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
      castiel_ip="${castiel_ip:-EMPTY}"
    else
      castiel_ip="N/A"
    fi

    # --- Evaluate bridge response ---
    bridge_status=""
    if [ "$bridge_ip" = "TIMEOUT" ]; then
      bridge_status="$(ylw 'TIMEOUT')"
    elif echo "$bridge_ip" | grep -qE "$PRIVATE_RE"; then
      bridge_status="$(red 'POISONED')"
      poison_count=$((poison_count + 1))
      log_alert "$domain" "$BRIDGE_RESOLVER" "$bridge_ip" "poisoned"
    else
      bridge_status="$(grn 'CLEAN')"
      clean_count=$((clean_count + 1))
    fi

    # --- Evaluate Castiel response ---
    castiel_status=""
    if [ "$castiel_ip" = "N/A" ]; then
      castiel_status="$(dim 'N/A')"
    elif [ "$castiel_ip" = "EMPTY" ]; then
      castiel_status="$(ylw 'EMPTY')"
    elif echo "$castiel_ip" | grep -qE "$PRIVATE_RE"; then
      castiel_status="$(red 'POISONED')"
      log_alert "$domain" "castiel" "$castiel_ip" "castiel_poisoned"
    else
      castiel_status="$(grn 'SAFE')"
    fi

    # --- Print row ---
    printf "  [%3d%%] %-22s  Bridge: %-15s %s  │  Castiel: %-15s %s\n" \
      "$pct" "$domain" "$bridge_ip" "$bridge_status" "$castiel_ip" "$castiel_status"
  done

  # --- Check Castiel alert log ---
  new_alerts=0
  if [ -f "$CASTIEL_ALERT_LOG" ]; then
    new_alerts=$(wc -l < "$CASTIEL_ALERT_LOG" 2>/dev/null | tr -d ' ')
  fi

  echo ""
  printf "  $(bold 'Totals'): Poisoned=$(red "$poison_count")  Clean=$(grn "$clean_count")  Castiel alerts=$(ylw "$new_alerts")\n"

  # --- Show latest Castiel alert ---
  if [ -f "$CASTIEL_ALERT_LOG" ]; then
    latest=$(tail -1 "$CASTIEL_ALERT_LOG" 2>/dev/null)
    if [ -n "$latest" ]; then
      latest_type=$(echo "$latest" | grep -o '"type":"[^"]*"' | head -1)
      latest_domain=$(echo "$latest" | grep -o '"domain":"[^"]*"' | head -1)
      latest_time=$(echo "$latest" | grep -o '"time":"[^"]*"' | head -1 | cut -c8-26)
      printf "  $(bold 'Last alert')  : %s %s @ %s\n" "$latest_type" "$latest_domain" "$latest_time"
    fi
  fi

  # --- Prometheus shadow metric ---
  shadow_metric=$(curl -s --max-time 2 "http://127.0.0.1:9090/metrics" 2>/dev/null | grep "castiel_shadow_poison_detected_total" | grep -v "^#" | head -1 || true)
  if [ -n "$shadow_metric" ]; then
    printf "  Shadow detect  : $(ylw "$shadow_metric")\n"
  fi

  echo ""
  dim "  Next sweep in ${INTERVAL}s..."
  echo ""

  sleep "$INTERVAL"
done
