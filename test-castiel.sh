#!/bin/bash
#
# Castiel Detection Test Suite
# Runs a series of DNS attack simulations against the Castiel daemon
# and verifies that each detection layer is working.
#
# Usage:
#   ./test-castiel.sh              # Run all tests
#   ./test-castiel.sh dga          # Run a single scenario
#   ./test-castiel.sh --quick      # Run all tests with shorter durations
#

set -e

TARGET="127.0.0.1:5300"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIM="$SCRIPT_DIR/cmd/attack-sim/attack-sim"
METRICS_URL="http://127.0.0.1:9090/metrics"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

QUICK=false
if [ "$1" == "--quick" ]; then
    QUICK=true
    shift
fi

# Durations
if $QUICK; then
    NORMAL_DUR="5s"
    ATTACK_DUR="5s"
    RATE_DUR="3s"
else
    NORMAL_DUR="15s"
    ATTACK_DUR="15s"
    RATE_DUR="5s"
fi

# Build attack-sim if needed
if [ ! -f "$SIM" ]; then
    echo -e "${CYAN}Building attack-sim...${NC}"
    cd "$SCRIPT_DIR/cmd/attack-sim"
    go build -o attack-sim .
    cd "$SCRIPT_DIR"
    SIM="$SCRIPT_DIR/cmd/attack-sim/attack-sim"
fi

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║        Castiel Detection Test Suite                  ║${NC}"
echo -e "${BOLD}║        Verifying all detection layers                ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e " Target: ${CYAN}$TARGET${NC}"
echo -e " Mode:   $([ $QUICK == true ] && echo 'quick' || echo 'full')"
echo ""

# Check if Castiel is running
echo -e "${CYAN}[0] Checking if Castiel daemon is running...${NC}"
if pgrep -x castiel >/dev/null 2>&1; then
    PID=$(pgrep -x castiel | head -1)
    echo -e "  ${GREEN}✓ Castiel is running (PID $PID)${NC}"
else
    echo -e "  ${YELLOW}⚠ Castiel daemon not detected. Start it from the app or run:${NC}"
    echo -e "    sudo /usr/local/bin/castiel -config /usr/local/etc/castiel/config.yaml &"
    echo -e "  ${YELLOW}Continuing anyway — make sure something is listening on $TARGET${NC}"
fi
echo ""

# Check metrics endpoint
echo -e "${CYAN}[0b] Checking metrics endpoint...${NC}"
if curl -s "$METRICS_URL" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓ Metrics endpoint responding at $METRICS_URL${NC}"
else
    echo -e "  ${YELLOW}⚠ Metrics endpoint not responding at $METRICS_URL${NC}"
fi
echo ""

# Capture baseline metrics
BASELINE_BLOCKED=$(curl -s "$METRICS_URL" 2>/dev/null | grep 'castiel_blocked_total' | awk '{sum+=$2} END {print sum+0}')
BASELINE_TOTAL=$(curl -s "$METRICS_URL" 2>/dev/null | grep 'castiel_queries_total' | awk '{sum+=$2} END {print sum+0}')
echo -e "  Baseline — Total queries: $BASELINE_TOTAL, Blocked: $BASELINE_BLOCKED"
echo ""

run_test() {
    local name="$1"
    local scenario="$2"
    local duration="$3"
    local qps="$4"
    local concurrency="$5"
    local description="$6"

    echo -e "${CYAN}[$name] $description${NC}"
    echo -e "  Scenario: $scenario | Duration: $duration | QPS: $qps | Workers: $concurrency"

    "$SIM" \
        -target "$TARGET" \
        -scenario "$scenario" \
        -duration "$duration" \
        -qps "$qps" \
        -concurrency "$concurrency" 2>&1 | grep -E "^\[|queries sent|RESULTS|Total|Success|Blocked|Block rate|per-scenario|^\s\s[a-z]"

    echo ""
}

# --- Test 1: Normal traffic (baseline — should mostly succeed) ---
echo -e "${BOLD}=== TEST 1: Normal Traffic (should pass through) ===${NC}"
run_test "1" "normal" "$NORMAL_DUR" 10 5 \
    "Legitimate DNS queries — should resolve normally"
echo -e "  ${GREEN}Expected: High success rate, low/no blocks${NC}"
echo ""

# --- Test 2: DGA Detection ---
echo -e "${BOLD}=== TEST 2: DGA Domain Detection ===${NC}"
run_test "2" "dga" "$ATTACK_DUR" 20 10 \
    "Random consonant-heavy domains — DGA detector should flag these"
echo -e "  ${GREEN}Expected: High block rate (NXDOMAIN or Refused)${NC}"
echo ""

# --- Test 3: DNS Tunneling Detection ---
echo -e "${BOLD}=== TEST 3: DNS Tunneling Detection ===${NC}"
run_test "3" "tunneling" "$ATTACK_DUR" 20 10 \
    "High-entropy subdomains — entropy detector should flag tunneling"
echo -e "  ${GREEN}Expected: High block rate (entropy threshold exceeded)${NC}"
echo ""

# --- Test 4: Rate Limiting ---
echo -e "${BOLD}=== TEST 4: Rate Limiting (DDoS simulation) ===${NC}"
run_test "4" "ratelimit" "$RATE_DUR" 0 20 \
    "Max-speed flood — rate limiter should drop/throttle queries"
echo -e "  ${GREEN}Expected: Many queries dropped or rate-limited${NC}"
echo ""

# --- Test 5: NXDOMAIN Flood ---
echo -e "${BOLD}=== TEST 5: NXDOMAIN Flood (Water Torture) ===${NC}"
run_test "5" "nxdomain" "$ATTACK_DUR" 30 10 \
    "Random non-existent domains — NXDOMAIN flood attack"
echo -e "  ${GREEN}Expected: NXDOMAIN responses, rate limiting on NXDOMAIN${NC}"
echo ""

# --- Test 6: Zone Transfer (AXFR) ---
echo -e "${BOLD}=== TEST 6: Zone Transfer Block (AXFR) ===${NC}"
run_test "6" "axfr" "$ATTACK_DUR" 5 5 \
    "AXFR zone transfer attempts — should be blocked"
echo -e "  ${GREEN}Expected: All AXFR requests refused/blocked${NC}"
echo ""

# --- Test 7: Blocklist ---
echo -e "${BOLD}=== TEST 7: Blocklist Detection ===${NC}"
run_test "7" "blocklist" "$ATTACK_DUR" 10 5 \
    "Known-malicious domains — blocklist should reject these"
echo -e "  ${GREEN}Expected: Blocked by threat intel feeds${NC}"
echo ""

# --- Test 8: DNS Rebinding ---
echo -e "${BOLD}=== TEST 8: DNS Rebinding Protection ===${NC}"
run_test "8" "rebinding" "$ATTACK_DUR" 10 5 \
    "Domains resolving to private IPs — rebinding protection should block"
echo -e "  ${GREEN}Expected: Public-to-private rebinding blocked${NC}"
echo ""

# --- Test 9: C2 Fast-Flux ---
echo -e "${BOLD}=== TEST 9: C2 / Fast-Flux Detection ===${NC}"
run_test "9" "c2" "$ATTACK_DUR" 15 10 \
    "C2 beaconing patterns — fast-flux detection should flag"
echo -e "  ${GREEN}Expected: C2 domains flagged by detection${NC}"
echo ""

# --- Test 10: All scenarios combined ---
echo -e "${BOLD}=== TEST 10: Combined Attack (all scenarios) ===${NC}"
run_test "10" "all" "$ATTACK_DUR" 30 10 \
    "All attack types simultaneously — full pipeline stress test"
echo -e "  ${GREEN}Expected: Mixed results, overall high block rate${NC}"
echo ""

# --- Post-test metrics comparison ---
echo -e "${BOLD}=== POST-TEST METRICS ===${NC}"
echo ""
sleep 1  # Give metrics time to update
AFTER_BLOCKED=$(curl -s "$METRICS_URL" 2>/dev/null | grep 'castiel_blocked_total' | awk '{sum+=$2} END {print sum+0}')
AFTER_TOTAL=$(curl -s "$METRICS_URL" 2>/dev/null | grep 'castiel_queries_total' | awk '{sum+=$2} END {print sum+0}')

DELTA_TOTAL=$((AFTER_TOTAL - BASELINE_TOTAL))
DELTA_BLOCKED=$((AFTER_BLOCKED - BASELINE_BLOCKED))

echo -e "  Before:  Total=$BASELINE_TOTAL  Blocked=$BASELINE_BLOCKED"
echo -e "  After:   Total=$AFTER_TOTAL  Blocked=$AFTER_BLOCKED"
echo -e "  ${BOLD}Delta:   Total=+$DELTA_TOTAL  Blocked=+$DELTA_BLOCKED${NC}"

if [ "$DELTA_TOTAL" -gt 0 ]; then
    PCT=$(echo "scale=1; $DELTA_BLOCKED * 100 / $DELTA_TOTAL" | bc 2>/dev/null || echo "N/A")
    echo -e "  Block rate during tests: ${BOLD}${PCT}%${NC}"
fi
echo ""

# Show blocked-by-reason breakdown
echo -e "${BOLD}  Blocked by reason:${NC}"
curl -s "$METRICS_URL" 2>/dev/null | grep 'castiel_blocked_by_reason' | while read line; do
    reason=$(echo "$line" | sed 's/.*reason="\([^"]*\)".*/\1/')
    count=$(echo "$line" | awk '{print $2}')
    echo -e "    $reason: $count"
done
echo ""

echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Test suite complete.                               ║${NC}"
echo -e "${BOLD}║  Check the Castiel app dashboard for live metrics.  ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
