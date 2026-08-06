# Castiel Detection Test — Does Castiel Alert on DNS Poisoning?

**Date**: Aug 6, 2026  
**Context**: Gatebreaker is actively DNS-poisoning over Thunderbolt (`bridge0`).
PF redirect on Mac B is confirmed working — Mac A's DNS queries to
`192.168.2.1:53` are being redirected to dnsmasq on port 5553, returning
`192.168.0.0` for Apple OCSP domains.

**Question**: Does Castiel detect and alert on this DNS poisoning when
it's running on Mac A?

---

## Step 1: Verify Castiel is stopped (current state)

```bash
sudo launchctl list | grep castiel
sudo pfctl -a castiel -s rules 2>/dev/null
```

If anything is running, stop it first:
```bash
sudo launchctl unload /Library/LaunchDaemons/com.castiel.dns.plist 2>/dev/null
sudo pfctl -a castiel -d 2>/dev/null
```

---

## Step 2: Confirm DNS is currently poisoned (baseline without Castiel)

```bash
dig +short ocsp.apple.com
```

Expected: `192.168.0.0` (poisoned by Gatebreaker)

---

## Step 3: Start Castiel

```bash
sudo launchctl load /Library/LaunchDaemons/com.castiel.dns.plist
sleep 3
```

Verify Castiel is running:
```bash
launchctl list | grep castiel
sudo pfctl -a castiel -s rules 2>/dev/null
curl -s http://127.0.0.1:9090/metrics | head -20
```

---

## Step 4: Test DNS resolution with Castiel active

```bash
dig +short ocsp.apple.com
dig +short ocsp2.apple.com
dig +short gateway.icloud.com
dig +short swscan.apple.com
dig +short xp.apple.com
dig +short push.apple.com
```

**Key question**: Does Castiel:
- A) Intercept the DNS query and resolve via DoH upstream (returns real Apple IP)?
- B) Let the poisoned response through (returns `192.168.0.0`)?
- C) Block the query entirely (timeout)?

Record which domains return real IPs vs poisoned IPs.

---

## Step 5: Check Castiel alerts

```bash
# Check alert log for detection entries
cat /tmp/castiel-src/logs/castiel_alerts.jsonl 2>/dev/null || cat logs/castiel_alerts.jsonl 2>/dev/null

# If the file doesn't exist, search for it
find / -name "castiel_alerts.jsonl" 2>/dev/null

# Check metrics for detection counters
curl -s http://127.0.0.1:9090/metrics | grep -i -E "alert|detect|block|poison|rebind"
```

---

## Step 6: Check Castiel logs for any activity

```bash
# Check system log for Castiel messages
log show --predicate 'process == "castiel"' --last 5m 2>/dev/null

# If Castiel logs to a file, check that too
ls -la /tmp/castiel-src/logs/ 2>/dev/null || ls -la logs/ 2>/dev/null
```

---

## Step 7: Test with a direct query to Castiel's DNS port

Castiel may listen on a different port (e.g. 5300) or intercept via PF
redirect on loopback. Check:

```bash
# What ports is Castiel listening on?
sudo lsof -i -P | grep castiel

# Try querying Castiel directly (adjust port if needed)
dig @127.0.0.1 -p 5300 ocsp.apple.com +short
dig @127.0.0.1 -p 53 ocsp.apple.com +short
```

---

## Step 8: Compare — poisoned query vs Castiel-intercepted query

```bash
# Query Gatebreaker's dnsmasq directly (should be poisoned)
dig @192.168.2.1 -p 53 ocsp.apple.com +short

# Query Castiel directly (should be clean if Castiel resolves upstream)
dig @127.0.0.1 -p 5300 ocsp.apple.com +short

# Normal system query (goes through whatever Castiel sets up)
dig ocsp.apple.com +short
```

---

## Step 9: Check if Castiel's PF redirect is competing with Gatebreaker's

```bash
# Show all PF NAT/redirect rules
sudo pfctl -s nat 2>/dev/null

# Show Castiel's anchor rules
sudo pfctl -a castiel -s nat 2>/dev/null
sudo pfctl -a castiel -s rules 2>/dev/null

# Show Gatebreaker's anchor rules
sudo pfctl -a "com.apple/dns_poison" -s nat 2>/dev/null
```

**Important**: If both Castiel and Gatebreaker have PF redirect rules on
`bridge0`, they may conflict. Castiel's redirect (loopback, port 5300)
may or may not take priority over Gatebreaker's redirect (port 5553).

---

## Step 10: Run Castiel's built-in test suite

```bash
cd /tmp/castiel-src
./test-castiel.sh --quick
```

---

## Report Back

Please share:
1. Output of Step 4 (which domains return real vs poisoned IPs)
2. Contents of `castiel_alerts.jsonl` (if it exists)
3. Output of `curl -s http://127.0.0.1:9090/metrics | grep -i -E "alert|detect|block|poison|rebind"`
4. Output of `sudo lsof -i -P | grep castiel` (what ports Castiel uses)
5. Output of `sudo pfctl -s nat` (all redirect rules — both Castiel and Gatebreaker)
6. Output of `log show --predicate 'process == "castiel"' --last 5m`
7. Result of `./test-castiel.sh --quick`

The key question is: **when Gatebreaker poisons DNS on the network layer
(PF redirect on bridge0), does Castiel — running on Mac A — see the
poisoned responses and alert?** Or does the poisoning happen upstream
(on Mac B) before Castiel ever sees the traffic?
