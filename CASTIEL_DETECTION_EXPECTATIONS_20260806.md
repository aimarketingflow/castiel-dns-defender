# Castiel Detection Expectations — Gatebreaker Attack Analysis

**Date**: Aug 6, 2026  
**Purpose**: Document what Castiel on Mac A should detect when Gatebreaker
attacks from Mac B, and identify gaps in detection coverage.

---

## Attack Architecture Overview

Gatebreaker's DNS poisoning attack has three components, all running on
Mac B (attacker):

1. **dnsmasq** — listens on `127.0.0.1:5553`, returns `192.168.0.0` for
   Apple OCSP/CDN domains
2. **PF redirect** — `rdr pass on bridge0 inet proto {udp,tcp} from
   192.168.2.2 to any port = 53 -> 127.0.0.1 port 5553`
3. **ARP spoof** (optional on Thunderbolt) — redirects victim traffic
   through attacker

### Traffic flow WITHOUT Castiel:

```
Mac A (192.168.2.2)
  → DNS query: "ocsp.apple.com" to 192.168.2.1:53
  → PF redirect on Mac B's bridge0 intercepts
  → Redirected to 127.0.0.1:5553 (dnsmasq)
  → dnsmasq returns 192.168.0.0 (poisoned)
  → Mac A receives poisoned response
  → Gatekeeper can't reach OCSP → fails open → bypass
```

### Traffic flow WITH Castiel:

```
Mac A (192.168.2.2)
  → DNS query: "ocsp.apple.com"
  → Castiel PF redirect on Mac A (loopback) intercepts FIRST
  → Castiel resolves via DoH upstream (encrypted, bypasses local DNS)
  → Returns REAL Apple IP to Mac A
  → Gatekeeper reaches OCSP normally → revocation enforced
```

**The key question**: Does Castiel's loopback PF redirect take priority
over Gatebreaker's bridge0 PF redirect? They operate at different layers:

- **Gatebreaker** redirects on Mac B's `bridge0` (incoming traffic from
  Mac A, before it reaches Mac B's DNS resolver)
- **Castiel** redirects on Mac A's `lo0` (outgoing DNS from Mac A,
  before it even leaves the machine)

If Castiel intercepts DNS queries on Mac A **before they leave the
machine**, then Gatebreaker's bridge0 redirect never sees them — Castiel
resolves via DoH (HTTPS to upstream DNS provider), which doesn't use
port 53 at all.

---

## What Castiel SHOULD detect

### 1. DNS Poisoning Attempts (if queries leak through)

If any DNS query for a poisoned domain reaches Mac B's dnsmasq and
returns `192.168.0.0`, Castiel should:

- **Alert**: "DNS rebinding blocked: ocsp.apple.com → 192.168.0.0"
- **Log**: Entry in `castiel_alerts.jsonl` with timestamp, domain,
  poisoned IP, action taken
- **Metric**: Increment `castiel_dns_queries_blocked_total` or similar
- **Notification**: macOS Notification Center popup

### 2. Domains Gatebreaker poisons

Gatebreaker's dnsmasq config poisons these domains to `192.168.0.0`:

| Domain | Purpose | Impact if poisoned |
|--------|---------|-------------------|
| `ocsp.apple.com` | OCSP responder | Gatekeeper bypass |
| `ocsp2.apple.com` | OCSP responder (secondary) | Gatekeeper bypass |
| `gateway.icloud.com` | iCloud gateway | iCloud connectivity loss |
| `swscan.apple.com` | Software update scan | Update checks fail |
| `xp.apple.com` | XProtect updates | Malware signature updates fail |
| `push.apple.com` | Push notifications | Notifications fail |

Castiel should alert on **any** of these returning `192.168.0.0`.

### 3. Expected alert log entries

```json
{"timestamp":"2026-08-06T...","domain":"ocsp.apple.com","query_type":"A","poisoned_ip":"192.168.0.0","action":"blocked","source":"dns_poison_detection"}
{"timestamp":"2026-08-06T...","domain":"ocsp2.apple.com","query_type":"A","poisoned_ip":"192.168.0.0","action":"blocked","source":"dns_poison_detection"}
```

### 4. Expected metrics

```
castiel_dns_queries_total{domain="ocsp.apple.com"} <incrementing>
castiel_dns_queries_blocked_total{reason="poisoned_response"} <incrementing>
castiel_dns_rebinding_attempts_total <incrementing>
```

---

## What Castiel might MISS (detection gaps)

### Gap 1: DoH bypasses local DNS entirely

If Castiel resolves via DoH (HTTPS to Cloudflare/Google DNS on port 443),
then **no DNS query on port 53 ever leaves Mac A** for Gatebreaker to
intercept. This is actually the BEST case — Castiel wins by not playing.

But it means Castiel may **never see the poisoned response** and therefore
**never generate an alert**. The attack is silently defeated, but there's
no detection evidence to show.

### Gap 2: PF redirect priority conflict

If Castiel's PF redirect doesn't fully intercept all DNS traffic (e.g.,
some apps use their own DNS resolver bypassing the system resolver), those
queries could still hit Gatebreaker's redirect on bridge0.

Symptom: `dig` works (goes through Castiel) but a specific app still gets
poisoned DNS.

### Gap 3: IP-level blocking (Phase 3)

When Gatebreaker shifts from DNS poisoning to IP-level blocking (PF rules
blocking `17.253.0.0/16`, `17.248.228.0/24`, `17.171.0.0/16` on ports
80/443), Castiel sees **nothing wrong**:

- DNS resolves correctly (Castiel does its job)
- No poisoned responses to detect
- No rebinding attempt to flag
- But the actual HTTPS connection to OCSP fails (timeout)
- Gatekeeper still fails open

**This is by design** — Castiel is a DNS defense tool, not a network
connectivity monitor. It cannot detect IP-level blocking because that
happens at a different OSI layer.

---

## Test Matrix

| Scenario | Gatebreaker | Castiel | DNS Result on Mac A | Castiel Alert? | Gatekeeper |
|----------|-------------|---------|---------------------|----------------|------------|
| Phase 1 | DNS poison | OFF | `192.168.0.0` | N/A | Bypassed |
| Phase 2 | DNS poison | ON | Real Apple IP | **Maybe** (see Gap 1) | Protected |
| Phase 3 | IP block | ON | Real Apple IP | No alerts | Bypassed |

---

## How to verify Castiel is actually intercepting

On Mac A with Castiel running and Gatebreaker attacking:

```bash
# 1. Check Castiel's PF redirect is active
sudo pfctl -a castiel -s rules 2>/dev/null

# 2. Check what port DNS is actually going to
sudo lsof -i -P | grep -E ":53|:5300|:5553"

# 3. Query system DNS (should go through Castiel)
dig +short ocsp.apple.com
# Expected: real Apple IP (17.x.x.x) — Castiel resolved via DoH

# 4. Query Gatebreaker's dnsmasq directly (bypasses Castiel)
dig @192.168.2.1 -p 53 +short ocsp.apple.com
# Expected: 192.168.0.0 (poisoned) — this is what Mac A WOULD get
# without Castiel

# 5. Check Castiel metrics for query counters
curl -s http://127.0.0.1:9090/metrics | grep -E "queries|blocked|alert"

# 6. Check alert log
cat logs/castiel_alerts.jsonl

# 7. Check if any DNS traffic is leaking to bridge0
sudo tcpdump -i bridge0 -n port 53 -c 10
# If Castiel is working: NO traffic on bridge0 port 53
# If Castiel is leaking: you'll see DNS queries to 192.168.2.1
```

---

## Summary

**Best case (Phase 2)**: Castiel intercepts all DNS on Mac A via loopback
PF redirect, resolves via DoH upstream, and Gatebreaker's bridge0 redirect
never sees any port 53 traffic. Gatekeeper stays protected. Castiel may
not generate alerts because it never sees the poisoned responses — it
prevents them by not using local DNS at all.

**Worst case (Phase 3)**: Gatebreaker blocks Apple OCSP at IP level. DNS
is irrelevant. Castiel sees clean DNS, no alerts, but Gatekeeper is still
bypassed because OCSP HTTPS connections time out. This is the
architectural limitation — only Apple can fix this by enabling CRLite.

**What to document on video**: For Phase 2, show both the `dig` result
(real IP via Castiel) AND the `dig @192.168.2.1 -p 53` result (poisoned)
to prove Castiel is actively preventing the poisoning, even if no alert
fires. The absence of poisoning IS the defense.
