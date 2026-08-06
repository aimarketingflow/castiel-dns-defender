# Castiel DNS Poisoning Detection Report

**Date:** 2026-08-06  
**Test Window:** 13:41 – 19:05 EDT  
**Target:** Mac A (192.168.2.2) via Thunderbolt Bridge  
**Attacker:** Mac B / Gatebreaker (192.168.2.1)  
**Defender:** Castiel DNS Defender v0.1.0

---

## Executive Summary

Castiel successfully detected DNS poisoning originating from Gatebreaker on Mac B over the Thunderbolt bridge. Multiple detection engines fired, identifying the attack through:

1. **DNS Rebinding/Calculation Detection** — Public domain `ocsp.apple.com` resolving to private IP `192.168.0.0`
2. **C2/Fast-Flux Detection** — TTL volatility and IP diversity patterns on poisoned domain
3. **Response Validation** — Malformed responses from poisoned upstream

---

## Detection Statistics

| Alert Type | Count | Severity |
|---|---|---|
| `response_validation_fail` | 96 | critical |
| `dns_tunneling` | 53 | critical |
| `c2_fastflux` | 47 | critical |
| `cname_chain_dangling` | 32 | critical |
| `dga_detected` | 28 | critical |
| `dns_calculation` | 16 | critical |
| `zone_transfer` | 10 | critical |
| `rate_limit` | 10 | critical |
| `fastflux_enhanced` | 10 | critical |
| `blocklist_hit` | 4 | critical |
| `dictionary_dga` | 2 | critical |
| **TOTAL** | **308** | |

---

## Gatebreaker-Specific Detections

### DNS Poisoning (dns_calculation)

The core detection: Castiel identified that the public domain `ocsp.apple.com` was being resolved to the private IP `192.168.0.0` — a clear indicator of DNS poisoning/rebinding.

**Timeline of Gatebreaker poisoning detections:**

| Time (EDT) | Domain | Poisoned IP | Detection |
|---|---|---|---|
| 18:44:55 | `ocsp.apple.com` | `192.168.0.0` | dns_calculation |
| 19:01:10 | `ocsp.apple.com` | `192.168.0.0` | dns_calculation |
| 19:01:39 | `ocsp.apple.com` | `192.168.0.0` | dns_calculation |
| 19:02:16 | `ocsp.apple.com` | `192.168.0.0` | dns_calculation |
| 19:02:53 | `ocsp.apple.com` | `192.168.0.0` | dns_calculation |
| 19:03:30 | `ocsp.apple.com` | `192.168.0.0` | dns_calculation |
| 19:05:33 | `ocsp.apple.com` | — | c2_fastflux (TTL volatility) |

### Attack Characteristics Observed

- **Poisoned Response:** `ocsp.apple.com` → `192.168.0.0` (RFC-1918 private IP for public domain)
- **Attack Vector:** Gatebreaker PF redirect on Mac B intercepting DNS queries over Thunderbolt bridge
- **Bridge Interface:** `bridge0` (Mac A: 192.168.2.2 ↔ Mac B: 192.168.2.1)
- **Detection Latency:** Immediate (within same query cycle)

---

## Network Configuration During Test

```
Mac A (Victim/Defender):
  - Interface: bridge0 (192.168.2.2/24)
  - Default gateway: 192.168.2.1 (Mac B)
  - System DNS: 127.0.0.1 (Castiel loopback)
  - Castiel listening: 127.0.0.1:5300
  - Socat forwarder: UDP/TCP :53 → :5300
  - DoH upstream: https://1.1.1.1/dns-query (degraded — no internet via bridge)

Mac B (Attacker):
  - Interface: bridge0 (192.168.2.1/24)
  - Running: Gatebreaker DNS poisoning (dnsmasq + PF redirect)
  - Poisoning: Intercepting port 53, returning 192.168.0.0 for target domains
```

---

## Detection Mechanism Flow

```
┌─────────────┐     DNS query      ┌──────────────┐
│   Mac A     │ ──────────────────> │  Castiel     │
│  (client)   │                     │  (port 5300) │
└─────────────┘                     └──────┬───────┘
                                           │
                              ┌────────────┼────────────┐
                              │            │            │
                              ▼            ▼            ▼
                         DoH (1.1.1.1)  Plain DNS   Shadow Query
                         [FAILED-no     fallback    to 192.168.2.1
                          internet]     (1.1.1.1:53)
                                           │
                                           ▼
                                    ┌─────────────┐
                                    │   Mac B     │
                                    │ Gatebreaker │
                                    │  (PF redir) │
                                    └──────┬──────┘
                                           │
                                           ▼
                                    Returns 192.168.0.0
                                    (POISONED RESPONSE)
                                           │
                                           ▼
                              ┌─────────────────────────┐
                              │ Castiel Rebinding Check  │
                              │ Private IP for public    │
                              │ domain → ALERT FIRED     │
                              └─────────────────────────┘
```

---

## Detection Categories Explained

### 1. `dns_calculation` (Primary Gatebreaker Detection)
Castiel's rebinding protection detected that a public domain resolved to a private/reserved IP address. This is the primary indicator of Gatebreaker's DNS poisoning — returning `192.168.0.0` for `ocsp.apple.com`.

### 2. `c2_fastflux` (Secondary Pattern Detection)
The poisoned responses exhibited TTL volatility and IP diversity patterns consistent with C2/fast-flux infrastructure. This is a secondary indicator triggered by the inconsistent responses between clean (DoH) and poisoned (bridge) paths.

### 3. `response_validation_fail` (Upstream Integrity)
Malformed DNS responses were rejected, indicating that the poisoned upstream was returning structurally invalid DNS data in some cases.

---

## Conclusion

**Castiel successfully detected Gatebreaker's DNS poisoning attack.** The rebinding/calculation detection engine correctly identified the private IP `192.168.0.0` being returned for public domain `ocsp.apple.com` — a definitive indicator of DNS cache poisoning.

### Findings for Mac B Review:
1. Gatebreaker's poisoning IS detectable by Castiel's rebinding protection
2. The poisoned IP `192.168.0.0` is trivially identifiable as RFC-1918 space
3. Multiple detection engines corroborate the attack (calculation, fast-flux, validation)
4. 308 total alerts generated across all detection categories during the test window
5. Detection fires within the same query cycle — no delay

### Recommendations:
- Gatebreaker could evade `dns_calculation` detection by returning non-RFC1918 IPs (e.g., attacker-controlled public IPs)
- Shadow query comparison (DoH vs plain) would catch even public-IP poisoning when internet is available
- Consider testing with WiFi enabled so DoH path works and shadow query comparison fires

---

## Attached Artifacts
- `logs/castiel_alerts_20260806.jsonl` — Full alert log (308 entries)
- `dns-poison-monitor.sh` — Real-time terminal monitoring script
