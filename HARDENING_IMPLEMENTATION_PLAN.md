# Castiel Hardening Implementation Plan

**Date:** 2026-08-06  
**Status:** Planning (pre-development)  
**Objective:** Close remaining detection gaps so Castiel catches DNS poisoning regardless of attacker sophistication.

---

## Current Detection Stack (Deployed)

| Layer | Detects | Limitation |
|---|---|---|
| Rebinding (private IP check) | RFC-1918 IPs for public domains | Evaded by using public attacker IPs |
| Apple ASN/IP Pinning | Public IPs outside Apple/CDN ranges | Evaded by routing through compromised CDN or using IPs within allowed ranges |
| Shadow Query (DoH vs bridge) | Disagreement between DoH and local resolver | Requires internet; only compares 2 sources |
| Fast-flux / C2 | TTL volatility, IP diversity | Evaded by consistent TTLs |

---

## Three New Layers to Implement

---

### Layer 1: Multi-Resolver Consensus

**Purpose:** Query 3+ independent resolvers for the same domain. If ANY resolver disagrees with the majority → poisoning detected. This is the strongest general-purpose detection because an attacker would need to compromise multiple independent DNS infrastructure providers simultaneously.

**Architecture:**

```
                    ┌─────────────────┐
   DNS query ──────►  Castiel Proxy   │
                    └────────┬────────┘
                             │ (async, after primary response)
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │ Cloudflare │  │   Google   │  │   Quad9    │
     │ 1.1.1.1    │  │  8.8.8.8   │  │  9.9.9.9   │
     │  (DoH)     │  │   (DoH)    │  │   (DoH)    │
     └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
           │                │               │
           ▼                ▼               ▼
     ┌─────────────────────────────────────────┐
     │         Consensus Engine                 │
     │  • Collect IP sets from each resolver   │
     │  • Compute majority agreement           │
     │  • Flag outliers as poisoned            │
     └─────────────────────────────────────────┘
```

**Implementation Details:**

| Component | Location | Description |
|---|---|---|
| `ConsensusChecker` struct | `internal/detectors/consensus.go` | Manages multiple DoH clients, collects responses |
| Config | `consensus_check` section in config.yaml | List of resolvers, quorum threshold, timeout |
| Integration | After step 10b in proxy handler (async) | Non-blocking — doesn't delay client response |
| Alert type | `consensus_violation` | Fired when a resolver returns IPs not seen by majority |

**Config Schema:**
```yaml
consensus_check:
  enabled: true
  resolvers:
    - url: "https://1.1.1.1/dns-query"
      name: "cloudflare"
    - url: "https://8.8.8.8/dns-query"
      name: "google"
    - url: "https://9.9.9.9:5053/dns-query"
      name: "quad9"
    - url: "https://194.242.2.2/dns-query"
      name: "mullvad"
  quorum: 3                # minimum agreeing resolvers to establish "truth"
  timeout_ms: 3000         # per-resolver timeout
  check_watchlist_only: true  # only run consensus for pinned domains
  sample_rate: 0.1         # check 10% of queries (reduces overhead)
```

**Detection Logic:**
1. For each response, async-query all configured resolvers
2. Collect IP sets: `{cloudflare: [17.253.27.133, 17.253.27.136], google: [17.253.27.133, 17.253.27.136], local: [203.0.113.50]}`
3. Compute intersection of majority (quorum) resolvers → "consensus IPs"
4. If any resolver returns IPs with zero overlap against consensus → flag as poisoned
5. Alert includes: which resolver disagreed, what IPs it returned, what consensus expected

**What it catches that current stack doesn't:**
- Attacker uses a public IP that happens to fall within an allowed CDN range (e.g., rents Akamai/Cloudflare IP space)
- Partial poisoning where only the local path is affected
- Sophisticated MitM that forges responses for specific resolver paths

**Estimated complexity:** Medium (2-3 hours)

---

### Layer 2: Canary Probe Scheduler

**Purpose:** Periodically probe all watchlist domains in the background, independent of user queries. Detects timing-window attacks (attacker only poisons during specific intervals) and ensures continuous coverage even for domains the user hasn't queried recently.

**Architecture:**

```
┌─────────────────────────────────────────────────┐
│              Canary Probe Scheduler              │
│                                                  │
│  Every 30-60s (randomized jitter):              │
│  ┌───────────────────────────────────────────┐  │
│  │ For each domain in watchlist:             │  │
│  │   1. Query bridge resolver (local path)   │  │
│  │   2. Query DoH (clean path)               │  │
│  │   3. Run ASN pinning check                │  │
│  │   4. Run consensus check                  │  │
│  │   5. Compare results                      │  │
│  │   6. Log to canary_results.jsonl          │  │
│  │   7. Alert on any discrepancy             │  │
│  └───────────────────────────────────────────┘  │
│                                                  │
│  Randomized timing prevents attacker from       │
│  predicting probe windows and disabling poison  │
│  during probes.                                  │
└─────────────────────────────────────────────────┘
```

**Implementation Details:**

| Component | Location | Description |
|---|---|---|
| `CanaryScheduler` struct | `internal/detectors/canary.go` | Background goroutine, timer, domain cycling |
| Config | `canary_probes` section in config.yaml | Interval, jitter, domains, resolvers |
| Integration | Started in `Proxy.Start()` as background goroutine | Independent of query path |
| Alert type | `canary_probe_failure` | Fired when canary detects poisoning |
| Log file | `canary_results.jsonl` | Historical record of all probe results |

**Config Schema:**
```yaml
canary_probes:
  enabled: true
  interval_seconds: 45      # base interval between probe sweeps
  jitter_seconds: 15        # random ±15s to prevent timing prediction
  timeout_ms: 3000
  domains: []               # empty = use apple_pinning watchlist
  local_resolver: "192.168.2.1:53"  # bridge/local resolver to probe
  doh_resolver: "https://1.1.1.1/dns-query"
  log_file: "/usr/local/var/log/castiel/canary_results.jsonl"
  alert_on_timeout: false   # don't alert if resolver is just offline
  alert_on_mismatch: true   # alert if local ≠ DoH
  alert_on_pin_violation: true
```

**Detection Logic:**
1. Goroutine wakes every `interval ± jitter` seconds
2. Cycles through watchlist domains (batch of 5-10 per sweep to avoid flooding)
3. For each domain:
   - Query local/bridge resolver (the potentially-poisoned path)
   - Query DoH (the clean/trusted path)
   - Compare: if local returns different IPs than DoH → mismatch alert
   - Run ASN pinning on local response → pin violation alert
4. Log every probe result (clean or poisoned) for historical analysis
5. Prometheus gauge: `castiel_canary_last_check_timestamp`, `castiel_canary_mismatches_total`

**What it catches that current stack doesn't:**
- Timing-window attacks (poison only during update checks, disable during probes)
- Intermittent/probabilistic poisoning (only poison 30% of queries)
- Slow-drift attacks (gradually change IPs over days)
- Attacks on domains the user hasn't queried yet

**Estimated complexity:** Medium (2-3 hours)

---

### Layer 3: TLS Certificate Verification

**Purpose:** After DNS resolution, perform a TLS handshake to the resolved IP and verify the certificate chains to an expected CA. This is the ultimate verification — even if an attacker has a legitimate public IP in a CDN range, they cannot forge a valid TLS certificate for `*.apple.com` without compromising a CA.

**Architecture:**

```
┌──────────────┐      DNS Response       ┌──────────────────┐
│  DNS Query   │ ──────────────────────► │  Normal Response  │
│  apple.com   │                          │  IP: 203.0.113.50│
└──────────────┘                          └────────┬─────────┘
                                                   │
                                                   ▼ (async post-check)
                                          ┌──────────────────┐
                                          │  TLS Verifier    │
                                          │                  │
                                          │  1. Connect to   │
                                          │     203.0.113.50 │
                                          │     :443         │
                                          │  2. TLS handshake│
                                          │     SNI=apple.com│
                                          │  3. Check cert:  │
                                          │     - Valid?     │
                                          │     - CA chain?  │
                                          │     - SAN match? │
                                          │     - Expected   │
                                          │       issuer?    │
                                          └────────┬─────────┘
                                                   │
                                    ┌──────────────┴───────────┐
                                    │                          │
                              ┌─────▼─────┐           ┌───────▼──────┐
                              │  VALID    │           │   INVALID    │
                              │  cert for │           │   cert or    │
                              │  apple.com│           │   wrong CA   │
                              │  → clean  │           │   → ALERT    │
                              └───────────┘           └──────────────┘
```

**Implementation Details:**

| Component | Location | Description |
|---|---|---|
| `TLSVerifier` struct | `internal/detectors/tls_verify.go` | Async TLS handshake with cert validation |
| Expected CAs map | Embedded + configurable | Maps domain patterns → expected CA issuers |
| Config | `tls_verification` section in config.yaml | Timeout, CA expectations, sample rate |
| Integration | Called async after pinning check for watched domains | Non-blocking |
| Alert type | `tls_cert_violation` | Fired when cert doesn't match expected CA |
| Cache | LRU cache of verified IP+domain pairs | Avoid repeated handshakes for same resolution |

**Config Schema:**
```yaml
tls_verification:
  enabled: true
  timeout_ms: 5000          # TLS handshake timeout
  sample_rate: 0.2          # verify 20% of watchlist queries (avoid overhead)
  cache_ttl_seconds: 300    # cache verified results for 5 min
  max_cache_entries: 1000
  verify_watchlist_only: true
  expected_cas:
    - domain_pattern: "*.apple.com"
      issuers:
        - "DigiCert Inc"
        - "Apple Inc"
        - "GeoTrust"
    - domain_pattern: "*.icloud.com"
      issuers:
        - "DigiCert Inc"
        - "Apple Inc"
    - domain_pattern: "*.cdn-apple.com"
      issuers:
        - "DigiCert Inc"
        - "GlobalSign"
        - "Let's Encrypt"
```

**Detection Logic:**
1. After DNS resolution for a watched domain, async-spawn TLS verification
2. Check LRU cache first — if IP+domain verified recently, skip
3. Establish TCP connection to resolved IP:443
4. Perform TLS handshake with `ServerName` (SNI) set to the queried domain
5. Validate certificate:
   - **Valid chain?** — cert chains to trusted root
   - **SAN match?** — cert covers the queried domain
   - **Expected issuer?** — cert issued by expected CA for this domain pattern
   - **Not expired?** — cert within validity period
   - **Not revoked?** — (optional) check OCSP stapling
6. If any check fails → alert with details (which check failed, what cert was presented)
7. Cache successful verifications to avoid repeated overhead

**What it catches that ALL other layers miss:**
- Attacker rents legitimate CDN IP space (passes ASN pinning)
- Attacker compromises one resolver but not others (consensus might still pass if 2/3 agree)
- Attacker uses IPs that historically served Apple traffic (passes baseline)
- **Only way to evade:** Compromise a Certificate Authority or steal Apple's private key

**Security notes:**
- TLS verification is the gold standard — DNS poisoning alone cannot forge a valid cert
- Even nation-state attackers struggle with this (need CA compromise or BGP hijack + cert issuance)
- This is effectively what browsers do — we're bringing that same assurance to the DNS layer

**Estimated complexity:** Medium-High (3-4 hours)

---

## Implementation Order

```
Phase 1 (immediate):  ✅ ASN/IP Pinning (DONE — deployed)
Phase 2 (next):       [ ] Multi-Resolver Consensus
Phase 3:              [ ] Canary Probe Scheduler  
Phase 4:              [ ] TLS Certificate Verification
```

**Rationale for order:**
1. **Consensus** builds on existing DoH infrastructure, gives broadest coverage improvement
2. **Canary** adds continuous monitoring independent of user queries (catches timing attacks)
3. **TLS** is the ultimate check but most complex, depends on internet access, and has the most overhead

---

## Combined Detection Matrix (After All 3 Implemented)

| Attack Technique | Rebinding | ASN Pin | Consensus | Canary | TLS | Detected? |
|---|---|---|---|---|---|---|
| Private IP (192.168.0.0) | ✅ | — | ✅ | ✅ | — | **YES** |
| Random public IP (203.x.x.x) | ❌ | ✅ | ✅ | ✅ | ✅ | **YES** |
| IP within CDN range | ❌ | ❌ | ✅ | ✅ | ✅ | **YES** |
| Compromised CDN node | ❌ | ❌ | ❌* | ✅ | ✅ | **YES** |
| Timing-window poisoning | ❌ | ❌ | ❌ | ✅ | ✅ | **YES** |
| All resolvers poisoned | ❌ | ❌ | ❌ | ❌ | ✅ | **YES** |
| CA compromise + DNS poison | ❌ | ❌ | ❌ | ❌ | ❌ | **NO** ⚠️ |

*Consensus may still catch this if attacker can't poison all 4 resolvers simultaneously.

**Only remaining gap:** CA compromise (nation-state level). Mitigation: Certificate Transparency log monitoring (future Layer 5).

---

## Estimated Total Effort

| Layer | Effort | Files | Tests |
|---|---|---|---|
| Multi-Resolver Consensus | 2-3 hrs | 2 new + 2 modified | 6-8 tests |
| Canary Probe Scheduler | 2-3 hrs | 2 new + 1 modified | 5-7 tests |
| TLS Certificate Verification | 3-4 hrs | 2 new + 2 modified | 8-10 tests |
| **Total** | **7-10 hrs** | **6 new + 5 modified** | **19-25 tests** |

---

## Dependencies

- **Internet access required** for Consensus and TLS verification (DoH resolvers, TLS handshake)
- **Bridge access required** for Canary probes (comparing local vs clean)
- **No external services** beyond DNS resolvers and TCP connections
- **No new Go dependencies** — uses stdlib `crypto/tls`, `net`, existing `miekg/dns`

---

## Success Criteria

After all three layers are deployed:
1. Gatebreaker returning ANY IP (private or public) for Apple domains → detected
2. Gatebreaker using timing windows → detected by canary within 60s
3. Gatebreaker using CDN-range IPs → detected by consensus + TLS
4. Zero false positives for legitimate Apple CDN rotations
5. All detection is async — no added latency to user DNS queries
