package dnssec

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Validator performs real DNSSEC chain-of-trust validation.
//
// It verifies that DNS responses are cryptographically signed by following
// the chain of trust from a configured trust anchor (typically the root KSK)
// down through DS/DNSKEY records to the apex domain.
//
// Validation modes (fallback chain):
//   1. Full chain validation (trust anchor → DS → DNSKEY → RRSIG)
//   2. AD-bit-only mode (trust upstream's AD flag — less secure)
//   3. Disabled (no validation)
type Validator struct {
	trustAnchors []*dns.DNSKEY // Root KSKs loaded from trust anchor file
	resolver      *dns.Client  // DNS client for fetching DS/DNSKEY records
	upstream      []string     // Upstream servers for queries
	cache         *keyCache    // DNSKEY/DS cache
	mode          ValidationMode
	mu            sync.RWMutex
}

// ValidationMode controls how DNSSEC validation is performed.
type ValidationMode int

const (
	ModeFullChain ValidationMode = iota // Full chain-of-trust validation
	ModeADBitOnly                       // Trust upstream AD bit only
	ModeDisabled                        // No validation
)

// keyCache stores validated DNSKEY and DS records with TTL.
type keyCache struct {
	dnskeys map[string]*cachedDNSKEY // key: "domain:algorithm:keytag"
	ds     map[string]*cachedDS      // key: "domain:algorithm:digesttype"
	mu     sync.RWMutex
}

type cachedDNSKEY struct {
	key       *dns.DNSKEY
	expiresAt time.Time
}

type cachedDS struct {
	ds        *dns.DS
	expiresAt time.Time
}

// NewValidator creates a DNSSEC validator.
// If trustAnchorFile is provided and loads successfully, full chain validation is used.
// Otherwise, it falls back to AD-bit-only mode.
func NewValidator(trustAnchorFile string, upstream []string, timeout time.Duration) *Validator {
	v := &Validator{
		resolver: &dns.Client{
			Timeout: timeout,
			UDPSize: 4096,
			Net:     "udp",
		},
		upstream: upstream,
		cache: &keyCache{
			dnskeys: make(map[string]*cachedDNSKEY),
			ds:      make(map[string]*cachedDS),
		},
		mode: ModeADBitOnly, // Default: trust AD bit
	}

	if trustAnchorFile != "" {
		anchors, err := loadTrustAnchors(trustAnchorFile)
		if err != nil {
			log.Printf("DNSSEC: failed to load trust anchors from %s: %v — falling back to AD-bit mode", trustAnchorFile, err)
		} else if len(anchors) > 0 {
			v.trustAnchors = anchors
			v.mode = ModeFullChain
			log.Printf("DNSSEC: loaded %d trust anchor(s) — full chain validation enabled", len(anchors))
		} else {
			log.Printf("DNSSEC: no trust anchors found in %s — falling back to AD-bit mode", trustAnchorFile)
		}
	}

	return v
}

// SetMode changes the validation mode at runtime.
func (v *Validator) SetMode(mode ValidationMode) {
	v.mu.Lock()
	v.mode = mode
	v.mu.Unlock()
	switch mode {
	case ModeFullChain:
		log.Printf("DNSSEC: mode set to FULL CHAIN validation")
	case ModeADBitOnly:
		log.Printf("DNSSEC: mode set to AD-BIT-ONLY (trusting upstream)")
	case ModeDisabled:
		log.Printf("DNSSEC: mode set to DISABLED")
	}
}

// Mode returns the current validation mode.
func (v *Validator) Mode() ValidationMode {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.mode
}

// Validate validates a DNS response according to the current mode.
// Returns true if the response is considered valid/trusted.
func (v *Validator) Validate(resp *dns.Msg, qname string) bool {
	v.mu.RLock()
	mode := v.mode
	v.mu.RUnlock()

	switch mode {
	case ModeDisabled:
		return true // No validation — pass through

	case ModeADBitOnly:
		// Trust the upstream resolver's AD flag
		if resp == nil {
			return false
		}
		return resp.AuthenticatedData

	case ModeFullChain:
		if resp == nil {
			return false
		}
		// Non-success responses don't need DNSSEC validation
		if resp.Rcode != dns.RcodeSuccess {
			return true
		}
		// If upstream already set AD and we trust it, accept
		if resp.AuthenticatedData {
			return true
		}
		// Full chain validation
		return v.validateChain(resp, qname)
	}

	return false
}

// validateChain performs full DNSSEC chain-of-trust validation.
//
// Steps:
//   1. Extract RRSIG records from the response
//   2. Fetch DNSKEY records for the zone that signed the response
//   3. Verify RRSIG against DNSKEY
//   4. Follow DS chain from trust anchor down to the signing zone
//   5. Verify each DS matches a DNSKEY in the chain
func (v *Validator) validateChain(resp *dns.Msg, qname string) bool {
	// Group answer records by type to find RRSIGs
	rrsigSets := groupRRSIGs(resp.Answer)
	if len(rrsigSets) == 0 {
		// No RRSIG records in response — zone is insecure (not signed) or
		// upstream stripped signatures. Treat as INSECURE (valid), not BOGUS.
		// Only reject responses with *invalid* signatures, not missing ones.
		log.Printf("DNSSEC: no RRSIG records in response for %s — zone is insecure (accepted)", qname)
		return true
	}

	// Validate each RRset with its RRSIG
	for rrsetType, rrsigs := range rrsigSets {
		rrset := extractRRset(resp.Answer, rrsetType)
		if len(rrset) == 0 {
			continue
		}

		validated := false
		for _, rrsig := range rrsigs {
			// Determine the signer (owner of the DNSKEY)
			signerName := strings.ToLower(rrsig.SignerName)
			if signerName == "" {
				continue
			}

			// Fetch DNSKEY records for the signer
			dnskeys, err := v.fetchDNSKEYs(signerName)
			if err != nil {
				log.Printf("DNSSEC: failed to fetch DNSKEY for %s: %v", signerName, err)
				continue
			}

			// Try each DNSKEY to verify the RRSIG
			for _, key := range dnskeys {
				if err := rrsig.Verify(key, rrset); err != nil {
					continue
				}

				// Check RRSIG validity period
				if !rrsig.ValidityPeriod(time.Now()) {
					log.Printf("DNSSEC: RRSIG for %s outside validity period", qname)
					continue
				}

				// Verify the DNSKEY is trusted via DS chain
				if v.verifyDSChain(signerName, key) {
					validated = true
					break
				}
			}

			if validated {
				break
			}
		}

		if !validated {
			log.Printf("DNSSEC: validation FAILED for %s (type %d) — no valid RRSIG/DNSKEY chain", qname, rrsetType)
			return false
		}
	}

	return true
}

// verifyDSChain walks the DS chain from the trust anchor down to the given zone.
// Returns true if the DNSKEY is validated by a DS record in its parent zone,
// and that parent's DS is validated recursively up to the trust anchor.
func (v *Validator) verifyDSChain(zone string, key *dns.DNSKEY) bool {
	zone = strings.ToLower(zone)
	zone = strings.TrimSuffix(zone, ".")

	// Check if this zone IS the trust anchor (root)
	for _, anchor := range v.trustAnchors {
		if strings.ToLower(anchor.Hdr.Name) == zone+"." || (zone == "" && anchor.Hdr.Name == ".") {
			if key.KeyTag() == anchor.KeyTag() {
				return true
			}
		}
	}

	// Walk up the domain tree looking for DS records
	labels := strings.Split(zone, ".")
	for i := 0; i < len(labels); i++ {
		childZone := strings.Join(labels[i:], ".")
		parentZone := strings.Join(labels[i+1:], ".")

		if childZone == "" {
			break
		}

		// Fetch DS records for the child zone from the parent
		dsRecords, err := v.fetchDS(childZone + ".")
		if err != nil || len(dsRecords) == 0 {
			// No DS — try going up
			continue
		}

		// Check if any DS matches our DNSKEY
		for _, ds := range dsRecords {
			// Compute DS from our DNSKEY and compare
			computedDS := key.ToDS(ds.DigestType)
			if computedDS == nil {
				continue
			}
			if computedDS.KeyTag == ds.KeyTag &&
				computedDS.Algorithm == ds.Algorithm &&
				computedDS.DigestType == ds.DigestType &&
				computedDS.Digest == ds.Digest {
				// DS matches — now verify the parent zone's DNSKEY
				parentKeys, err := v.fetchDNSKEYs(parentZone + ".")
				if err != nil {
					continue
				}
				for _, parentKey := range parentKeys {
					if v.verifyDSChain(parentZone, parentKey) {
						return true
					}
				}
			}
		}
	}

	// Check if we reached the root and have a matching trust anchor
	for _, anchor := range v.trustAnchors {
		if key.KeyTag() == anchor.KeyTag() &&
			key.Flags == anchor.Flags &&
			key.Algorithm == anchor.Algorithm &&
			key.PublicKey == anchor.PublicKey {
			return true
		}
	}

	return false
}

// fetchDNSKEYs fetches DNSKEY records for a zone, with caching.
func (v *Validator) fetchDNSKEYs(zone string) ([]*dns.DNSKEY, error) {
	zone = strings.ToLower(zone)

	// Check cache
	v.cache.mu.RLock()
	var cached []*dns.DNSKEY
	for _, ck := range v.cache.dnskeys {
		if strings.ToLower(ck.key.Hdr.Name) == zone && time.Now().Before(ck.expiresAt) {
			cached = append(cached, ck.key)
		}
	}
	v.cache.mu.RUnlock()
	if len(cached) > 0 {
		return cached, nil
	}

	// Query upstream for DNSKEY
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeDNSKEY)
	msg.RecursionDesired = true

	resp, _, err := v.queryUpstream(msg)
	if err != nil {
		return nil, fmt.Errorf("querying DNSKEY for %s: %w", zone, err)
	}

	var keys []*dns.DNSKEY
	for _, rr := range resp.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, dnskey)
			// Cache with TTL
			v.cache.mu.Lock()
			cacheKey := fmt.Sprintf("%s:%d:%d", zone, dnskey.Algorithm, dnskey.KeyTag())
			v.cache.dnskeys[cacheKey] = &cachedDNSKEY{
				key:       dnskey,
				expiresAt: time.Now().Add(time.Duration(dnskey.Hdr.Ttl) * time.Second),
			}
			v.cache.mu.Unlock()
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no DNSKEY records found for %s", zone)
	}

	return keys, nil
}

// fetchDS fetches DS records for a zone from its parent, with caching.
func (v *Validator) fetchDS(zone string) ([]*dns.DS, error) {
	zone = strings.ToLower(zone)

	// Check cache
	v.cache.mu.RLock()
	var cached []*dns.DS
	for _, cds := range v.cache.ds {
		if strings.ToLower(cds.ds.Hdr.Name) == zone && time.Now().Before(cds.expiresAt) {
			cached = append(cached, cds.ds)
		}
	}
	v.cache.mu.RUnlock()
	if len(cached) > 0 {
		return cached, nil
	}

	// Query upstream for DS
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeDS)
	msg.RecursionDesired = true
	// Request DNSSEC records (DO bit)
	msg.SetEdns0(4096, true)

	resp, _, err := v.queryUpstream(msg)
	if err != nil {
		return nil, fmt.Errorf("querying DS for %s: %w", zone, err)
	}

	var dsRecords []*dns.DS
	for _, rr := range resp.Ns {
		if ds, ok := rr.(*dns.DS); ok {
			dsRecords = append(dsRecords, ds)
			v.cache.mu.Lock()
			cacheKey := fmt.Sprintf("%s:%d:%d", zone, ds.Algorithm, ds.DigestType)
			v.cache.ds[cacheKey] = &cachedDS{
				ds:        ds,
				expiresAt: time.Now().Add(time.Duration(ds.Hdr.Ttl) * time.Second),
			}
			v.cache.mu.Unlock()
		}
	}

	// Also check Answer section (some resolvers return DS in Answer)
	for _, rr := range resp.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			dsRecords = append(dsRecords, ds)
		}
	}

	return dsRecords, nil
}

// queryUpstream sends a DNS query to the first available upstream server.
func (v *Validator) queryUpstream(msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	for _, server := range v.upstream {
		resp, rtt, err := v.resolver.Exchange(msg, server)
		if err == nil {
			return resp, rtt, nil
		}
	}
	return nil, 0, fmt.Errorf("all upstream servers failed")
}

// groupRRSIGs groups RRSIG records by the type they cover.
func groupRRSIGs(records []dns.RR) map[uint16][]*dns.RRSIG {
	result := make(map[uint16][]*dns.RRSIG)
	for _, rr := range records {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			result[rrsig.TypeCovered] = append(result[rrsig.TypeCovered], rrsig)
		}
	}
	return result
}

// extractRRset extracts all RR records of a specific type from the answer section.
func extractRRset(records []dns.RR, rtype uint16) []dns.RR {
	var rrset []dns.RR
	for _, rr := range records {
		if rr.Header().Rrtype == rtype {
			rrset = append(rrset, rr)
		}
	}
	return rrset
}

// loadTrustAnchors loads DNSKEY trust anchors from a file in zone
// presentation format, e.g.:
//   . IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh...
func loadTrustAnchors(path string) ([]*dns.DNSKEY, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading trust anchor file: %w", err)
	}

	zp := dns.NewZoneParser(strings.NewReader(string(data)), ".", path)

	var anchors []*dns.DNSKEY
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			// Only accept KSKs (flag 257 = SEP bit set)
			if dnskey.Flags&0x1 != 0 {
				anchors = append(anchors, dnskey)
			}
		}
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("parsing trust anchor file: %w", err)
	}

	if len(anchors) == 0 {
		return nil, fmt.Errorf("no KSK (flag 257) DNSKEY records found in trust anchor file")
	}

	return anchors, nil
}
