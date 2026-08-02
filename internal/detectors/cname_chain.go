package detectors

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// CNAMEChainValidator validates CNAME chains in DNS responses to detect:
//   - Dangling CNAMEs (CNAME pointing to non-existent domain)
//   - CNAME loops (A -> B -> A)
//   - Excessive chain depth (>10 hops, potential DoS amplification)
//   - Cross-bailiwick CNAMEs (legitimate domain CNAME'd to attacker domain)
//
// This addresses the gap where attackers register dangling CNAMEs at
// hosting providers or exploit ghost domain CNAME references.
type CNAMEChainValidator struct {
	maxChainDepth int
}

type CNAMEChainFinding struct {
	Type   string // "loop", "dangling", "excessive_depth", "cross_bailiwick"
	Detail string
	Chain  []string
}

func NewCNAMEChainValidator(maxDepth int) *CNAMEChainValidator {
	if maxDepth <= 0 {
		maxDepth = 10
	}
	return &CNAMEChainValidator{maxChainDepth: maxDepth}
}

// ValidateChain analyzes the CNAME chain in a DNS response.
// queryDomain is the originally queried domain.
// Returns a finding if something suspicious is detected, nil otherwise.
func (v *CNAMEChainValidator) ValidateChain(resp *dns.Msg, queryDomain string) *CNAMEChainFinding {
	if resp == nil {
		return nil
	}
	queryDomain = strings.TrimSuffix(queryDomain, ".")

	// Extract CNAME chain from answer section
	chain := v.extractCNAMEChain(resp.Answer, queryDomain)
	if len(chain) == 0 {
		return nil
	}

	// 1. Check for CNAME loops (check before dangling)
	if loop := v.detectLoop(resp.Answer, queryDomain); loop != nil {
		return loop
	}

	// 2. Check for excessive chain depth
	if len(chain) > v.maxChainDepth {
		return &CNAMEChainFinding{
			Type:   "excessive_depth",
			Detail: fmt.Sprintf("CNAME chain depth %d exceeds max %d (potential DoS amplification)", len(chain), v.maxChainDepth),
			Chain:  chain,
		}
	}

	// 3. Check for dangling CNAME (chain ends without a terminal A/AAAA record)
	if v.isDangling(resp, chain) {
		return &CNAMEChainFinding{
			Type:   "dangling",
			Detail: fmt.Sprintf("Dangling CNAME: %s -> %s (no terminal A/AAAA record)", chain[0], chain[len(chain)-1]),
			Chain:  chain,
		}
	}

	// 4. Check for cross-bailiwick CNAME (CNAME to a different domain hierarchy)
	if finding := v.checkCrossBailiwick(chain, queryDomain); finding != nil {
		return finding
	}

	return nil
}

// extractCNAMEChain builds the CNAME chain starting from queryDomain.
func (v *CNAMEChainValidator) extractCNAMEChain(answers []dns.RR, queryDomain string) []string {
	cnameMap := make(map[string]string)
	for _, rr := range answers {
		if cname, ok := rr.(*dns.CNAME); ok {
			cnameMap[strings.TrimSuffix(cname.Header().Name, ".")] = strings.TrimSuffix(cname.Target, ".")
		}
	}

	var chain []string
	current := queryDomain
	visited := make(map[string]bool)

	for {
		if visited[current] {
			break // loop detected, handled separately
		}
		visited[current] = true

		target, exists := cnameMap[current]
		if !exists {
			break
		}
		chain = append(chain, target)
		current = target
	}

	return chain
}

// detectLoop checks if following CNAME records from queryDomain creates a cycle.
func (v *CNAMEChainValidator) detectLoop(answers []dns.RR, queryDomain string) *CNAMEChainFinding {
	cnameMap := make(map[string]string)
	for _, rr := range answers {
		if cname, ok := rr.(*dns.CNAME); ok {
			cnameMap[strings.TrimSuffix(cname.Header().Name, ".")] = strings.TrimSuffix(cname.Target, ".")
		}
	}

	var chain []string
	visited := make(map[string]bool)
	current := queryDomain
	for {
		if visited[current] {
			// Found a loop — build the loop portion
			loopStart := -1
			for i, d := range chain {
				if d == current {
					loopStart = i
					break
				}
			}
			if loopStart >= 0 {
				loop := append(chain[loopStart:], current)
				return &CNAMEChainFinding{
					Type:   "loop",
					Detail: fmt.Sprintf("CNAME loop detected: %s", strings.Join(loop, " -> ")),
					Chain:  loop,
				}
			}
			return &CNAMEChainFinding{
				Type:   "loop",
				Detail: fmt.Sprintf("CNAME loop detected at %s", current),
				Chain:  append(chain, current),
			}
		}
		visited[current] = true

		target, exists := cnameMap[current]
		if !exists {
			break
		}
		chain = append(chain, target)
		current = target
	}
	return nil
}

// isDangling checks if the CNAME chain ends without a terminal A/AAAA record.
func (v *CNAMEChainValidator) isDangling(resp *dns.Msg, chain []string) bool {
	if len(chain) == 0 {
		return false
	}

	// If response is NXDOMAIN, the chain is dangling
	if resp.Rcode == dns.RcodeNameError {
		return true
	}

	// Check if the final CNAME target has an A/AAAA record in the answer
	finalTarget := chain[len(chain)-1]
	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.A:
			if strings.TrimSuffix(rr.Header().Name, ".") == finalTarget {
				return false
			}
		case *dns.AAAA:
			if strings.TrimSuffix(rr.Header().Name, ".") == finalTarget {
				return false
			}
		}
	}

	// No terminal record found — could be a CNAME to another domain
	// that needs a separate query. Only flag as dangling if response
	// has no A/AAAA records at all.
	hasAddressRecord := false
	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			hasAddressRecord = true
		}
	}

	return !hasAddressRecord && resp.Rcode == dns.RcodeSuccess
}

// checkCrossBailiwick detects when a CNAME chain crosses from one domain
// hierarchy to an unrelated one (potential CNAME hijacking).
func (v *CNAMEChainValidator) checkCrossBailiwick(chain []string, queryDomain string) *CNAMEChainFinding {
	if len(chain) < 2 {
		return nil
	}

	queryApex := ExtractApexDomain(queryDomain)

	// Check if any CNAME target has a different apex domain
	for _, target := range chain {
		targetApex := ExtractApexDomain(target)
		if targetApex != queryApex {
			// Cross-bailiwick CNAME — could be legitimate (e.g., CDN CNAMEs)
			// but flag if it's to a suspicious TLD or known bad pattern
			if isSuspiciousCNAMETarget(target) {
				return &CNAMEChainFinding{
					Type:   "cross_bailiwick",
					Detail: fmt.Sprintf("Cross-bailiwick CNAME: %s -> %s (different apex %s)", queryDomain, target, targetApex),
					Chain:  chain,
				}
			}
		}
	}

	return nil
}

// isSuspiciousCNAMETarget checks if a CNAME target looks suspicious.
func isSuspiciousCNAMETarget(target string) bool {
	labels := strings.Split(target, ".")
	if len(labels) < 2 {
		return false
	}
	tld := strings.ToLower("." + labels[len(labels)-1])
	if suspiciousTLDs[tld] {
		return true
	}
	// Check for very long random-looking CNAME targets
	apex := labels[0]
	if len(apex) > 20 {
		ent := shannonEntropy(strings.ReplaceAll(apex, "-", ""))
		if ent > 3.5 {
			return true
		}
	}
	return false
}
