package detectors

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// ResponseValidationError indicates a DNS response packet failed validation.
type ResponseValidationError struct {
	Field   string
	Detail  string
}

func (e ResponseValidationError) Error() string {
	return fmt.Sprintf("response validation error: %s — %s", e.Field, e.Detail)
}

// ValidateResponse performs strict validation of a DNS response packet
// to detect malformed packets that could exploit pre-processing logic
// vulnerabilities (TUDOOR-style attacks).
//
// Returns nil if the response is valid, or an error describing the issue.
func ValidateResponse(resp *dns.Msg, query *dns.Msg) error {
	if resp == nil {
		return ResponseValidationError{Field: "nil", Detail: "response is nil"}
	}

	// 1. Validate response ID matches query ID
	if query != nil && resp.Id != query.Id {
		return ResponseValidationError{
			Field:  "ID",
			Detail: fmt.Sprintf("response ID %d does not match query ID %d", resp.Id, query.Id),
		}
	}

	// 2. Validate question section matches query
	if query != nil && len(resp.Question) > 0 && len(query.Question) > 0 {
		rq := resp.Question[0]
		qq := query.Question[0]
		if rq.Name != qq.Name || rq.Qtype != qq.Qtype || rq.Qclass != qq.Qclass {
			return ResponseValidationError{
				Field:  "Question",
				Detail: fmt.Sprintf("response question does not match query question"),
			}
		}
	}

	// 3. Validate rcode is a known value
	if resp.Rcode < 0 || resp.Rcode > 22 {
		return ResponseValidationError{
			Field:  "Rcode",
			Detail: fmt.Sprintf("invalid rcode %d", resp.Rcode),
		}
	}

	// 4. Validate answer records pertain to the queried domain (bailiwick check)
	if query != nil && len(query.Question) > 0 {
		queryDomain := strings.TrimSuffix(query.Question[0].Name, ".")
		queryType := query.Question[0].Qtype

		// Track CNAME targets so we can allow records for domains in the chain
		cnameTargets := make(map[string]bool)
		cnameTargets[queryDomain] = true

		for _, rr := range resp.Answer {
			rrDomain := strings.TrimSuffix(rr.Header().Name, ".")

			// For NXDOMAIN responses, answer section should be empty or contain SOA
			if resp.Rcode == dns.RcodeNameError {
				if rr.Header().Rrtype != dns.TypeSOA {
					return ResponseValidationError{
						Field:  "Answer",
						Detail: fmt.Sprintf("NXDOMAIN response contains non-SOA record in answer section (type %s)", dns.TypeToString[rr.Header().Rrtype]),
					}
				}
			}

			// Track CNAME targets for bailiwick allowance
			if rr.Header().Rrtype == dns.TypeCNAME {
				if cname, ok := rr.(*dns.CNAME); ok {
					target := strings.TrimSuffix(cname.Target, ".")
					cnameTargets[target] = true
				}
			}

			// Check for out-of-bailiwick records that shouldn't be cached
			// Allow records for domains in the CNAME chain and SOA records
			if rr.Header().Rrtype != dns.TypeCNAME && rr.Header().Rrtype != dns.TypeSOA {
				if !cnameTargets[rrDomain] && !isSubdomainOf(rrDomain, queryDomain) {
					return ResponseValidationError{
						Field:  "Bailiwick",
						Detail: fmt.Sprintf("answer record for %s does not match queried domain %s (out-of-bailiwick)", rrDomain, queryDomain),
					}
				}
			}
		}

		// 5. Validate that response type makes sense for query type
		// (e.g., don't accept A records in response to MX query unless CNAME chain)
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			if err := validateAnswerTypes(resp.Answer, queryType, queryDomain); err != nil {
				return err
			}
		}
	}

	// 6. Validate EDNS0 options in response are known
	if opt := resp.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if !isKnownEDNSOption(o.Option()) {
				return ResponseValidationError{
					Field:  "EDNS0",
					Detail: fmt.Sprintf("unknown EDNS0 option code %d in response", o.Option()),
				}
			}
		}
	}

	return nil
}

// validateAnswerTypes checks that answer records are relevant to the query type.
func validateAnswerTypes(answers []dns.RR, queryType uint16, queryDomain string) error {
	hasCNAME := false
	for _, rr := range answers {
		rrType := rr.Header().Rrtype
		rrDomain := strings.TrimSuffix(rr.Header().Name, ".")

		if rrType == dns.TypeCNAME {
			hasCNAME = true
			continue
		}

		// If this is a CNAME target record, the domain will differ — that's OK
		if hasCNAME && rrDomain != queryDomain {
			continue
		}

		// For the queried domain, the record type should match the query type
		// (or be a type that commonly accompanies it)
		if rrDomain == queryDomain {
			if rrType != queryType {
				// Allow common companion types
				valid := false
				switch queryType {
				case dns.TypeA:
					valid = rrType == dns.TypeA || rrType == dns.TypeAAAA
				case dns.TypeAAAA:
					valid = rrType == dns.TypeAAAA || rrType == dns.TypeA
				case dns.TypeMX:
					valid = rrType == dns.TypeMX || rrType == dns.TypeA || rrType == dns.TypeAAAA
				case dns.TypeSRV:
					valid = rrType == dns.TypeSRV || rrType == dns.TypeA || rrType == dns.TypeAAAA
				case dns.TypeANY:
					valid = true // ANY accepts any type
				default:
					valid = rrType == queryType
				}
				if !valid {
					return ResponseValidationError{
						Field:  "AnswerType",
						Detail: fmt.Sprintf("answer type %s does not match query type %s for %s",
							dns.TypeToString[rrType], dns.TypeToString[queryType], queryDomain),
					}
				}
			}
		}
	}

	return nil
}

// isSubdomainOf checks if domain is a subdomain of parent.
func isSubdomainOf(domain, parent string) bool {
	domain = strings.TrimSuffix(domain, ".")
	parent = strings.TrimSuffix(parent, ".")
	if domain == parent {
		return true
	}
	return strings.HasSuffix(domain, "."+parent)
}
