package main

import (
	"encoding/base32"
	"strings"

	"github.com/miekg/dns"
)

// classifyDNSTT reports whether msg looks like a dnstt tunnel query for the given suffix.
func classifyDNSTT(msg *dns.Msg, suffix string) bool {
	if len(msg.Question) != 1 {
		return false
	}
	q := msg.Question[0]
	if q.Qtype != dns.TypeTXT || q.Qclass != dns.ClassINET {
		return false
	}
	if !strings.HasSuffix(strings.ToLower(q.Name), "."+strings.ToLower(suffix)+".") &&
		!strings.EqualFold(strings.TrimSuffix(q.Name, "."), suffix) {
		return false
	}

	var hasOpt bool
	for _, extra := range msg.Extra {
		if _, ok := extra.(*dns.OPT); ok {
			hasOpt = true
			// Be tolerant of resolvers rewriting UDPSize; only require EDNS presence.
			// Optionally, we could check opt.Version() == 0 here, but it's not necessary
			// for protocol correctness.
		}
	}
	if !hasOpt {
		return false
	}

	// Strong fingerprint: QNAME prefix must decode as a valid dnstt payload
	// with at least an 8-byte ClientID.
	if _, ok := extractDNSTTSessionID(msg, suffix); !ok {
		return false
	}
	return true
}

// extractDNSTTSessionID extracts the 8-byte ClientID used as session id.
// It assumes msg is already classified as dnstt and suffix matches.
func extractDNSTTSessionID(msg *dns.Msg, suffix string) ([]byte, bool) {
	if len(msg.Question) == 0 {
		return nil, false
	}
	q := msg.Question[0]
	name := strings.TrimSuffix(q.Name, ".")
	suffix = strings.ToLower(suffix)

	lowerName := strings.ToLower(name)
	var prefix string
	if strings.HasSuffix(lowerName, "."+suffix) {
		prefix = name[:len(name)-(len(suffix)+1)]
	} else if strings.EqualFold(lowerName, suffix) {
		prefix = ""
	} else {
		return nil, false
	}

	if prefix == "" {
		return nil, false
	}

	labels := strings.Split(prefix, ".")
	var sb strings.Builder
	for _, l := range labels {
		if l == "" {
			continue
		}
		sb.WriteString(l)
	}

	encoded := strings.ToLower(sb.String())
	if encoded == "" {
		return nil, false
	}

	dec := base32.StdEncoding.WithPadding(base32.NoPadding)
	buf, err := dec.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return nil, false
	}
	if len(buf) < 8 {
		return nil, false
	}
	id := make([]byte, 8)
	copy(id, buf[:8])
	return id, true
}

