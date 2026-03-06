package main

import (
	"github.com/miekg/dns"
)

// extractDNSTTSessionID returns the 8-byte ClientID from the QNAME prefix for consistent hashing.
// Returns (nil, false) if the prefix is empty, not valid base32, or decodes to fewer than 8 bytes.
func extractDNSTTSessionID(msg *dns.Msg, suffix string) ([]byte, bool) {
	buf, ok := decodeQnamePrefixPayload(msg, suffix)
	if !ok || len(buf) < 8 {
		return nil, false
	}
	id := make([]byte, 8)
	copy(id, buf[:8])
	return id, true
}

