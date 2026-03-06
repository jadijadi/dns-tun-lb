package main

import (
	"github.com/miekg/dns"
)

// extractSlipstreamSessionID returns an 8-byte connection ID from the QUIC payload in the QNAME for consistent hashing.
// Wire format follows RFC 9000 and slipstream-rust (picoquic; client SCID length 8 bytes per slipstream_stateless_packet.c).
// Long header (byte 0 & 0x80): byte 5 = DCID length, byte 6+dcidLen = SCID length, SCID at 7+dcidLen. Use SCID for client→server.
// Short header: DCID at [1:9]; slipstream uses fixed 8-byte DCID. Returns (nil, false) if too short or invalid.
func extractSlipstreamSessionID(msg *dns.Msg, suffix string) ([]byte, bool) {
	payload, ok := decodeQnamePrefixPayload(msg, suffix)
	if !ok || len(payload) < 7 {
		return nil, false
	}

	id := make([]byte, 8)
	if payload[0]&0x80 != 0 {
		// Long header: DCID length at 5, SCID length at 6+dcidLen, SCID starts at 7+dcidLen
		dcidLen := int(payload[5])
		if 6+dcidLen+1 > len(payload) {
			return nil, false
		}
		scidLen := int(payload[6+dcidLen])
		if 7+dcidLen+scidLen > len(payload) {
			return nil, false
		}
		scid := payload[7+dcidLen : 7+dcidLen+scidLen]
		copy(id, scid)
		return id, true
	}
	// Short header: DCID at [1:9] (slipstream uses 8-byte DCID)
	if len(payload) < 9 {
		return nil, false
	}
	copy(id, payload[1:9])
	return id, true
}
