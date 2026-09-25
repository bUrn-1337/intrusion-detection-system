// Package upper implements Module 3: transport layer parsing.
//
// Parse runs after lower.Parse and decodes the TCP, UDP, ICMP or ICMPv6
// header that starts at L4Offset, filling the Module 3 fields of a
// packet.ParsedPacket. All decoding is done by hand from RawData with
// encoding/binary. Parse is stateless: it looks at one packet at a time and
// keeps nothing between calls.
//
// Bounds: Parse reads only RawData[L4Offset:IPEnd()]. Ethernet padding and
// anything else after the IP packet is never treated as a header or payload.
//
// Error handling: Parse never panics. Every problem is recorded with AddError,
// prefixed with the layer name ("tcp:", "udp:", "icmp:", "icmpv6:"), and the
// fields decoded before the problem are kept. A packet without a transport
// header (L4Offset == -1: non-first fragments, ESP, No Next Header) gets
// L4Proto and nothing else, without an error.
//
// Checksums: see packet.ParsedPacket.L4ChecksumStatus for when a checksum is
// verified. An invalid checksum only sets the status; it is not a parse
// error.
//
// Checksum offloading: packets captured on the host that sent them often
// carry a checksum the NIC has not filled in yet, because the NIC computes
// it after the packet was handed to the capture tap. Such packets show up as
// L4ChecksumInvalid even though they leave the host correct. The rule engine
// must not treat Invalid as an attack by itself when the source address is
// local. Parse does not try to detect offloading.
//
// Known limitation: with an IPv6 Routing header that still has segments left,
// the pseudo-header should use the final destination from the Routing header,
// not IPDst. Parse always uses IPDst, so such packets may show Invalid.
package upper

import (
	"encoding/binary"
	"fmt"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// IP protocol numbers.
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

const (
	tcpMinHeaderLen = 20
	udpHeaderLen    = 8
	icmpHeaderLen   = 4

	// groThreshold is the largest IPTotalLen treated as a single on-wire
	// packet. Anything larger is assumed to be a GRO/TSO merge (or a BIG
	// TCP / jumbogram packet, which is larger still) whose transport
	// checksum does not cover the merged bytes, so it is left unchecked.
	// On a jumbo-frame network this also skips real large packets, which
	// only costs a verification, never a false Invalid.
	groThreshold = 1500

	// maxTCPOptions caps the option walk. Every step advances at least one
	// byte through at most 40 bytes of options, so this is only a safety
	// net against future edits.
	maxTCPOptions = 40
)

// Parse fills the Module 3 fields of p. It expects p to have been through
// lower.Parse. It never panics, never modifies RawData, and records every
// problem with p.AddError. A nil p, or one without an IP header
// (IPVersion == 0), is left unchanged.
func Parse(p *packet.ParsedPacket) {
	if p == nil || p.IPVersion == 0 {
		return
	}
	switch p.IPProto {
	case protoTCP:
		p.L4Proto = packet.L4TCP
	case protoUDP:
		p.L4Proto = packet.L4UDP
	case protoICMP, protoICMPv6:
		p.L4Proto = packet.L4ICMP
	default:
		p.L4Proto = packet.L4Other
		return
	}
	if p.L4Offset < 0 {
		return // no transport header in this packet
	}

	end := p.IPEnd()
	if p.L4Offset > end {
		// Module 2 never produces this, but a hand-built packet might.
		p.AddError(fmt.Sprintf("%s: transport offset %d is past the end of the IP packet (%d)", layerName(p), p.L4Offset, end))
		return
	}
	seg := p.RawData[p.L4Offset:end]

	switch p.IPProto {
	case protoTCP:
		parseTCP(p, seg)
	case protoUDP:
		parseUDP(p, seg)
	default:
		parseICMP(p, seg)
	}
}

func parseTCP(p *packet.ParsedPacket, seg []byte) {
	if len(seg) < tcpMinHeaderLen {
		p.AddError(fmt.Sprintf("tcp: truncated header: %d bytes available, need %d%s", len(seg), tcpMinHeaderLen, truncNote(p)))
		return
	}
	p.SrcPort = binary.BigEndian.Uint16(seg[0:])
	p.DstPort = binary.BigEndian.Uint16(seg[2:])
	p.TCPSeq = binary.BigEndian.Uint32(seg[4:])
	p.TCPAck = binary.BigEndian.Uint32(seg[8:])
	flags := seg[13]
	p.TCPFlags = packet.TCPFlags{
		FIN: flags&0x01 != 0,
		SYN: flags&0x02 != 0,
		RST: flags&0x04 != 0,
		PSH: flags&0x08 != 0,
		ACK: flags&0x10 != 0,
		URG: flags&0x20 != 0,
	}
	p.TCPWindow = binary.BigEndian.Uint16(seg[14:])

	dataOffset := int(seg[12] >> 4)
	hdrLen := dataOffset * 4
	if dataOffset < 5 {
		p.AddError(fmt.Sprintf("tcp: data offset %d is below the minimum 5", dataOffset))
		return
	}
	if hdrLen > len(seg) {
		p.AddError(fmt.Sprintf("tcp: header runs past end of packet: %d bytes, %d available%s", hdrLen, len(seg), truncNote(p)))
		return
	}
	walkTCPOptions(p, seg[tcpMinHeaderLen:hdrLen])
	p.PayloadOffset = p.L4Offset + hdrLen
	p.L4ChecksumStatus = checksumStatus(p, protoTCP, seg, true)
}

// walkTCPOptions checks the option list for structural errors. Option
// values are not stored.
func walkTCPOptions(p *packet.ParsedPacket, opts []byte) {
	i := 0
	for n := 0; i < len(opts) && n < maxTCPOptions; n++ {
		kind := opts[i]
		switch kind {
		case 0: // End of Option List
			return
		case 1: // No-Operation
			i++
			continue
		}
		if i+1 >= len(opts) {
			p.AddError(fmt.Sprintf("tcp: option kind %d at offset %d has no length byte", kind, i))
			return
		}
		optLen := int(opts[i+1])
		if optLen < 2 {
			p.AddError(fmt.Sprintf("tcp: option kind %d has invalid length %d", kind, optLen))
			return
		}
		if i+optLen > len(opts) {
			p.AddError(fmt.Sprintf("tcp: option kind %d length %d runs past end of header", kind, optLen))
			return
		}
		i += optLen
	}
}

func parseUDP(p *packet.ParsedPacket, seg []byte) {
	if len(seg) < udpHeaderLen {
		p.AddError(fmt.Sprintf("udp: truncated header: %d bytes available, need %d%s", len(seg), udpHeaderLen, truncNote(p)))
		return
	}
	p.SrcPort = binary.BigEndian.Uint16(seg[0:])
	p.DstPort = binary.BigEndian.Uint16(seg[2:])
	p.UDPLen = binary.BigEndian.Uint16(seg[4:])
	csum := binary.BigEndian.Uint16(seg[6:])

	// Compare the length with the IP packet as declared, not as captured:
	// a snaplen-truncated capture is not a malformed datagram.
	ulen := int64(p.UDPLen)
	avail := declaredEnd(p) - int64(p.L4Offset)
	switch {
	case ulen == 0 && avail > 0xFFFF:
		// Jumbogram (RFC 2675) or UDP GRO packet over 64 KiB: the length
		// does not fit in 16 bits, so it is 0 and the IP length rules.
		// These are always over groThreshold, so the checksum stays
		// unchecked.
		p.PayloadOffset = p.L4Offset + udpHeaderLen
		return
	case ulen < udpHeaderLen:
		p.AddError(fmt.Sprintf("udp: length %d is less than the %d-byte header", ulen, udpHeaderLen))
		return
	case ulen > avail:
		p.AddError(fmt.Sprintf("udp: length %d runs past end of IP packet: %d bytes available", ulen, avail))
		return
	case ulen < avail:
		p.AddError(fmt.Sprintf("udp: %d bytes of trailing data after the datagram", avail-ulen))
	}
	p.PayloadOffset = p.L4Offset + udpHeaderLen

	if csum == 0 {
		// IPv4: 0 means the sender did not compute a checksum. IPv6: the
		// checksum is mandatory (RFC 8200 section 8.1), so 0 is an error.
		if p.IPVersion == 6 {
			p.AddError("udp: zero checksum is not allowed over IPv6")
			p.L4ChecksumStatus = packet.L4ChecksumInvalid
		}
		return
	}
	if ulen <= int64(len(seg)) {
		// The checksum covers the datagram, not trailing IP data.
		p.L4ChecksumStatus = checksumStatus(p, protoUDP, seg[:ulen], true)
	}
}

func parseICMP(p *packet.ParsedPacket, seg []byte) {
	name := layerName(p)
	if len(seg) < icmpHeaderLen {
		p.AddError(fmt.Sprintf("%s: truncated header: %d bytes available, need %d%s", name, len(seg), icmpHeaderLen, truncNote(p)))
		return
	}
	p.ICMPType = seg[0]
	p.ICMPCode = seg[1]
	p.PayloadOffset = p.L4Offset + icmpHeaderLen

	isV6 := p.IPProto == protoICMPv6
	if isV6 != (p.IPVersion == 6) {
		p.AddError(fmt.Sprintf("%s: protocol %d carried over IPv%d", name, p.IPProto, p.IPVersion))
		return
	}
	// ICMPv6 includes the IPv6 pseudo-header; ICMPv4 covers the message only.
	p.L4ChecksumStatus = checksumStatus(p, protoICMPv6, seg, isV6)
}

// layerName returns the error prefix for p's transport protocol.
func layerName(p *packet.ParsedPacket) string {
	switch p.IPProto {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	case protoICMPv6:
		return "icmpv6"
	default:
		return "icmp"
	}
}

// declaredEnd is where the IP header says the packet ends, which can be past
// the captured data.
func declaredEnd(p *packet.ParsedPacket) int64 {
	return int64(p.L3Offset) + int64(p.IPTotalLen)
}

// captureTruncated reports whether the IP packet was cut short by snaplen.
func captureTruncated(p *packet.ParsedPacket) bool {
	return int64(p.IPEnd()) < declaredEnd(p)
}

func truncNote(p *packet.ParsedPacket) string {
	if captureTruncated(p) {
		return " (capture truncated)"
	}
	return ""
}

// checksumStatus verifies the checksum over data (the transport header and
// payload, with the checksum field in place), adding the IP pseudo-header
// for proto when pseudo is true. It returns Unchecked for packets whose
// checksum cannot be verified from this frame; see
// packet.ParsedPacket.L4ChecksumStatus.
func checksumStatus(p *packet.ParsedPacket, proto uint8, data []byte, pseudo bool) uint8 {
	if p.IPFragmented || p.IPTotalLen > groThreshold || captureTruncated(p) {
		return packet.L4ChecksumUnchecked
	}
	sum := sumWords(0, data)
	if pseudo {
		var ok bool
		if sum, ok = addPseudoHeader(p, sum, proto, len(data)); !ok {
			return packet.L4ChecksumUnchecked
		}
	}
	if fold(sum) == 0xFFFF {
		return packet.L4ChecksumValid
	}
	return packet.L4ChecksumInvalid
}

// addPseudoHeader adds the IPv4 or IPv6 pseudo-header to sum. length is the
// upper-layer length: the transport header plus payload, not the IP length
// and, for IPv6, not including extension headers. proto is the transport
// protocol, not the IPv6 header's Next Header field, which names the first
// extension header when there is one.
func addPseudoHeader(p *packet.ParsedPacket, sum uint64, proto uint8, length int) (uint64, bool) {
	switch {
	case p.IPVersion == 4 && len(p.IPSrc) == 4 && len(p.IPDst) == 4:
		// src(4) dst(4) zero(1) proto(1) length(2)
		sum = sumWords(sum, p.IPSrc)
		sum = sumWords(sum, p.IPDst)
		return sum + uint64(proto) + uint64(length&0xFFFF), true
	case p.IPVersion == 6 && len(p.IPSrc) == 16 && len(p.IPDst) == 16:
		// src(16) dst(16) length(4) zero(3) next header(1)
		sum = sumWords(sum, p.IPSrc)
		sum = sumWords(sum, p.IPDst)
		l := uint32(length)
		return sum + uint64(l>>16) + uint64(l&0xFFFF) + uint64(proto), true
	}
	return sum, false
}

// sumWords adds b to sum as big-endian 16-bit words, padding an odd last
// byte with zero (RFC 1071).
func sumWords(sum uint64, b []byte) uint64 {
	n := len(b) &^ 1
	for i := 0; i < n; i += 2 {
		sum += uint64(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b) != n {
		sum += uint64(b[n]) << 8
	}
	return sum
}

// fold reduces sum to a 16-bit one's-complement sum. A correct checksum
// makes the sum over the covered bytes 0xFFFF.
func fold(sum uint64) uint16 {
	for sum > 0xFFFF {
		sum = sum>>16 + sum&0xFFFF
	}
	return uint16(sum)
}
