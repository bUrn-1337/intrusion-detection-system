// Package lower implements Module 2: link and network layer parsing.
//
// Parse decodes the Ethernet header (skipping 802.1Q and 802.1ad VLAN tags),
// then IPv4, IPv6 (including its extension header chain) or ARP, and fills
// the Module 2 fields of a packet.ParsedPacket. All decoding is done by hand
// from RawData with encoding/binary.
//
// Error handling: Parse never panics and never stops without saying why.
// Every problem is recorded with AddError, prefixed with the layer name
// ("ethernet:", "vlan:", "ipv4:", "ipv6:", "arp:"). Fields decoded before the
// problem are kept. Normal stopping points are not errors: an 802.3/LLC frame,
// an EtherType other than IPv4/IPv6/ARP, IPv6 ESP, and IPv6 No Next Header.
//
// Aliasing: the MAC and IP address fields (EthSrc, EthDst, IPSrc, IPDst and
// the ARP addresses) are copies, not slices of RawData. The rule engine is
// expected to keep addresses in long-lived state (per-source counters, scan
// tracking), and an alias would pin the whole frame, up to the 256 KiB
// snaplen, for as long as the address is held. Six or sixteen bytes per
// address is cheaper. RawData itself is never modified.
//
// Values of EthType below 0x0600 are 802.3 length fields, not EtherTypes.
// Parse stores the value as-is, leaves L3Offset at -1 and IPVersion at 0.
package lower

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

const (
	ethHeaderLen = 14
	vlanTagLen   = 4
	// maxVLANTags caps how many VLAN tags Parse walks. Real networks use at
	// most two (QinQ); the cap stops crafted frames with endless tags.
	maxVLANTags = 4

	ethTypeVLAN = 0x8100 // 802.1Q
	ethTypeQinQ = 0x88A8 // 802.1ad
	// minEtherType is the smallest EtherType value. Anything below it is an
	// 802.3 length field.
	minEtherType = 0x0600

	ipv4MinHeaderLen = 20
	ipv6HeaderLen    = 40
	// maxIPv4Len and maxIPv6Len are the largest packets the 16-bit length
	// fields can describe (IPv6 counts the fixed header separately).
	maxIPv4Len = 0xFFFF
	maxIPv6Len = 0xFFFF + ipv6HeaderLen

	// maxIPv6ExtHeaders caps how many IPv6 extension headers Parse walks.
	// Long chains are an evasion technique (they push the transport header
	// past what some devices inspect); anything over the cap is reported.
	maxIPv6ExtHeaders = 10

	arpLen = 28
)

// IPv6 extension header and upper-layer Next Header values.
const (
	nhHopByHop = 0
	nhRouting  = 43
	nhFragment = 44
	nhESP      = 50
	nhAH       = 51
	nhNoNext   = 59
	nhDestOpts = 60
)

// Parse fills the Module 2 fields of p from p.RawData. It expects a packet
// fresh from Module 1 (offsets at -1, Module 2 fields zero). It never panics,
// never modifies RawData, and records every problem with p.AddError. A nil p
// is ignored.
func Parse(p *packet.ParsedPacket) {
	if p == nil {
		return
	}
	raw := p.RawData
	if len(raw) < ethHeaderLen {
		p.AddError(fmt.Sprintf("ethernet: frame too short: %d bytes, need %d", len(raw), ethHeaderLen))
		return
	}

	p.EthDst = cloneMAC(raw[0:6])
	p.EthSrc = cloneMAC(raw[6:12])

	// typeOff is the offset of the current EtherType/TPID field.
	typeOff := 12
	etherType := binary.BigEndian.Uint16(raw[typeOff:])
	for tags := 0; etherType == ethTypeVLAN || etherType == ethTypeQinQ; tags++ {
		if tags == maxVLANTags {
			p.EthType = etherType
			p.AddError(fmt.Sprintf("vlan: more than %d VLAN tags", maxVLANTags))
			return
		}
		// A tag is TPID (already read) + 2 bytes TCI + the next EtherType.
		next := typeOff + vlanTagLen
		if next+2 > len(raw) {
			p.EthType = etherType
			p.AddError(fmt.Sprintf("vlan: tag %d truncated at offset %d", tags+1, typeOff))
			return
		}
		typeOff = next
		etherType = binary.BigEndian.Uint16(raw[typeOff:])
	}
	p.EthType = etherType

	if etherType < minEtherType {
		// 802.3 length field (LLC/SNAP frame): not IP, not an error.
		return
	}
	p.L3Offset = typeOff + 2

	switch etherType {
	case packet.EthTypeIPv4:
		parseIPv4(p)
	case packet.EthTypeIPv6:
		parseIPv6(p)
	case packet.EthTypeARP:
		parseARP(p)
	}
}

func parseIPv4(p *packet.ParsedPacket) {
	raw, l3 := p.RawData, p.L3Offset
	avail := len(raw) - l3
	if avail < ipv4MinHeaderLen {
		p.AddError(fmt.Sprintf("ipv4: truncated header: %d bytes captured, need %d", avail, ipv4MinHeaderLen))
		return
	}
	h := raw[l3:]
	if v := h[0] >> 4; v != 4 {
		p.AddError(fmt.Sprintf("ipv4: version field is %d but EtherType is IPv4", v))
		return
	}

	p.IPVersion = 4
	ihl := int(h[0] & 0x0F)
	hdrLen := ihl * 4
	totalLen := int(binary.BigEndian.Uint16(h[2:]))
	flagsFrag := binary.BigEndian.Uint16(h[6:])
	p.IPID = uint32(binary.BigEndian.Uint16(h[4:]))
	p.MoreFragments = flagsFrag&0x2000 != 0
	// DF (0x4000) has no field in the contract, so it is not stored.
	p.FragOffset = (flagsFrag & 0x1FFF) * 8
	p.IPFragmented = p.MoreFragments || p.FragOffset > 0
	p.IPTTL = h[8]
	p.IPProto = h[9]
	p.IPSrc = cloneIP(h[12:16])
	p.IPDst = cloneIP(h[16:20])

	// Total length above 1500 is NOT malformed: GRO/TSO on the capture host
	// merges TCP segments into one large packet before libpcap sees it, so
	// captures routinely contain IPv4 packets up to 64 KiB.
	//
	// Linux BIG TCP goes further and builds GRO packets over 64 KiB, which
	// cannot fit the 16-bit field, so it writes 0 there. Treat 0 as "use the
	// wire length" when the frame really is that big; otherwise 0 falls
	// through to the malformed check below.
	if totalLen == 0 && int(p.WireLen)-l3 > maxIPv4Len {
		totalLen = int(p.WireLen) - l3
	}
	p.IPTotalLen = uint32(totalLen)

	if ihl < 5 {
		p.AddError(fmt.Sprintf("ipv4: header length %d bytes is below the minimum %d", hdrLen, ipv4MinHeaderLen))
		return
	}
	if hdrLen > avail {
		p.AddError(fmt.Sprintf("ipv4: header runs past captured data: %d bytes, %d captured", hdrLen, avail))
		return
	}
	p.IPChecksumValid = checksum(h[:hdrLen]) == 0

	if totalLen < hdrLen {
		p.AddError(fmt.Sprintf("ipv4: total length %d is less than header length %d", totalLen, hdrLen))
		return
	}
	if p.FragOffset > 0 {
		return // non-first fragment: no transport header
	}
	p.L4Offset = l3 + hdrLen
}

func parseIPv6(p *packet.ParsedPacket) {
	raw, l3 := p.RawData, p.L3Offset
	avail := len(raw) - l3
	if avail < ipv6HeaderLen {
		p.AddError(fmt.Sprintf("ipv6: truncated header: %d bytes captured, need %d", avail, ipv6HeaderLen))
		return
	}
	h := raw[l3:]
	if v := h[0] >> 4; v != 6 {
		p.AddError(fmt.Sprintf("ipv6: version field is %d but EtherType is IPv6", v))
		return
	}

	// Traffic class and flow label have no fields in the contract.
	p.IPVersion = 6
	p.IPChecksumValid = true // IPv6 has no header checksum
	payloadLen := int(binary.BigEndian.Uint16(h[4:]))
	nextHeader := h[6]
	p.IPTTL = h[7]
	p.IPSrc = cloneIP(h[8:24])
	p.IPDst = cloneIP(h[24:40])

	// As for IPv4, lengths above 1500 are normal (GRO/TSO) and not flagged.
	// Payload length 0 on a frame too big for the field is a jumbogram or a
	// Linux BIG TCP GRO packet; use the wire length.
	totalLen := payloadLen + ipv6HeaderLen
	if payloadLen == 0 && int(p.WireLen)-l3 > maxIPv6Len {
		totalLen = int(p.WireLen) - l3
	}
	p.IPTotalLen = uint32(totalLen)

	// Walk the extension header chain inside the IP packet, never into
	// Ethernet padding.
	end := p.IPEnd()
	off := l3 + ipv6HeaderLen
	for n := 0; ; n++ {
		p.IPProto = nextHeader

		switch nextHeader {
		case nhHopByHop, nhRouting, nhDestOpts, nhAH, nhFragment:
			// Extension header; walked below.
		case nhESP, nhNoNext:
			// ESP: everything after is encrypted. No Next Header: nothing
			// follows. Either way there is no transport header to find.
			return
		default:
			// Upper-layer protocol: the chain ends here.
			if p.FragOffset == 0 {
				p.L4Offset = off
			}
			return
		}

		if n == maxIPv6ExtHeaders {
			p.AddError(fmt.Sprintf("ipv6: more than %d extension headers", maxIPv6ExtHeaders))
			return
		}
		if off+2 > end {
			p.AddError(fmt.Sprintf("ipv6: extension header %d (type %d) truncated at offset %d", n+1, nextHeader, off))
			return
		}
		var extLen int
		switch nextHeader {
		case nhFragment:
			extLen = 8
		case nhAH:
			// AH's length field counts 4-byte units minus 2 (RFC 4302),
			// unlike the other headers' 8-byte units minus 1.
			extLen = (int(raw[off+1]) + 2) * 4
		default:
			extLen = (int(raw[off+1]) + 1) * 8
		}
		if off+extLen > end {
			p.AddError(fmt.Sprintf("ipv6: extension header %d (type %d) runs past end of packet: %d bytes at offset %d", n+1, nextHeader, extLen, off))
			return
		}
		if nextHeader == nhHopByHop && n != 0 {
			p.AddError("ipv6: hop-by-hop header is not first in the chain")
		}

		if nextHeader == nhFragment {
			fragField := binary.BigEndian.Uint16(raw[off+2:])
			p.FragOffset = fragField &^ 0x7 // 13-bit offset in 8-byte units, already x8
			p.MoreFragments = fragField&0x1 != 0
			p.IPFragmented = p.MoreFragments || p.FragOffset > 0
			p.IPID = binary.BigEndian.Uint32(raw[off+4:])
			if p.FragOffset > 0 {
				// The rest is fragment data, not more headers.
				p.IPProto = raw[off]
				return
			}
		}

		nextHeader = raw[off]
		off += extLen
	}
}

func parseARP(p *packet.ParsedPacket) {
	raw, l3 := p.RawData, p.L3Offset
	avail := len(raw) - l3
	if avail < 8 {
		p.AddError(fmt.Sprintf("arp: truncated header: %d bytes captured, need 8", avail))
		return
	}
	a := raw[l3:]
	htype := binary.BigEndian.Uint16(a[0:])
	ptype := binary.BigEndian.Uint16(a[2:])
	hlen, plen := a[4], a[5]
	if htype != 1 || ptype != packet.EthTypeIPv4 || hlen != 6 || plen != 4 {
		p.AddError(fmt.Sprintf("arp: unsupported hardware/protocol: htype=%d ptype=0x%04x hlen=%d plen=%d, only Ethernet/IPv4 is decoded", htype, ptype, hlen, plen))
		return
	}
	if avail < arpLen {
		p.AddError(fmt.Sprintf("arp: truncated: %d bytes captured, need %d", avail, arpLen))
		return
	}

	p.ARPOp = binary.BigEndian.Uint16(a[6:])
	p.ARPSenderMAC = cloneMAC(a[8:14])
	p.ARPSenderIP = cloneIP(a[14:18])
	p.ARPTargetMAC = cloneMAC(a[18:24])
	p.ARPTargetIP = cloneIP(a[24:28])
	if p.ARPOp != packet.ARPRequest && p.ARPOp != packet.ARPReply {
		p.AddError(fmt.Sprintf("arp: unexpected opcode %d", p.ARPOp))
	}
}

// checksum returns the Internet checksum (RFC 1071) of b, which must have
// even length. Over a header that includes its own correct checksum field,
// the result is 0.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum > 0xFFFF {
		sum = sum>>16 + sum&0xFFFF
	}
	return ^uint16(sum)
}

func cloneMAC(b []byte) net.HardwareAddr { return net.HardwareAddr(append([]byte(nil), b...)) }

func cloneIP(b []byte) net.IP { return net.IP(append([]byte(nil), b...)) }
