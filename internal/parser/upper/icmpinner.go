package upper

import (
	"encoding/binary"
	"net"
)

// ICMPInner is the start of the packet quoted by an ICMP error message:
// the packet that caused the error, as its sender sent it. For a port
// unreachable, Src is the host that sent the probe and Dst:DstPort is the
// closed port.
type ICMPInner struct {
	Src, Dst net.IP // copies: 4 bytes for IPv4, 16 for IPv6
	// Proto is the quoted IPv4 protocol, or for IPv6 the Next Header after
	// any extension headers.
	Proto uint8
	// SrcPort and DstPort are the quoted TCP or UDP ports. They are only
	// set when HasPorts is true.
	SrcPort, DstPort uint16
	// HasPorts is true when Proto is TCP or UDP, the quoted packet is not a
	// non-first fragment, and at least the 4 port bytes were quoted.
	HasPorts bool
}

// Error message types that quote the invoking packet after an 8-byte
// ICMP header (RFC 792, RFC 4443).
var (
	icmpv4ErrorTypes = [256]bool{3: true, 4: true, 5: true, 11: true, 12: true}
	icmpv6ErrorTypes = [256]bool{1: true, 2: true, 3: true, 4: true}
)

// maxInnerExtHeaders caps the IPv6 extension header walk in a quote.
const maxInnerExtHeaders = 8

// ParseICMPInner decodes the packet quoted by an ICMP (v6 false) or
// ICMPv6 (v6 true) error message. msg is the whole ICMP message, starting
// at its type byte. It reads only msg and never panics.
//
// It returns false when msg is not an error message (Destination
// Unreachable, Source Quench, Redirect, Time Exceeded, Parameter Problem;
// for ICMPv6 Destination Unreachable, Packet Too Big, Time Exceeded,
// Parameter Problem), or when the quoted IP header is truncated, has the
// wrong IP version for the ICMP version, or has an IPv6 extension header
// chain that is truncated or longer than 8 headers. A quote that stops
// inside the transport header is still returned, without ports: RFC 792
// only requires 8 bytes of it, and some routers send fewer.
func ParseICMPInner(msg []byte, v6 bool) (ICMPInner, bool) {
	const hdr = 8 // type, code, checksum, 4 bytes unused / pointer / MTU / gateway
	if len(msg) < hdr {
		return ICMPInner{}, false
	}
	q := msg[hdr:]
	var in ICMPInner
	var l4 int     // offset of the transport header in q
	var first bool // not a non-first fragment
	if v6 {
		if !icmpv6ErrorTypes[msg[0]] || len(q) < 40 || q[0]>>4 != 6 {
			return ICMPInner{}, false
		}
		in.Src, in.Dst = cloneBytes(q[8:24]), cloneBytes(q[24:40])
		nh, off := q[6], 40
		first = true
		for range maxInnerExtHeaders {
			var n int
			switch nh {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(q) < off+2 {
					return ICMPInner{}, false
				}
				n = (int(q[off+1]) + 1) * 8
			case 44: // fragment
				if len(q) < off+8 {
					return ICMPInner{}, false
				}
				n = 8
				if binary.BigEndian.Uint16(q[off+2:])&0xfff8 != 0 {
					first = false
				}
			case 51: // authentication header
				if len(q) < off+2 {
					return ICMPInner{}, false
				}
				n = (int(q[off+1]) + 2) * 4
			default:
				in.Proto, l4 = nh, off
				return withPorts(in, q, l4, first), true
			}
			nh = q[off]
			off += n
		}
		return ICMPInner{}, false
	}

	if !icmpv4ErrorTypes[msg[0]] || len(q) < 20 || q[0]>>4 != 4 {
		return ICMPInner{}, false
	}
	ihl := int(q[0]&0x0f) * 4
	if ihl < 20 || len(q) < ihl {
		return ICMPInner{}, false
	}
	in.Src, in.Dst = cloneBytes(q[12:16]), cloneBytes(q[16:20])
	in.Proto, l4 = q[9], ihl
	first = binary.BigEndian.Uint16(q[6:])&0x1fff == 0
	return withPorts(in, q, l4, first), true
}

// withPorts sets the ports of in from the transport header at q[l4:].
func withPorts(in ICMPInner, q []byte, l4 int, first bool) ICMPInner {
	if first && (in.Proto == protoTCP || in.Proto == protoUDP) && l4 <= len(q)-4 {
		in.SrcPort = binary.BigEndian.Uint16(q[l4:])
		in.DstPort = binary.BigEndian.Uint16(q[l4+2:])
		in.HasPorts = true
	}
	return in
}

func cloneBytes(b []byte) net.IP { return append(net.IP(nil), b...) }
