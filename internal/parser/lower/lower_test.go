package lower_test

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
)

// ---- frame builders ----

var (
	macA = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a} // source
	macB = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b} // destination
	ip4A = []byte{10, 0, 0, 1}
	ip4B = []byte{10, 0, 0, 2}
	ip6A = []byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}
	ip6B = []byte{0x20, 0x01, 0x0d, 0xb8, 15: 2}
)

const (
	macAStr = "02:00:00:00:00:0a"
	macBStr = "02:00:00:00:00:0b"
)

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ethHdr returns an Ethernet header macA -> macB with the given EtherType.
func ethHdr(etherType uint16) []byte { return cat(macB, macA, u16(etherType)) }

// tcpHdr returns a minimal 20-byte TCP SYN header, 1234 -> 80.
func tcpHdr() []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], 1234)
	binary.BigEndian.PutUint16(h[2:], 80)
	h[12] = 5 << 4
	h[13] = 0x02
	return h
}

// udpHdr returns an 8-byte UDP header 5353 -> 53 followed by data.
func udpHdr(data []byte) []byte {
	return cat(u16(5353), u16(53), u16(uint16(8+len(data))), u16(0), data)
}

// ip4 returns an IPv4 header (plus opts) and payload, ID 0x1234, TTL 64,
// 10.0.0.1 -> 10.0.0.2. mut, if non-nil, edits the header before the
// checksum is computed.
func ip4(proto uint8, opts, payload []byte, mut func(h []byte)) []byte {
	hl := 20 + len(opts)
	h := make([]byte, hl)
	h[0] = 0x40 | byte(hl/4)
	binary.BigEndian.PutUint16(h[2:], uint16(hl+len(payload)))
	binary.BigEndian.PutUint16(h[4:], 0x1234)
	h[8] = 64
	h[9] = proto
	copy(h[12:], ip4A)
	copy(h[16:], ip4B)
	copy(h[20:], opts)
	if mut != nil {
		mut(h)
	}
	binary.BigEndian.PutUint16(h[10:], inetChecksum(h))
	return cat(h, payload)
}

func inetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum > 0xFFFF {
		sum = sum>>16 + sum&0xFFFF
	}
	return ^uint16(sum)
}

func setTotalLen(n uint16) func([]byte) {
	return func(h []byte) { binary.BigEndian.PutUint16(h[2:], n) }
}

func setFrag(offsetBytes uint16, mf bool) func([]byte) {
	return func(h []byte) {
		v := offsetBytes / 8
		if mf {
			v |= 0x2000
		}
		binary.BigEndian.PutUint16(h[6:], v)
	}
}

// ip6 returns an IPv6 header with next header nh, hop limit 64,
// 2001:db8::1 -> 2001:db8::2, followed by rest (extension headers and
// payload), which the payload length covers.
func ip6(nh uint8, rest []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(rest)))
	h[6] = nh
	h[7] = 64
	copy(h[8:], ip6A)
	copy(h[24:], ip6B)
	return cat(h, rest)
}

// optsExt returns an 8-byte Hop-by-Hop / Destination Options / Routing
// header with one PadN option.
func optsExt(next uint8) []byte { return []byte{next, 0, 1, 4, 0, 0, 0, 0} }

// fragExt returns an IPv6 Fragment header.
func fragExt(next uint8, offsetBytes uint16, m bool, id uint32) []byte {
	v := offsetBytes &^ 7
	if m {
		v |= 1
	}
	return cat([]byte{next, 0}, u16(v), u32(id))
}

// ahExt returns an Authentication Header with payload length field plen,
// so its real size is (plen+2)*4 bytes.
func ahExt(next, plen uint8) []byte {
	h := make([]byte, (int(plen)+2)*4)
	h[0], h[1] = next, plen
	return h
}

func arp(htype uint16, op uint16) []byte {
	return cat(u16(htype), u16(0x0800), []byte{6, 4}, u16(op),
		macA, ip4A, make([]byte, 6), ip4B)
}

func pad60(b []byte) []byte {
	if len(b) >= 60 {
		return b
	}
	return cat(b, make([]byte, 60-len(b)))
}

// ---- expected results ----

// summary is the comparable subset of the Module 2 fields.
type summary struct {
	EthDst, EthSrc string
	EthType        uint16
	L3, L4, IPEnd  int
	Ver            uint8
	Src, Dst       string
	TTL, Proto     uint8
	TotalLen       uint32
	CsumOK         bool
	ID             uint32
	FragOff        uint16
	MF, Frag       bool
	ARPOp          uint16
	ARPSMAC        string
	ARPSIP         string
	ARPTMAC        string
	ARPTIP         string
}

func ipStr(ip []byte) string {
	if ip == nil {
		return ""
	}
	return net.IP(ip).String()
}

func summarize(p *packet.ParsedPacket) summary {
	return summary{
		EthDst: p.EthDst.String(), EthSrc: p.EthSrc.String(), EthType: p.EthType,
		L3: p.L3Offset, L4: p.L4Offset, IPEnd: p.IPEnd(),
		Ver: p.IPVersion, Src: ipStr(p.IPSrc), Dst: ipStr(p.IPDst),
		TTL: p.IPTTL, Proto: p.IPProto, TotalLen: p.IPTotalLen, CsumOK: p.IPChecksumValid,
		ID: p.IPID, FragOff: p.FragOffset, MF: p.MoreFragments, Frag: p.IPFragmented,
		ARPOp: p.ARPOp, ARPSMAC: p.ARPSenderMAC.String(), ARPSIP: ipStr(p.ARPSenderIP),
		ARPTMAC: p.ARPTargetMAC.String(), ARPTIP: ipStr(p.ARPTargetIP),
	}
}

// eth returns the expected summary for a frame with only Ethernet decoded.
func eth(etherType uint16, l3 int) summary {
	return summary{EthDst: macBStr, EthSrc: macAStr, EthType: etherType, L3: l3, L4: -1, IPEnd: -1}
}

// v4 returns the expected summary for an ip4() packet at l3 with a valid
// header of hdrLen bytes and the given total length.
func v4(l3, hdrLen int, proto uint8, total uint32) summary {
	return summary{
		EthDst: macBStr, EthSrc: macAStr, EthType: packet.EthTypeIPv4,
		L3: l3, L4: l3 + hdrLen, IPEnd: l3 + int(total),
		Ver: 4, Src: "10.0.0.1", Dst: "10.0.0.2", TTL: 64, Proto: proto,
		TotalLen: total, CsumOK: true, ID: 0x1234,
	}
}

// v6 returns the expected summary for an ip6() packet at l3 whose
// transport header starts l4Rel bytes after l3.
func v6(l3, l4Rel int, proto uint8, total uint32) summary {
	return summary{
		EthDst: macBStr, EthSrc: macAStr, EthType: packet.EthTypeIPv6,
		L3: l3, L4: l3 + l4Rel, IPEnd: l3 + int(total),
		Ver: 6, Src: "2001:db8::1", Dst: "2001:db8::2", TTL: 64, Proto: proto,
		TotalLen: total, CsumOK: true,
	}
}

func with(s summary, f func(*summary)) summary { f(&s); return s }

// ---- table ----

type parseCase struct {
	name    string
	frame   []byte
	wireLen uint32 // 0 means len(frame)
	want    summary
	errs    []string // substrings, one per expected ParseErrors entry, in order
}

func parseCases() []parseCase {
	tcp := tcpHdr()
	udp2 := udpHdr([]byte("hi"))
	big := make([]byte, 2980)

	destChain := func(n int, last uint8) []byte {
		var b []byte
		for i := 0; i < n; i++ {
			next := uint8(60)
			if i == n-1 {
				next = last
			}
			b = append(b, optsExt(next)...)
		}
		return b
	}

	return []parseCase{
		// Ethernet
		{
			name:  "ipv4 tcp",
			frame: cat(ethHdr(0x0800), ip4(6, nil, tcp, nil)),
			want:  v4(14, 20, 6, 40),
		},
		{
			name:  "frame shorter than 14 bytes",
			frame: cat(macB, macA, []byte{0x08}),
			want:  summary{L3: -1, L4: -1, IPEnd: -1},
			errs:  []string{"ethernet: frame too short: 13 bytes"},
		},
		{
			name:  "empty frame",
			frame: nil,
			want:  summary{L3: -1, L4: -1, IPEnd: -1},
			errs:  []string{"ethernet: frame too short: 0 bytes"},
		},
		{
			name:  "802.3 length field is not IP and not an error",
			frame: pad60(cat(macB, macA, u16(0x0026), []byte{0x42, 0x42, 0x03})),
			want:  eth(0x0026, -1),
		},
		{
			name:  "other EtherType (LLDP)",
			frame: pad60(cat(ethHdr(0x88CC), []byte{0x02, 0x07})),
			want:  eth(0x88CC, 14),
		},
		{
			name:  "single 802.1Q tag",
			frame: cat(macB, macA, u16(0x8100), u16(100), u16(0x0800), ip4(6, nil, tcp, nil)),
			want:  v4(18, 20, 6, 40),
		},
		{
			name: "stacked QinQ tags",
			frame: cat(macB, macA, u16(0x88A8), u16(200), u16(0x8100), u16(100), u16(0x86DD),
				ip6(6, tcp)),
			want: v6(22, 40, 6, 60),
		},
		{
			name: "more VLAN tags than the cap",
			frame: cat(macB, macA, u16(0x8100), u16(1), u16(0x8100), u16(2), u16(0x8100), u16(3),
				u16(0x8100), u16(4), u16(0x8100), u16(5), u16(0x0800), ip4(6, nil, tcp, nil)),
			want: eth(0x8100, -1),
			errs: []string{"vlan: more than 4 VLAN tags"},
		},
		{
			name:  "truncated VLAN tag",
			frame: cat(macB, macA, u16(0x8100), u16(100), []byte{0x08}),
			want:  eth(0x8100, -1),
			errs:  []string{"vlan: tag 1 truncated"},
		},

		// IPv4
		{
			name:  "ipv4 with options",
			frame: cat(ethHdr(0x0800), ip4(6, []byte{7, 7, 4, 0, 0, 0, 0, 0}, tcp, nil)),
			want:  v4(14, 28, 6, 48),
		},
		{
			name: "ipv4 bad checksum is reported by the field, not as an error",
			frame: func() []byte {
				b := cat(ethHdr(0x0800), ip4(6, nil, tcp, nil))
				b[14+10] ^= 0xFF
				return b
			}(),
			want: with(v4(14, 20, 6, 40), func(s *summary) { s.CsumOK = false }),
		},
		{
			name:  "ipv4 IHL below 5",
			frame: cat(ethHdr(0x0800), ip4(6, nil, tcp, func(h []byte) { h[0] = 0x44 })),
			want:  with(v4(14, 20, 6, 40), func(s *summary) { s.L4, s.CsumOK = -1, false }),
			errs:  []string{"ipv4: header length 16 bytes is below the minimum 20"},
		},
		{
			name:  "ipv4 total length less than header length",
			frame: cat(ethHdr(0x0800), ip4(6, nil, tcp, setTotalLen(10))),
			want:  with(v4(14, 20, 6, 10), func(s *summary) { s.L4 = -1 }),
			errs:  []string{"ipv4: total length 10 is less than header length 20"},
		},
		{
			name:  "ipv4 total length 0 on a normal frame is malformed",
			frame: cat(ethHdr(0x0800), ip4(6, nil, tcp, setTotalLen(0))),
			want:  with(v4(14, 20, 6, 0), func(s *summary) { s.L4 = -1 }),
			errs:  []string{"ipv4: total length 0 is less than header length 20"},
		},
		{
			name:  "ipv4 fixed header truncated",
			frame: cat(ethHdr(0x0800), ip4(6, nil, tcp, nil)[:12]),
			want:  eth(0x0800, 14),
			errs:  []string{"ipv4: truncated header: 12 bytes captured, need 20"},
		},
		{
			name:  "ipv4 options run past captured bytes",
			frame: cat(ethHdr(0x0800), ip4(6, make([]byte, 20), tcp, nil)[:30]),
			want:  with(v4(14, 40, 6, 60), func(s *summary) { s.L4, s.CsumOK, s.IPEnd = -1, false, 44 }),
			errs:  []string{"ipv4: header runs past captured data: 40 bytes, 30 captured"},
		},
		{
			name:  "60-byte padded frame: IPEnd excludes padding",
			frame: pad60(cat(ethHdr(0x0800), ip4(17, nil, udp2, nil))),
			want:  v4(14, 20, 17, 30), // IPEnd 44, frame 60
		},
		{
			name:  "ipv4 first fragment",
			frame: cat(ethHdr(0x0800), ip4(17, nil, udp2, setFrag(0, true))),
			want:  with(v4(14, 20, 17, 30), func(s *summary) { s.MF, s.Frag = true, true }),
		},
		{
			name:  "ipv4 non-first fragment has no L4 header",
			frame: cat(ethHdr(0x0800), ip4(17, nil, udp2, setFrag(1480, false))),
			want: with(v4(14, 20, 17, 30), func(s *summary) {
				s.L4, s.FragOff, s.Frag = -1, 1480, true
			}),
		},
		{
			name:  "ipv4 total length over 1500 is not an error (GRO/TSO)",
			frame: cat(ethHdr(0x0800), ip4(6, nil, cat(tcp, big), nil)),
			want:  v4(14, 20, 6, 3020),
		},
		{
			name:    "ipv4 total length beyond captured bytes (snaplen) is not an error",
			frame:   cat(ethHdr(0x0800), ip4(6, nil, tcp, setTotalLen(9000))),
			wireLen: 9014,
			want:    with(v4(14, 20, 6, 9000), func(s *summary) { s.IPEnd = 54 }),
		},
		{
			name:    "ipv4 BIG TCP: total length 0 on a frame over 64 KiB",
			frame:   cat(ethHdr(0x0800), ip4(6, nil, tcp, setTotalLen(0))),
			wireLen: 70014,
			want:    with(v4(14, 20, 6, 70000), func(s *summary) { s.IPEnd = 54 }),
		},

		// Version / EtherType mismatch
		{
			name:  "EtherType IPv4 carrying an IPv6 header",
			frame: cat(ethHdr(0x0800), ip6(6, tcp)),
			want:  eth(0x0800, 14),
			errs:  []string{"ipv4: version field is 6 but EtherType is IPv4"},
		},
		{
			name:  "EtherType IPv6 carrying an IPv4 header",
			frame: cat(ethHdr(0x86DD), ip4(6, nil, cat(tcp, tcp), nil)),
			want:  eth(0x86DD, 14),
			errs:  []string{"ipv6: version field is 4 but EtherType is IPv6"},
		},

		// IPv6
		{
			name:  "ipv6 tcp",
			frame: cat(ethHdr(0x86DD), ip6(6, tcp)),
			want:  v6(14, 40, 6, 60),
		},
		{
			name:  "ipv6 truncated header",
			frame: cat(ethHdr(0x86DD), ip6(6, tcp)[:39]),
			want:  eth(0x86DD, 14),
			errs:  []string{"ipv6: truncated header: 39 bytes captured, need 40"},
		},
		{
			name:  "ipv6 hop-by-hop + fragment (first) + udp",
			frame: cat(ethHdr(0x86DD), ip6(0, cat(optsExt(44), fragExt(17, 0, true, 0xDEADBEEF), udp2))),
			want: with(v6(14, 56, 17, 66), func(s *summary) {
				s.ID, s.MF, s.Frag = 0xDEADBEEF, true, true
			}),
		},
		{
			name: "ipv6 non-first fragment stops the walk",
			// The fragment's next header is Destination Options, but the
			// bytes after the Fragment header are data from the middle of
			// the datagram. Walking into them would read proto 6.
			frame: cat(ethHdr(0x86DD), ip6(44, cat(fragExt(60, 1448, false, 7), []byte{6, 0, 0, 0, 0, 0, 0, 0}))),
			want: with(v6(14, 0, 60, 56), func(s *summary) {
				s.L4, s.ID, s.FragOff, s.Frag = -1, 7, 1448, true
			}),
		},
		{
			name: "ipv6 authentication header uses (len+2)*4",
			// plen 4 -> 24 bytes. The (len+1)*8 formula would give 40.
			frame: cat(ethHdr(0x86DD), ip6(51, cat(ahExt(6, 4), tcp))),
			want:  v6(14, 64, 6, 84),
		},
		{
			name:  "ipv6 routing + destination options",
			frame: cat(ethHdr(0x86DD), ip6(43, cat(optsExt(60), optsExt(6), tcp))),
			want:  v6(14, 56, 6, 76),
		},
		{
			name:  "ipv6 ESP: rest is encrypted",
			frame: cat(ethHdr(0x86DD), ip6(50, make([]byte, 24))),
			want:  with(v6(14, 0, 50, 64), func(s *summary) { s.L4 = -1 }),
		},
		{
			name:  "ipv6 ESP after an extension header",
			frame: cat(ethHdr(0x86DD), ip6(60, cat(optsExt(50), make([]byte, 24)))),
			want:  with(v6(14, 0, 50, 72), func(s *summary) { s.L4 = -1 }),
		},
		{
			name:  "ipv6 no next header",
			frame: pad60(cat(ethHdr(0x86DD), ip6(59, nil))),
			want:  with(v6(14, 0, 59, 40), func(s *summary) { s.L4 = -1 }),
		},
		{
			name:  "ipv6 ten extension headers is allowed",
			frame: cat(ethHdr(0x86DD), ip6(60, cat(destChain(10, 6), tcp))),
			want:  v6(14, 120, 6, 140),
		},
		{
			name:  "ipv6 extension header chain longer than the cap",
			frame: cat(ethHdr(0x86DD), ip6(60, cat(destChain(11, 6), tcp))),
			want:  with(v6(14, 0, 60, 148), func(s *summary) { s.L4 = -1 }),
			errs:  []string{"ipv6: more than 10 extension headers"},
		},
		{
			name:  "ipv6 extension header runs past payload length",
			frame: cat(ethHdr(0x86DD), ip6(0, []byte{6, 5, 1, 4, 0, 0, 0, 0})), // claims 48 bytes
			want:  with(v6(14, 0, 0, 48), func(s *summary) { s.L4 = -1 }),
			errs:  []string{"ipv6: extension header 1 (type 0) runs past end of packet"},
		},
		{
			name: "ipv6 extension header walk ignores Ethernet padding",
			// Payload length 0, but the 6 padding bytes would parse as a
			// hop-by-hop header if the walk used len(RawData).
			frame: pad60(cat(ethHdr(0x86DD), ip6(0, nil))),
			want:  with(v6(14, 0, 0, 40), func(s *summary) { s.L4 = -1 }),
			errs:  []string{"ipv6: extension header 1 (type 0) truncated at offset 54"},
		},
		{
			name:  "ipv6 hop-by-hop not first",
			frame: cat(ethHdr(0x86DD), ip6(60, cat(optsExt(0), optsExt(6), tcp))),
			want:  v6(14, 56, 6, 76),
			errs:  []string{"ipv6: hop-by-hop header is not first"},
		},
		{
			name:  "ipv6 payload length over 1500 is not an error",
			frame: cat(ethHdr(0x86DD), ip6(6, cat(tcp, big))),
			want:  v6(14, 40, 6, 3040),
		},
		{
			name: "ipv6 jumbo / BIG TCP: payload length 0 on a frame over 64 KiB",
			frame: func() []byte {
				b := cat(ethHdr(0x86DD), ip6(6, tcp))
				b[14+4], b[14+5] = 0, 0
				return b
			}(),
			wireLen: 70014,
			want:    with(v6(14, 40, 6, 70000), func(s *summary) { s.IPEnd = 74 }),
		},

		// ARP
		{
			name:  "arp request",
			frame: pad60(cat(ethHdr(0x0806), arp(1, 1))),
			want: with(eth(0x0806, 14), func(s *summary) {
				s.ARPOp, s.ARPSMAC, s.ARPSIP, s.ARPTMAC, s.ARPTIP = 1, macAStr, "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2"
			}),
		},
		{
			name:  "arp reply",
			frame: cat(ethHdr(0x0806), arp(1, 2)),
			want: with(eth(0x0806, 14), func(s *summary) {
				s.ARPOp, s.ARPSMAC, s.ARPSIP, s.ARPTMAC, s.ARPTIP = 2, macAStr, "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2"
			}),
		},
		{
			name:  "arp in a VLAN",
			frame: cat(macB, macA, u16(0x8100), u16(5), u16(0x0806), arp(1, 1)),
			want: with(eth(0x0806, 18), func(s *summary) {
				s.ARPOp, s.ARPSMAC, s.ARPSIP, s.ARPTMAC, s.ARPTIP = 1, macAStr, "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2"
			}),
		},
		{
			name:  "arp unexpected opcode is kept with an error",
			frame: cat(ethHdr(0x0806), arp(1, 3)),
			want: with(eth(0x0806, 14), func(s *summary) {
				s.ARPOp, s.ARPSMAC, s.ARPSIP, s.ARPTMAC, s.ARPTIP = 3, macAStr, "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2"
			}),
			errs: []string{"arp: unexpected opcode 3"},
		},
		{
			name:  "arp non-Ethernet hardware type",
			frame: pad60(cat(ethHdr(0x0806), arp(6, 1))),
			want:  eth(0x0806, 14),
			errs:  []string{"arp: unsupported hardware/protocol: htype=6"},
		},
		{
			name:  "arp truncated fixed header",
			frame: cat(ethHdr(0x0806), arp(1, 1)[:7]),
			want:  eth(0x0806, 14),
			errs:  []string{"arp: truncated header: 7 bytes captured, need 8"},
		},
		{
			name:  "arp truncated addresses",
			frame: cat(ethHdr(0x0806), arp(1, 1)[:20]),
			want:  eth(0x0806, 14),
			errs:  []string{"arp: truncated: 20 bytes captured, need 28"},
		},
	}
}

func newPacket(frame []byte, wireLen uint32) *packet.ParsedPacket {
	if wireLen == 0 {
		wireLen = uint32(len(frame))
	}
	p := packet.NewParsedPacket(time.Unix(0, 0), uint32(len(frame)), wireLen)
	p.RawData = frame
	return p
}

func TestParse(t *testing.T) {
	for _, tt := range parseCases() {
		t.Run(tt.name, func(t *testing.T) {
			p := newPacket(tt.frame, tt.wireLen)
			orig := bytes.Clone(tt.frame)

			lower.Parse(p)

			if got := summarize(p); got != tt.want {
				t.Errorf("fields mismatch\n got: %+v\nwant: %+v", got, tt.want)
			}
			if len(p.ParseErrors) != len(tt.errs) {
				t.Fatalf("ParseErrors = %q, want %d error(s) matching %q", p.ParseErrors, len(tt.errs), tt.errs)
			}
			for i, want := range tt.errs {
				if !strings.Contains(p.ParseErrors[i], want) {
					t.Errorf("ParseErrors[%d] = %q, want it to contain %q", i, p.ParseErrors[i], want)
				}
			}
			checkInvariants(t, p, orig)
		})
	}
}

// TestParseCopiesAddresses checks the documented aliasing rule: address
// fields do not share memory with RawData.
func TestParseCopiesAddresses(t *testing.T) {
	check := func(t *testing.T, frame []byte) {
		t.Helper()
		p := newPacket(frame, 0)
		lower.Parse(p)
		before := summarize(p)
		for i := range frame {
			frame[i] ^= 0xFF
		}
		if after := summarize(p); after.EthSrc != before.EthSrc || after.EthDst != before.EthDst ||
			after.Src != before.Src || after.Dst != before.Dst ||
			after.ARPSMAC != before.ARPSMAC || after.ARPSIP != before.ARPSIP ||
			after.ARPTMAC != before.ARPTMAC || after.ARPTIP != before.ARPTIP {
			t.Errorf("address fields changed when RawData changed:\nbefore: %+v\n after: %+v", before, after)
		}
	}
	t.Run("ipv4", func(t *testing.T) { check(t, cat(ethHdr(0x0800), ip4(6, nil, tcpHdr(), nil))) })
	t.Run("ipv6", func(t *testing.T) { check(t, cat(ethHdr(0x86DD), ip6(6, tcpHdr()))) })
	t.Run("arp", func(t *testing.T) { check(t, cat(ethHdr(0x0806), arp(1, 1))) })
}

func TestParseNil(t *testing.T) {
	lower.Parse(nil) // must not panic
}

// checkInvariants asserts properties that must hold for any input.
func checkInvariants(t *testing.T, p *packet.ParsedPacket, orig []byte) {
	t.Helper()
	n := len(p.RawData)
	if !bytes.Equal(p.RawData, orig) {
		t.Fatal("Parse modified RawData")
	}
	if p.L3Offset < -1 || p.L3Offset > n {
		t.Errorf("L3Offset %d out of range [-1, %d]", p.L3Offset, n)
	}
	if p.L4Offset != -1 && (p.L4Offset < p.L3Offset || p.L3Offset < 0 || p.L4Offset > n) {
		t.Errorf("L4Offset %d out of range (L3Offset %d, len %d)", p.L4Offset, p.L3Offset, n)
	}
	if p.IPVersion != 0 && p.IPVersion != 4 && p.IPVersion != 6 {
		t.Errorf("IPVersion = %d", p.IPVersion)
	}
	if p.IPVersion != 0 && p.L3Offset < 0 {
		t.Errorf("IPVersion %d with L3Offset %d", p.IPVersion, p.L3Offset)
	}
	if e := p.IPEnd(); e < -1 || e > n || (e >= 0 && e < p.L3Offset) {
		t.Errorf("IPEnd() = %d out of range (L3Offset %d, len %d)", e, p.L3Offset, n)
	}
	if p.IPFragmented != (p.MoreFragments || p.FragOffset > 0) {
		t.Errorf("IPFragmented = %v, MoreFragments = %v, FragOffset = %d", p.IPFragmented, p.MoreFragments, p.FragOffset)
	}
	if !p.IPFragmented && p.FragPayloadLen != 0 {
		t.Errorf("unfragmented packet has FragPayloadLen %d", p.FragPayloadLen)
	}
	if p.FragPayloadLen > p.IPTotalLen {
		t.Errorf("FragPayloadLen %d > IPTotalLen %d", p.FragPayloadLen, p.IPTotalLen)
	}
	if p.FragOffset > 0 && p.L4Offset != -1 {
		t.Errorf("non-first fragment has L4Offset %d", p.L4Offset)
	}
	if p.IPVersion == 6 && !p.IPChecksumValid {
		t.Error("IPv6 packet with IPChecksumValid = false")
	}
	if p.IPVersion != 0 && p.ARPOp != 0 {
		t.Errorf("both IPVersion %d and ARPOp %d set", p.IPVersion, p.ARPOp)
	}
}

func FuzzParse(f *testing.F) {
	for _, tt := range parseCases() {
		extra := uint32(0)
		if tt.wireLen > uint32(len(tt.frame)) {
			extra = tt.wireLen - uint32(len(tt.frame))
		}
		f.Add(tt.frame, extra)
	}
	f.Fuzz(func(t *testing.T, data []byte, extraWire uint32) {
		wire := uint64(len(data)) + uint64(extraWire)
		if wire > math.MaxUint32 {
			wire = math.MaxUint32
		}
		p := packet.NewParsedPacket(time.Unix(0, 0), uint32(len(data)), uint32(wire))
		p.RawData = data
		orig := bytes.Clone(data)

		lower.Parse(p)

		checkInvariants(t, p, orig)
		// Everything Module 3 will do with the result must be safe too.
		if p.L4Offset >= 0 {
			if end := p.IPEnd(); end >= p.L4Offset {
				_ = p.RawData[p.L4Offset:end]
			}
		}
		p.PayloadOffset = p.L4Offset
		_ = p.Payload()
	})
}
