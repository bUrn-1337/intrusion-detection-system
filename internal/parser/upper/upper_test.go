package upper_test

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
)

// ---- frame builders ----

var (
	macA = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a}
	macB = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}
	ip4A = []byte{10, 0, 0, 1}
	ip4B = []byte{10, 0, 0, 2}
	ip6A = []byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}
	ip6B = []byte{0x20, 0x01, 0x0d, 0xb8, 15: 2}
)

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
	tcpURG = 0x20
)

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func ethHdr(etherType uint16) []byte { return cat(macB, macA, u16(etherType)) }

// ip4 returns Ethernet + IPv4 (10.0.0.1 -> 10.0.0.2, TTL 64) + seg. mut, if
// non-nil, edits the IP header before its checksum is computed.
func ip4(proto uint8, seg []byte, mut func(h []byte)) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(seg)))
	binary.BigEndian.PutUint16(h[4:], 0x1234)
	h[8] = 64
	h[9] = proto
	copy(h[12:], ip4A)
	copy(h[16:], ip4B)
	if mut != nil {
		mut(h)
	}
	binary.BigEndian.PutUint16(h[10:], ^fold(sumWords(0, h)))
	return cat(ethHdr(0x0800), h, seg)
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

// ip6 returns Ethernet + IPv6 (2001:db8::1 -> 2001:db8::2, hop limit 64) +
// ext + seg, with next header nh.
func ip6(nh uint8, ext, seg []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(ext)+len(seg)))
	h[6] = nh
	h[7] = 64
	copy(h[8:], ip6A)
	copy(h[24:], ip6B)
	return cat(ethHdr(0x86DD), h, ext, seg)
}

// optsExt returns an 8-byte IPv6 options extension header.
func optsExt(next uint8) []byte { return []byte{next, 0, 1, 4, 0, 0, 0, 0} }

// tcp returns a TCP segment 40000 -> 443, seq 1000, ack 2000, window
// 64240, with a zero checksum. len(opts) must be a multiple of 4.
func tcp(flags byte, opts []byte, payload string) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], 40000)
	binary.BigEndian.PutUint16(h[2:], 443)
	binary.BigEndian.PutUint32(h[4:], 1000)
	binary.BigEndian.PutUint32(h[8:], 2000)
	h[12] = byte((20+len(opts))/4) << 4
	h[13] = flags
	binary.BigEndian.PutUint16(h[14:], 64240)
	return cat(h, opts, []byte(payload))
}

// udp returns a UDP datagram 40000 -> 53 with a zero checksum.
func udp(payload string) []byte {
	return cat(u16(40000), u16(53), u16(uint16(8+len(payload))), u16(0), []byte(payload))
}

// icmp returns an ICMP/ICMPv6 message with a zero checksum.
func icmp(typ, code byte, body []byte) []byte { return cat([]byte{typ, code, 0, 0}, body) }

func pad60(b []byte) []byte {
	for len(b) < 60 {
		b = append(b, 0xAA) // non-zero, so it would break a checksum
	}
	return b
}

// csumField returns the offset in frame of the transport checksum field,
// or -1. It uses lower.Parse to find the transport header.
func csumField(frame []byte) (field int, p *packet.ParsedPacket) {
	p = newPacket(bytes.Clone(frame), 0)
	lower.Parse(p)
	if p.L4Offset < 0 {
		return -1, p
	}
	switch p.IPProto {
	case 6:
		return p.L4Offset + 16, p
	case 17:
		return p.L4Offset + 6, p
	case 1, 58:
		return p.L4Offset + 2, p
	}
	return -1, p
}

// seal returns frame with a correct transport checksum. This is a second,
// test-only implementation; the gopacket cross-check provides a third.
func seal(frame []byte) []byte {
	field, p := csumField(frame)
	out := bytes.Clone(frame)
	if field < 0 {
		panic("seal: no transport header")
	}
	out[field], out[field+1] = 0, 0
	end := int(int64(p.L3Offset) + int64(p.IPTotalLen))
	if p.IPProto == 17 {
		end = p.L4Offset + int(binary.BigEndian.Uint16(out[p.L4Offset+4:]))
	}
	seg := out[p.L4Offset:end]
	sum := sumWords(0, seg)
	if p.IPProto != 1 {
		sum = sumWords(sum, p.IPSrc)
		sum = sumWords(sum, p.IPDst)
		n := uint32(len(seg))
		sum += uint64(n>>16) + uint64(n&0xFFFF) + uint64(p.IPProto)
	}
	c := ^fold(sum)
	if c == 0 && p.IPProto == 17 {
		c = 0xFFFF
	}
	binary.BigEndian.PutUint16(out[field:], c)
	return out
}

// corrupt returns a sealed copy of frame with a wrong checksum.
func corrupt(frame []byte) []byte {
	out := seal(frame)
	field, _ := csumField(out)
	out[field+1] ^= 0x5A
	return out
}

// setUDPLen overwrites the UDP length field of a built frame.
func setUDPLen(frame []byte, n uint16) []byte {
	field, _ := csumField(frame)
	out := bytes.Clone(frame)
	binary.BigEndian.PutUint16(out[field-2:], n)
	return out
}

func sumWords(sum uint64, b []byte) uint64 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint64(b[i])<<8 | uint64(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint64(b[len(b)-1]) << 8
	}
	return sum
}

func fold(sum uint64) uint16 {
	for sum>>16 != 0 {
		sum = sum>>16 + sum&0xFFFF
	}
	return uint16(sum)
}

// ---- expected results ----

// result is the comparable set of Module 3 fields.
type result struct {
	L4Proto            string
	PayloadOffset      int
	SrcPort, DstPort   uint16
	Flags              packet.TCPFlags
	Seq, Ack           uint32
	Win                uint16
	UDPLen             uint16
	ICMPType, ICMPCode uint8
	EchoID, EchoSeq    uint16
	HasEcho            bool
	Csum               uint8
	Payload            string
}

func resultOf(p *packet.ParsedPacket) result {
	return result{
		L4Proto: p.L4Proto, PayloadOffset: p.PayloadOffset,
		SrcPort: p.SrcPort, DstPort: p.DstPort,
		Flags: p.TCPFlags, Seq: p.TCPSeq, Ack: p.TCPAck, Win: p.TCPWindow,
		UDPLen: p.UDPLen, ICMPType: p.ICMPType, ICMPCode: p.ICMPCode,
		EchoID: p.ICMPEchoID, EchoSeq: p.ICMPEchoSeq, HasEcho: p.HasICMPEcho,
		Csum: p.L4ChecksumStatus, Payload: string(p.Payload()),
	}
}

const (
	unchecked = packet.L4ChecksumUnchecked
	valid     = packet.L4ChecksumValid
	invalid   = packet.L4ChecksumInvalid
)

// wantTCP is the result for a tcp() segment.
func wantTCP(flags packet.TCPFlags, payloadOff int, payload string, csum uint8) result {
	return result{L4Proto: packet.L4TCP, PayloadOffset: payloadOff, SrcPort: 40000, DstPort: 443,
		Flags: flags, Seq: 1000, Ack: 2000, Win: 64240, Csum: csum, Payload: payload}
}

// wantUDP is the result for a udp() datagram.
func wantUDP(udpLen uint16, payloadOff int, payload string, csum uint8) result {
	return result{L4Proto: packet.L4UDP, PayloadOffset: payloadOff, SrcPort: 40000, DstPort: 53,
		UDPLen: udpLen, Csum: csum, Payload: payload}
}

func wantICMP(typ, code uint8, payloadOff int, payload string, csum uint8) result {
	return result{L4Proto: packet.L4ICMP, PayloadOffset: payloadOff, ICMPType: typ, ICMPCode: code,
		Csum: csum, Payload: payload}
}

// wantEcho is the result for an echo request or reply built from
// echoBody's id 0x1234 and seq 1: the payload starts after them.
func wantEcho(typ uint8, payloadOff int, payload string, csum uint8) result {
	r := wantICMP(typ, 0, payloadOff, payload, csum)
	r.EchoID, r.EchoSeq, r.HasEcho = 0x1234, 1, true
	return r
}

var (
	syn    = packet.TCPFlags{SYN: true}
	ack    = packet.TCPFlags{ACK: true}
	pshAck = packet.TCPFlags{PSH: true, ACK: true}
)

// ---- table ----

type parseCase struct {
	name    string
	frame   []byte
	wireLen uint32 // 0 means len(frame)
	want    result
	errs    []string // substrings, one per ParseErrors entry (both modules), in order
}

func parseCases() []parseCase {
	// MSS 1460, SACK permitted, timestamps, NOP, window scale 7: 20 bytes.
	fullOpts := cat([]byte{2, 4, 0x05, 0xb4}, []byte{4, 2}, []byte{8, 10, 0, 0, 0, 1, 0, 0, 0, 0}, []byte{1}, []byte{3, 3, 7})
	big := strings.Repeat("x", 2000)
	echoBody := []byte{0x12, 0x34, 0x00, 0x01, 'p', 'i', 'n', 'g'}
	nsBody := cat([]byte{0, 0, 0, 0}, ip6B) // reserved + target address

	return []parseCase{
		// ---- TCP ----
		{
			name:  "tcp over ipv4",
			frame: seal(ip4(6, tcp(tcpSYN, nil, ""), nil)),
			want:  wantTCP(syn, 54, "", valid),
		},
		{
			name:  "tcp with MSS, SACK-permitted, timestamps, window scale",
			frame: seal(ip4(6, tcp(tcpPSH|tcpACK, fullOpts, "hello"), nil)),
			want:  wantTCP(pshAck, 74, "hello", valid),
		},
		{
			name:  "tcp all six flags",
			frame: seal(ip4(6, tcp(0x3F, nil, ""), nil)),
			want: wantTCP(packet.TCPFlags{SYN: true, ACK: true, FIN: true, RST: true, PSH: true, URG: true},
				54, "", valid),
		},
		{
			name:  "tcp invalid checksum over ipv4",
			frame: corrupt(ip4(6, tcp(tcpSYN, nil, ""), nil)),
			want:  wantTCP(syn, 54, "", invalid),
		},
		{
			name:  "tcp over ipv6",
			frame: seal(ip6(6, nil, tcp(tcpACK, nil, "data"))),
			want:  wantTCP(ack, 74, "data", valid),
		},
		{
			name:  "tcp invalid checksum over ipv6",
			frame: corrupt(ip6(6, nil, tcp(tcpACK, nil, "data"))),
			want:  wantTCP(ack, 74, "data", invalid),
		},
		{
			// The pseudo-header uses next header 6 (not 0 from the IPv6
			// header) and the TCP length (not the IPv6 payload length).
			name:  "tcp over ipv6 after hop-by-hop and destination options",
			frame: seal(ip6(0, cat(optsExt(60), optsExt(6)), tcp(tcpACK, nil, "data"))),
			want:  wantTCP(ack, 90, "data", valid),
		},
		{
			name: "tcp data offset below 5",
			frame: func() []byte {
				b := seal(ip4(6, tcp(tcpSYN, nil, ""), nil))
				b[34+12] = 4 << 4
				return b
			}(),
			want: wantTCP(syn, -1, "", unchecked),
			errs: []string{"tcp: data offset 4 is below the minimum 5"},
		},
		{
			name: "tcp data offset past end of packet",
			frame: func() []byte {
				b := seal(ip4(6, tcp(tcpSYN, nil, ""), nil))
				b[34+12] = 15 << 4
				return b
			}(),
			want: wantTCP(syn, -1, "", unchecked),
			errs: []string{"tcp: header runs past end of packet: 60 bytes, 20 available"},
		},
		{
			name: "tcp data offset one word past end of packet",
			frame: func() []byte {
				b := seal(ip4(6, tcp(tcpSYN, nil, ""), nil))
				b[34+12] = 6 << 4
				return b
			}(),
			want: wantTCP(syn, -1, "", unchecked),
			errs: []string{"tcp: header runs past end of packet: 24 bytes, 20 available"},
		},
		{
			name:  "tcp option with length 1",
			frame: seal(ip4(6, tcp(tcpSYN, []byte{3, 1, 0, 0}, ""), nil)),
			want:  wantTCP(syn, 58, "", valid),
			errs:  []string{"tcp: option kind 3 has invalid length 1"},
		},
		{
			name:  "tcp option with length 0",
			frame: seal(ip4(6, tcp(tcpSYN, []byte{2, 0, 0, 0}, ""), nil)),
			want:  wantTCP(syn, 58, "", valid),
			errs:  []string{"tcp: option kind 2 has invalid length 0"},
		},
		{
			name:  "tcp option running past the header",
			frame: seal(ip4(6, tcp(tcpSYN, []byte{1, 1, 8, 10}, ""), nil)),
			want:  wantTCP(syn, 58, "", valid),
			errs:  []string{"tcp: option kind 8 length 10 runs past end of header"},
		},
		{
			name:  "tcp option missing its length byte",
			frame: seal(ip4(6, tcp(tcpSYN, []byte{1, 1, 1, 8}, ""), nil)),
			want:  wantTCP(syn, 58, "", valid),
			errs:  []string{"tcp: option kind 8 at offset 3 has no length byte"},
		},
		{
			name:  "tcp options ending exactly at the header end",
			frame: seal(ip4(6, tcp(tcpSYN, []byte{2, 4, 0x05, 0xb4, 1, 3, 3, 7}, ""), nil)),
			want:  wantTCP(syn, 62, "", valid),
		},
		{
			name:  "tcp end-of-list option stops the walk",
			frame: seal(ip4(6, tcp(tcpSYN, []byte{1, 0, 0xff, 0xff}, ""), nil)),
			want:  wantTCP(syn, 58, "", valid),
		},
		{
			name:  "tcp in a 60-byte padded frame",
			frame: pad60(seal(ip4(6, tcp(tcpACK, nil, ""), nil))),
			want:  wantTCP(ack, 54, "", valid),
		},
		{
			name:    "tcp payload cut by snaplen is unchecked",
			frame:   seal(ip4(6, tcp(tcpACK, nil, strings.Repeat("x", 100)), nil))[:70],
			wireLen: 154,
			want:    wantTCP(ack, 54, strings.Repeat("x", 16), unchecked),
		},
		{
			name:    "tcp header cut by snaplen",
			frame:   seal(ip4(6, tcp(tcpACK, nil, "abc"), nil))[:44],
			wireLen: 57,
			want:    result{L4Proto: packet.L4TCP, PayloadOffset: -1},
			errs:    []string{"tcp: truncated header: 10 bytes available, need 20 (capture truncated)"},
		},
		{
			name:  "tcp GRO-size packet is unchecked",
			frame: seal(ip4(6, tcp(tcpACK, nil, big), nil)),
			want:  wantTCP(ack, 54, big, unchecked),
		},
		{
			name:  "tcp first fragment is parsed but unchecked",
			frame: seal(ip4(6, tcp(tcpSYN, nil, "part"), setFrag(0, true))),
			want:  wantTCP(syn, 54, "part", unchecked),
		},
		{
			name:  "tcp non-first fragment: L4Proto only",
			frame: ip4(6, tcp(tcpSYN, nil, "tail"), setFrag(1480, false)),
			want:  result{L4Proto: packet.L4TCP, PayloadOffset: -1},
		},

		// ---- UDP ----
		{
			name:  "udp over ipv4",
			frame: seal(ip4(17, udp("query"), nil)),
			want:  wantUDP(13, 42, "query", valid),
		},
		{
			name:  "udp invalid checksum over ipv4",
			frame: corrupt(ip4(17, udp("query"), nil)),
			want:  wantUDP(13, 42, "query", invalid),
		},
		{
			name:  "udp zero checksum over ipv4 means no checksum",
			frame: ip4(17, udp("query"), nil),
			want:  wantUDP(13, 42, "query", unchecked),
		},
		{
			name:  "udp over ipv6",
			frame: seal(ip6(17, nil, udp("query"))),
			want:  wantUDP(13, 62, "query", valid),
		},
		{
			name:  "udp invalid checksum over ipv6",
			frame: corrupt(ip6(17, nil, udp("query"))),
			want:  wantUDP(13, 62, "query", invalid),
		},
		{
			name:  "udp zero checksum over ipv6 is invalid",
			frame: ip6(17, nil, udp("query")),
			want:  wantUDP(13, 62, "query", invalid),
			errs:  []string{"udp: zero checksum is not allowed over IPv6"},
		},
		{
			name:  "udp length below 8",
			frame: setUDPLen(ip4(17, udp("query"), nil), 4),
			want:  wantUDP(4, -1, "", unchecked),
			errs:  []string{"udp: length 4 is less than the 8-byte header"},
		},
		{
			name:  "udp length 7",
			frame: setUDPLen(ip4(17, udp("query"), nil), 7),
			want:  wantUDP(7, -1, "", unchecked),
			errs:  []string{"udp: length 7 is less than the 8-byte header"},
		},
		{
			name:  "udp length past the IP packet",
			frame: setUDPLen(ip4(17, udp("query"), nil), 100),
			want:  wantUDP(100, -1, "", unchecked),
			errs:  []string{"udp: length 100 runs past end of IP packet: 13 bytes available"},
		},
		{
			name:  "udp trailing data inside the IP packet",
			frame: seal(ip4(17, cat(udp("hi"), []byte("JUNK")), nil)),
			want:  wantUDP(10, 42, "hi", valid),
			errs:  []string{"udp: 4 bytes of trailing data after the datagram"},
		},
		{
			name:  "udp header truncated",
			frame: ip4(17, udp("")[:5], nil),
			want:  result{L4Proto: packet.L4UDP, PayloadOffset: -1},
			errs:  []string{"udp: truncated header: 5 bytes available, need 8"},
		},
		{
			name:    "udp payload cut by snaplen is unchecked, not malformed",
			frame:   seal(ip4(17, udp(strings.Repeat("y", 100)), nil))[:60],
			wireLen: 142,
			want:    wantUDP(108, 42, strings.Repeat("y", 18), unchecked),
		},
		{
			name: "udp jumbogram: length 0 over a >64 KiB IPv6 packet",
			frame: func() []byte {
				b := ip6(17, nil, udp("big"))
				b[14+4], b[14+5] = 0, 0 // IPv6 payload length 0
				b[54+4], b[54+5] = 0, 0 // UDP length 0
				b[54+6] = 0x12          // non-zero checksum
				return b
			}(),
			wireLen: 70014,
			want:    wantUDP(0, 62, "big", unchecked),
		},

		// ---- ICMP ----
		{
			name:  "icmp echo request",
			frame: seal(ip4(1, icmp(8, 0, echoBody), nil)),
			want:  wantEcho(8, 42, "ping", valid),
		},
		{
			name:  "icmp invalid checksum",
			frame: corrupt(ip4(1, icmp(8, 0, echoBody), nil)),
			want:  wantEcho(8, 42, "ping", invalid),
		},
		{
			name:  "icmp in a padded frame",
			frame: pad60(seal(ip4(1, icmp(0, 0, echoBody[:4]), nil))),
			want:  wantEcho(0, 42, "", valid),
		},
		{
			name:  "icmp echo too short for id and seq",
			frame: seal(ip4(1, icmp(8, 0, echoBody[:3]), nil)),
			want:  wantICMP(8, 0, 38, string(echoBody[:3]), valid),
		},
		{
			name:  "icmp echo code is not checked",
			frame: seal(ip4(1, icmp(0, 5, echoBody), nil)),
			want:  func() result { r := wantEcho(0, 42, "ping", valid); r.ICMPCode = 5; return r }(),
		},
		{
			name:  "icmp timestamp request is not an echo",
			frame: seal(ip4(1, icmp(13, 0, echoBody), nil)),
			want:  wantICMP(13, 0, 38, string(echoBody), valid),
		},
		{
			name:  "icmpv6 echo request",
			frame: seal(ip6(58, nil, icmp(128, 0, echoBody))),
			want:  wantEcho(128, 62, "ping", valid),
		},
		{
			name:  "icmpv6 echo reply",
			frame: seal(ip6(58, nil, icmp(129, 0, echoBody))),
			want:  wantEcho(129, 62, "ping", valid),
		},
		{
			name:  "icmpv6 type 8 is not an echo",
			frame: seal(ip6(58, nil, icmp(8, 0, echoBody))),
			want:  wantICMP(8, 0, 58, string(echoBody), valid),
		},
		{
			name:  "icmpv6 invalid checksum",
			frame: corrupt(ip6(58, nil, icmp(128, 0, echoBody))),
			want:  wantEcho(128, 62, "ping", invalid),
		},
		{
			name:  "icmpv6 neighbor solicitation",
			frame: seal(ip6(58, nil, icmp(135, 0, nsBody))),
			want:  wantICMP(135, 0, 58, string(nsBody), valid),
		},
		{
			name:  "icmp header truncated",
			frame: ip4(1, []byte{8, 0, 0}, nil),
			want:  result{L4Proto: packet.L4ICMP, PayloadOffset: -1},
			errs:  []string{"icmp: truncated header: 3 bytes available, need 4"},
		},
		{
			name:  "icmpv6 carried over ipv4",
			frame: ip4(58, icmp(128, 0, echoBody), nil),
			want:  wantICMP(128, 0, 38, string(echoBody), unchecked),
			errs:  []string{"icmpv6: protocol 58 carried over IPv4"},
		},

		// ---- no transport header ----
		{
			name:  "other protocol (GRE)",
			frame: ip4(47, []byte{0, 0, 0x08, 0x00}, nil),
			want:  result{L4Proto: packet.L4Other, PayloadOffset: -1},
		},
		{
			name:  "ipv6 ESP",
			frame: ip6(50, nil, make([]byte, 16)),
			want:  result{L4Proto: packet.L4Other, PayloadOffset: -1},
		},
		{
			name:  "ipv6 non-first fragment: L4Proto only",
			frame: ip6(44, []byte{17, 0, 0x05, 0xa8, 0, 0, 0, 1}, []byte("fragment tail")),
			want:  result{L4Proto: packet.L4UDP, PayloadOffset: -1},
		},
		{
			name:  "arp: nothing to do",
			frame: cat(ethHdr(0x0806), u16(1), u16(0x0800), []byte{6, 4}, u16(1), macA, ip4A, make([]byte, 6), ip4B),
			want:  result{PayloadOffset: -1},
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
			upper.Parse(p)

			if got := resultOf(p); got != tt.want {
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

func TestParseNilAndUnparsed(t *testing.T) {
	upper.Parse(nil) // must not panic

	// Without lower.Parse, IPVersion is 0 and nothing happens.
	p := newPacket(seal(ip4(6, tcp(tcpSYN, nil, ""), nil)), 0)
	upper.Parse(p)
	if got := resultOf(p); got != (result{PayloadOffset: -1}) || p.HasErrors() {
		t.Errorf("Parse before lower.Parse changed the packet: %+v, errors %q", got, p.ParseErrors)
	}
}

func TestICMPLabel(t *testing.T) {
	tests := []struct {
		ver, typ, code uint8
		want           string
	}{
		{4, 8, 0, "Echo Request"},
		{4, 0, 0, "Echo Reply"},
		{6, 128, 0, "Echo Request"},
		{6, 129, 0, "Echo Reply"},
		{4, 3, 3, "Destination Unreachable (port unreachable)"},
		{4, 3, 1, "Destination Unreachable (host unreachable)"},
		{4, 3, 4, "Destination Unreachable (fragmentation needed)"},
		{4, 3, 13, "Destination Unreachable (communication administratively prohibited)"},
		{4, 3, 99, "Destination Unreachable (code 99)"},
		{6, 1, 4, "Destination Unreachable (port unreachable)"},
		{6, 1, 1, "Destination Unreachable (administratively prohibited)"},
		{4, 11, 0, "Time Exceeded (TTL exceeded in transit)"},
		{6, 3, 0, "Time Exceeded (hop limit exceeded in transit)"},
		{4, 5, 1, "Redirect (for host)"},
		{6, 137, 0, "Redirect"},
		{6, 2, 0, "Packet Too Big"},
		{4, 12, 0, "Parameter Problem (pointer indicates the error)"},
		{6, 4, 1, "Parameter Problem (unrecognized next header)"},
		{4, 9, 0, "Router Advertisement"},
		{4, 10, 0, "Router Solicitation"},
		{6, 133, 0, "Router Solicitation"},
		{6, 134, 0, "Router Advertisement"},
		{6, 135, 0, "Neighbor Solicitation"},
		{6, 136, 0, "Neighbor Advertisement"},
		{4, 8, 7, "Echo Request (code 7)"},
		// Type numbers differ between versions.
		{4, 128, 0, "type 128 code 0"},
		{6, 8, 0, "type 8 code 0"},
		{4, 200, 3, "type 200 code 3"},
		{0, 8, 0, "type 8 code 0"},
	}
	for _, tt := range tests {
		if got := upper.ICMPLabel(tt.ver, tt.typ, tt.code); got != tt.want {
			t.Errorf("ICMPLabel(%d, %d, %d) = %q, want %q", tt.ver, tt.typ, tt.code, got, tt.want)
		}
	}
}

// checkInvariants asserts properties that must hold for any input.
func checkInvariants(t *testing.T, p *packet.ParsedPacket, orig []byte) {
	t.Helper()
	if !bytes.Equal(p.RawData, orig) {
		t.Fatal("Parse modified RawData")
	}
	if p.IPVersion == 0 && p.L4Proto != "" {
		t.Errorf("L4Proto %q set without an IP header", p.L4Proto)
	}
	if p.L4ChecksumStatus > packet.L4ChecksumInvalid {
		t.Errorf("L4ChecksumStatus = %d", p.L4ChecksumStatus)
	}
	if p.PayloadOffset != -1 {
		if p.L4Offset < 0 || p.PayloadOffset < p.L4Offset || p.PayloadOffset > p.IPEnd() {
			t.Errorf("PayloadOffset %d outside [L4Offset %d, IPEnd %d]", p.PayloadOffset, p.L4Offset, p.IPEnd())
		}
	}
	if p.L4Offset < 0 && (p.PayloadOffset != -1 || p.SrcPort != 0 || p.DstPort != 0 ||
		p.ICMPType != 0 || p.L4ChecksumStatus != packet.L4ChecksumUnchecked) {
		t.Errorf("transport fields set without a transport header: %+v", resultOf(p))
	}
	if p.ICMPInnerSrc != nil && (p.L4Proto != packet.L4ICMP || len(p.ICMPInnerSrc) != len(p.IPSrc) || len(p.ICMPInnerDst) != len(p.IPDst)) {
		t.Errorf("ICMP inner %v -> %v on a %q packet from %v", p.ICMPInnerSrc, p.ICMPInnerDst, p.L4Proto, p.IPSrc)
	}
	if p.ICMPInnerSrc == nil && (p.ICMPInnerDst != nil || p.ICMPInnerHasPorts || p.ICMPInnerProto != 0) {
		t.Errorf("ICMP inner fields set without ICMPInnerSrc")
	}
	if pl := p.Payload(); p.PayloadOffset >= 0 && len(pl) > p.IPEnd()-p.PayloadOffset {
		t.Errorf("Payload() has %d bytes, more than the IP packet allows", len(pl))
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
		wire := min(uint64(len(data))+uint64(extraWire), math.MaxUint32)
		p := packet.NewParsedPacket(time.Unix(0, 0), uint32(len(data)), uint32(wire))
		p.RawData = data
		orig := bytes.Clone(data)

		lower.Parse(p)
		upper.Parse(p)

		checkInvariants(t, p, orig)
		_ = upper.ICMPLabel(p.IPVersion, p.ICMPType, p.ICMPCode)
	})
}
