package upper_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
)

// quoted4 returns an IPv4 header (src -> dst, proto, IHL from len(opts))
// followed by l4, as an ICMP error quotes it.
func quoted4(src, dst []byte, proto uint8, opts, l4 []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x40 | byte((20+len(opts))/4)
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(opts)+len(l4)))
	h[8] = 64
	h[9] = proto
	copy(h[12:], src)
	copy(h[16:], dst)
	return cat(h, opts, l4)
}

// quoted6 returns an IPv6 header (src -> dst, next header nh) followed by
// ext and l4.
func quoted6(src, dst []byte, nh uint8, ext, l4 []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(ext)+len(l4)))
	h[6] = nh
	h[7] = 64
	copy(h[8:], src)
	copy(h[24:], dst)
	return cat(h, ext, l4)
}

// ports8 is the first 8 bytes of a UDP header sport -> dport.
func ports8(sport, dport uint16) []byte { return cat(u16(sport), u16(dport), u16(8), u16(0)) }

// unreach returns an ICMP error message: type, code, 4 unused bytes, quote.
func unreach(typ, code byte, quote []byte) []byte {
	return cat([]byte{typ, code, 0, 0, 0, 0, 0, 0}, quote)
}

func TestParseICMPInner(t *testing.T) {
	prober4, target4 := []byte{203, 0, 113, 7}, []byte{192, 0, 2, 10}
	prober6 := []byte{0x20, 0x01, 0x0d, 0xb8, 15: 7}
	target6 := []byte{0x20, 0x01, 0x0d, 0xb8, 15: 10}
	udp4 := quoted4(prober4, target4, 17, nil, ports8(40000, 161))
	fragExt := func(next uint8, off uint16) []byte {
		return cat([]byte{next, 0}, u16(off), []byte{0, 0, 0, 1})
	}

	tests := []struct {
		name     string
		msg      []byte
		v6       bool
		ok       bool
		want     upper.ICMPInner
		wantPort bool
	}{
		{"v4 port unreachable", unreach(3, 3, udp4), false, true,
			upper.ICMPInner{Src: prober4, Dst: target4, Proto: 17, SrcPort: 40000, DstPort: 161, HasPorts: true}, true},
		{"v4 tcp quote", unreach(3, 13, quoted4(prober4, target4, 6, nil, tcp(0x02, nil, "")[:8])), false, true,
			upper.ICMPInner{Src: prober4, Dst: target4, Proto: 6, SrcPort: 40000, DstPort: 443, HasPorts: true}, true},
		{"v4 time exceeded", unreach(11, 0, udp4), false, true,
			upper.ICMPInner{Src: prober4, Dst: target4, Proto: 17, SrcPort: 40000, DstPort: 161, HasPorts: true}, true},
		// With 8 bytes of options the ports are at 28, not 20: reading at 20
		// would give 0x0102 and 0x0304.
		{"v4 inner options", unreach(3, 3, quoted4(prober4, target4, 17, []byte{1, 2, 3, 4, 5, 6, 7, 0}, ports8(40000, 161))), false, true,
			upper.ICMPInner{Src: prober4, Dst: target4, Proto: 17, SrcPort: 40000, DstPort: 161, HasPorts: true}, true},
		{"v4 only 4 port bytes", unreach(3, 3, udp4[:24]), false, true,
			upper.ICMPInner{Src: prober4, Dst: target4, Proto: 17, SrcPort: 40000, DstPort: 161, HasPorts: true}, true},
		{"v4 quote stops inside ports", unreach(3, 3, udp4[:23]), false, true,
			upper.ICMPInner{Src: prober4, Dst: target4, Proto: 17}, false},
		{"v4 header only", unreach(3, 3, udp4[:20]), false, true,
			upper.ICMPInner{Src: prober4, Dst: target4, Proto: 17}, false},
		{"v4 icmp quote has no ports", unreach(3, 1, quoted4(prober4, target4, 1, nil, []byte{8, 0, 0, 0, 0, 1, 0, 1})), false, true,
			upper.ICMPInner{Src: prober4, Dst: target4, Proto: 1}, false},
		{"v4 non-first fragment", unreach(3, 3, func() []byte {
			q := bytes.Clone(udp4)
			binary.BigEndian.PutUint16(q[6:], 185) // offset 1480
			return q
		}()), false, true, upper.ICMPInner{Src: prober4, Dst: target4, Proto: 17}, false},
		{"v4 first fragment keeps ports", unreach(3, 3, func() []byte {
			q := bytes.Clone(udp4)
			binary.BigEndian.PutUint16(q[6:], 0x2000) // MF
			return q
		}()), false, true, upper.ICMPInner{Src: prober4, Dst: target4, Proto: 17, SrcPort: 40000, DstPort: 161, HasPorts: true}, true},
		{"v4 truncated header", unreach(3, 3, udp4[:19]), false, false, upper.ICMPInner{}, false},
		{"v4 options past the quote", unreach(3, 3, quoted4(prober4, target4, 17, []byte{1, 0, 0, 0}, nil)[:22]), false, false, upper.ICMPInner{}, false},
		{"v4 ihl below 5", unreach(3, 3, func() []byte { q := bytes.Clone(udp4); q[0] = 0x44; return q }()), false, false, upper.ICMPInner{}, false},
		{"v4 quote is ipv6", unreach(3, 3, quoted6(prober6, target6, 17, nil, ports8(1, 2))), false, false, upper.ICMPInner{}, false},
		{"v4 echo request is not an error", unreach(8, 0, udp4), false, false, upper.ICMPInner{}, false},
		{"v4 echo reply is not an error", unreach(0, 0, udp4), false, false, upper.ICMPInner{}, false},
		{"message shorter than 8", []byte{3, 3, 0, 0, 0, 0, 0}, false, false, upper.ICMPInner{}, false},
		{"empty", nil, false, false, upper.ICMPInner{}, false},

		{"v6 port unreachable", unreach(1, 4, quoted6(prober6, target6, 17, nil, ports8(40000, 161))), true, true,
			upper.ICMPInner{Src: prober6, Dst: target6, Proto: 17, SrcPort: 40000, DstPort: 161, HasPorts: true}, true},
		{"v6 after options header", unreach(1, 4, quoted6(prober6, target6, 60, optsExt(17), ports8(40000, 161))), true, true,
			upper.ICMPInner{Src: prober6, Dst: target6, Proto: 17, SrcPort: 40000, DstPort: 161, HasPorts: true}, true},
		// AH counts its length in 4-byte units minus 2: 24 bytes here.
		{"v6 after hop-by-hop, routing and AH", unreach(1, 4, quoted6(prober6, target6, 0,
			cat([]byte{43, 0, 1, 4, 0, 0, 0, 0}, []byte{51, 0, 0, 0, 0, 0, 0, 0}, cat([]byte{17, 4, 0, 0}, make([]byte, 20))), ports8(40000, 161))), true, true,
			upper.ICMPInner{Src: prober6, Dst: target6, Proto: 17, SrcPort: 40000, DstPort: 161, HasPorts: true}, true},
		{"v6 first fragment", unreach(1, 4, quoted6(prober6, target6, 44, fragExt(17, 0), ports8(40000, 161))), true, true,
			upper.ICMPInner{Src: prober6, Dst: target6, Proto: 17, SrcPort: 40000, DstPort: 161, HasPorts: true}, true},
		{"v6 non-first fragment", unreach(1, 4, quoted6(prober6, target6, 44, fragExt(17, 1480), ports8(40000, 161))), true, true,
			upper.ICMPInner{Src: prober6, Dst: target6, Proto: 17}, false},
		{"v6 packet too big", unreach(2, 0, quoted6(prober6, target6, 6, nil, ports8(40000, 443))), true, true,
			upper.ICMPInner{Src: prober6, Dst: target6, Proto: 6, SrcPort: 40000, DstPort: 443, HasPorts: true}, true},
		{"v6 truncated fixed header", unreach(1, 4, quoted6(prober6, target6, 17, nil, nil)[:39]), true, false, upper.ICMPInner{}, false},
		{"v6 truncated extension header", unreach(1, 4, quoted6(prober6, target6, 60, optsExt(17), nil)[:41]), true, false, upper.ICMPInner{}, false},
		{"v6 extension header loop", unreach(1, 4, quoted6(prober6, target6, 60, bytes.Repeat(optsExt(60), 9), nil)), true, false, upper.ICMPInner{}, false},
		{"v6 quote is ipv4", unreach(1, 4, udp4), true, false, upper.ICMPInner{}, false},
		{"v6 echo request is not an error", unreach(128, 0, quoted6(prober6, target6, 17, nil, ports8(1, 2))), true, false, upper.ICMPInner{}, false},
		{"v6 neighbor solicitation", unreach(135, 0, make([]byte, 60)), true, false, upper.ICMPInner{}, false},
		{"garbage", bytes.Repeat([]byte{0xff}, 64), false, false, upper.ICMPInner{}, false},
		{"garbage v6", bytes.Repeat([]byte{0x01}, 64), true, false, upper.ICMPInner{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := bytes.Clone(tt.msg)
			got, ok := upper.ParseICMPInner(tt.msg, tt.v6)
			if !bytes.Equal(tt.msg, orig) {
				t.Fatal("ParseICMPInner modified its input")
			}
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (%+v)", ok, tt.ok, got)
			}
			if !ok {
				if got.Src != nil || got.Dst != nil || got.Proto != 0 || got.HasPorts {
					t.Errorf("fields set on failure: %+v", got)
				}
				return
			}
			if !net.IP(got.Src).Equal(tt.want.Src) || !net.IP(got.Dst).Equal(tt.want.Dst) ||
				got.Proto != tt.want.Proto || got.SrcPort != tt.want.SrcPort ||
				got.DstPort != tt.want.DstPort || got.HasPorts != tt.wantPort {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestParseICMPInnerCopies checks that the addresses do not alias the
// message, since RawData buffers can be reused by the capture layer.
func TestParseICMPInnerCopies(t *testing.T) {
	msg := unreach(3, 3, quoted4([]byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}, 17, nil, ports8(1, 2)))
	in, ok := upper.ParseICMPInner(msg, false)
	if !ok {
		t.Fatal("not decoded")
	}
	for i := range msg {
		msg[i] = 0
	}
	if !in.Src.Equal(net.IP{1, 2, 3, 4}) || !in.Dst.Equal(net.IP{5, 6, 7, 8}) {
		t.Errorf("addresses alias the message: %v %v", in.Src, in.Dst)
	}
}

// TestParseFillsICMPInner checks the ParsedPacket fields end to end, with
// the inner header at the right offset after the outer IP header.
func TestParseFillsICMPInner(t *testing.T) {
	quote := quoted4([]byte{10, 0, 0, 2}, []byte{10, 0, 0, 1}, 17, nil, ports8(40000, 161))
	tests := []struct {
		name  string
		frame []byte
		want  bool
		dport uint16
	}{
		{"v4 port unreachable", seal(ip4(1, icmp(3, 3, cat(make([]byte, 4), quote)), nil)), true, 161},
		{"v4 echo reply", seal(ip4(1, icmp(0, 0, cat(make([]byte, 4), quote)), nil)), false, 0},
		{"v6 port unreachable", seal(ip6(58, nil, icmp(1, 4, cat(make([]byte, 4), quoted6(ip6B, ip6A, 17, nil, ports8(40000, 161)))))), true, 161},
		{"v6 echo request", seal(ip6(58, nil, icmp(128, 0, cat(make([]byte, 4), quoted6(ip6B, ip6A, 17, nil, ports8(40000, 161)))))), false, 0},
		// A UDP datagram whose payload looks like a quote is not ICMP.
		{"udp carrying a quote", seal(ip4(17, cat(u16(1), u16(2), u16(uint16(8+8+len(quote))), u16(0), []byte{3, 3, 0, 0, 0, 0, 0, 0}, quote), nil)), false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPacket(bytes.Clone(tt.frame), 0)
			lower.Parse(p)
			upper.Parse(p)
			if got := p.ICMPInnerSrc != nil; got != tt.want {
				t.Fatalf("inner decoded = %v, want %v (errors %v)", got, tt.want, p.ParseErrors)
			}
			if tt.want && (!p.ICMPInnerHasPorts || p.ICMPInnerProto != 17 || p.ICMPInnerDstPort != tt.dport || p.ICMPInnerSrcPort != 40000 || !p.ICMPInnerDst.Equal(p.IPSrc) || !p.ICMPInnerSrc.Equal(p.IPDst)) {
				t.Errorf("inner = %v:%d -> %v:%d proto %d ports %v", p.ICMPInnerSrc, p.ICMPInnerSrcPort, p.ICMPInnerDst, p.ICMPInnerDstPort, p.ICMPInnerProto, p.ICMPInnerHasPorts)
			}
			if p.HasErrors() {
				t.Errorf("errors: %v", p.ParseErrors)
			}
		})
	}
}

func FuzzICMPInner(f *testing.F) {
	q4 := quoted4([]byte{203, 0, 113, 7}, []byte{192, 0, 2, 10}, 17, nil, ports8(40000, 161))
	q6 := quoted6(ip6A, ip6B, 60, optsExt(17), ports8(40000, 161))
	f.Add(unreach(3, 3, q4), false)
	f.Add(unreach(3, 3, quoted4(ip4A, ip4B, 6, []byte{1, 1, 1, 0}, ports8(1, 2))), false)
	f.Add(unreach(11, 0, q4[:22]), false)
	f.Add(unreach(1, 4, q6), true)
	f.Add(unreach(1, 4, quoted6(ip6A, ip6B, 44, []byte{17, 0, 0, 0, 0, 0, 0, 1}, ports8(1, 2))), true)
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, msg []byte, v6 bool) {
		orig := bytes.Clone(msg)
		in, ok := upper.ParseICMPInner(msg, v6)
		if !bytes.Equal(msg, orig) {
			t.Fatal("modified input")
		}
		if !ok {
			if in.Src != nil || in.Dst != nil || in.HasPorts {
				t.Fatalf("fields set on failure: %+v", in)
			}
			return
		}
		want := 4
		if v6 {
			want = 16
		}
		if len(in.Src) != want || len(in.Dst) != want {
			t.Fatalf("address lengths %d, %d for v6=%v", len(in.Src), len(in.Dst), v6)
		}
		if in.HasPorts && in.Proto != 6 && in.Proto != 17 {
			t.Fatalf("ports for protocol %d", in.Proto)
		}
		if !in.HasPorts && (in.SrcPort != 0 || in.DstPort != 0) {
			t.Fatalf("ports set without HasPorts: %+v", in)
		}
		if len(msg) < 8+20 {
			t.Fatalf("decoded a %d-byte message", len(msg))
		}
	})
}
