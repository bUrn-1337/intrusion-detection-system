package rules

// Test helpers: frames are built with gopacket (test files only) and run
// through the real Module 2-4 parsers, so rules see exactly what they see
// in production.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/bUrn-1337/intrusion-detection-system/internal/capture"
	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/app"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
)

var t0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func at(d time.Duration) time.Time { return t0.Add(d) }

// pkt describes one frame. proto is "tcp", "udp", "icmp" or "arp". For
// arp, src and dst are the sender and target IPs, the operation is a
// reply unless arpOp says otherwise, and the sender and target MACs are
// the Ethernet source and destination unless arpSHA or arpTHA is set. An icmp pkt is an Echo
// Request, or with unreach set a port unreachable (ICMPv4 3/3, ICMPv6
// 1/4) quoting the IP header and first 8 transport bytes of *unreach.
type pkt struct {
	proto        string
	src, dst     string
	sport, dport uint16
	flags        string // TCP flag letters, e.g. "S", "SA", "A", "R", "PA"
	seq, ack     uint32
	zeroWin      bool // TCP window 0 instead of 64240
	payload      string
	unreach      *pkt
	ttl          uint8     // IPv4 TTL or IPv6 hop limit; 0 means 64
	ethDst       [6]byte   // zero means 02:00:00:00:00:02
	ethSrc       [6]byte   // zero means 02:00:00:00:00:01
	zeroMACs     bool      // both Ethernet MACs all zero, as on Linux loopback
	icmp         *[2]uint8 // ICMP type and code, overriding Echo Request
	echoID       uint16    // echo Identifier and Sequence Number, for an echo request or reply
	echoSeq      uint16
	arpOp        uint16   // 0 means reply
	arpSHA       *[6]byte // ARP sender MAC, overriding the Ethernet source
	arpTHA       *[6]byte // ARP target MAC, overriding the Ethernet destination
}

func (s pkt) layers(tb testing.TB) []gopacket.SerializableLayer {
	tb.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}}
	if s.ethDst != [6]byte{} {
		eth.DstMAC = net.HardwareAddr(s.ethDst[:])
	}
	if s.ethSrc != [6]byte{} {
		eth.SrcMAC = net.HardwareAddr(s.ethSrc[:])
	}
	if s.zeroMACs {
		eth.SrcMAC, eth.DstMAC = make(net.HardwareAddr, 6), make(net.HardwareAddr, 6)
	}
	ttl := s.ttl
	if ttl == 0 {
		ttl = 64
	}
	if s.proto == "arp" {
		eth.EthernetType = layers.EthernetTypeARP
		op, sha, tha := s.arpOp, eth.SrcMAC, eth.DstMAC
		if op == 0 {
			op = layers.ARPReply
		}
		if s.arpSHA != nil {
			sha = net.HardwareAddr(s.arpSHA[:])
		}
		if s.arpTHA != nil {
			tha = net.HardwareAddr(s.arpTHA[:])
		}
		return []gopacket.SerializableLayer{eth, &layers.ARP{
			AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
			Operation: op, SourceHwAddress: sha, SourceProtAddress: net.ParseIP(s.src).To4(),
			DstHwAddress: tha, DstProtAddress: net.ParseIP(s.dst).To4(),
		}}
	}
	src, dst := net.ParseIP(s.src), net.ParseIP(s.dst)
	if src == nil || dst == nil {
		tb.Fatalf("bad address in %+v", s)
	}
	v6 := src.To4() == nil
	var ip gopacket.NetworkLayer
	var l3 gopacket.SerializableLayer
	var ipProto layers.IPProtocol
	switch s.proto {
	case "tcp":
		ipProto = layers.IPProtocolTCP
	case "udp":
		ipProto = layers.IPProtocolUDP
	case "icmp":
		ipProto = layers.IPProtocolICMPv4
		if v6 {
			ipProto = layers.IPProtocolICMPv6
		}
	default:
		tb.Fatalf("bad proto %q", s.proto)
	}
	if v6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 := &layers.IPv6{Version: 6, HopLimit: ttl, NextHeader: ipProto, SrcIP: src, DstIP: dst}
		ip, l3 = ip6, ip6
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{Version: 4, TTL: ttl, Protocol: ipProto, SrcIP: src.To4(), DstIP: dst.To4()}
		ip, l3 = ip4, ip4
	}
	out := []gopacket.SerializableLayer{eth, l3}
	switch s.proto {
	case "tcp":
		tcp := &layers.TCP{SrcPort: layers.TCPPort(s.sport), DstPort: layers.TCPPort(s.dport), Seq: s.seq, Ack: s.ack, Window: 64240}
		if s.zeroWin {
			tcp.Window = 0
		}
		for _, c := range s.flags {
			switch c {
			case 'S':
				tcp.SYN = true
			case 'A':
				tcp.ACK = true
			case 'F':
				tcp.FIN = true
			case 'R':
				tcp.RST = true
			case 'P':
				tcp.PSH = true
			case 'U':
				tcp.URG = true
			default:
				tb.Fatalf("bad flag %q", c)
			}
		}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			tb.Fatal(err)
		}
		out = append(out, tcp)
	case "udp":
		udp := &layers.UDP{SrcPort: layers.UDPPort(s.sport), DstPort: layers.UDPPort(s.dport)}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			tb.Fatal(err)
		}
		out = append(out, udp)
	case "icmp":
		v6Type, v4Type := layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0), layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)
		if s.unreach != nil {
			v6Type = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodePortUnreachable)
			v4Type = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodePort)
			inner := s.unreach.bytes(tb)[14:] // strip Ethernet
			ihl := 40
			if !v6 {
				ihl = int(inner[0]&0x0f) * 4
			}
			quote := inner[:ihl+8]
			if v6 {
				quote = append(make([]byte, 4), quote...) // ICMPv6 layer has no unused field
			}
			s.payload = string(quote)
		}
		if s.icmp != nil {
			v6Type = layers.CreateICMPv6TypeCode(s.icmp[0], s.icmp[1])
			v4Type = layers.CreateICMPv4TypeCode(s.icmp[0], s.icmp[1])
		}
		if v6 {
			icmp := &layers.ICMPv6{TypeCode: v6Type}
			if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
				tb.Fatal(err)
			}
			out = append(out, icmp)
			if t := v6Type.Type(); t == layers.ICMPv6TypeEchoRequest || t == layers.ICMPv6TypeEchoReply {
				// The ICMPv6 layer has no id and seq; ICMPv4's does.
				s.payload = string([]byte{byte(s.echoID >> 8), byte(s.echoID), byte(s.echoSeq >> 8), byte(s.echoSeq)}) + s.payload
			}
		} else {
			out = append(out, &layers.ICMPv4{TypeCode: v4Type, Id: s.echoID, Seq: s.echoSeq})
		}
	}
	if s.payload != "" {
		out = append(out, gopacket.Payload(s.payload))
	}
	return out
}

// fragFrame builds an Ethernet frame holding one IP fragment. data is the
// fragment's part of the original IP payload (for the first fragment it
// starts with the transport header), offset is in bytes and must be a
// multiple of 8. IPv4 fragments have TTL 64 and a valid header checksum;
// IPv6 fragments have one Fragment header whose Next Header is proto.
func fragFrame(tb testing.TB, src, dst string, id uint32, proto uint8, offset int, mf bool, data []byte) []byte {
	tb.Helper()
	sa, da := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	if offset%8 != 0 || offset > 0xfff8 {
		tb.Fatalf("bad fragment offset %d", offset)
	}
	eth := []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00}
	if sa.Is4() {
		h := make([]byte, 20)
		h[0] = 0x45
		binary.BigEndian.PutUint16(h[2:], uint16(20+len(data)))
		binary.BigEndian.PutUint16(h[4:], uint16(id))
		ff := uint16(offset / 8)
		if mf {
			ff |= 0x2000
		}
		binary.BigEndian.PutUint16(h[6:], ff)
		h[8], h[9] = 64, proto
		copy(h[12:], sa.AsSlice())
		copy(h[16:], da.AsSlice())
		var sum uint32
		for i := 0; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(h[i:]))
		}
		for sum > 0xffff {
			sum = sum&0xffff + sum>>16
		}
		binary.BigEndian.PutUint16(h[10:], ^uint16(sum))
		return slices.Concat(eth, h, data)
	}
	eth[12], eth[13] = 0x86, 0xdd
	h := make([]byte, 48)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(data)))
	h[6], h[7] = 44, 64
	copy(h[8:], sa.AsSlice())
	copy(h[24:], da.AsSlice())
	h[40] = proto
	ff := uint16(offset)
	if mf {
		ff |= 1
	}
	binary.BigEndian.PutUint16(h[42:], ff)
	binary.BigEndian.PutUint32(h[44:], id)
	return slices.Concat(eth, h, data)
}

// bytes serializes the frame.
func (s pkt) bytes(tb testing.TB) []byte {
	tb.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, s.layers(tb)...); err != nil {
		tb.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// parsed returns the frame after lower, upper and app parsing.
func (s pkt) parsed(tb testing.TB, ts time.Time) *packet.ParsedPacket {
	tb.Helper()
	return parseFrame(s.bytes(tb), ts)
}

func parseFrame(b []byte, ts time.Time) *packet.ParsedPacket {
	p := packet.NewParsedPacket(ts, uint32(len(b)), uint32(len(b)))
	p.RawData = b
	lower.Parse(p)
	upper.Parse(p)
	app.Parse(p)
	return p
}

func mustParse(tb testing.TB, text string) *RuleSet {
	tb.Helper()
	rs, err := Parse(strings.NewReader(text), "test.rules")
	if err != nil {
		tb.Fatalf("Parse: %v", err)
	}
	return rs
}

// frame is one record for a synthetic pcap.
type frame struct {
	ts time.Time
	b  []byte
}

func writePcap(tb testing.TB, frames []frame) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "test.pcap")
	f, err := os.Create(path)
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		tb.Fatal(err)
	}
	for _, fr := range frames {
		ci := gopacket.CaptureInfo{Timestamp: fr.ts, CaptureLength: len(fr.b), Length: len(fr.b)}
		if err := w.WritePacket(ci, fr.b); err != nil {
			tb.Fatal(err)
		}
	}
	return path
}

// replay runs a pcap through capture -> lower -> upper -> app -> engine
// and returns every alert, including those from Flush.
func replay(tb testing.TB, path string, e *Engine) []Alert {
	tb.Helper()
	cfg := capture.DefaultConfig()
	cfg.PcapFile = path
	c, err := capture.New(cfg)
	if err != nil {
		tb.Fatal(err)
	}
	defer c.Close()
	var out []Alert
	for p := range c.Start(context.Background()) {
		lower.Parse(p)
		upper.Parse(p)
		app.Parse(p)
		out = append(out, e.Process(p)...)
	}
	if err := c.Err(); err != nil {
		tb.Fatal(err)
	}
	return append(out, e.Flush()...)
}

// alertLine formats an alert compactly for comparisons and failure output.
func alertLine(a Alert) string {
	return fmt.Sprintf("%s sid=%d %s:%d->%s:%d count=%d t=%s first=%s last=%s %v",
		a.Kind, a.SID, a.SrcIP, a.SrcPort, a.DstIP, a.DstPort, a.Count,
		a.Time.Sub(t0), a.FirstSeen.Sub(t0), a.LastSeen.Sub(t0), a.Details)
}

func alertLines(as []Alert) string {
	var b strings.Builder
	for _, a := range as {
		b.WriteString("\n  " + alertLine(a))
	}
	return b.String()
}

// bySID counts alerts per (sid, kind).
func bySID(as []Alert) map[string]int {
	m := make(map[string]int)
	for _, a := range as {
		m[fmt.Sprintf("%d/%s", a.SID, a.Kind)]++
	}
	return m
}
