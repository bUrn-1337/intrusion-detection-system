package rules

// Test helpers: frames are built with gopacket (test files only) and run
// through the real Module 2-4 parsers, so rules see exactly what they see
// in production.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
// arp, src and dst are the sender and target IPs.
type pkt struct {
	proto        string
	src, dst     string
	sport, dport uint16
	flags        string // TCP flag letters, e.g. "S", "SA", "A", "R", "PA"
	seq, ack     uint32
	payload      string
}

func (s pkt) layers(tb testing.TB) []gopacket.SerializableLayer {
	tb.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}}
	if s.proto == "arp" {
		eth.EthernetType = layers.EthernetTypeARP
		return []gopacket.SerializableLayer{eth, &layers.ARP{
			AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
			Operation: layers.ARPReply, SourceHwAddress: eth.SrcMAC, SourceProtAddress: net.ParseIP(s.src).To4(),
			DstHwAddress: eth.DstMAC, DstProtAddress: net.ParseIP(s.dst).To4(),
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
		ip6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: ipProto, SrcIP: src, DstIP: dst}
		ip, l3 = ip6, ip6
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: ipProto, SrcIP: src.To4(), DstIP: dst.To4()}
		ip, l3 = ip4, ip4
	}
	out := []gopacket.SerializableLayer{eth, l3}
	switch s.proto {
	case "tcp":
		tcp := &layers.TCP{SrcPort: layers.TCPPort(s.sport), DstPort: layers.TCPPort(s.dport), Seq: s.seq, Ack: s.ack, Window: 64240}
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
		if v6 {
			icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
			if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
				tb.Fatal(err)
			}
			out = append(out, icmp)
		} else {
			out = append(out, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)})
		}
	}
	if s.payload != "" {
		out = append(out, gopacket.Payload(s.payload))
	}
	return out
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
