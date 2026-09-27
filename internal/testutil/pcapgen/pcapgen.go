// Package pcapgen builds synthetic Ethernet frames and writes them to pcap
// files, for tests: scenario generators, fuzz seeds and edge-case files.
// It is imported only from _test.go files, so gopacket's serialization
// code never ends up in the ids binaries.
package pcapgen

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// T0 is the start time of generated captures. Scenarios never depend on
// wall-clock time, so a fixed start keeps runs reproducible.
var T0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// Pkt describes one frame. Proto is "tcp", "udp" or "icmp" (echo request;
// ICMPv6 for IPv6 addresses). Flags are TCP flag letters from "SAFRPU".
type Pkt struct {
	Proto        string
	Src, Dst     string
	Sport, Dport uint16
	Flags        string
	Seq, Ack     uint32
	Payload      []byte
}

// Bytes serializes the frame with correct lengths and checksums.
func (p Pkt) Bytes(tb testing.TB) []byte {
	tb.Helper()
	src, dst := net.ParseIP(p.Src), net.ParseIP(p.Dst)
	if src == nil || dst == nil {
		tb.Fatalf("pcapgen: bad address in %+v", p)
	}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}}
	v6 := src.To4() == nil
	var ipProto layers.IPProtocol
	switch p.Proto {
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
		tb.Fatalf("pcapgen: bad proto %q", p.Proto)
	}
	var ip gopacket.NetworkLayer
	var l3 gopacket.SerializableLayer
	if v6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: ipProto, SrcIP: src, DstIP: dst}
		ip, l3 = ip6, ip6
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{Version: 4, TTL: 64, Flags: layers.IPv4DontFragment, Protocol: ipProto, SrcIP: src.To4(), DstIP: dst.To4()}
		ip, l3 = ip4, ip4
	}
	ls := []gopacket.SerializableLayer{eth, l3}
	switch p.Proto {
	case "tcp":
		tcp := &layers.TCP{SrcPort: layers.TCPPort(p.Sport), DstPort: layers.TCPPort(p.Dport), Seq: p.Seq, Ack: p.Ack, Window: 64240}
		for _, c := range p.Flags {
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
				tb.Fatalf("pcapgen: bad TCP flag %q", c)
			}
		}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			tb.Fatal(err)
		}
		ls = append(ls, tcp)
	case "udp":
		udp := &layers.UDP{SrcPort: layers.UDPPort(p.Sport), DstPort: layers.UDPPort(p.Dport)}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			tb.Fatal(err)
		}
		ls = append(ls, udp)
	case "icmp":
		if v6 {
			icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
			if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
				tb.Fatal(err)
			}
			ls = append(ls, icmp)
		} else {
			ls = append(ls, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 1, Seq: 1})
		}
	}
	if len(p.Payload) > 0 {
		ls = append(ls, gopacket.Payload(p.Payload))
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		tb.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// Writer writes frames to a pcap file. Now is the timestamp of the next
// frame; Add and the Conn helpers advance it by Step after each frame.
type Writer struct {
	tb   testing.TB
	f    *os.File
	w    *pcapgo.Writer
	Now  time.Time
	Step time.Duration
}

// Create starts an Ethernet pcap file with a 262144-byte snaplen.
func Create(tb testing.TB, path string) *Writer {
	tb.Helper()
	f, err := os.Create(path)
	if err != nil {
		tb.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(262144, layers.LinkTypeEthernet); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { f.Close() })
	return &Writer{tb: tb, f: f, w: w, Now: T0, Step: time.Millisecond}
}

// Frame writes raw frame bytes at w.Now, then advances w.Now by w.Step.
func (w *Writer) Frame(b []byte) {
	w.tb.Helper()
	if err := w.w.WritePacket(gopacket.CaptureInfo{Timestamp: w.Now, CaptureLength: len(b), Length: len(b)}, b); err != nil {
		w.tb.Fatal(err)
	}
	w.Now = w.Now.Add(w.Step)
}

// Add serializes and writes p.
func (w *Writer) Add(p Pkt) {
	w.tb.Helper()
	w.Frame(p.Bytes(w.tb))
}

// Wait advances the clock without writing anything.
func (w *Writer) Wait(d time.Duration) { w.Now = w.Now.Add(d) }

// Close flushes and closes the file.
func (w *Writer) Close() {
	w.tb.Helper()
	if err := w.f.Close(); err != nil {
		w.tb.Fatal(err)
	}
}

// Conn is a TCP connection with correct sequence numbers in both
// directions.
type Conn struct {
	w              *Writer
	Client, Server string
	CPort, SPort   uint16
	cseq, sseq     uint32
}

// Conn starts a connection description; nothing is written until
// Handshake or a Send.
func (w *Writer) Conn(client string, cport uint16, server string, sport uint16) *Conn {
	return &Conn{w: w, Client: client, Server: server, CPort: cport, SPort: sport, cseq: 1000, sseq: 5000}
}

// SYN writes only the client's SYN (a half-open attempt).
func (c *Conn) SYN() {
	c.w.tb.Helper()
	c.w.Add(Pkt{Proto: "tcp", Src: c.Client, Dst: c.Server, Sport: c.CPort, Dport: c.SPort, Flags: "S", Seq: c.cseq})
}

// Refuse writes the server's RST/ACK answer to a SYN.
func (c *Conn) Refuse() {
	c.w.tb.Helper()
	c.w.Add(Pkt{Proto: "tcp", Src: c.Server, Dst: c.Client, Sport: c.SPort, Dport: c.CPort, Flags: "RA", Ack: c.cseq + 1})
}

// SYNACK writes the server's SYN/ACK answer to a SYN.
func (c *Conn) SYNACK() {
	c.w.tb.Helper()
	c.w.Add(Pkt{Proto: "tcp", Src: c.Server, Dst: c.Client, Sport: c.SPort, Dport: c.CPort, Flags: "SA", Seq: c.sseq, Ack: c.cseq + 1})
}

// Handshake writes SYN, SYN/ACK, ACK.
func (c *Conn) Handshake() {
	c.w.tb.Helper()
	c.SYN()
	c.SYNACK()
	c.cseq++
	c.sseq++
	c.w.Add(Pkt{Proto: "tcp", Src: c.Client, Dst: c.Server, Sport: c.CPort, Dport: c.SPort, Flags: "A", Seq: c.cseq, Ack: c.sseq})
}

// Send writes a data segment from the client (fromClient) or the server,
// followed by the peer's ACK.
func (c *Conn) Send(fromClient bool, payload []byte) {
	c.w.tb.Helper()
	if fromClient {
		c.w.Add(Pkt{Proto: "tcp", Src: c.Client, Dst: c.Server, Sport: c.CPort, Dport: c.SPort, Flags: "PA", Seq: c.cseq, Ack: c.sseq, Payload: payload})
		c.cseq += uint32(len(payload))
		c.w.Add(Pkt{Proto: "tcp", Src: c.Server, Dst: c.Client, Sport: c.SPort, Dport: c.CPort, Flags: "A", Seq: c.sseq, Ack: c.cseq})
		return
	}
	c.w.Add(Pkt{Proto: "tcp", Src: c.Server, Dst: c.Client, Sport: c.SPort, Dport: c.CPort, Flags: "PA", Seq: c.sseq, Ack: c.cseq, Payload: payload})
	c.sseq += uint32(len(payload))
	c.w.Add(Pkt{Proto: "tcp", Src: c.Client, Dst: c.Server, Sport: c.CPort, Dport: c.SPort, Flags: "A", Seq: c.cseq, Ack: c.sseq})
}

// Close writes a FIN exchange started by the client.
func (c *Conn) Close() {
	c.w.tb.Helper()
	c.w.Add(Pkt{Proto: "tcp", Src: c.Client, Dst: c.Server, Sport: c.CPort, Dport: c.SPort, Flags: "FA", Seq: c.cseq, Ack: c.sseq})
	c.cseq++
	c.w.Add(Pkt{Proto: "tcp", Src: c.Server, Dst: c.Client, Sport: c.SPort, Dport: c.CPort, Flags: "FA", Seq: c.sseq, Ack: c.cseq})
	c.sseq++
	c.w.Add(Pkt{Proto: "tcp", Src: c.Client, Dst: c.Server, Sport: c.CPort, Dport: c.SPort, Flags: "A", Seq: c.cseq, Ack: c.sseq})
}

// DNSQuery builds a DNS query message for one name. qtype is the numeric
// type (1 = A, 28 = AAAA, 252 = AXFR).
func DNSQuery(id uint16, name string, qtype uint16) []byte {
	m := binary.BigEndian.AppendUint16(nil, id)
	m = append(m, 0x01, 0x00)             // RD
	m = append(m, 0, 1, 0, 0, 0, 0, 0, 0) // qd=1
	m = append(m, DNSName(name)...)
	m = binary.BigEndian.AppendUint16(m, qtype)
	return binary.BigEndian.AppendUint16(m, 1) // IN
}

// DNSAnswerA builds a response to an A query with one address, using a
// compression pointer to the question name.
func DNSAnswerA(id uint16, name string, addr [4]byte) []byte {
	m := binary.BigEndian.AppendUint16(nil, id)
	m = append(m, 0x81, 0x80)             // QR RD RA
	m = append(m, 0, 1, 0, 1, 0, 0, 0, 0) // qd=1 an=1
	m = append(m, DNSName(name)...)
	m = append(m, 0, 1, 0, 1)
	m = append(m, 0xC0, 12)         // pointer to the question name
	m = append(m, 0, 1, 0, 1)       // A IN
	m = append(m, 0, 0, 0x0e, 0x10) // TTL 3600
	m = append(m, 0, 4)
	return append(m, addr[:]...)
}

// DNSName encodes a dotted name as labels.
func DNSName(name string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				out = append(out, byte(i-start))
				out = append(out, name[start:i]...)
			}
			start = i + 1
		}
	}
	return append(out, 0)
}

// TCPDNS adds the 2-byte length prefix used by DNS over TCP.
func TCPDNS(msg []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
}

// TLSClientHello builds a minimal TLS 1.2 ClientHello record with an SNI
// extension.
func TLSClientHello(sni string) []byte {
	name := []byte(sni)
	sn := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3)) // server_name_list
	sn = append(sn, 0)                                            // host_name
	sn = binary.BigEndian.AppendUint16(sn, uint16(len(name)))
	sn = append(sn, name...)
	ext := binary.BigEndian.AppendUint16(nil, 0) // server_name
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(sn)))
	ext = append(ext, sn...)

	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id
	body = append(body, 0, 2, 0xc0, 0x2f)    // one cipher suite
	body = append(body, 1, 0)                // null compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{22, 3, 1}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}
