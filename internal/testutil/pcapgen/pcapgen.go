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

// Pkt describes one frame. Proto is "tcp", "udp" or "icmp" (ICMPv6 for
// IPv6 addresses). An "icmp" Pkt is an Echo Request, or with Unreach set
// a port unreachable (ICMPv4 3/3, ICMPv6 1/4) quoting the IP header and
// first 8 transport bytes of *Unreach; Payload is then ignored. ICMP sets
// any other type and code (the 4 bytes after the checksum are zero unless
// it is an echo). An echo request or reply (ICMP 8/0, ICMPv6 128/129)
// carries the identifier and sequence number in Echo, default 1 and 1,
// followed by Payload. Flags are TCP flag letters from "SAFRPU". A TCP
// segment advertises a 64240-byte window unless ZeroWindow is set.
type Pkt struct {
	Proto        string
	Src, Dst     string
	Sport, Dport uint16
	Flags        string
	Seq, Ack     uint32
	Payload      []byte
	Unreach      *Pkt
	ICMP         *[2]uint8        // ICMP type and code
	Echo         *[2]uint16       // echo identifier and sequence number; nil means 1, 1
	TTL          uint8            // IPv4 TTL or IPv6 hop limit; 0 means 64
	EthDst       net.HardwareAddr // nil means 02:00:00:00:00:02
	EthSrc       net.HardwareAddr // nil means 02:00:00:00:00:01
	ZeroWindow   bool             // TCP window 0
}

// Broadcast is the Ethernet broadcast address, for Pkt.EthDst.
var Broadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// ZeroMAC is the all-zero address Linux puts on loopback frames, for
// Pkt.EthSrc and Pkt.EthDst.
var ZeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

// Bytes serializes the frame with correct lengths and checksums.
func (p Pkt) Bytes(tb testing.TB) []byte {
	tb.Helper()
	src, dst := net.ParseIP(p.Src), net.ParseIP(p.Dst)
	if src == nil || dst == nil {
		tb.Fatalf("pcapgen: bad address in %+v", p)
	}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}}
	if p.EthDst != nil {
		eth.DstMAC = p.EthDst
	}
	if p.EthSrc != nil {
		eth.SrcMAC = p.EthSrc
	}
	ttl := p.TTL
	if ttl == 0 {
		ttl = 64
	}
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
		ip6 := &layers.IPv6{Version: 6, HopLimit: ttl, NextHeader: ipProto, SrcIP: src, DstIP: dst}
		ip, l3 = ip6, ip6
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{Version: 4, TTL: ttl, Flags: layers.IPv4DontFragment, Protocol: ipProto, SrcIP: src.To4(), DstIP: dst.To4()}
		ip, l3 = ip4, ip4
	}
	ls := []gopacket.SerializableLayer{eth, l3}
	switch p.Proto {
	case "tcp":
		tcp := &layers.TCP{SrcPort: layers.TCPPort(p.Sport), DstPort: layers.TCPPort(p.Dport), Seq: p.Seq, Ack: p.Ack, Window: 64240}
		if p.ZeroWindow {
			tcp.Window = 0
		}
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
		v6Type := layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)
		echo := [2]uint16{1, 1}
		if p.Echo != nil {
			echo = *p.Echo
		}
		isEcho := true
		v4 := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: echo[0], Seq: echo[1]}
		if p.Unreach != nil {
			isEcho = false
			v6Type = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodePortUnreachable)
			v4 = &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodePort)}
			inner := p.Unreach.Bytes(tb)[14:] // strip Ethernet
			hdr := 40
			if !v6 {
				hdr = int(inner[0]&0x0f) * 4
			}
			quote := inner[:min(len(inner), hdr+8)]
			if v6 {
				quote = append(make([]byte, 4), quote...) // the ICMPv6 layer has no unused field
			}
			p.Payload = quote
		} else if p.ICMP != nil {
			v6Type = layers.CreateICMPv6TypeCode(p.ICMP[0], p.ICMP[1])
			v4 = &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(p.ICMP[0], p.ICMP[1])}
			isEcho = v6 && (p.ICMP[0] == 128 || p.ICMP[0] == 129) || !v6 && (p.ICMP[0] == 8 || p.ICMP[0] == 0)
			switch {
			case isEcho && !v6:
				v4.Id, v4.Seq = echo[0], echo[1]
			case !isEcho && v6:
				p.Payload = append(make([]byte, 4), p.Payload...) // unused field
			}
		}
		if isEcho && v6 { // the ICMPv6 layer has no identifier or sequence fields
			p.Payload = append([]byte{byte(echo[0] >> 8), byte(echo[0]), byte(echo[1] >> 8), byte(echo[1])}, p.Payload...)
		}
		if v6 {
			icmp := &layers.ICMPv6{TypeCode: v6Type}
			if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
				tb.Fatal(err)
			}
			ls = append(ls, icmp)
		} else {
			ls = append(ls, v4)
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

// Frag describes one IP fragment. Data is the fragment's part of the
// original IP payload (the first fragment's starts with the transport
// header); Offset is in bytes, a multiple of 8. IPv4 fragments get a valid
// header checksum; IPv6 fragments one Fragment header whose Next Header is
// Proto.
type Frag struct {
	Src, Dst string
	ID       uint32
	Proto    uint8
	Offset   int
	MF       bool
	Data     []byte
	TTL      uint8 // 0 means 64
}

// Bytes builds the frame.
func (f Frag) Bytes(tb testing.TB) []byte {
	tb.Helper()
	src, dst := net.ParseIP(f.Src), net.ParseIP(f.Dst)
	if src == nil || dst == nil || f.Offset%8 != 0 || f.Offset > 0xfff8 {
		tb.Fatalf("pcapgen: bad fragment %+v", f)
	}
	ttl := f.TTL
	if ttl == 0 {
		ttl = 64
	}
	eth := []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00}
	if s4 := src.To4(); s4 != nil {
		h := make([]byte, 20)
		h[0] = 0x45
		binary.BigEndian.PutUint16(h[2:], uint16(20+len(f.Data)))
		binary.BigEndian.PutUint16(h[4:], uint16(f.ID))
		ff := uint16(f.Offset / 8)
		if f.MF {
			ff |= 0x2000
		}
		binary.BigEndian.PutUint16(h[6:], ff)
		h[8], h[9] = ttl, f.Proto
		copy(h[12:], s4)
		copy(h[16:], dst.To4())
		var sum uint32
		for i := 0; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(h[i:]))
		}
		for sum > 0xffff {
			sum = sum&0xffff + sum>>16
		}
		binary.BigEndian.PutUint16(h[10:], ^uint16(sum))
		return append(append(eth, h...), f.Data...)
	}
	eth[12], eth[13] = 0x86, 0xdd
	h := make([]byte, 48)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(f.Data)))
	h[6], h[7] = 44, ttl
	copy(h[8:], src.To16())
	copy(h[24:], dst.To16())
	h[40] = f.Proto
	ff := uint16(f.Offset)
	if f.MF {
		ff |= 1
	}
	binary.BigEndian.PutUint16(h[42:], ff)
	binary.BigEndian.PutUint32(h[44:], f.ID)
	return append(append(eth, h...), f.Data...)
}

// Fragment splits p the way a sender with link MTU mtu does: p is
// serialized with correct checksums, and its IP payload is cut into
// fragments whose IP packets fit in mtu bytes.
func Fragment(tb testing.TB, p Pkt, id uint32, mtu int) []Frag {
	tb.Helper()
	b := p.Bytes(tb)[14:]
	hdr, proto, room, end := 20, b[9], mtu-20, int(binary.BigEndian.Uint16(b[2:]))
	if b[0]>>4 == 6 {
		hdr, proto, room, end = 40, b[6], mtu-48, 40+int(binary.BigEndian.Uint16(b[4:]))
	}
	payload := b[hdr:end] // without Ethernet padding
	room &^= 7
	var out []Frag
	for off := 0; off < len(payload); off += room {
		end := min(off+room, len(payload))
		out = append(out, Frag{Src: p.Src, Dst: p.Dst, ID: id, Proto: proto, Offset: off, MF: end < len(payload), Data: payload[off:end], TTL: p.TTL})
	}
	return out
}

// AddFrag writes one fragment.
func (w *Writer) AddFrag(f Frag) {
	w.tb.Helper()
	w.Frame(f.Bytes(w.tb))
}

// Writer writes frames to a pcap file. Now is the timestamp of the next
// frame; Add and the Conn helpers advance it by Step after each frame.
type Writer struct {
	tb   testing.TB
	f    *os.File
	w    *pcapgo.Writer
	Now  time.Time
	Step time.Duration
	// Snap, if positive, captures at most Snap bytes of each frame (as
	// tcpdump -s does); the record keeps the frame's full length.
	Snap int
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
	n := len(b)
	if w.Snap > 0 && len(b) > w.Snap {
		b = b[:w.Snap]
	}
	if err := w.w.WritePacket(gopacket.CaptureInfo{Timestamp: w.Now, CaptureLength: len(b), Length: n}, b); err != nil {
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
// directions. ServerTTL, if set, is the TTL of every packet the server
// sends (0 means 64).
type Conn struct {
	w              *Writer
	Client, Server string
	CPort, SPort   uint16
	ServerTTL      uint8
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
	c.w.Add(Pkt{Proto: "tcp", Src: c.Server, Dst: c.Client, Sport: c.SPort, Dport: c.CPort, TTL: c.ServerTTL, Flags: "RA", Ack: c.cseq + 1})
}

// SYNACK writes the server's SYN/ACK answer to a SYN.
func (c *Conn) SYNACK() {
	c.w.tb.Helper()
	c.w.Add(Pkt{Proto: "tcp", Src: c.Server, Dst: c.Client, Sport: c.SPort, Dport: c.CPort, TTL: c.ServerTTL, Flags: "SA", Seq: c.sseq, Ack: c.cseq + 1})
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
		c.w.Add(Pkt{Proto: "tcp", Src: c.Server, Dst: c.Client, Sport: c.SPort, Dport: c.CPort, TTL: c.ServerTTL, Flags: "A", Seq: c.sseq, Ack: c.cseq})
		return
	}
	c.w.Add(Pkt{Proto: "tcp", Src: c.Server, Dst: c.Client, Sport: c.SPort, Dport: c.CPort, TTL: c.ServerTTL, Flags: "PA", Seq: c.sseq, Ack: c.cseq, Payload: payload})
	c.sseq += uint32(len(payload))
	c.w.Add(Pkt{Proto: "tcp", Src: c.Client, Dst: c.Server, Sport: c.CPort, Dport: c.SPort, Flags: "A", Seq: c.cseq, Ack: c.sseq})
}

// SetISN sets the initial sequence numbers of both directions (default
// 1000 and 5000), before Handshake. The first data byte follows at ISN+1.
func (c *Conn) SetISN(client, server uint32) { c.cseq, c.sseq = client, server }

// pkt is a segment of the connection with its own sequence number and
// the current acknowledgment of the peer's data.
func (c *Conn) pkt(fromClient bool, flags string, payload []byte) Pkt {
	if fromClient {
		return Pkt{Proto: "tcp", Src: c.Client, Dst: c.Server, Sport: c.CPort, Dport: c.SPort, Flags: flags, Seq: c.cseq, Ack: c.sseq, Payload: payload}
	}
	return Pkt{Proto: "tcp", Src: c.Server, Dst: c.Client, Sport: c.SPort, Dport: c.CPort, TTL: c.ServerTTL, Flags: flags, Seq: c.sseq, Ack: c.cseq, Payload: payload}
}

// Seg writes one data segment that starts off bytes after the sender's
// next sequence number (negative for a retransmission), without an ACK
// and without advancing the sequence number: with Advance, it writes
// segments out of order, retransmitted or overlapping.
func (c *Conn) Seg(fromClient bool, off int, payload []byte) {
	c.w.tb.Helper()
	p := c.pkt(fromClient, "PA", payload)
	p.Seq += uint32(off)
	c.w.Add(p)
}

// Advance moves the sender's next sequence number n bytes on (after the
// segments written with Seg) and writes the peer's ACK.
func (c *Conn) Advance(fromClient bool, n int) {
	c.w.tb.Helper()
	if fromClient {
		c.cseq += uint32(n)
	} else {
		c.sseq += uint32(n)
	}
	c.Ack(!fromClient, false)
}

// Push writes a data segment without the peer's ACK.
func (c *Conn) Push(fromClient bool, payload []byte) {
	c.w.tb.Helper()
	c.Seg(fromClient, 0, payload)
	if fromClient {
		c.cseq += uint32(len(payload))
	} else {
		c.sseq += uint32(len(payload))
	}
}

// Ack writes a bare ACK, advertising a zero window if zeroWindow.
func (c *Conn) Ack(fromClient, zeroWindow bool) {
	c.w.tb.Helper()
	p := c.pkt(fromClient, "A", nil)
	p.ZeroWindow = zeroWindow
	c.w.Add(p)
}

// Reset writes a RST/ACK.
func (c *Conn) Reset(fromClient bool) {
	c.w.tb.Helper()
	c.w.Add(c.pkt(fromClient, "RA", nil))
}

// Close writes a FIN exchange started by the client.
func (c *Conn) Close() {
	c.w.tb.Helper()
	c.w.Add(Pkt{Proto: "tcp", Src: c.Client, Dst: c.Server, Sport: c.CPort, Dport: c.SPort, Flags: "FA", Seq: c.cseq, Ack: c.sseq})
	c.cseq++
	c.w.Add(Pkt{Proto: "tcp", Src: c.Server, Dst: c.Client, Sport: c.SPort, Dport: c.CPort, TTL: c.ServerTTL, Flags: "FA", Seq: c.sseq, Ack: c.cseq})
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

// ARP describes one Ethernet/IPv4 ARP frame. Op is 1 (request) or 2
// (reply). Unset MACs take the usual values: EthSrc is SenderMAC; for a
// request EthDst is broadcast and TargetMAC zero, for a reply EthDst is
// TargetMAC.
type ARP struct {
	Op                   uint16
	SenderIP, TargetIP   string
	SenderMAC, TargetMAC net.HardwareAddr
	EthSrc, EthDst       net.HardwareAddr
}

// ARP operations.
const (
	ARPRequest = 1
	ARPReply   = 2
)

// Bytes serializes the frame.
func (a ARP) Bytes(tb testing.TB) []byte {
	tb.Helper()
	sip, tip := net.ParseIP(a.SenderIP).To4(), net.ParseIP(a.TargetIP).To4()
	if sip == nil || tip == nil || len(a.SenderMAC) != 6 {
		tb.Fatalf("pcapgen: bad ARP %+v", a)
	}
	tha, esrc, edst := a.TargetMAC, a.EthSrc, a.EthDst
	if tha == nil {
		tha = ZeroMAC
		if a.Op == ARPReply {
			tb.Fatalf("pcapgen: ARP reply without TargetMAC: %+v", a)
		}
	}
	if esrc == nil {
		esrc = a.SenderMAC
	}
	if edst == nil {
		edst = Broadcast
		if a.Op == ARPReply {
			edst = tha
		}
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: esrc, DstMAC: edst, EthernetType: layers.EthernetTypeARP},
		&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
			Operation: a.Op, SourceHwAddress: a.SenderMAC, SourceProtAddress: sip, DstHwAddress: tha, DstProtAddress: tip})
	if err != nil {
		tb.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// AddARP serializes and writes a.
func (w *Writer) AddARP(a ARP) {
	w.tb.Helper()
	w.Frame(a.Bytes(w.tb))
}

// MAC returns the locally administered address 02:00:00:00:hi:lo, for
// hosts numbered n in generated captures.
func MAC(n uint16) net.HardwareAddr {
	return net.HardwareAddr{2, 0, 0, 0, byte(n >> 8), byte(n)}
}
