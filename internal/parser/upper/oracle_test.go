package upper_test

// Cross-check against gopacket. gopacket builds the frames and computes
// their transport checksums (SerializeOptions.ComputeChecksums), so our
// checksum code is checked against an independent implementation. It is
// used here only as a test oracle; the parser itself never imports it.

import (
	"bytes"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
)

var (
	oMacA = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	oMacB = net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	oIP4A = net.IP{192, 168, 1, 10}
	oIP4B = net.IP{93, 184, 216, 34}
	oIP6A = net.ParseIP("2001:db8:1::10")
	oIP6B = net.ParseIP("2606:2800:220:1::1")
)

type checksummer interface {
	SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
}

func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	// Transport checksums cover a pseudo-header from the network layer.
	var nl gopacket.NetworkLayer
	for _, l := range ls {
		if n, ok := l.(gopacket.NetworkLayer); ok {
			nl = n
		}
	}
	for _, l := range ls {
		if c, ok := l.(checksummer); ok {
			if err := c.SetNetworkLayerForChecksum(nl); err != nil {
				t.Fatal(err)
			}
		}
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return bytes.Clone(buf.Bytes())
}

func oEth(t layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: oMacA, DstMAC: oMacB, EthernetType: t}
}

func oIPv4(proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{Version: 4, IHL: 5, TTL: 57, Id: 0xBEEF, Flags: layers.IPv4DontFragment,
		Protocol: proto, SrcIP: oIP4A, DstIP: oIP4B}
}

func oIPv6(nh layers.IPProtocol) *layers.IPv6 {
	return &layers.IPv6{Version: 6, HopLimit: 255, NextHeader: nh, SrcIP: oIP6A, DstIP: oIP6B}
}

// Ports without a gopacket application decoder, so the oracle stops at UDP.
func oUDP() *layers.UDP { return &layers.UDP{SrcPort: 40000, DstPort: 9999} }

func oPayload(s string) gopacket.Payload { return gopacket.Payload(s) }

// offsetIn returns where sub starts inside data. With gopacket.NoCopy, layer
// slices share data's backing array, so the capacity difference is the
// offset.
func offsetIn(data, sub []byte) int { return cap(data) - cap(sub) }

func TestParseMatchesGopacket(t *testing.T) {
	syn := &layers.TCP{SrcPort: 44321, DstPort: 443, Seq: 0x01020304, SYN: true, Window: 64240,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: []byte{0, 0, 0, 1, 0, 0, 0, 0}},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
		}}
	dataSeg := func() *layers.TCP {
		return &layers.TCP{SrcPort: 44321, DstPort: 443, Seq: 0xfffffff0, Ack: 0x7a7b7c7d,
			ACK: true, PSH: true, Window: 502}
	}
	finRst := &layers.TCP{SrcPort: 80, DstPort: 51000, Seq: 9, Ack: 10, FIN: true, RST: true, URG: true, ACK: true, Window: 0, Urgent: 1}
	hbh := oIPv6(layers.IPProtocolIPv6HopByHop)
	hbh.HopByHop = &layers.IPv6HopByHop{Options: []*layers.IPv6HopByHopOption{
		{OptionType: 0x1e, OptionData: []byte{1, 2, 3, 4}},
	}}
	hbh.HopByHop.NextHeader = layers.IPProtocolTCP
	unreachBody := oPayload(string(serialize(t, oIPv4(layers.IPProtocolUDP), oUDP(), oPayload("orig"))))

	eth4 := func() *layers.Ethernet { return oEth(layers.EthernetTypeIPv4) }
	eth6 := func() *layers.Ethernet { return oEth(layers.EthernetTypeIPv6) }

	tests := []struct {
		name   string
		layers []gopacket.SerializableLayer
	}{
		{"ipv4 tcp syn with options", []gopacket.SerializableLayer{eth4(), oIPv4(layers.IPProtocolTCP), syn}},
		{"ipv4 tcp ack with payload", []gopacket.SerializableLayer{eth4(), oIPv4(layers.IPProtocolTCP), dataSeg(), oPayload("GET / HTTP/1.1\r\nHost: x\r\n\r\n")}},
		{"ipv4 tcp odd-length payload", []gopacket.SerializableLayer{eth4(), oIPv4(layers.IPProtocolTCP), finRst, oPayload("abc")}},
		{"ipv4 tcp padded", []gopacket.SerializableLayer{eth4(), oIPv4(layers.IPProtocolTCP), dataSeg()}},
		{"ipv4 udp", []gopacket.SerializableLayer{eth4(), oIPv4(layers.IPProtocolUDP), oUDP(), oPayload("some udp payload bytes")}},
		{"ipv4 udp odd length, padded", []gopacket.SerializableLayer{eth4(), oIPv4(layers.IPProtocolUDP), oUDP(), oPayload("x")}},
		{"802.1Q ipv4 udp", []gopacket.SerializableLayer{oEth(layers.EthernetTypeDot1Q),
			&layers.Dot1Q{VLANIdentifier: 42, Type: layers.EthernetTypeIPv4}, oIPv4(layers.IPProtocolUDP), oUDP(), oPayload("vlan")}},
		{"ipv4 icmp echo", []gopacket.SerializableLayer{eth4(), oIPv4(layers.IPProtocolICMPv4),
			&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 0x4242, Seq: 7}, oPayload("abcdefghijklmnopq")}},
		{"ipv4 icmp port unreachable", []gopacket.SerializableLayer{eth4(), oIPv4(layers.IPProtocolICMPv4),
			&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 3)}, unreachBody}},
		{"ipv6 tcp", []gopacket.SerializableLayer{eth6(), oIPv6(layers.IPProtocolTCP), dataSeg(), oPayload("hello")}},
		{"ipv6 hop-by-hop tcp", []gopacket.SerializableLayer{eth6(), hbh, dataSeg(), oPayload("hbh!")}},
		{"ipv6 udp", []gopacket.SerializableLayer{eth6(), oIPv6(layers.IPProtocolUDP), oUDP(), oPayload("v6 udp")}},
		{"ipv6 icmpv6 echo", []gopacket.SerializableLayer{eth6(), oIPv6(layers.IPProtocolICMPv6),
			&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)},
			&layers.ICMPv6Echo{Identifier: 0x1234, SeqNumber: 1}, oPayload("ping6")}},
		{"ipv6 neighbor solicitation", []gopacket.SerializableLayer{eth6(), oIPv6(layers.IPProtocolICMPv6),
			&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(135, 0)},
			&layers.ICMPv6NeighborSolicitation{TargetAddress: oIP6B, Options: []layers.ICMPv6Option{
				{Type: layers.ICMPv6OptSourceAddress, Data: oMacA},
			}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := serialize(t, tt.layers...)
			p := newPacket(bytes.Clone(data), 0)
			lower.Parse(p)
			upper.Parse(p)
			if p.HasErrors() {
				t.Errorf("ParseErrors = %q", p.ParseErrors)
			}
			eq(t, "L4ChecksumStatus", p.L4ChecksumStatus, packet.L4ChecksumValid)

			g := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{NoCopy: true})
			if el := g.ErrorLayer(); el != nil {
				t.Fatalf("gopacket decode error: %v", el.Error())
			}
			// Where gopacket says the IP packet ends (it trims padding).
			ipPayload := g.NetworkLayer().LayerPayload()
			ipEnd := offsetIn(data, ipPayload) + len(ipPayload)
			eq(t, "IPEnd", p.IPEnd(), ipEnd)

			switch {
			case g.Layer(layers.LayerTypeTCP) != nil:
				tc := g.Layer(layers.LayerTypeTCP).(*layers.TCP)
				eq(t, "L4Proto", p.L4Proto, packet.L4TCP)
				eq(t, "L4Offset", p.L4Offset, offsetIn(data, tc.LayerContents()))
				eq(t, "SrcPort", p.SrcPort, uint16(tc.SrcPort))
				eq(t, "DstPort", p.DstPort, uint16(tc.DstPort))
				eq(t, "TCPSeq", p.TCPSeq, tc.Seq)
				eq(t, "TCPAck", p.TCPAck, tc.Ack)
				eq(t, "TCPWindow", p.TCPWindow, tc.Window)
				eq(t, "TCPFlags", p.TCPFlags, packet.TCPFlags{SYN: tc.SYN, ACK: tc.ACK, FIN: tc.FIN,
					RST: tc.RST, PSH: tc.PSH, URG: tc.URG})
				eq(t, "PayloadOffset", p.PayloadOffset, offsetIn(data, tc.LayerPayload()))
				eq(t, "Payload", string(p.Payload()), string(tc.LayerPayload()))

			case g.Layer(layers.LayerTypeUDP) != nil:
				u := g.Layer(layers.LayerTypeUDP).(*layers.UDP)
				eq(t, "L4Proto", p.L4Proto, packet.L4UDP)
				eq(t, "L4Offset", p.L4Offset, offsetIn(data, u.LayerContents()))
				eq(t, "SrcPort", p.SrcPort, uint16(u.SrcPort))
				eq(t, "DstPort", p.DstPort, uint16(u.DstPort))
				eq(t, "UDPLen", p.UDPLen, u.Length)
				eq(t, "PayloadOffset", p.PayloadOffset, offsetIn(data, u.LayerPayload()))
				eq(t, "Payload", string(p.Payload()), string(u.LayerPayload()))

			case g.Layer(layers.LayerTypeICMPv4) != nil:
				ic := g.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
				l4 := offsetIn(data, ic.LayerContents())
				eq(t, "L4Proto", p.L4Proto, packet.L4ICMP)
				eq(t, "L4Offset", p.L4Offset, l4)
				eq(t, "ICMPType", p.ICMPType, ic.TypeCode.Type())
				eq(t, "ICMPCode", p.ICMPCode, ic.TypeCode.Code())
				// gopacket's ICMPv4 layer always takes 8 bytes (id/seq, or
				// the unused word of an error); ours takes 8 only for echo.
				off := l4 + 4
				if typ := ic.TypeCode.Type(); typ == 0 || typ == 8 {
					off = offsetIn(data, ic.LayerPayload())
					eq(t, "ICMPEchoID", p.ICMPEchoID, ic.Id)
					eq(t, "ICMPEchoSeq", p.ICMPEchoSeq, ic.Seq)
				}
				eq(t, "HasICMPEcho", p.HasICMPEcho, off != l4+4)
				eq(t, "PayloadOffset", p.PayloadOffset, off)
				eq(t, "Payload", string(p.Payload()), string(data[off:ipEnd]))

			case g.Layer(layers.LayerTypeICMPv6) != nil:
				ic := g.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
				l4 := offsetIn(data, ic.LayerContents())
				eq(t, "L4Proto", p.L4Proto, packet.L4ICMP)
				eq(t, "L4Offset", p.L4Offset, l4)
				eq(t, "ICMPType", p.ICMPType, ic.TypeCode.Type())
				eq(t, "ICMPCode", p.ICMPCode, ic.TypeCode.Code())
				pl := ic.LayerPayload()
				echo, isEcho := g.Layer(layers.LayerTypeICMPv6Echo).(*layers.ICMPv6Echo)
				if isEcho {
					// gopacket's echo layer does not expose the data, so
					// take it from the ICMPv6 payload after id and seq.
					pl = pl[4:]
					eq(t, "ICMPEchoID", p.ICMPEchoID, echo.Identifier)
					eq(t, "ICMPEchoSeq", p.ICMPEchoSeq, echo.SeqNumber)
				}
				eq(t, "HasICMPEcho", p.HasICMPEcho, isEcho)
				eq(t, "PayloadOffset", p.PayloadOffset, offsetIn(data, pl))
				eq(t, "Payload", string(p.Payload()), string(pl))

			default:
				t.Fatalf("gopacket found no transport layer in %v", g)
			}

			// Any single-byte change inside the checksummed segment must
			// make the checksum Invalid.
			bad := bytes.Clone(data)
			bad[ipEnd-1] ^= 0x01
			q := newPacket(bad, 0)
			lower.Parse(q)
			upper.Parse(q)
			eq(t, "L4ChecksumStatus after corruption", q.L4ChecksumStatus, packet.L4ChecksumInvalid)
		})
	}
}

func eq[T comparable](t *testing.T, field string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, gopacket says %v", field, got, want)
	}
}
