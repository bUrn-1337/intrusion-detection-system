package lower_test

// Cross-check against gopacket's decoders. gopacket is used here only as a
// test oracle; the parser itself never imports it.

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
)

var (
	oMacA = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	oMacB = net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	oIP4A = net.IP{192, 168, 1, 10}
	oIP4B = net.IP{93, 184, 216, 34}
	oIP6A = net.ParseIP("fe80::1")
	oIP6B = net.ParseIP("2606:2800:220:1::1")
)

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
		switch l := l.(type) {
		case *layers.TCP:
			if err := l.SetNetworkLayerForChecksum(nl); err != nil {
				t.Fatal(err)
			}
		case *layers.UDP:
			if err := l.SetNetworkLayerForChecksum(nl); err != nil {
				t.Fatal(err)
			}
		}
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func oEth(t layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: oMacA, DstMAC: oMacB, EthernetType: t}
}

func oIPv4(proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{Version: 4, IHL: 5, TTL: 57, Id: 0xBEEF, Flags: layers.IPv4DontFragment,
		Protocol: proto, SrcIP: oIP4A, DstIP: oIP4B}
}

func oIPv6(nh layers.IPProtocol) *layers.IPv6 {
	return &layers.IPv6{Version: 6, TrafficClass: 0x2e, FlowLabel: 0xabcde, HopLimit: 255,
		NextHeader: nh, SrcIP: oIP6A, DstIP: oIP6B}
}

func oTCP() *layers.TCP {
	return &layers.TCP{SrcPort: 44321, DstPort: 443, Seq: 1, SYN: true, Window: 64240}
}

// Ports without a gopacket application decoder, so the oracle stops at UDP.
func oUDP() *layers.UDP { return &layers.UDP{SrcPort: 40000, DstPort: 9999} }

func oPayload(s string) gopacket.Payload { return gopacket.Payload(s) }

// offsetIn returns where sub starts inside data. With gopacket.NoCopy, layer
// slices share data's backing array, so the capacity difference is the
// offset, even when gopacket trims padding off a layer's payload.
func offsetIn(data, sub []byte) int { return cap(data) - cap(sub) }

func TestParseMatchesGopacket(t *testing.T) {
	arpLayer := func(op uint16) *layers.ARP {
		return &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
			HwAddressSize: 6, ProtAddressSize: 4, Operation: op,
			SourceHwAddress: oMacA, SourceProtAddress: oIP4A,
			DstHwAddress: oMacB, DstProtAddress: oIP4B}
	}
	withOpts := oIPv4(layers.IPProtocolICMPv4)
	withOpts.Options = []layers.IPv4Option{
		{OptionType: 7, OptionLength: 7, OptionData: []byte{4, 0, 0, 0, 0}}, // record route
		{OptionType: 0, OptionLength: 1},                                    // end of list
	}
	firstFrag := oIPv4(layers.IPProtocolUDP)
	firstFrag.Flags = layers.IPv4MoreFragments
	laterFrag := oIPv4(layers.IPProtocolUDP)
	laterFrag.FragOffset = 185
	hbh := oIPv6(layers.IPProtocolIPv6HopByHop)
	hbh.HopByHop = &layers.IPv6HopByHop{Options: []*layers.IPv6HopByHopOption{
		{OptionType: 0x1e, OptionData: []byte{1, 2, 3, 4}},
	}}
	hbh.HopByHop.NextHeader = layers.IPProtocolUDP
	hbhFrag := oIPv6(layers.IPProtocolIPv6HopByHop)
	hbhFrag.HopByHop = &layers.IPv6HopByHop{Options: []*layers.IPv6HopByHopOption{
		{OptionType: 0x1e, OptionData: []byte{1, 2, 3, 4}},
	}}
	hbhFrag.HopByHop.NextHeader = layers.IPProtocolIPv6Fragment

	tests := []struct {
		name   string
		layers []gopacket.SerializableLayer
	}{
		{"ipv4 tcp", []gopacket.SerializableLayer{oEth(layers.EthernetTypeIPv4), oIPv4(layers.IPProtocolTCP), oTCP(), oPayload("GET / HTTP/1.1\r\n\r\n")}},
		{"ipv4 udp padded", []gopacket.SerializableLayer{oEth(layers.EthernetTypeIPv4), oIPv4(layers.IPProtocolUDP), oUDP(), oPayload("x")}},
		{"ipv4 options icmp", []gopacket.SerializableLayer{oEth(layers.EthernetTypeIPv4), withOpts,
			&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 1, Seq: 1}, oPayload("ping")}},
		{"ipv4 first fragment", []gopacket.SerializableLayer{oEth(layers.EthernetTypeIPv4), firstFrag, oUDP(), oPayload("first fragment data")}},
		{"ipv4 later fragment", []gopacket.SerializableLayer{oEth(layers.EthernetTypeIPv4), laterFrag, oPayload("tail data of a fragmented datagram")}},
		{"802.1Q ipv4 udp", []gopacket.SerializableLayer{oEth(layers.EthernetTypeDot1Q),
			&layers.Dot1Q{VLANIdentifier: 42, Type: layers.EthernetTypeIPv4}, oIPv4(layers.IPProtocolUDP), oUDP(), oPayload("vlan")}},
		{"QinQ ipv4 tcp", []gopacket.SerializableLayer{oEth(layers.EthernetTypeQinQ),
			&layers.Dot1Q{VLANIdentifier: 100, Type: layers.EthernetTypeDot1Q},
			&layers.Dot1Q{VLANIdentifier: 200, Type: layers.EthernetTypeIPv4}, oIPv4(layers.IPProtocolTCP), oTCP()}},
		{"ipv6 tcp", []gopacket.SerializableLayer{oEth(layers.EthernetTypeIPv6), oIPv6(layers.IPProtocolTCP), oTCP(), oPayload("hello")}},
		{"ipv6 hop-by-hop udp", []gopacket.SerializableLayer{oEth(layers.EthernetTypeIPv6), hbh, oUDP(), oPayload("hbh")}},
		{"ipv6 fragment", []gopacket.SerializableLayer{oEth(layers.EthernetTypeIPv6), oIPv6(layers.IPProtocolIPv6Fragment),
			&layers.IPv6Fragment{NextHeader: layers.IPProtocolUDP, FragmentOffset: 181, Identification: 0x01020304}, oPayload("fragment tail")}},
		{"ipv6 hop-by-hop first fragment", []gopacket.SerializableLayer{oEth(layers.EthernetTypeIPv6), hbhFrag,
			&layers.IPv6Fragment{NextHeader: layers.IPProtocolUDP, MoreFragments: true, Identification: 7}, oUDP(), oPayload("first part")}},
		{"802.1Q ipv6 udp", []gopacket.SerializableLayer{oEth(layers.EthernetTypeDot1Q),
			&layers.Dot1Q{VLANIdentifier: 7, Type: layers.EthernetTypeIPv6}, oIPv6(layers.IPProtocolUDP), oUDP(), oPayload("v6 in vlan")}},
		{"arp request", []gopacket.SerializableLayer{oEth(layers.EthernetTypeARP), arpLayer(layers.ARPRequest)}},
		{"arp reply", []gopacket.SerializableLayer{oEth(layers.EthernetTypeARP), arpLayer(layers.ARPReply)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := serialize(t, tt.layers...)
			if tt.name == "ipv4 udp padded" && len(data) != 60 {
				t.Fatalf("frame is %d bytes, want 60 (gopacket pads short Ethernet frames)", len(data))
			}
			p := newPacket(append([]byte(nil), data...), 0)
			lower.Parse(p)
			if p.HasErrors() {
				t.Errorf("ParseErrors = %q", p.ParseErrors)
			}

			g := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{NoCopy: true})
			if el := g.ErrorLayer(); el != nil {
				t.Fatalf("gopacket decode error: %v", el.Error())
			}

			eth := g.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
			wantType := eth.EthernetType
			for _, l := range g.Layers() {
				if q, ok := l.(*layers.Dot1Q); ok {
					wantType = q.Type
				}
			}
			eq(t, "EthSrc", p.EthSrc.String(), eth.SrcMAC.String())
			eq(t, "EthDst", p.EthDst.String(), eth.DstMAC.String())
			eq(t, "EthType", p.EthType, uint16(wantType))

			wantL4 := -1
			if tl := g.TransportLayer(); tl != nil {
				wantL4 = offsetIn(data, tl.LayerContents())
			} else if ic := g.Layer(layers.LayerTypeICMPv4); ic != nil {
				wantL4 = offsetIn(data, ic.LayerContents())
			}

			switch {
			case g.Layer(layers.LayerTypeIPv4) != nil:
				ip := g.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				eq(t, "L3Offset", p.L3Offset, offsetIn(data, ip.LayerContents()))
				eq(t, "IPVersion", p.IPVersion, ip.Version)
				eq(t, "IPSrc", p.IPSrc.String(), ip.SrcIP.String())
				eq(t, "IPDst", p.IPDst.String(), ip.DstIP.String())
				eq(t, "IPTTL", p.IPTTL, ip.TTL)
				eq(t, "IPProto", p.IPProto, uint8(ip.Protocol))
				eq(t, "IPTotalLen", p.IPTotalLen, uint32(ip.Length))
				eq(t, "IPID", p.IPID, uint32(ip.Id))
				eq(t, "MoreFragments", p.MoreFragments, ip.Flags&layers.IPv4MoreFragments != 0)
				eq(t, "FragOffset", p.FragOffset, ip.FragOffset*8)
				wantFrag := uint32(0)
				if ip.FragOffset > 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
					wantFrag = uint32(ip.Length) - uint32(ip.IHL)*4
				}
				eq(t, "FragPayloadLen", p.FragPayloadLen, wantFrag)
				eq(t, "IPChecksumValid", p.IPChecksumValid, true)
				// gopacket trims the IPv4 payload to Total Length, so its end
				// is where the IP packet ends.
				payload := ip.LayerPayload()
				eq(t, "IPEnd", p.IPEnd(), offsetIn(data, payload)+len(payload))
				if ip.FragOffset == 0 {
					// gopacket stops at fragments; the header is still here.
					wantL4 = offsetIn(data, ip.LayerContents()) + int(ip.IHL)*4
				}
				eq(t, "L4Offset", p.L4Offset, wantL4)

			case g.Layer(layers.LayerTypeIPv6) != nil:
				ip := g.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				eq(t, "L3Offset", p.L3Offset, offsetIn(data, ip.LayerContents()))
				eq(t, "IPVersion", p.IPVersion, ip.Version)
				eq(t, "IPSrc", p.IPSrc.String(), ip.SrcIP.String())
				eq(t, "IPDst", p.IPDst.String(), ip.DstIP.String())
				eq(t, "IPTTL", p.IPTTL, ip.HopLimit)
				eq(t, "IPTotalLen", p.IPTotalLen, uint32(ip.Length)+40)
				eq(t, "IPChecksumValid", p.IPChecksumValid, true)
				final := ip.NextHeader
				if ip.HopByHop != nil {
					final = ip.HopByHop.NextHeader
				}
				if f, ok := g.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment); ok {
					final = f.NextHeader
					eq(t, "IPID", p.IPID, f.Identification)
					eq(t, "FragOffset", p.FragOffset, f.FragmentOffset*8)
					eq(t, "MoreFragments", p.MoreFragments, f.MoreFragments)
					if f.FragmentOffset > 0 || f.MoreFragments {
						// gopacket's fragment payload is what follows the
						// Fragment header, up to the IPv6 payload length.
						eq(t, "FragPayloadLen", p.FragPayloadLen, uint32(len(f.LayerPayload())))
					}
					if f.FragmentOffset == 0 {
						// gopacket stops at fragments; the header is still here.
						wantL4 = offsetIn(data, f.LayerPayload())
					}
				}
				eq(t, "IPProto", p.IPProto, uint8(final))
				eq(t, "L4Offset", p.L4Offset, wantL4)

			case g.Layer(layers.LayerTypeARP) != nil:
				a := g.Layer(layers.LayerTypeARP).(*layers.ARP)
				eq(t, "L3Offset", p.L3Offset, offsetIn(data, a.LayerContents()))
				eq(t, "ARPOp", p.ARPOp, a.Operation)
				eq(t, "ARPSenderMAC", p.ARPSenderMAC.String(), net.HardwareAddr(a.SourceHwAddress).String())
				eq(t, "ARPSenderIP", p.ARPSenderIP.String(), net.IP(a.SourceProtAddress).String())
				eq(t, "ARPTargetMAC", p.ARPTargetMAC.String(), net.HardwareAddr(a.DstHwAddress).String())
				eq(t, "ARPTargetIP", p.ARPTargetIP.String(), net.IP(a.DstProtAddress).String())
				eq(t, "IPVersion", p.IPVersion, uint8(0))
				eq(t, "L4Offset", p.L4Offset, -1)

			default:
				t.Fatalf("gopacket found no network layer in %v", g)
			}
		})
	}
}

func eq[T comparable](t *testing.T, field string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, gopacket says %v", field, got, want)
	}
}
