package app_test

// Cross-check DNS decoding against gopacket. Messages are built with
// layers.DNS (which never compresses), plus a few hand-compressed ones, and
// gopacket's own decoder supplies the expected values. It is used here only
// as a test oracle; the parser itself never imports it.

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

func oDNS(t *testing.T, d *layers.DNS) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, d); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return bytes.Clone(buf.Bytes())
}

func oQ(name string, typ layers.DNSType) layers.DNSQuestion {
	return layers.DNSQuestion{Name: []byte(name), Type: typ, Class: layers.DNSClassIN}
}

func oA(name string, ip string) layers.DNSResourceRecord {
	return layers.DNSResourceRecord{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.ParseIP(ip).To4()}
}

func TestDNSMatchesGopacket(t *testing.T) {
	type msg struct {
		name string
		b    []byte
	}
	msgs := []msg{
		{"a query", oDNS(t, &layers.DNS{ID: 0x1111, RD: true, Questions: []layers.DNSQuestion{oQ("example.com", layers.DNSTypeA)}})},
		{"aaaa query, mixed case", oDNS(t, &layers.DNS{ID: 0x2222, RD: true, Questions: []layers.DNSQuestion{oQ("WwW.ExAmPlE.oRg", layers.DNSTypeAAAA)}})},
		{"mx query", oDNS(t, &layers.DNS{ID: 3, Questions: []layers.DNSQuestion{oQ("mail.example.net", layers.DNSTypeMX)}})},
		{"txt query, deep name", oDNS(t, &layers.DNS{ID: 4, Questions: []layers.DNSQuestion{oQ("a.b.c.d.e.f.g.example.com", layers.DNSTypeTXT)}})},
		{"srv query with additional", oDNS(t, &layers.DNS{ID: 5, Questions: []layers.DNSQuestion{oQ("_sip._tcp.example.com", layers.DNSTypeSRV)},
			Additionals: []layers.DNSResourceRecord{oA("x.example.com", "10.0.0.1")}})},
		{"response with two answers", oDNS(t, &layers.DNS{ID: 6, QR: true, RD: true, RA: true,
			Questions: []layers.DNSQuestion{oQ("example.com", layers.DNSTypeA)},
			Answers:   []layers.DNSResourceRecord{oA("example.com", "93.184.216.34"), oA("example.com", "93.184.216.35")}})},
		{"nxdomain with authority", oDNS(t, &layers.DNS{ID: 7, QR: true, ResponseCode: layers.DNSResponseCodeNXDomain,
			Questions:   []layers.DNSQuestion{oQ("nope.example.com", layers.DNSTypeA)},
			Authorities: []layers.DNSResourceRecord{oA("example.com", "10.9.9.9")}})},
		{"two questions", oDNS(t, &layers.DNS{ID: 8, Questions: []layers.DNSQuestion{oQ("one.example", layers.DNSTypePTR), oQ("two.example", layers.DNSTypeNS)}})},
		{"servfail response", oDNS(t, &layers.DNS{ID: 9, QR: true, ResponseCode: layers.DNSResponseCodeServFail,
			Questions: []layers.DNSQuestion{oQ("broken.example", layers.DNSTypeSOA)}})},
		// Hand-compressed: the answer name is a pointer to the question.
		{"compressed answer", []byte("\x00\x0a\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" +
			"\x03www\x07example\x03com\x00\x00\x01\x00\x01" +
			"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22")},
		// Hand-compressed: the second question points into the first.
		{"compressed second question", []byte("\x00\x0b\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00" +
			"\x07example\x03com\x00\x00\x01\x00\x01" +
			"\x03api\xc0\x0c\x00\x1c\x00\x01")},
	}

	for _, m := range msgs {
		for _, tcp := range []bool{false, true} {
			name := m.name
			if tcp {
				name += " over tcp"
			}
			t.Run(name, func(t *testing.T) {
				gp := gopacket.NewPacket(m.b, layers.LayerTypeDNS, gopacket.Default)
				if el := gp.ErrorLayer(); el != nil {
					t.Fatalf("gopacket could not decode the message: %v", el.Error())
				}
				d := gp.Layer(layers.LayerTypeDNS).(*layers.DNS)
				q := d.Questions[0]
				want := map[string]string{
					"dns_len":     strconv.Itoa(len(m.b)),
					"id":          strconv.Itoa(int(d.ID)),
					"is_response": strconv.FormatBool(d.QR),
					"rcode":       strconv.Itoa(int(d.ResponseCode)),
					"qdcount":     strconv.Itoa(int(d.QDCount)),
					"ancount":     strconv.Itoa(int(d.ANCount)),
					"nscount":     strconv.Itoa(int(d.NSCount)),
					"arcount":     strconv.Itoa(int(d.ARCount)),
					"qname":       strings.ToLower(string(q.Name)),
					"qtype":       strconv.Itoa(int(q.Type)),
					"qclass":      strconv.Itoa(int(q.Class)),
				}
				if n := q.Type.String(); !strings.HasPrefix(n, "Unknown") {
					want["qtype_name"] = n
				}

				frame := udp4(40000, 53, string(m.b))
				if d.QR {
					frame = udp4(53, 40000, string(m.b))
				}
				if tcp {
					frame = tcp4(40000, 53, tcpDNS(string(m.b)))
				}
				p := parse(frame)
				if p.AppProtocol != packet.AppDNS {
					t.Fatalf("AppProtocol = %q", p.AppProtocol)
				}
				for k, v := range want {
					if p.AppFields[k] != v {
						t.Errorf("%s = %q, gopacket says %q", k, p.AppFields[k], v)
					}
				}
				if len(p.AppFields) != len(want) || p.HasErrors() {
					t.Errorf("fields %v, errors %q", p.AppFields, p.ParseErrors)
				}
			})
		}
	}
}
