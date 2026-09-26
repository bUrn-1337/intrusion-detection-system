package rules

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// benchExtraRules are 22 rules of the kinds a small deployment adds to
// rules.conf's 8, for 30 in total.
const benchExtraRules = `
pass udp 10.0.0.53 53 -> 10.0.0.0/8 any (msg:"trusted resolver answers"; sid:2000001;)
alert tcp any any -> any 23 (msg:"telnet"; flags:S; sid:2000002;)
alert tcp any any -> any [135,139,445] (msg:"smb from outside"; flags:S; sid:2000003;)
alert tcp !10.0.0.0/8 any -> 10.0.0.0/8 3389 (msg:"rdp from outside"; flags:S; sid:2000004;)
alert tcp any any -> any 22 (msg:"ssh burst"; flags:S; detection_filter:track by_src, count 20, seconds 60; sid:2000005;)
alert tcp any any -> any any (msg:"null scan"; flags:0; sid:2000006;)
alert tcp any any -> any any (msg:"xmas scan"; flags:FPU; sid:2000007;)
alert tcp any any -> any any (msg:"syn-fin"; flags:SF+; sid:2000008;)
alert tcp any any -> any 80 (msg:"path traversal"; content:"../"; sid:2000009;)
alert tcp any any -> any 80 (msg:"cmd.exe"; content:"cmd.exe"; nocase; sid:2000010;)
alert tcp any any -> any 80 (msg:"sqli union"; content:"union select"; nocase; sid:2000011;)
alert tcp any any -> any any (msg:"shellshock"; content:"() {"; app_proto:http; sid:2000012;)
alert tcp any any -> any any (msg:"old curl"; app_proto:http; content:"curl/7.1"; sid:2000013;)
alert tcp any any -> any any (msg:"http admin"; app_proto:http; app_field:uri=/admin; sid:2000014;)
alert tcp any any -> any any (msg:"http TRACE"; app_proto:http; app_field:method=TRACE; sid:2000015;)
alert tcp any 80 -> any any (msg:"http 500"; app_proto:http; app_field:status_code=500; detection_filter:track by_src, count 10, seconds 60; sid:2000016;)
alert tcp any any -> any any (msg:"tls malformed"; app_proto:tls; app_reason:malformed; sid:2000017;)
alert udp any any -> any 53 (msg:"dns any query"; app_proto:dns; app_field:qtype_name=ANY; sid:2000018;)
alert udp any any -> any 69 (msg:"tftp"; sid:2000019;)
alert icmp any any -> any any (msg:"icmp flood"; detection_filter:track by_dst, count 500, seconds 1; sid:2000020;)
alert arp any any -> 10.0.0.1 any (msg:"gateway arp"; detection_filter:track by_src, count 30, seconds 10; sid:2000021;)
alert ip 198.51.100.0/24 any -> any any (msg:"known bad net"; sid:2000022;)
`

// benchMix is a traffic sample: mostly web and TLS sessions from
// 10.0.0.0/24 clients, DNS, some ICMP, ARP and background UDP, and about
// 2% hostile packets.
func benchMix(tb testing.TB) []*packet.ParsedPacket {
	var ps []pkt
	for i := range 64 {
		c := fmt.Sprintf("10.0.0.%d", 10+i%50)
		cport := uint16(40000 + i)
		web := "93.184.216.34"
		cseq, sseq := uint32(i)*100000, uint32(i)*300000
		ps = append(ps,
			pkt{proto: "tcp", src: c, dst: web, sport: cport, dport: 80, flags: "S", seq: cseq},
			pkt{proto: "tcp", src: web, dst: c, sport: 80, dport: cport, flags: "SA", seq: sseq, ack: cseq + 1},
			pkt{proto: "tcp", src: c, dst: web, sport: cport, dport: 80, flags: "A", seq: cseq + 1, ack: sseq + 1},
			pkt{proto: "tcp", src: c, dst: web, sport: cport, dport: 80, flags: "PA", seq: cseq + 1, ack: sseq + 1,
				payload: "GET /index.html?q=hello HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"},
			pkt{proto: "tcp", src: web, dst: c, sport: 80, dport: cport, flags: "PA", seq: sseq + 1, ack: cseq + 90,
				payload: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1200\r\n\r\n" + string(make([]byte, 1200))},
			pkt{proto: "tcp", src: c, dst: web, sport: cport, dport: 80, flags: "A", seq: cseq + 90, ack: sseq + 1300},
			pkt{proto: "tcp", src: c, dst: "142.250.1.1", sport: cport + 1000, dport: 443, flags: "PA", seq: cseq, ack: sseq,
				payload: "\x17\x03\x03\x04\x00" + string(make([]byte, 1024))},
			pkt{proto: "tcp", src: "142.250.1.1", dst: c, sport: 443, dport: cport + 1000, flags: "PA", seq: sseq, ack: cseq,
				payload: "\x17\x03\x03\x05\x78" + string(make([]byte, 1400))},
			pkt{proto: "tcp", src: c, dst: "142.250.1.1", sport: cport + 1000, dport: 443, flags: "A", seq: cseq, ack: sseq},
			pkt{proto: "udp", src: c, dst: "10.0.0.53", sport: cport, dport: 53, payload: dnsQuery(fmt.Sprintf("host%d.example.com", i), 1)},
			pkt{proto: "udp", src: c, dst: "10.0.0.123", sport: 123, dport: 123, payload: string(make([]byte, 48))},
		)
		if i%4 == 0 {
			ps = append(ps,
				pkt{proto: "icmp", src: c, dst: "8.8.8.8"},
				pkt{proto: "arp", src: c, dst: "10.0.0.1"},
				pkt{proto: "tcp", src: "2001:db8::10", dst: "2001:db8::80", sport: cport, dport: 443, flags: "PA", seq: 1, ack: 1,
					payload: "\x17\x03\x03\x02\x00" + string(make([]byte, 512))})
		}
		if i%16 == 0 { // a little hostile traffic, so alerts and dedup are exercised
			bad := fmt.Sprintf("198.51.100.%d", i)
			ps = append(ps,
				pkt{proto: "tcp", src: bad, dst: web, sport: cport, dport: 80, flags: "PA", seq: 1, ack: 1,
					payload: "GET /../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n"},
				pkt{proto: "tcp", src: bad, dst: "10.0.0.5", sport: cport, dport: 23, flags: "S", seq: 1},
				pkt{proto: "udp", src: c, dst: "10.0.0.53", sport: cport, dport: 53, payload: dnsQuery("example.com", 252)})
		}
	}
	out := make([]*packet.ParsedPacket, len(ps))
	for i, p := range ps {
		out[i] = p.parsed(tb, t0)
	}
	return out
}

func benchRules(tb testing.TB) *RuleSet {
	def, err := os.ReadFile("../../rules.conf")
	if err != nil {
		tb.Fatal(err)
	}
	rs := mustParse(tb, string(def)+benchExtraRules)
	if rs.Len() != 30 {
		tb.Fatalf("%d rules, want 30", rs.Len())
	}
	return rs
}

// BenchmarkEngine measures Process on already-parsed packets: the rule
// engine's own cost. Packets are 10µs apart in packet time, so windows
// and handshakes expire as they would on a busy link.
func BenchmarkEngine(b *testing.B) {
	rs := benchRules(b)
	mix := benchMix(b)
	e := NewEngine(rs, EngineConfig{})
	var alerts int
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := mix[i%len(mix)]
		p.Timestamp = t0.Add(time.Duration(i) * 10 * time.Microsecond)
		alerts += len(e.Process(p))
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "pkts/s")
	b.ReportMetric(float64(alerts)/float64(b.N), "alerts/pkt")
}
