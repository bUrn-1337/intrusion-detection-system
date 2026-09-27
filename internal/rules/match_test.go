package rules

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// firing returns the sids that alert for p on a fresh engine.
func firing(t *testing.T, rules string, p pkt) []int {
	t.Helper()
	e := NewEngine(mustParse(t, rules), EngineConfig{})
	var sids []int
	for _, a := range e.Process(p.parsed(t, t0)) {
		sids = append(sids, a.SID)
	}
	return sids
}

func dnsQuery(name string, qtype uint16) string {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1)
	return string(b)
}

func TestMatch(t *testing.T) {
	const (
		c   = "10.0.0.1"
		s   = "10.0.0.2"
		get = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
	)
	tcp := func(src, dst string, sport, dport uint16, flags, payload string) pkt {
		return pkt{proto: "tcp", src: src, dst: dst, sport: sport, dport: dport, flags: flags, seq: 1, ack: 1, payload: payload}
	}
	fwd := tcp(c, s, 40000, 80, "PA", get)
	rev := tcp(s, c, 80, 40000, "PA", "HTTP/1.1 200 OK\r\n\r\n")

	tests := []struct {
		name string
		rule string // header and options, sid is appended
		p    pkt
		want bool
	}{
		// Direction.
		{"-> forward", "alert tcp 10.0.0.1 any -> 10.0.0.2 80 (msg:\"m\";", fwd, true},
		{"-> reverse", "alert tcp 10.0.0.1 any -> 10.0.0.2 80 (msg:\"m\";", rev, false},
		{"<> forward", "alert tcp 10.0.0.1 any <> 10.0.0.2 80 (msg:\"m\";", fwd, true},
		{"<> reverse", "alert tcp 10.0.0.1 any <> 10.0.0.2 80 (msg:\"m\";", rev, true},
		{"<> needs both ends", "alert tcp 10.0.0.1 any <> 10.0.0.3 80 (msg:\"m\";", rev, false},
		// Addresses.
		{"cidr in", "alert tcp 10.0.0.0/30 any -> any any (msg:\"m\";", fwd, true},
		{"cidr out", "alert tcp 10.0.0.4/30 any -> any any (msg:\"m\";", fwd, false},
		{"negated address", "alert tcp !10.0.0.1 any -> any any (msg:\"m\";", fwd, false},
		{"negated address other", "alert tcp !10.0.0.9 any -> any any (msg:\"m\";", fwd, true},
		{"list with negation", "alert tcp [10.0.0.0/24,!10.0.0.1] any -> any any (msg:\"m\";", fwd, false},
		{"ipv6 rule, ipv4 packet", "alert tcp ::/0 any -> any any (msg:\"m\";", fwd, false},
		{"ipv6", "alert tcp 2001:db8::/32 any -> 2001:db8::2 80 (msg:\"m\";", tcp("2001:db8::1", "2001:db8::2", 1, 80, "S", ""), true},
		// Ports.
		{"port range in", "alert tcp any 30000:50000 -> any 1:1023 (msg:\"m\";", fwd, true},
		{"port range out", "alert tcp any 40001: -> any any (msg:\"m\";", fwd, false},
		{"negated port", "alert tcp any any -> any !80 (msg:\"m\";", fwd, false},
		{"port list", "alert tcp any any -> any [22,80,443] (msg:\"m\";", fwd, true},
		{"port list negated item", "alert tcp any any -> any [1:1023,!80] (msg:\"m\";", fwd, false},
		// Flags.
		{"flags exact S on SYN", "alert tcp any any -> any any (msg:\"m\"; flags:S;", tcp(c, s, 1, 80, "S", ""), true},
		{"flags exact S on SYN-ACK", "alert tcp any any -> any any (msg:\"m\"; flags:S;", tcp(c, s, 1, 80, "SA", ""), false},
		{"flags exact SA on SYN-ACK", "alert tcp any any -> any any (msg:\"m\"; flags:AS;", tcp(c, s, 1, 80, "SA", ""), true},
		{"flags S+ on SYN-ACK", "alert tcp any any -> any any (msg:\"m\"; flags:S+;", tcp(c, s, 1, 80, "SA", ""), true},
		{"flags S+ on ACK", "alert tcp any any -> any any (msg:\"m\"; flags:S+;", tcp(c, s, 1, 80, "A", ""), false},
		{"flags 0 on null scan", "alert tcp any any -> any any (msg:\"m\"; flags:0;", tcp(c, s, 1, 80, "", ""), true},
		{"flags 0 on ACK", "alert tcp any any -> any any (msg:\"m\"; flags:0;", tcp(c, s, 1, 80, "A", ""), false},
		{"flags FPU xmas", "alert tcp any any -> any any (msg:\"m\"; flags:FPU;", tcp(c, s, 1, 80, "FPU", ""), true},
		// Content.
		{"content", "alert tcp any any -> any any (msg:\"m\"; content:\"/index.html\";", fwd, true},
		{"content absent", "alert tcp any any -> any any (msg:\"m\"; content:\"/admin\";", fwd, false},
		{"content hex", "alert tcp any any -> any any (msg:\"m\"; content:\"HTTP/1.1|0d 0a|Host\";", fwd, true},
		{"content case differs", "alert tcp any any -> any any (msg:\"m\"; content:\"HOST: EXAMPLE\";", fwd, false},
		{"content nocase", "alert tcp any any -> any any (msg:\"m\"; content:\"HOST: EXAMPLE\"; nocase;", fwd, true},
		{"nocase only on its content", "alert tcp any any -> any any (msg:\"m\"; content:\"HOST\"; nocase; content:\"GET\";", fwd, true},
		{"nocase only on its content 2", "alert tcp any any -> any any (msg:\"m\"; content:\"get\"; content:\"HOST\"; nocase;", fwd, false},
		{"all contents must match", "alert tcp any any -> any any (msg:\"m\"; content:\"GET\"; content:\"POST\";", fwd, false},
		{"content binary", "alert tcp any any -> any any (msg:\"m\"; content:\"|00 ff 41|\";", tcp(c, s, 1, 9999, "PA", "x\x00\xffAy"), true},
		{"content on empty payload", "alert tcp any any -> any any (msg:\"m\"; content:\"x\";", tcp(c, s, 1, 80, "S", ""), false},
		// App layer.
		{"app_proto", "alert tcp any any -> any any (msg:\"m\"; app_proto:http;", fwd, true},
		{"app_proto mismatch", "alert tcp any any -> any any (msg:\"m\"; app_proto:tls;", fwd, false},
		{"app_field case-insensitive value", "alert tcp any any -> any any (msg:\"m\"; app_field:method=get;", fwd, true},
		{"app_field wrong value", "alert tcp any any -> any any (msg:\"m\"; app_field:method=POST;", fwd, false},
		{"app_field missing key", "alert tcp any any -> any any (msg:\"m\"; app_field:status_code=200;", fwd, false},
		{"app_field two", "alert tcp any any -> any any (msg:\"m\"; app_field:method=GET; app_field:host=Example.com;", fwd, true},
		{"app_field AXFR", "alert udp any any -> any 53 (msg:\"m\"; app_field:qtype_name=axfr;", pkt{proto: "udp", src: c, dst: s, sport: 5353, dport: 53, payload: dnsQuery("example.com", 252)}, true},
		{"app_field A is not AXFR", "alert udp any any -> any 53 (msg:\"m\"; app_field:qtype_name=AXFR;", pkt{proto: "udp", src: c, dst: s, sport: 5353, dport: 53, payload: dnsQuery("example.com", 1)}, false},
		{"app_reason malformed", "alert udp any any -> any any (msg:\"m\"; app_reason:malformed;", pkt{proto: "udp", src: c, dst: s, sport: 5353, dport: 53, payload: "short"}, true},
		{"app_reason absent", "alert udp any any -> any any (msg:\"m\"; app_reason:malformed;", pkt{proto: "udp", src: c, dst: s, sport: 5353, dport: 53, payload: dnsQuery("example.com", 1)}, false},
		{"app_reason suspicious", "alert tcp any any -> any any (msg:\"m\"; app_reason:suspicious;", tcp(c, s, 1, 80, "PA", "GET /a/%252e%252e%252fb HTTP/1.1\r\nHost: x\r\n\r\n"), true},
		// Protocols.
		{"ip rule on udp", "alert ip 10.0.0.1 any -> any any (msg:\"m\";", pkt{proto: "udp", src: c, dst: s, sport: 1, dport: 2}, true},
		{"ip rule on icmp", "alert ip any any -> 10.0.0.2 any (msg:\"m\";", pkt{proto: "icmp", src: c, dst: s}, true},
		{"tcp rule on udp", "alert tcp any any -> any any (msg:\"m\";", pkt{proto: "udp", src: c, dst: s, sport: 1, dport: 2}, false},
		{"udp rule", "alert udp any 1 -> any 2 (msg:\"m\";", pkt{proto: "udp", src: c, dst: s, sport: 1, dport: 2}, true},
		{"icmp rule", "alert icmp any any -> any any (msg:\"m\";", pkt{proto: "icmp", src: c, dst: s}, true},
		{"icmpv6 rule", "alert icmp any any -> 2001:db8::2 any (msg:\"m\";", pkt{proto: "icmp", src: "2001:db8::1", dst: "2001:db8::2"}, true},
		{"icmp rule on tcp", "alert icmp any any -> any any (msg:\"m\";", fwd, false},
		{"arp rule", "alert arp 10.0.0.1 any -> 10.0.0.2 any (msg:\"m\";", pkt{proto: "arp", src: c, dst: s}, true},
		{"arp rule wrong sender", "alert arp 10.0.0.9 any -> any any (msg:\"m\";", pkt{proto: "arp", src: c, dst: s}, false},
		{"ip rule on arp", "alert ip any any -> any any (msg:\"m\";", pkt{proto: "arp", src: c, dst: s}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firing(t, tt.rule+" sid:1;)", tt.p)
			if (len(got) == 1) != tt.want {
				t.Errorf("fired %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPassSuppresses(t *testing.T) {
	p := pkt{proto: "tcp", src: "10.0.0.1", dst: "10.0.0.2", sport: 40000, dport: 80, flags: "S"}
	alert := `alert tcp any any -> any any (msg:"all tcp"; sid:1;)` + "\n" + `alert ip any any -> any any (msg:"all ip"; sid:2;)`

	if got := firing(t, alert, p); !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatalf("without pass: %v", got)
	}
	// The pass rule is last in the file but still checked first, and it
	// silences every alert rule, including ip rules.
	rs := mustParse(t, alert+"\n"+`pass tcp 10.0.0.1 any -> any 80 (msg:"trusted"; sid:3;)`)
	e := NewEngine(rs, EngineConfig{})
	if got := e.Process(p.parsed(t, t0)); len(got) != 0 {
		t.Errorf("with pass: %v", alertLines(got))
	}
	if s := e.Stats(); s.Passed != 1 || s.Alerts != 0 {
		t.Errorf("stats %+v", s)
	}
	// A packet the pass rule does not match still alerts.
	other := p
	other.dport = 81
	if got := e.Process(other.parsed(t, t0)); len(got) != 2 {
		t.Errorf("other packet: %v", alertLines(got))
	}
}

func TestWhitelist(t *testing.T) {
	rs := mustParse(t, `alert ip any any -> any any (msg:"m"; sid:1;)`)
	e := NewEngine(rs, EngineConfig{Whitelist: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}})
	in := pkt{proto: "udp", src: "10.0.0.7", dst: "8.8.8.8", sport: 1, dport: 2}
	out := pkt{proto: "udp", src: "8.8.8.8", dst: "10.0.0.7", sport: 2, dport: 1}
	if got := e.Process(in.parsed(t, t0)); len(got) != 0 {
		t.Errorf("whitelisted source alerted: %v", alertLines(got))
	}
	if got := e.Process(out.parsed(t, t0)); len(got) != 1 {
		t.Errorf("whitelisted destination should still alert: %v", alertLines(got))
	}
	if s := e.Stats(); s.Whitelisted != 1 || s.Packets != 2 {
		t.Errorf("stats %+v", s)
	}
}

func TestAlertFields(t *testing.T) {
	rs := mustParse(t, `alert tcp any any -> any 80 (msg:"web"; sid:42; rev:3; severity:high; category:web;)`)
	e := NewEngine(rs, EngineConfig{})
	p := pkt{proto: "tcp", src: "10.0.0.1", dst: "10.0.0.2", sport: 40000, dport: 80, flags: "S"}
	got := e.Process(p.parsed(t, at(time.Second)))
	want := []Alert{{
		Time: at(time.Second), FirstSeen: at(time.Second), LastSeen: at(time.Second),
		SID: 42, Rev: 3, Msg: "web", Severity: "high", Category: "web", Proto: "TCP",
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 80, Count: 1, Kind: KindAlert,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

// TestDefaultRules runs packets that each default rule targets through
// rules.conf and checks which sids fire.
func TestDefaultRules(t *testing.T) {
	rs, err := Load("../../rules.conf")
	if err != nil {
		t.Fatal(err)
	}
	c, s := "192.168.1.10", "192.168.1.20"
	tests := []struct {
		name string
		p    pkt
		want []int
	}{
		{"axfr over tcp", pkt{proto: "tcp", src: c, dst: s, sport: 40000, dport: 53, flags: "PA", payload: string(binary.BigEndian.AppendUint16(nil, uint16(len(dnsQuery("example.com", 252))))) + dnsQuery("example.com", 252)}, []int{1000101}},
		{"axfr over udp", pkt{proto: "udp", src: c, dst: s, sport: 40000, dport: 53, payload: dnsQuery("example.com", 252)}, []int{1000101}},
		{"ordinary dns", pkt{proto: "udp", src: c, dst: s, sport: 40000, dport: 53, payload: dnsQuery("example.com", 1)}, nil},
		{"malformed dns", pkt{proto: "udp", src: c, dst: s, sport: 40000, dport: 53, payload: "\x00\x01"}, []int{1000102}},
		{"basic auth", pkt{proto: "tcp", src: c, dst: s, sport: 40000, dport: 80, flags: "PA", payload: "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"}, []int{1000201}},
		{"bearer auth", pkt{proto: "tcp", src: c, dst: s, sport: 40000, dport: 80, flags: "PA", payload: "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abc\r\n\r\n"}, nil},
		{"double encoding", pkt{proto: "tcp", src: c, dst: s, sport: 40000, dport: 80, flags: "PA", payload: "GET /a/%252e%252e/etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"}, []int{1000202}},
		{"single encoding", pkt{proto: "tcp", src: c, dst: s, sport: 40000, dport: 80, flags: "PA", payload: "GET /a%20b HTTP/1.1\r\nHost: x\r\n\r\n"}, nil},
		{"ftp pass", pkt{proto: "tcp", src: c, dst: s, sport: 40000, dport: 21, flags: "PA", payload: "PASS hunter2\r\n"}, []int{1000301}},
		{"ftp user", pkt{proto: "tcp", src: c, dst: s, sport: 40000, dport: 21, flags: "PA", payload: "USER bob\r\n"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(rs, EngineConfig{})
			var got []int
			for _, a := range e.Process(tt.p.parsed(t, t0)) {
				got = append(got, a.SID)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fired %v, want %v", got, tt.want)
			}
		})
	}

	// FTP brute force: the 5th 530 within 30s to the same client fires.
	e := NewEngine(rs, EngineConfig{})
	fail := pkt{proto: "tcp", src: s, dst: c, sport: 21, dport: 40000, flags: "PA", payload: "530 Login incorrect.\r\n"}
	var fired []int
	for i := range 7 {
		for _, a := range e.Process(fail.parsed(t, at(time.Duration(i)*5*time.Second))) {
			fired = append(fired, i)
			if a.SID != 1000302 || a.Details["tracked_addr"] != c || a.Details["count"] != "5" {
				t.Errorf("brute force alert %s", alertLine(a))
			}
		}
	}
	if !reflect.DeepEqual(fired, []int{4}) {
		t.Errorf("brute force fired at %v, want [4]", fired)
	}
	sum := e.Flush()
	if len(sum) != 1 || sum[0].Kind != KindSummary || sum[0].Count != 3 {
		t.Errorf("brute force flush: %s", alertLines(sum))
	}
	// Spread over more than 30s it does not fire.
	e = NewEngine(rs, EngineConfig{})
	for i := range 10 {
		if got := e.Process(fail.parsed(t, at(time.Duration(i)*8*time.Second))); len(got) != 0 {
			t.Errorf("slow failures fired at %d: %s", i, alertLines(got))
		}
	}
}

func TestDetectionFilterBySrcAndDst(t *testing.T) {
	rs := mustParse(t, `alert udp any any -> any any (msg:"src"; sid:1; detection_filter:track by_src, count 3, seconds 10;)`+"\n"+
		`alert udp any any -> any any (msg:"dst"; sid:2; detection_filter:track by_dst, count 3, seconds 10;)`)
	e := NewEngine(rs, EngineConfig{})
	var got []string
	// Three sources to one destination: only by_dst reaches 3.
	for i, src := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		p := pkt{proto: "udp", src: src, dst: "10.0.0.9", sport: 1, dport: 2}
		for _, a := range e.Process(p.parsed(t, at(time.Duration(i)*time.Second))) {
			got = append(got, a.Msg+" "+a.Details["tracked_addr"])
		}
	}
	if want := []string{"dst 10.0.0.9"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
