package rules

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

const (
	floodSrc = "203.0.113.7"
	floodDst = "192.0.2.10"
)

func udpPkt(src string, sport uint16, dst string, dport uint16, payload string) pkt {
	return pkt{proto: "udp", src: src, dst: dst, sport: sport, dport: dport, payload: payload}
}

// udpAlerts runs pkts and returns the alerts (not summaries) of sid.
func sidAlerts(t *testing.T, e *Engine, pkts []timedPkt, sid int) []Alert {
	t.Helper()
	var out []Alert
	for _, a := range flat(runPkts(t, e, pkts)) {
		if a.SID == sid && a.Kind == KindAlert {
			out = append(out, a)
		}
	}
	return out
}

// firesAt runs pkts and returns the index of the packet that produced
// the first alert of sid, or -1.
func firesAt(t *testing.T, e *Engine, pkts []timedPkt, sid int) int {
	t.Helper()
	for i, as := range runPkts(t, e, pkts) {
		for _, a := range as {
			if a.SID == sid && a.Kind == KindAlert {
				return i
			}
		}
	}
	return -1
}

func TestUDPFloodThreshold(t *testing.T) {
	e := NewEngine(mustParse(t, `alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:by_src; count:5; seconds:1;)`), EngineConfig{})
	var pkts []timedPkt
	for i := range 5 {
		pkts = append(pkts, timedPkt{time.Duration(i) * 100 * time.Millisecond, udpPkt(floodSrc, 40000, floodDst, uint16(9+i%2), "xxxx")})
	}
	if i := firesAt(t, e, pkts, 1); i != 4 {
		t.Fatalf("fired at packet %d, want 4 (the 5th)", i)
	}
	e = NewEngine(mustParse(t, `alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:by_src; count:5; seconds:1;)`), EngineConfig{})
	as := sidAlerts(t, e, pkts, 1)
	if len(as) != 1 {
		t.Fatalf("%d alerts", len(as))
	}
	d := as[0].Details
	want := map[string]string{"detector": "udp_flood", "track": "by_src", "tracked_addr": floodSrc, "metric": "packets",
		"packets": "5", "bytes": "60", "replies": "0", "reply_ratio": "0.0000", "max_reply_ratio": "0.02",
		"packets_per_sec": "5", "bytes_per_sec": "60", "top_dst_port": "9", "seconds": "1"}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("details[%s] = %q, want %q (all %v)", k, d[k], v, d)
		}
	}
	if _, ok := d["distinct_sources"]; ok {
		t.Error("by_src has distinct_sources")
	}
}

// TestUDPFloodWindow: the 5 packets must fall within the window; the
// first bucket leaves it one span after the first packet.
func TestUDPFloodWindow(t *testing.T) {
	rules := `alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:by_src; count:5; seconds:1;)`
	var pkts []timedPkt
	for _, ms := range []int{0, 100, 200, 300, 1000} {
		pkts = append(pkts, timedPkt{time.Duration(ms) * time.Millisecond, udpPkt(floodSrc, 40000, floodDst, 9, "")})
	}
	if i := firesAt(t, NewEngine(mustParse(t, rules), EngineConfig{}), pkts, 1); i != -1 {
		t.Errorf("fired at %d with the first packet a full span old", i)
	}
	pkts[4].t = 999 * time.Millisecond
	if i := firesAt(t, NewEngine(mustParse(t, rules), EngineConfig{}), pkts, 1); i != 4 {
		t.Errorf("fired at %d, want 4", i)
	}
}

func TestUDPFloodReplyRatioBySrc(t *testing.T) {
	rules := `alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:by_src; count:10; seconds:5; max_reply_ratio:0.1;)`
	fwd := func(i int) timedPkt {
		return timedPkt{time.Duration(i) * time.Millisecond, udpPkt(floodSrc, 40000, floodDst, 443, "q")}
	}
	reply := udpPkt(floodDst, 443, floodSrc, 40000, "ack")
	tests := []struct {
		name    string
		replies []pkt
		fires   bool
	}{
		{"no replies", nil, true},
		{"ratio exactly max", []pkt{reply}, true},
		{"ratio above max", []pkt{reply, reply}, false},
		// Only the swapped flow is a reply.
		{"other source port", []pkt{reply, udpPkt(floodDst, 443, floodSrc, 40001, "")}, true},
		{"other peer", []pkt{reply, udpPkt("192.0.2.11", 443, floodSrc, 40000, "")}, true},
		{"same direction", []pkt{reply, udpPkt(floodSrc, 40000, floodDst, 443, "")}, true},
		// ICMP errors never are.
		{"port unreachable", []pkt{reply, {proto: "icmp", src: floodDst, dst: floodSrc, unreach: &pkt{proto: "udp", src: floodSrc, dst: floodDst, sport: 40000, dport: 443}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(mustParse(t, rules), EngineConfig{})
			var pkts []timedPkt
			// The first forward packet opens the flow; replies follow it.
			pkts = append(pkts, fwd(0))
			for _, r := range tt.replies {
				pkts = append(pkts, timedPkt{time.Millisecond, r})
			}
			for i := 2; i <= 10; i++ {
				pkts = append(pkts, fwd(i))
			}
			// "same direction" adds a forward packet, so it fires one
			// packet early; only whether it fires matters here.
			as := sidAlerts(t, e, pkts, 1)
			if got := len(as) > 0; got != tt.fires {
				t.Fatalf("fired %v, want %v", got, tt.fires)
			}
		})
	}
}

// TestUDPFloodReplyBeforeFlow: a packet the other way before any forward
// traffic is not a reply.
func TestUDPFloodReplyBeforeFlow(t *testing.T) {
	e := NewEngine(mustParse(t, `alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:by_src; count:3; seconds:5; max_reply_ratio:0;)`), EngineConfig{})
	pkts := []timedPkt{{0, udpPkt(floodDst, 443, floodSrc, 40000, "")}}
	for i := 1; i <= 3; i++ {
		pkts = append(pkts, timedPkt{time.Duration(i) * time.Millisecond, udpPkt(floodSrc, 40000, floodDst, 443, "")})
	}
	// The early packet counts as forward traffic of floodDst, not as a reply.
	as := sidAlerts(t, e, pkts, 1)
	if len(as) != 1 || as[0].Details["tracked_addr"] != floodSrc || as[0].Details["replies"] != "0" {
		t.Fatalf("alerts %v", alertLines(as))
	}
}

// TestUDPFloodByDstAggregate: for by_dst, a reply is anything the victim
// sends to any of the sources, on any ports, and every source's traffic
// adds up.
func TestUDPFloodByDstAggregate(t *testing.T) {
	rules := `alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:by_dst; count:10; seconds:5; max_reply_ratio:0.1;)`
	src := func(i int) string { return "198.51.100." + string(rune('0'+i)) }
	tests := []struct {
		name    string
		replies []pkt
		fires   bool
	}{
		{"none", nil, true},
		{"one reply to one source", []pkt{udpPkt(floodDst, 53, src(1), 5353, "")}, true},
		{"replies to two sources", []pkt{udpPkt(floodDst, 53, src(1), 5353, ""), udpPkt(floodDst, 1, src(2), 2, "")}, false},
		{"to a non-source", []pkt{udpPkt(floodDst, 53, src(1), 1, ""), udpPkt(floodDst, 53, "198.51.100.99", 1, "")}, true},
		{"from another host", []pkt{udpPkt(floodDst, 53, src(1), 1, ""), udpPkt("192.0.2.99", 53, src(2), 1, "")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(mustParse(t, rules), EngineConfig{})
			var pkts []timedPkt
			for i := range 3 {
				pkts = append(pkts, timedPkt{0, udpPkt(src(i), uint16(1000+i), floodDst, uint16(80+i), "")})
			}
			for _, r := range tt.replies {
				pkts = append(pkts, timedPkt{time.Millisecond, r})
			}
			for i := 3; i < 10; i++ {
				pkts = append(pkts, timedPkt{2 * time.Millisecond, udpPkt(src(i), uint16(1000+i), floodDst, 80, "")})
			}
			as := sidAlerts(t, e, pkts, 1)
			if got := len(as) > 0; got != tt.fires {
				t.Fatalf("fired %v, want %v: %v", got, tt.fires, alertLines(as))
			}
			if tt.fires {
				d := as[0].Details
				if d["tracked_addr"] != floodDst || d["distinct_sources"] != "10" || d["top_dst_port"] != "80" || d["track"] != "by_dst" {
					t.Errorf("details %v", d)
				}
			}
		})
	}
}

// TestUDPFloodSelf: on lo a host sends to itself. For by_dst each such
// packet goes from the receiver to a source, so only the reverse flow
// (as for by_src) may count as a reply.
func TestUDPFloodSelf(t *testing.T) {
	const lo = "127.0.0.1"
	for _, track := range []string{"by_src", "by_dst"} {
		rules := `alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:` + track + `; count:10; seconds:5;)`
		for _, echo := range []bool{false, true} {
			var pkts []timedPkt
			for range 20 {
				pkts = append(pkts, timedPkt{time.Millisecond, udpPkt(lo, 40000, lo, 9, "x")})
				if echo {
					pkts = append(pkts, timedPkt{time.Millisecond, udpPkt(lo, 9, lo, 40000, "x")})
				}
			}
			as := sidAlerts(t, NewEngine(mustParse(t, rules), EngineConfig{}), pkts, 1)
			if fires := len(as) > 0; fires == echo {
				t.Errorf("%s, echo %v: fired %v: %v", track, echo, fires, alertLines(as))
			}
			if !echo && len(as) > 0 && (as[0].Details["tracked_addr"] != lo || as[0].Details["replies"] != "0") {
				t.Errorf("%s: details %v", track, as[0].Details)
			}
		}
	}
}

func TestUDPFloodDistinctSourcesCap(t *testing.T) {
	e := NewEngine(mustParse(t, `alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:by_dst; count:150; seconds:5;)`), EngineConfig{})
	var pkts []timedPkt
	for i := range 150 {
		a := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		pkts = append(pkts, timedPkt{0, udpPkt(a.String(), 1, floodDst, 80, "")})
	}
	as := sidAlerts(t, e, pkts, 1)
	if len(as) != 1 || as[0].Details["distinct_sources"] != "100+" {
		t.Fatalf("alerts %v", alertLines(as))
	}
}

func TestUDPFloodBytes(t *testing.T) {
	// 4 packets of 8 + 92 = 100 UDP bytes each.
	rules := func(n string) string {
		return `alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:by_dst; metric:bytes; count:` + n + `; seconds:5;)`
	}
	var pkts []timedPkt
	for range 4 {
		pkts = append(pkts, timedPkt{0, udpPkt(floodSrc, 1, floodDst, 2, strings.Repeat("x", 92))})
	}
	if i := firesAt(t, NewEngine(mustParse(t, rules("400")), EngineConfig{}), pkts, 1); i != 3 {
		t.Errorf("400 bytes: fired at %d, want 3", i)
	}
	if i := firesAt(t, NewEngine(mustParse(t, rules("401")), EngineConfig{}), pkts, 1); i != -1 {
		t.Errorf("401 bytes: fired at %d", i)
	}
	as := sidAlerts(t, NewEngine(mustParse(t, rules("400")), EngineConfig{}), pkts, 1)
	if d := as[0].Details; d["bytes"] != "400" || d["packets"] != "4" || d["metric"] != "bytes" {
		t.Errorf("details %v", d)
	}
	// The reply ratio is replies per forward packet, not per byte: 1
	// reply to 4 packets is 25% (not 0.25%) and stops the rule.
	withReply := append(pkts[:3:3], timedPkt{0, udpPkt(floodDst, 2, floodSrc, 1, "")}, pkts[3])
	if i := firesAt(t, NewEngine(mustParse(t, rules("400")), EngineConfig{}), withReply, 1); i != -1 {
		t.Errorf("400 bytes, 1 reply per 4 packets: fired at %d", i)
	}
	// Byte counts beyond maxCount parse for metric:bytes.
	mustParse(t, rules("100000000000"))
}

// TestUDPFloodFiltering: whitelisted and passed packets never count as
// forward traffic, but still count as replies; the rule's addresses
// select the forward traffic.
func TestUDPFloodFiltering(t *testing.T) {
	rules := `pass udp 192.0.2.10 53 -> any any (msg:"p"; sid:9;)
alert udp any any -> 192.0.2.0/24 any (msg:"m"; sid:1; detect:udp_flood; track:by_src; count:3; seconds:5; max_reply_ratio:0.4;)`
	fwd := udpPkt(floodSrc, 5000, floodDst, 53, "")
	// A passed reply lowers the ratio: 1/3 <= 0.4 fires, 2/3 does not.
	reply := udpPkt(floodDst, 53, floodSrc, 5000, "")
	e := NewEngine(mustParse(t, rules), EngineConfig{})
	if as := sidAlerts(t, e, []timedPkt{{0, fwd}, {0, reply}, {0, reply}, {0, fwd}, {0, fwd}}, 1); len(as) != 0 {
		t.Errorf("passed replies ignored: %v", alertLines(as))
	}
	e = NewEngine(mustParse(t, rules), EngineConfig{})
	if as := sidAlerts(t, e, []timedPkt{{0, fwd}, {0, reply}, {0, fwd}, {0, fwd}}, 1); len(as) != 1 {
		t.Errorf("one reply: %v", alertLines(as))
	}
	// Whitelisted sources never count.
	e = NewEngine(mustParse(t, rules), EngineConfig{Whitelist: []netip.Prefix{netip.MustParsePrefix(floodSrc + "/32")}})
	if as := sidAlerts(t, e, []timedPkt{{0, fwd}, {0, fwd}, {0, fwd}}, 1); len(as) != 0 {
		t.Errorf("whitelisted: %v", alertLines(as))
	}
	// Outside the rule's destination.
	e = NewEngine(mustParse(t, rules), EngineConfig{})
	out := udpPkt(floodSrc, 5000, "198.51.100.1", 53, "")
	if as := sidAlerts(t, e, []timedPkt{{0, out}, {0, out}, {0, out}}, 1); len(as) != 0 {
		t.Errorf("outside the rule: %v", alertLines(as))
	}
}

func TestUDPFloodReload(t *testing.T) {
	rule := `alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:by_dst; count:3; seconds:5;)`
	e := NewEngine(mustParse(t, rule), EngineConfig{})
	runPkts(t, e, []timedPkt{{0, udpPkt(floodSrc, 1, floodDst, 2, "")}, {0, udpPkt(floodSrc, 1, floodDst, 2, "")}})
	s := e.Stats().Tables
	if s[TableUDPFlood].Keys != 1 || s[TableUDPFlows].Keys != 2 { // one pair, one source set
		t.Fatalf("tables %+v", s)
	}
	e.next.Store(mustParse(t, rule))
	if as := sidAlerts(t, e, []timedPkt{{time.Second, udpPkt(floodSrc, 1, floodDst, 2, "")}}, 1); len(as) != 1 {
		t.Errorf("state lost on unchanged reload")
	}
	e.next.Store(mustParse(t, `alert udp any any -> any any (msg:"m"; sid:1;)`))
	e.Process(udpPkt(floodSrc, 1, floodDst, 2, "").parsed(t, at(2*time.Second)))
	if s := e.Stats().Tables; s[TableUDPFlood].Keys != 0 || s[TableUDPFlows].Keys != 0 {
		t.Fatalf("tables not cleared %+v", s)
	}
}

func TestFloodParseErrors(t *testing.T) {
	const udp = `alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; `
	const icmp = `alert icmp any any -> any any (msg:"m"; sid:1; `
	for _, tc := range []struct{ text, want string }{
		{udp + `track:by_src; count:10;)`, "detect:udp_flood needs seconds"},
		{udp + `count:10; seconds:5;)`, "detect:udp_flood needs track"},
		{udp + `track:by_src; count:100001; seconds:5;)`, `count: "100001": want an integer from 1 to 100000 (larger counts need detect:udp_flood metric:bytes)`},
		{udp + `track:by_src; count:1099511627777; seconds:5; metric:bytes;)`, `count: "1099511627777": want an integer from 1 to 100000`},
		{udp + `track:by_src; count:10; seconds:5; metric:octets;)`, `metric "octets": want packets or bytes`},
		{udp + `track:by_src; count:10; seconds:5; max_reply_ratio:1.5;)`, `max_reply_ratio "1.5": want a number from 0 to 1`},
		{udp + `track:by_src; count:10; seconds:5; max_reply_ratio:x;)`, `max_reply_ratio "x"`},
		{udp + `track:by_src; count:10; seconds:5; kind:echo;)`, "option kind is not valid with detect:udp_flood"},
		{`alert ip any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:by_src; count:10; seconds:5;)`, "detect:udp_flood requires protocol udp"},
		{`alert tcp any any -> any any (msg:"m"; sid:1; metric:bytes;)`, "option metric is only valid with detect:udp_flood"},
		{`alert tcp any any -> any any (msg:"m"; sid:1; max_reply_ratio:0.1;)`, "option max_reply_ratio is only valid with detect:udp_flood"},
		{`alert tcp any any -> any any (msg:"m"; sid:1; detect:syn_flood; track:by_src; count:100001; seconds:5;)`, `count: "100001": want an integer from 1 to 100000`},
		{`alert tcp any any -> any any (msg:"m"; sid:1; detection_filter:track by_src, count 100001, seconds 5;)`, `count "100001"`},
		{icmp + `detect:icmp_flood; count:10; seconds:5;)`, "detect:icmp_flood needs kind"},
		{icmp + `detect:icmp_flood; kind:ping; count:10; seconds:5;)`, `kind "ping": want echo, unsolicited_reply, error_flood`},
		{icmp + `detect:icmp_flood; kind:echo; count:10; seconds:5;)`, "detect:icmp_flood kind:echo needs track"},
		{icmp + `detect:icmp_flood; kind:error_flood; track:by_src; count:10; seconds:5;)`, "track is only valid with kind:echo"},
		{icmp + `detect:icmp_flood; kind:unsolicited_reply; count:10;)`, "detect:icmp_flood needs seconds"},
		{`alert ip any any -> any any (msg:"m"; sid:1; detect:icmp_flood; kind:echo; track:by_src; count:10; seconds:5;)`, "detect:icmp_flood requires protocol icmp"},
		{icmp + `detect:icmp_tunnel; count:10;)`, "detect:icmp_tunnel needs seconds"},
		{icmp + `detect:icmp_tunnel; count:10; seconds:60; track:by_src;)`, "option track is not valid with detect:icmp_tunnel"},
		{`alert udp any any -> any any (msg:"m"; sid:1; detect:icmp_tunnel; count:10; seconds:60;)`, "detect:icmp_tunnel requires protocol icmp"},
		{icmp + `detect:icmp_tunnel; count:10; seconds:60; dsize:>10;)`, "option dsize cannot be combined with detect"},
	} {
		_, err := Parse(strings.NewReader(tc.text), "f.rules")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: error %v, want %q", tc.text, err, tc.want)
		}
	}
	rs := mustParse(t, udp+`track:by_src; count:10; seconds:5;)`)
	if r := rs.rules[0]; r.metric != MetricPackets || r.maxReplyRatio != 0.02 {
		t.Errorf("defaults: metric %q ratio %v", r.metric, r.maxReplyRatio)
	}
}
