package rules

import (
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func echoReq(src, dst string, id, seq uint16) pkt {
	return pkt{proto: "icmp", src: src, dst: dst, echoID: id, echoSeq: seq, payload: "abcdefghijklmnopqrstuvwabcdefghi"}
}

func echoRep(src, dst string, id, seq uint16) pkt {
	typ := uint8(0)
	if netip.MustParseAddr(src).Is6() {
		typ = 129
	}
	return pkt{proto: "icmp", src: src, dst: dst, icmp: &[2]uint8{typ, 0}, echoID: id, echoSeq: seq, payload: "abcdefghijklmnopqrstuvwabcdefghi"}
}

func icmpErr(src, dst string, typ, code uint8) pkt {
	return pkt{proto: "icmp", src: src, dst: dst, icmp: &[2]uint8{typ, code}, payload: "0123456789abcdefghijklmnopqrstuvwxyz"}
}

func TestICMPEchoFlood(t *testing.T) {
	rules := `alert icmp any any -> any any (msg:"src"; sid:1; detect:icmp_flood; kind:echo; track:by_src; count:5; seconds:1;)
alert icmp any any -> any any (msg:"dst"; sid:2; detect:icmp_flood; kind:echo; track:by_dst; count:5; seconds:1;)`
	var pkts []timedPkt
	for i := range 5 {
		// One source to one destination, with replies and an error
		// mixed in: neither counts.
		pkts = append(pkts, timedPkt{time.Duration(i) * 10 * time.Millisecond, echoReq(floodSrc, floodDst, 7, uint16(i))},
			timedPkt{time.Duration(i) * 10 * time.Millisecond, echoRep(floodDst, floodSrc, 7, uint16(i))},
			timedPkt{time.Duration(i) * 10 * time.Millisecond, icmpErr(floodDst, floodSrc, 3, 1)})
	}
	res := runPkts(t, NewEngine(mustParse(t, rules), EngineConfig{}), pkts)
	for sid, want := range map[int]int{1: 12, 2: 12} { // the 5th request is packet 12
		got := -1
		for i, as := range res {
			for _, a := range as {
				if a.SID == sid && got < 0 {
					got = i
				}
			}
		}
		if got != want {
			t.Errorf("sid %d fired at packet %d, want %d", sid, got, want)
		}
	}
	as := flat(res)
	for _, a := range as {
		d := a.Details
		switch a.SID {
		case 1:
			if d["tracked_addr"] != floodSrc || d["track"] != "by_src" || d["packets"] != "5" || d["distinct_destinations"] != "1" || d["kind"] != "echo" {
				t.Errorf("by_src details %v", d)
			}
		case 2:
			if d["tracked_addr"] != floodDst || d["track"] != "by_dst" || d["distinct_sources"] != "1" || d["packets_per_sec"] != "5" {
				t.Errorf("by_dst details %v", d)
			}
		}
	}
	// 4 are not enough, and ICMPv6 requests count.
	e := NewEngine(mustParse(t, rules), EngineConfig{})
	var v6 []timedPkt
	for i := range 5 {
		v6 = append(v6, timedPkt{0, echoReq("2001:db8::7", "2001:db8::10", 1, uint16(i))})
	}
	if i := firesAt(t, e, v6, 1); i != 4 {
		t.Errorf("v6 fired at %d, want 4", i)
	}
}

func TestICMPUnsolicitedReply(t *testing.T) {
	const victim, amp = "192.0.2.50", "198.51.100.9"
	rules := `alert icmp any any -> any any (msg:"m"; sid:1; detect:icmp_flood; kind:unsolicited_reply; count:3; seconds:5;)`
	req := func(ts time.Duration, seq uint16) timedPkt { return timedPkt{ts, echoReq(victim, amp, 1, seq)} }
	rep := func(ts time.Duration, seq uint16) timedPkt { return timedPkt{ts, echoRep(amp, victim, 1, seq)} }
	tests := []struct {
		name string
		pkts []timedPkt
		want int // index of the firing packet, or -1
	}{
		{"three unsolicited", []timedPkt{rep(0, 1), rep(0, 2), rep(0, 3)}, 2},
		{"two unsolicited", []timedPkt{rep(0, 1), rep(0, 2)}, -1},
		{"answered", []timedPkt{req(0, 1), req(0, 2), req(0, 3), rep(0, 1), rep(0, 2), rep(0, 3)}, -1},
		// A request may be answered more than once (duplicates).
		{"duplicate replies", []timedPkt{req(0, 1), rep(0, 1), rep(0, 1), rep(0, 1)}, -1},
		{"seq mismatch", []timedPkt{req(0, 1), rep(0, 2), rep(0, 3), rep(0, 4)}, 3},
		{"id mismatch", []timedPkt{req(0, 1), {0, echoRep(amp, victim, 2, 1)}, rep(0, 5), rep(0, 6)}, 3},
		{"responder mismatch", []timedPkt{req(0, 1), {0, echoRep("198.51.100.10", victim, 1, 1)}, rep(0, 5), rep(0, 6)}, 3},
		{"requester mismatch", []timedPkt{{0, echoReq("192.0.2.51", amp, 1, 1)}, rep(0, 1), rep(0, 5), rep(0, 6)}, 3},
		// Requests wait 10s.
		{"reply at 10s", []timedPkt{req(0, 1), rep(10*time.Second, 1), rep(10*time.Second, 5), rep(10*time.Second, 6)}, -1},
		{"reply after 10s", []timedPkt{req(0, 1), rep(10*time.Second+1, 1), rep(10*time.Second+1, 5), rep(10*time.Second+1, 6)}, 3},
		// Anyone may answer a request to a group address.
		{"broadcast request", []timedPkt{{0, pkt{proto: "icmp", src: victim, dst: "255.255.255.255", echoID: 1, echoSeq: 1}}, rep(0, 1), {0, echoRep("198.51.100.10", victim, 1, 1)}, rep(0, 5)}, -1},
		{"ethernet broadcast request", []timedPkt{{0, pkt{proto: "icmp", src: victim, dst: "198.51.100.255", ethDst: [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, echoID: 1, echoSeq: 1}}, rep(0, 1), {0, echoRep("198.51.100.10", victim, 1, 1)}, rep(0, 5)}, -1},
		{"v6 multicast request", []timedPkt{{0, echoReq("fe80::1", "ff02::1", 3, 4)}, {0, echoRep("fe80::2", "fe80::1", 3, 4)}, {0, echoRep("fe80::3", "fe80::1", 3, 4)}, {0, echoRep("fe80::4", "fe80::1", 3, 4)}}, -1},
		{"v6 unsolicited", []timedPkt{{0, echoRep("fe80::2", "fe80::1", 3, 4)}, {0, echoRep("fe80::3", "fe80::1", 3, 4)}, {0, echoRep("fe80::4", "fe80::1", 3, 4)}}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firesAt(t, NewEngine(mustParse(t, rules), EngineConfig{}), tt.pkts, 1); got != tt.want {
				t.Errorf("fired at %d, want %d", got, tt.want)
			}
		})
	}
	// A reply cut short before its identifier and sequence number cannot
	// be matched and is not counted.
	short := echoRep(amp, victim, 1, 1).bytes(t)[:14+20+4]
	e0 := NewEngine(mustParse(t, rules), EngineConfig{})
	for i := range 3 {
		if as := e0.Process(parseFrame(short, at(time.Duration(i)))); len(as) > 0 {
			t.Errorf("short reply %d: %v", i, alertLines(as))
		}
	}
	// Requests from a whitelisted host are still recorded.
	e := NewEngine(mustParse(t, rules), EngineConfig{Whitelist: []netip.Prefix{netip.MustParsePrefix(victim + "/32")}})
	if got := firesAt(t, e, []timedPkt{req(0, 1), req(0, 2), req(0, 3), rep(0, 1), rep(0, 2), rep(0, 3)}, 1); got != -1 {
		t.Errorf("whitelisted requests: fired at %d", got)
	}
	// Details.
	as := sidAlerts(t, NewEngine(mustParse(t, rules), EngineConfig{}), []timedPkt{rep(0, 1), {0, echoRep("198.51.100.10", victim, 1, 1)}, rep(0, 3)}, 1)
	if len(as) != 1 || as[0].Details["distinct_sources"] != "2" || as[0].Details["tracked_addr"] != victim || as[0].Details["kind"] != "unsolicited_reply" {
		t.Errorf("alerts %v", alertLines(as))
	}
}

func TestEchoRequestsTable(t *testing.T) {
	rules := `alert icmp any any -> any any (msg:"m"; sid:1; detect:icmp_flood; kind:unsolicited_reply; count:3; seconds:5;)`
	e := NewEngine(mustParse(t, rules), EngineConfig{})
	runPkts(t, e, []timedPkt{{0, echoReq(floodSrc, floodDst, 1, 1)}, {0, echoReq(floodSrc, floodDst, 1, 2)}, {0, echoReq(floodSrc, floodDst, 1, 2)}})
	if n := e.Stats().Tables[TableEchoRequests].Keys; n != 2 {
		t.Errorf("echo_requests %d, want 2", n)
	}
	runPkts(t, e, []timedPkt{{11 * time.Second, echoReq(floodSrc, floodDst, 1, 3)}})
	if n := e.Stats().Tables[TableEchoRequests].Keys; n != 1 {
		t.Errorf("echo_requests %d after 11s, want 1", n)
	}
	// Without an unsolicited_reply rule, requests are not tracked.
	e.next.Store(mustParse(t, `alert icmp any any -> any any (msg:"m"; sid:1; detect:icmp_flood; kind:echo; track:by_src; count:3; seconds:5;)`))
	runPkts(t, e, []timedPkt{{12 * time.Second, echoReq(floodSrc, floodDst, 1, 4)}})
	if n := e.Stats().Tables[TableEchoRequests].Keys; n != 0 {
		t.Errorf("echo_requests %d without the rule", n)
	}
}

func TestICMPErrorFlood(t *testing.T) {
	rules := `alert icmp any any -> any any (msg:"m"; sid:1; detect:icmp_flood; kind:error_flood; count:4; seconds:5;)`
	const victim = "192.0.2.50"
	tests := []struct {
		name string
		pkts []pkt
		want int
	}{
		{"unreachables", []pkt{icmpErr("10.0.0.1", victim, 3, 3), icmpErr("10.0.0.2", victim, 3, 1), icmpErr("10.0.0.1", victim, 3, 3), icmpErr("10.0.0.3", victim, 3, 3)}, 3},
		{"three", []pkt{icmpErr("10.0.0.1", victim, 3, 3), icmpErr("10.0.0.1", victim, 3, 3), icmpErr("10.0.0.1", victim, 3, 3)}, -1},
		{"time exceeded and parameter problem", []pkt{icmpErr("10.0.0.1", victim, 11, 0), icmpErr("10.0.0.1", victim, 12, 0), icmpErr("10.0.0.1", victim, 11, 1), icmpErr("10.0.0.1", victim, 12, 0)}, 3},
		{"not errors", []pkt{echoReq("10.0.0.1", victim, 1, 1), echoRep("10.0.0.1", victim, 1, 1), icmpErr("10.0.0.1", victim, 5, 1), icmpErr("10.0.0.1", victim, 13, 0), icmpErr("10.0.0.1", victim, 4, 0)}, -1},
		{"other receivers", []pkt{icmpErr("10.0.0.1", victim, 3, 3), icmpErr("10.0.0.1", victim, 3, 3), icmpErr("10.0.0.1", victim, 3, 3), icmpErr("10.0.0.1", "192.0.2.51", 3, 3)}, -1},
		{"v6 errors", []pkt{icmpErr("2001:db8::1", "2001:db8::50", 1, 4), icmpErr("2001:db8::1", "2001:db8::50", 2, 0), icmpErr("2001:db8::1", "2001:db8::50", 3, 0), icmpErr("2001:db8::1", "2001:db8::50", 4, 0)}, 3},
		{"v6 not errors", []pkt{icmpErr("2001:db8::1", "2001:db8::50", 128, 0), icmpErr("2001:db8::1", "2001:db8::50", 135, 0), icmpErr("2001:db8::1", "2001:db8::50", 143, 0), icmpErr("2001:db8::1", "2001:db8::50", 11, 0)}, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pkts []timedPkt
			for _, p := range tt.pkts {
				pkts = append(pkts, timedPkt{0, p})
			}
			if got := firesAt(t, NewEngine(mustParse(t, rules), EngineConfig{}), pkts, 1); got != tt.want {
				t.Errorf("fired at %d, want %d", got, tt.want)
			}
		})
	}
	var pkts []timedPkt
	for i := range 4 {
		pkts = append(pkts, timedPkt{0, icmpErr("10.0.0."+strconv.Itoa(1+i%2), victim, 3, uint8(3-i/3*2))}) // 3 port, 1 host
	}
	as := sidAlerts(t, NewEngine(mustParse(t, rules), EngineConfig{}), pkts, 1)
	if len(as) != 1 || as[0].Details["top_error"] != "Destination Unreachable (port unreachable)" || as[0].Details["distinct_sources"] != "2" || as[0].Details["track"] != "by_dst" {
		t.Errorf("alerts %v", alertLines(as))
	}
}
