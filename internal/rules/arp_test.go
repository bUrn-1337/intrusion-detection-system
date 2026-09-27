package rules

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

func hw(n byte) [6]byte { return [6]byte{2, 0, 0, 0, 0, n} }

var bcastMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// arpReply is a reply from spa at sha to tpa (at 02:..:fe).
func arpReply(spa, tpa string, sha [6]byte) pkt {
	return pkt{proto: "arp", arpOp: packet.ARPReply, src: spa, dst: tpa, ethSrc: sha, ethDst: hw(0xfe)}
}

// arpRequest is a broadcast request from spa at sha for tpa.
func arpRequest(spa, tpa string, sha [6]byte) pkt {
	var zero [6]byte
	return pkt{proto: "arp", arpOp: packet.ARPRequest, src: spa, dst: tpa, ethSrc: sha, ethDst: bcastMAC, arpTHA: &zero}
}

type timedPkt struct {
	t time.Duration
	p pkt
}

// arpRules holds one rule per kind, with the thresholds of rules.conf.
const arpRules = `
alert arp any any -> any any (msg:"static"; sid:1; detect:arp_spoof; kind:static_violation;)
alert arp any any -> any any (msg:"change"; sid:2; detect:arp_spoof; kind:mac_change;)
alert arp any any -> any any (msg:"flip"; sid:3; detect:arp_spoof; kind:flip_flop; count:3; seconds:60;)
alert arp any any -> any any (msg:"unsol"; sid:4; detect:arp_spoof; kind:unsolicited_reply; count:5; seconds:30;)
alert arp any any -> any any (msg:"multi"; sid:5; detect:arp_spoof; kind:multi_ip; count:10; seconds:60;)
alert arp any any -> any any (msg:"mismatch"; sid:6; detect:arp_spoof; kind:mismatch;)
alert arp any any -> any any (msg:"invalid"; sid:7; detect:arp_spoof; kind:invalid_mac;)
`

// runPkts feeds pkts to e and returns the alerts of each packet.
func runPkts(t *testing.T, e *Engine, pkts []timedPkt) [][]Alert {
	t.Helper()
	out := make([][]Alert, len(pkts))
	for i, tp := range pkts {
		out[i] = e.Process(tp.p.parsed(t, at(tp.t)))
	}
	return out
}

func flat(as [][]Alert) []Alert {
	var out []Alert
	for _, a := range as {
		out = append(out, a...)
	}
	return out
}

func TestARPTableLearn(t *testing.T) {
	var st tableStat
	a := newARPTable(100, &st)
	ip := netip.MustParseAddr("10.0.0.1")
	m1, m2 := mac6(hw(1)), mac6(hw(2))

	if l := a.learn(ip, m1, at(0)); l.changed {
		t.Fatal("first sighting counted as a change")
	}
	if l := a.learn(ip, m1, at(time.Minute)); l.changed {
		t.Fatal("same MAC counted as a change")
	}
	l := a.learn(ip, m2, at(time.Hour))
	if !l.changed || l.returned || l.old != m1 || l.stable != time.Hour {
		t.Fatalf("change: %+v", l)
	}
	b := a.lookup(ip)
	if b.mac != m2 || b.first != at(0) || b.since != at(time.Hour) || b.last != at(time.Hour) || len(b.hist) != 1 {
		t.Fatalf("binding %+v", b)
	}
	if l := a.learn(ip, m1, at(time.Hour+time.Second)); !l.changed || !l.returned {
		t.Fatalf("back to m1: %+v", l)
	}
	if st.keys.Load() != 1 {
		t.Errorf("keys %d", st.keys.Load())
	}
}

func TestARPTableHistoryCap(t *testing.T) {
	var st tableStat
	a := newARPTable(100, &st)
	ip := netip.MustParseAddr("10.0.0.1")
	// 20 changes through 20 new MACs: none is a return.
	for i := range 21 {
		if l := a.learn(ip, mac6(hw(byte(i+1))), at(time.Duration(i)*time.Second)); l.returned {
			t.Fatalf("change %d counted as a return", i)
		}
	}
	b := a.lookup(ip)
	if len(b.hist) != arpHistory {
		t.Fatalf("history %d, want %d", len(b.hist), arpHistory)
	}
	if b.hist[0].to != mac6(hw(14)) || b.hist[arpHistory-1].to != mac6(hw(21)) {
		t.Errorf("history not the last %d changes: %+v", arpHistory, b.hist)
	}
	// hw(13) dropped out of the history, so going back to it is no
	// return; hw(14) is still in it.
	if l := a.learn(ip, mac6(hw(12)), at(30*time.Second)); l.returned {
		t.Error("MAC older than the history counted as a return")
	}
	if l := a.learn(ip, mac6(hw(16)), at(31*time.Second)); !l.returned {
		t.Error("MAC in the history not counted as a return")
	}
}

func TestARPTableIdleEvictionBackwards(t *testing.T) {
	var st tableStat
	a := newARPTable(2, &st)
	ip1, ip2, ip3 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")

	// Idle expiry: exactly arpIdle later the binding is still there.
	a.learn(ip1, mac6(hw(1)), at(0))
	if l := a.learn(ip1, mac6(hw(2)), at(arpIdle)); !l.changed {
		t.Fatal("binding expired at exactly arpIdle")
	}
	if l := a.learn(ip1, mac6(hw(3)), at(2*arpIdle+time.Millisecond)); l.changed || a.lookup(ip1).first != at(2*arpIdle+time.Millisecond) {
		t.Fatalf("idle binding not expired: %+v", l)
	}
	if st.evictions.Load() != 0 {
		t.Error("idle expiry counted as an eviction")
	}

	// Eviction: the least recently seen goes first.
	base := 3 * arpIdle
	a.learn(ip2, mac6(hw(2)), at(base))
	a.learn(ip1, mac6(hw(3)), at(base+time.Second)) // refresh ip1
	a.learn(ip3, mac6(hw(4)), at(base+2*time.Second))
	if a.lookup(ip2) != nil || a.lookup(ip1) == nil || a.lookup(ip3) == nil {
		t.Fatal("wrong binding evicted")
	}
	if st.evictions.Load() != 1 || st.keys.Load() != 2 {
		t.Errorf("evictions %d keys %d", st.evictions.Load(), st.keys.Load())
	}

	// Backwards time: taken as the binding's last time.
	l := a.learn(ip3, mac6(hw(5)), at(base))
	if !l.changed || l.stable != 0 || a.lookup(ip3).since != at(base+2*time.Second) {
		t.Errorf("backwards change: %+v since %v", l, a.lookup(ip3).since.Sub(t0))
	}

	a.clear()
	if st.keys.Load() != 0 || a.lookup(ip1) != nil {
		t.Error("clear")
	}
}

func TestARPRequestsExpiry(t *testing.T) {
	var st tableStat
	r := newARPRequests(2, &st)
	k1 := arpReqKey{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
	k2 := arpReqKey{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.3")}
	k3 := arpReqKey{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")}
	r.add(k1, at(0))
	if !r.outstanding(k1, at(arpRequestTimeout)) {
		t.Error("request expired at exactly the timeout")
	}
	if r.outstanding(k3, at(arpRequestTimeout)) {
		t.Error("reverse direction matched")
	}
	if r.outstanding(k1, at(arpRequestTimeout+time.Millisecond)) {
		t.Error("request outstanding after the timeout")
	}
	// A repeated request restarts the timeout.
	r.add(k1, at(10*time.Second))
	r.add(k1, at(14*time.Second))
	if !r.outstanding(k1, at(19*time.Second)) {
		t.Error("repeated request did not restart the timeout")
	}
	// Cap: the oldest goes.
	r.add(k2, at(19*time.Second))
	r.add(k3, at(19*time.Second))
	if r.outstanding(k1, at(19*time.Second)) || !r.outstanding(k2, at(19*time.Second)) || st.evictions.Load() != 1 {
		t.Errorf("eviction: evictions %d", st.evictions.Load())
	}
}

// TestARPLearnsOnlyFromARP: IP traffic never teaches a binding, so an IP
// packet from 10.0.0.5 with some MAC followed by ARP from 10.0.0.5 with
// another MAC is no change.
func TestARPLearnsOnlyFromARP(t *testing.T) {
	e := NewEngine(mustParse(t, arpRules), EngineConfig{})
	as := flat(runPkts(t, e, []timedPkt{
		{0, pkt{proto: "udp", src: "10.0.0.5", dst: "10.0.0.9", sport: 1000, dport: 53, ethSrc: hw(0x55)}},
		{time.Second, pkt{proto: "tcp", src: "10.0.0.5", dst: "10.0.0.9", sport: 1000, dport: 80, flags: "S", ethSrc: hw(0x66)}},
	}))
	if e.arpTable.lookup(netip.MustParseAddr("10.0.0.5")) != nil {
		t.Fatal("IP traffic created a binding")
	}
	as = append(as, flat(runPkts(t, e, []timedPkt{
		{2 * time.Second, arpReply("10.0.0.5", "10.0.0.9", hw(5))},
	}))...)
	if len(as) != 0 {
		t.Fatalf("alerts:%s", alertLines(as))
	}
	if b := e.arpTable.lookup(netip.MustParseAddr("10.0.0.5")); b == nil || b.mac != mac6(hw(5)) {
		t.Fatalf("binding %+v", b)
	}
}

// TestARPZeroSender: RFC 5227 probes (sender 0.0.0.0) teach nothing and
// are checked for invalid_mac only.
func TestARPZeroSender(t *testing.T) {
	e := NewEngine(mustParse(t, arpRules), EngineConfig{})
	var pkts []timedPkt
	for i := range 12 {
		p := arpRequest("0.0.0.0", "10.0.0.7", hw(byte(i+1)))
		p.ethSrc = hw(0x99) // Ethernet source differs: no mismatch for probes
		pkts = append(pkts, timedPkt{time.Duration(i) * time.Second, p})
	}
	// Replies defending the address go to 0.0.0.0 and are solicited.
	for i := range 6 {
		pkts = append(pkts, timedPkt{time.Duration(i)*time.Second + 500*time.Millisecond, arpReply("10.0.0.7", "0.0.0.0", hw(7))})
	}
	// Replies from 0.0.0.0 answer no request but are not claims either.
	for i := range 6 {
		pkts = append(pkts, timedPkt{time.Duration(i)*time.Second + 700*time.Millisecond, arpReply("0.0.0.0", "10.0.0.9", hw(0x66))})
	}
	as := flat(runPkts(t, e, pkts))
	if len(as) != 0 {
		t.Fatalf("alerts:%s", alertLines(as))
	}
	if e.arpTable.lookup(netip.IPv4Unspecified()) != nil {
		t.Fatal("0.0.0.0 learned")
	}
	zero := [6]byte{}
	p := arpRequest("0.0.0.0", "10.0.0.8", hw(1))
	p.arpSHA = &zero
	as = flat(runPkts(t, e, []timedPkt{{20 * time.Second, p}}))
	if len(as) != 1 || as[0].SID != 7 || as[0].Details["reason"] != "zero" || as[0].SrcIP != "0.0.0.0" {
		t.Fatalf("want one invalid_mac for a zero-sender probe:%s", alertLines(as))
	}
}

func TestARPStaticViolation(t *testing.T) {
	rs := mustParse(t, "arpbind 10.0.0.1 02:00:00:00:00:01\n"+arpRules)
	e := NewEngine(rs, EngineConfig{})
	res := runPkts(t, e, []timedPkt{
		{0, arpReply("10.0.0.1", "10.0.0.9", hw(1))}, // the real gateway
		{time.Second, arpReply("10.0.0.1", "10.0.0.9", hw(0x66))},
		{2 * time.Second, arpReply("10.0.0.1", "10.0.0.9", hw(1))},
		{3 * time.Second, arpReply("10.0.0.1", "10.0.0.9", hw(0x66))},
		{4 * time.Second, arpReply("10.0.0.1", "10.0.0.9", hw(1))},
		{5 * time.Second, arpReply("10.0.0.1", "10.0.0.9", hw(0x66))},
	})
	if len(res[0]) != 0 {
		t.Fatalf("bound MAC alerted:%s", alertLines(res[0]))
	}
	if len(res[1]) != 1 || res[1][0].SID != 1 {
		t.Fatalf("want static_violation on the first spoofed packet:%s", alertLines(res[1]))
	}
	d := res[1][0].Details
	if d["claimed_mac"] != "02:00:00:00:00:66" || d["bound_mac"] != "02:00:00:00:00:01" || d["ip"] != "10.0.0.1" {
		t.Errorf("details %v", d)
	}
	// Static bindings take precedence: the address is not learned, so the
	// flipping is not also a mac_change or flip_flop.
	if as := flat(res); len(alertsOf(as, 2))+len(alertsOf(as, 3)) != 0 {
		t.Errorf("mac_change/flip_flop on a static address:%s", alertLines(as))
	}
	if e.arpTable.lookup(netip.MustParseAddr("10.0.0.1")) != nil {
		t.Error("static address learned")
	}
}

func TestARPMACChange(t *testing.T) {
	e := NewEngine(mustParse(t, arpRules), EngineConfig{})
	res := runPkts(t, e, []timedPkt{
		{0, arpRequest("10.0.0.5", "10.0.0.1", hw(5))},
		{time.Hour, arpRequest("10.0.0.5", "10.0.0.1", hw(6))},
	})
	if len(res[0]) != 0 || len(res[1]) != 1 || res[1][0].SID != 2 {
		t.Fatalf("alerts:%s%s", alertLines(res[0]), alertLines(res[1]))
	}
	d := res[1][0].Details
	if d["old_mac"] != "02:00:00:00:00:05" || d["new_mac"] != "02:00:00:00:00:06" || d["old_stable"] != "1h0m0s" || d["op"] != "request" {
		t.Errorf("details %v", d)
	}
}

// TestARPFlipFlopThreshold: A B A B A. The changes B->A, A->B, B->A are
// returns; the third within 60s fires, and three spread over more than
// 60s do not.
func TestARPFlipFlopThreshold(t *testing.T) {
	for _, tc := range []struct {
		name    string
		gap     time.Duration
		fires   bool
		changes string // changes within the last 60s
	}{
		{"within", 20 * time.Second, true, "4"},    // returns at 40s, 60s, 80s: 40s apart
		{"exact", 30 * time.Second, true, "3"},     // returns at 60, 90, 120: exactly 60s
		{"outside", 30*time.Second + 1, false, ""}, // 60s + 2ns
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(mustParse(t, arpRules), EngineConfig{})
			var pkts []timedPkt
			for i := range 5 {
				m := hw(1)
				if i%2 == 1 {
					m = hw(2)
				}
				pkts = append(pkts, timedPkt{time.Duration(i) * tc.gap, arpReply("10.0.0.1", "10.0.0.9", m)})
			}
			res := runPkts(t, e, pkts)
			for i := range 4 {
				if len(alertsOf(res[i], 3)) != 0 {
					t.Fatalf("flip_flop before the third return, packet %d", i)
				}
			}
			got := alertsOf(res[4], 3)
			if (len(got) == 1) != tc.fires {
				t.Fatalf("fires=%v:%s", tc.fires, alertLines(flat(res)))
			}
			if tc.fires {
				d := got[0].Details
				if d["mac"] != "02:00:00:00:00:01" || d["previous_mac"] != "02:00:00:00:00:02" || d["returns"] != "3" || d["changes"] != tc.changes {
					t.Errorf("details %v", d)
				}
			}
		})
	}
}

// TestARPFlipFlopNeedsReturn: a MAC changing to a new MAC each time is a
// mac_change every time but never a flip_flop.
func TestARPFlipFlopNeedsReturn(t *testing.T) {
	e := NewEngine(mustParse(t, arpRules), EngineConfig{})
	var pkts []timedPkt
	for i := range 8 {
		pkts = append(pkts, timedPkt{time.Duration(i) * time.Second, arpReply("10.0.0.1", "10.0.0.9", hw(byte(i+1)))})
	}
	as := flat(runPkts(t, e, pkts))
	if len(alertsOf(as, 3)) != 0 || len(alertsOf(as, 2)) != 1 {
		t.Fatalf("alerts:%s", alertLines(as))
	}
}

func TestARPUnsolicitedThreshold(t *testing.T) {
	e := NewEngine(mustParse(t, arpRules), EngineConfig{})
	var pkts []timedPkt
	// Solicited: the victim asks, the host answers within 5s.
	for i := range 10 {
		ts := time.Duration(i) * time.Second
		pkts = append(pkts,
			timedPkt{ts, arpRequest("10.0.0.9", "10.0.0.1", hw(9))},
			timedPkt{ts + arpRequestTimeout, arpReply("10.0.0.1", "10.0.0.9", hw(1))})
	}
	if as := flat(runPkts(t, e, pkts)); len(as) != 0 {
		t.Fatalf("solicited replies alerted:%s", alertLines(as))
	}
	// Unsolicited: four in 30s do nothing, the fifth fires.
	pkts = nil
	for i := range 5 {
		pkts = append(pkts, timedPkt{100*time.Second + time.Duration(i)*7500*time.Millisecond, arpReply("10.0.0.1", "10.0.0.9", hw(0x66))})
	}
	res := runPkts(t, e, pkts)
	for i := range 4 {
		if len(alertsOf(res[i], 4)) != 0 {
			t.Fatalf("unsolicited_reply after %d replies", i+1)
		}
	}
	got := alertsOf(res[4], 4)
	if len(got) != 1 || got[0].Details["replies"] != "5" || got[0].Details["mac"] != "02:00:00:00:00:66" || got[0].Details["window"] != "30s" {
		t.Fatalf("want unsolicited_reply on the fifth:%s", alertLines(res[4]))
	}
}

// TestARPRequestExpiry: a reply more than 5s after its request is
// unsolicited.
func TestARPRequestExpiry(t *testing.T) {
	rules := `alert arp any any -> any any (msg:"unsol"; sid:4; detect:arp_spoof; kind:unsolicited_reply; count:1; seconds:30;)`
	for _, tc := range []struct {
		delay time.Duration
		fires bool
	}{{arpRequestTimeout, false}, {arpRequestTimeout + time.Millisecond, true}} {
		e := NewEngine(mustParse(t, rules), EngineConfig{})
		as := flat(runPkts(t, e, []timedPkt{
			{0, arpRequest("10.0.0.9", "10.0.0.1", hw(9))},
			{tc.delay, arpReply("10.0.0.1", "10.0.0.9", hw(1))},
		}))
		if (len(as) == 1) != tc.fires {
			t.Errorf("delay %v: fires=%v:%s", tc.delay, tc.fires, alertLines(as))
		}
	}
}

// TestARPGratuitous: gratuitous ARPs (sender IP == target IP) are free
// the first two times per (IP, MAC) within seconds; later ones count as
// unsolicited replies.
func TestARPGratuitous(t *testing.T) {
	rules := `alert arp any any -> any any (msg:"unsol"; sid:4; detect:arp_spoof; kind:unsolicited_reply; count:1; seconds:30;)`
	grat := func(op uint16) pkt {
		if op == packet.ARPRequest {
			return arpRequest("10.0.0.5", "10.0.0.5", hw(5))
		}
		return pkt{proto: "arp", arpOp: packet.ARPReply, src: "10.0.0.5", dst: "10.0.0.5", ethSrc: hw(5), ethDst: bcastMAC}
	}
	// A boot announcement: two gratuitous requests 2s apart, then one more
	// after the window. Nothing fires even at count:1.
	e := NewEngine(mustParse(t, rules), EngineConfig{})
	as := flat(runPkts(t, e, []timedPkt{
		{0, grat(packet.ARPRequest)},
		{2 * time.Second, grat(packet.ARPRequest)},
		{33 * time.Second, grat(packet.ARPReply)},
	}))
	if len(as) != 0 {
		t.Fatalf("announcement alerted:%s", alertLines(as))
	}
	// The third within 30s counts.
	e = NewEngine(mustParse(t, rules), EngineConfig{})
	res := runPkts(t, e, []timedPkt{
		{0, grat(packet.ARPReply)},
		{15 * time.Second, grat(packet.ARPRequest)},
		{30 * time.Second, grat(packet.ARPReply)},
	})
	if len(res[0])+len(res[1]) != 0 || len(res[2]) != 1 || res[2][0].Details["gratuitous"] != "true" {
		t.Fatalf("alerts:%s", alertLines(flat(res)))
	}
	// With count:5, a gratuitous reply every 2s fires on the seventh.
	e = NewEngine(mustParse(t, arpRules), EngineConfig{})
	var pkts []timedPkt
	for i := range 7 {
		pkts = append(pkts, timedPkt{time.Duration(i) * 2 * time.Second, grat(packet.ARPReply)})
	}
	res = runPkts(t, e, pkts)
	for i := range 6 {
		if len(res[i]) != 0 {
			t.Fatalf("alert on gratuitous %d:%s", i+1, alertLines(res[i]))
		}
	}
	if len(alertsOf(res[6], 4)) != 1 {
		t.Fatalf("want unsolicited_reply on the seventh:%s", alertLines(res[6]))
	}
}

func TestARPMultiIPThreshold(t *testing.T) {
	e := NewEngine(mustParse(t, arpRules), EngineConfig{})
	var pkts []timedPkt
	for i := range 10 {
		ip := fmt.Sprintf("10.0.1.%d", i)
		// Each reply is solicited, so only multi_ip can fire.
		pkts = append(pkts,
			timedPkt{time.Duration(i) * 6 * time.Second, arpRequest("10.0.0.9", ip, hw(9))},
			timedPkt{time.Duration(i)*6*time.Second + time.Millisecond, arpReply(ip, "10.0.0.9", hw(0x77))},
			// Requests from the same MAC for many IPs do not count.
			timedPkt{time.Duration(i)*6*time.Second + 2*time.Millisecond, arpRequest("10.0.0.8", fmt.Sprintf("10.0.2.%d", i), hw(0x88))})
	}
	res := runPkts(t, e, pkts)
	for i := range len(res) - 2 {
		if len(res[i]) != 0 {
			t.Fatalf("alert before the tenth IP, packet %d:%s", i, alertLines(res[i]))
		}
	}
	got := res[len(res)-2]
	if len(got) != 1 || got[0].SID != 5 || got[0].Details["distinct_ips"] != "10" || got[0].Details["mac"] != "02:00:00:00:00:77" ||
		!strings.HasPrefix(got[0].Details["ips"], "10.0.1.0,10.0.1.1,") {
		t.Fatalf("want multi_ip on the tenth IP:%s", alertLines(got))
	}
	// Dedup is per MAC: another MAC is a separate alert.
	if dk := (dedupKey{sid: 5, mac: mac6(hw(0x77)), hasMAC: true}); e.dedup.m[dk] == nil {
		t.Error("multi_ip not deduplicated by MAC")
	}
}

func TestARPMismatchInvalid(t *testing.T) {
	e := NewEngine(mustParse(t, arpRules), EngineConfig{})
	mism := arpReply("10.0.0.3", "10.0.0.9", hw(3))
	sha := hw(0x33)
	mism.arpSHA = &sha
	mcast := [6]byte{0x01, 0x00, 0x5e, 0, 0, 1}
	inv := func(ip string, m [6]byte) pkt {
		p := arpRequest(ip, "10.0.0.9", hw(4))
		p.arpSHA = &m
		return p
	}
	res := runPkts(t, e, []timedPkt{
		{0, mism},
		{time.Second, inv("10.0.0.4", bcastMAC)},
		{2 * time.Second, inv("10.0.0.5", mcast)},
		{3 * time.Second, inv("10.0.0.6", [6]byte{})},
	})
	if len(res[0]) != 1 || res[0][0].SID != 6 || res[0][0].Details["eth_src"] != "02:00:00:00:00:03" || res[0][0].Details["arp_sender_mac"] != "02:00:00:00:00:33" {
		t.Fatalf("mismatch:%s", alertLines(res[0]))
	}
	for i, reason := range []string{"broadcast", "multicast", "zero"} {
		got := alertsOf(res[i+1], 7)
		if len(got) != 1 || got[0].Details["reason"] != reason {
			t.Errorf("invalid_mac %s:%s", reason, alertLines(res[i+1]))
		}
	}
	// Invalid MACs are not learned.
	for _, ip := range []string{"10.0.0.4", "10.0.0.5", "10.0.0.6"} {
		if e.arpTable.lookup(netip.MustParseAddr(ip)) != nil {
			t.Errorf("%s learned with an invalid MAC", ip)
		}
	}
}

// TestARPWhitelistPass: whitelisted senders and pass rules suppress
// arp_spoof alerts and counts, but the tables still learn.
func TestARPWhitelistPass(t *testing.T) {
	rules := arpRules + `pass arp 10.0.1.0/24 any -> any any (msg:"proxy arp"; sid:100; arp_op:reply;)` + "\n"
	e := NewEngine(mustParse(t, rules), EngineConfig{Whitelist: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}})
	var pkts []timedPkt
	for i := range 20 {
		pkts = append(pkts, timedPkt{time.Duration(i) * time.Second, arpReply(fmt.Sprintf("10.0.1.%d", i+1), "10.0.0.9", hw(0x77))})
	}
	for i := range 6 {
		m := hw(1)
		if i%2 == 1 {
			m = hw(2)
		}
		pkts = append(pkts, timedPkt{time.Duration(20+i) * time.Second, arpReply("10.0.0.1", "10.0.0.9", m)})
	}
	as := flat(runPkts(t, e, pkts))
	if len(as) != 0 {
		t.Fatalf("alerts:%s", alertLines(as))
	}
	if b := e.arpTable.lookup(netip.MustParseAddr("10.0.0.1")); b == nil || len(b.hist) != 5 {
		t.Error("whitelisted sender not learned")
	}
}

func TestARPOpMatch(t *testing.T) {
	for _, tc := range []struct {
		rule string
		p    pkt
		want bool
	}{
		{`alert arp any any -> any any (msg:"m"; sid:1; arp_op:request;)`, arpRequest("10.0.0.1", "10.0.0.2", hw(1)), true},
		{`alert arp any any -> any any (msg:"m"; sid:1; arp_op:request;)`, arpReply("10.0.0.1", "10.0.0.2", hw(1)), false},
		{`alert arp any any -> any any (msg:"m"; sid:1; arp_op:reply;)`, arpReply("10.0.0.1", "10.0.0.2", hw(1)), true},
		{`alert arp any any -> any any (msg:"m"; sid:1; arp_op:reply; eth_dst:broadcast;)`, arpReply("10.0.0.1", "10.0.0.2", hw(1)), false},
		{`alert arp any any -> any any (msg:"m"; sid:1; arp_op:request; eth_dst:broadcast;)`, arpRequest("10.0.0.1", "10.0.0.2", hw(1)), true},
	} {
		e := NewEngine(mustParse(t, tc.rule), EngineConfig{})
		if got := len(e.Process(tc.p.parsed(t, t0))) == 1; got != tc.want {
			t.Errorf("%s on op %d: got %v", tc.rule, tc.p.arpOp, got)
		}
	}
}

func TestARPParseErrors(t *testing.T) {
	const arp = `alert arp any any -> any any (msg:"m"; sid:1; `
	for _, tc := range []struct{ text, want string }{
		{"arpbind 10.0.0.1", "arpbind: want arpbind IPV4_ADDRESS MAC_ADDRESS"},
		{"arpbind 10.0.0.1 02:00:00:00:00:01 x", "arpbind: want arpbind IPV4_ADDRESS MAC_ADDRESS"},
		{"arpbind fe80::1 02:00:00:00:00:01", `arpbind address "fe80::1": want an IPv4 address other than 0.0.0.0`},
		{"arpbind 0.0.0.0 02:00:00:00:00:01", `arpbind address "0.0.0.0"`},
		{"arpbind 10.0.0.300 02:00:00:00:00:01", `arpbind address "10.0.0.300"`},
		{"arpbind 10.0.0.1 02:00:00:00:01", `arpbind MAC "02:00:00:00:01": want six hex octets`},
		{"arpbind 10.0.0.1 02:00:00:00:00:00:00:01", `arpbind MAC "02:00:00:00:00:00:00:01"`},
		{"arpbind 10.0.0.1 ff:ff:ff:ff:ff:ff", "arpbind MAC ff:ff:ff:ff:ff:ff is broadcast, not a host address"},
		{"arpbind 10.0.0.1 01:00:5e:00:00:01", "is multicast"},
		{"arpbind 10.0.0.1 00:00:00:00:00:00", "is zero"},
		{"arpbind 10.0.0.1 02:00:00:00:00:01\narpbind 10.0.0.1 02:00:00:00:00:02", "f.rules:2: arpbind 10.0.0.1 given twice (first defined on line 1)"},
		{arp + `detect:arp_spoof;)`, "detect:arp_spoof needs kind"},
		{arp + `detect:arp_spoof; kind:overlap;)`, `kind "overlap": want static_violation, mac_change, flip_flop, unsolicited_reply, multi_ip, mismatch, invalid_mac`},
		{`alert ip any any -> any any (msg:"m"; sid:1; detect:frag_attack; kind:mac_change;)`, `kind "mac_change": want overlap, tiny, oversize or flood`},
		{arp + `detect:arp_spoof; kind:flip_flop; count:3;)`, "detect:arp_spoof kind:flip_flop needs count and seconds"},
		{arp + `detect:arp_spoof; kind:multi_ip;)`, "detect:arp_spoof kind:multi_ip needs count and seconds"},
		{arp + `detect:arp_spoof; kind:multi_ip; count:1001; seconds:60;)`, "kind:multi_ip count 1001: at most 1000"},
		{arp + `detect:arp_spoof; kind:mismatch; seconds:3;)`, "count and seconds are only valid with kind:flip_flop, kind:unsolicited_reply, kind:multi_ip"},
		{arp + `detect:arp_spoof; kind:mismatch; track:by_src;)`, "option track is not valid with detect:arp_spoof"},
		{`alert ip any any -> any any (msg:"m"; sid:1; detect:arp_spoof; kind:mismatch;)`, "detect:arp_spoof requires protocol arp"},
		{arp + `kind:mismatch;)`, "option kind is only valid with detect:frag_attack, detect:arp_spoof"},
		{arp + `arp_op:ask;)`, `arp_op "ask": want request or reply`},
		{`alert ip any any -> any any (msg:"m"; sid:1; arp_op:reply;)`, "arp_op requires protocol arp"},
		{arp + `arp_op:reply; arp_op:request;)`, "option arp_op given more than once"},
		{arp + `detect:arp_spoof; kind:mismatch; arp_op:reply;)`, "option arp_op cannot be combined with detect"},
		{`pass arp any any -> any any (msg:"m"; sid:1; detect:arp_spoof; kind:mismatch;)`, "detect cannot be used with a pass rule"},
	} {
		_, err := Parse(strings.NewReader(tc.text), "f.rules")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: error %v, want %q", tc.text, err, tc.want)
		}
	}
}

func TestARPBindParse(t *testing.T) {
	rs := mustParse(t, "# gateway\n  arpbind   192.168.1.1   AA-BB-CC-DD-EE-01\narpbind 192.168.1.2 aabb.ccdd.ee02\n"+
		`alert arp any any -> any any (msg:"m"; sid:1; detect:arp_spoof; kind:static_violation;)`)
	if rs.Len() != 1 || len(rs.arpStatic) != 2 {
		t.Fatalf("rules %d static %v", rs.Len(), rs.arpStatic)
	}
	if m := rs.arpStatic[netip.MustParseAddr("192.168.1.1")]; m.String() != "aa:bb:cc:dd:ee:01" {
		t.Errorf("binding %s", m)
	}
	if m := rs.arpStatic[netip.MustParseAddr("192.168.1.2")]; m.String() != "aa:bb:cc:dd:ee:02" {
		t.Errorf("binding %s", m)
	}
}

// TestARPReloadTables: the ARP tables are cleared when the last arp_spoof
// rule goes, and rule state survives an unchanged reload.
func TestARPReloadTables(t *testing.T) {
	e := NewEngine(mustParse(t, arpRules), EngineConfig{})
	runPkts(t, e, []timedPkt{{0, arpRequest("10.0.0.5", "10.0.0.1", hw(5))}})
	if s := e.Stats().Tables; s[TableARPBindings].Keys != 1 || s[TableARPRequests].Keys != 1 {
		t.Fatalf("tables %+v", s)
	}
	e.next.Store(mustParse(t, `alert arp any any -> any any (msg:"m"; sid:1;)`))
	e.Process(arpRequest("10.0.0.6", "10.0.0.1", hw(6)).parsed(t, at(time.Second)))
	if s := e.Stats().Tables; s[TableARPBindings].Keys != 0 || s[TableARPRequests].Keys != 0 {
		t.Fatalf("tables not cleared %+v", s)
	}
}
