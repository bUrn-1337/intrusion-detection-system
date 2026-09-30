package rules

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// TTL anomaly detector tests.

const (
	ttlHome = "var HOME_NET [10.0.0.0/8,fd00::/8]\n"
	// ttlRule is the rules.conf rule with the defaults spelled out.
	ttlRule = ttlHome + `alert ip any any -> any any (msg:"ttl"; sid:9; detect:ttl_anomaly; count:5; seconds:60; min_samples:10; max_hop_diff:3;)`
	ttlSrc  = "198.51.100.7"
	ttlDst  = "10.0.0.2"
)

// ttlPkts returns n UDP packets from src with the given TTL, starting at
// start and step apart.
func ttlPkts(src string, ttl uint8, n int, start, step time.Duration) []tpkt {
	dst := ttlDst
	if strings.Contains(src, ":") {
		dst = "fd00::2"
	}
	var out []tpkt
	for i := range n {
		out = append(out, tpkt{at(start + time.Duration(i)*step), pkt{proto: "udp", src: src, dst: dst, sport: 5000, dport: 53, payload: "q", ttl: ttl}})
	}
	return out
}

func ttlAlerts(as []Alert) []Alert {
	var out []Alert
	for _, a := range as {
		if a.SID == 9 && a.Kind == KindAlert {
			out = append(out, a)
		}
	}
	return out
}

func TestInitialTTL(t *testing.T) {
	for ttl, want := range map[uint8]uint8{
		1: 32, 6: 32, 32: 32, 33: 64, 50: 64, 64: 64, 65: 128, 114: 128, 128: 128, 129: 255, 240: 255, 255: 255,
	} {
		if got := initialTTL(ttl); got != want {
			t.Errorf("initialTTL(%d) = %d, want %d", ttl, got, want)
		}
	}
}

func TestTTLAnomaly(t *testing.T) {
	sec := time.Second
	// 10 packets at distance 14 (TTL 50, initial 64) establish it.
	base := ttlPkts(ttlSrc, 50, 10, 0, sec)
	tests := []struct {
		name  string
		rules string
		pkts  []tpkt
		want  int // alerts from sid 9
	}{
		{"fires at count", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 60, 5, 20*sec, sec)), 1},
		{"one short of count", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 60, 4, 20*sec, sec)), 0},
		{"single shifted packet", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 60, 1, 20*sec, sec), ttlPkts(ttlSrc, 50, 20, 21*sec, sec)), 0},
		// max_hop_diff 3: distance 17 (TTL 47) is within, 18 (TTL 46) is not.
		{"hop diff at limit", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 47, 5, 20*sec, sec)), 0},
		{"hop diff past limit", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 46, 5, 20*sec, sec)), 1},
		{"hop diff below", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 54, 5, 20*sec, sec)), 1},
		{"max_hop_diff 0", strings.Replace(ttlRule, "max_hop_diff:3", "max_hop_diff:0", 1), slices.Concat(base, ttlPkts(ttlSrc, 51, 5, 20*sec, sec)), 1},
		// min_samples 10: after 9 samples nothing is established.
		{"not established", ttlRule, slices.Concat(ttlPkts(ttlSrc, 50, 9, 0, sec), ttlPkts(ttlSrc, 60, 5, 20*sec, sec)), 0},
		{"just established", ttlRule, slices.Concat(ttlPkts(ttlSrc, 50, 10, 0, sec), ttlPkts(ttlSrc, 60, 5, 20*sec, sec)), 1},
		// Window: 5 anomalies spanning exactly 60s fire; 60.001s do not.
		{"window edge", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 60, 5, 20*sec, 15*sec)), 1},
		{"past window", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 60, 5, 20*sec, 15*sec+time.Millisecond/4)), 0},
		// A NAT address with a 64-initial and a 128-initial host at the
		// same distance: one distance, never anomalous.
		{"nat mixed os", ttlRule, interleave(ttlPkts(ttlSrc, 50, 30, 0, sec), ttlPkts(ttlSrc, 114, 30, 500*time.Millisecond, sec)), 0},
		// Two paths (e.g. ECMP) both established: neither is anomalous.
		{"two established", ttlRule, interleave(ttlPkts(ttlSrc, 50, 30, 0, sec), ttlPkts(ttlSrc, 40, 30, 500*time.Millisecond, sec)), 0},
		// TTL <= 5 is ignored: traceroute probes.
		{"low ttl ignored", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 5, 10, 20*sec, sec)), 0},
		{"ttl 6 counts", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 6, 5, 20*sec, sec)), 1},
		// scope:external skips $HOME_NET sources; scope:all tracks them.
		{"home source skipped", ttlRule, slices.Concat(ttlPkts("10.9.9.9", 50, 10, 0, sec), ttlPkts("10.9.9.9", 60, 5, 20*sec, sec)), 0},
		{"scope all", strings.Replace(ttlRule, "seconds:60;", "seconds:60; scope:all;", 1), slices.Concat(ttlPkts("10.9.9.9", 50, 10, 0, sec), ttlPkts("10.9.9.9", 60, 5, 20*sec, sec)), 1},
		// IPv6 hop limits.
		{"ipv6", ttlRule, slices.Concat(ttlPkts("2001:db8::7", 50, 10, 0, sec), ttlPkts("2001:db8::7", 60, 5, 20*sec, sec)), 1},
		{"ipv6 home skipped", ttlRule, slices.Concat(ttlPkts("fd00::7", 50, 10, 0, sec), ttlPkts("fd00::7", 60, 5, 20*sec, sec)), 0},
		// The rule's addresses and protocol limit what is tracked.
		{"rule proto", strings.Replace(ttlRule, "alert ip", "alert tcp", 1), slices.Concat(base, ttlPkts(ttlSrc, 60, 5, 20*sec, sec)), 0},
		{"rule addresses", strings.Replace(ttlRule, "alert ip any", "alert ip !"+ttlSrc, 1), slices.Concat(base, ttlPkts(ttlSrc, 60, 5, 20*sec, sec)), 0},
		// A source idle for over an hour is forgotten, established
		// distance and all.
		{"idle source forgotten", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 60, 5, 2*time.Hour, sec)), 0},
		{"within idle", ttlRule, slices.Concat(base, ttlPkts(ttlSrc, 60, 5, 50*time.Minute, sec)), 1},
		// Each source is judged on its own history.
		{"per source", ttlRule, slices.Concat(base, ttlPkts("198.51.100.8", 60, 15, 20*sec, sec)), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as, _ := runPackets(t, tt.rules, EngineConfig{}, tt.pkts)
			if got := ttlAlerts(as); len(got) != tt.want {
				t.Errorf("got %d alerts, want %d:%s", len(got), tt.want, alertLines(as))
			}
		})
	}
}

// interleave merges two time-ordered packet lists.
func interleave(a, b []tpkt) []tpkt {
	out := slices.Concat(a, b)
	slices.SortStableFunc(out, func(x, y tpkt) int { return x.ts.Compare(y.ts) })
	return out
}

func TestTTLAnomalyDetails(t *testing.T) {
	pkts := slices.Concat(ttlPkts(ttlSrc, 50, 12, 0, time.Second), ttlPkts(ttlSrc, 60, 3, 20*time.Second, time.Second), ttlPkts(ttlSrc, 100, 2, 23*time.Second, time.Second))
	as, _ := runPackets(t, ttlRule, EngineConfig{}, pkts)
	got := ttlAlerts(as)
	if len(got) != 1 {
		t.Fatalf("got %d alerts:%s", len(got), alertLines(as))
	}
	d := got[0].Details
	want := map[string]string{
		"detector":              "ttl_anomaly",
		"track":                 "by_src",
		"tracked_addr":          ttlSrc,
		"count":                 "5",
		"seconds":               "60",
		"window":                "4s",
		"established_distances": "14(12)",
		"anomalous_distances":   "4,28",
		"sample_ttls":           "60,100",
		"max_hop_diff":          "3",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("details[%s] = %q, want %q", k, d[k], v)
		}
	}
	if got[0].SrcIP != ttlSrc {
		t.Errorf("src %s", got[0].SrcIP)
	}
}

// TestTTLAnomalyRouteChange documents what a lasting route change does:
// the new distance is anomalous until it has min_samples samples itself,
// so a steady flow fires once (min_samples anomalies, deduplicated into
// one alert), then goes quiet.
func TestTTLAnomalyRouteChange(t *testing.T) {
	pkts := slices.Concat(ttlPkts(ttlSrc, 50, 20, 0, time.Second), ttlPkts(ttlSrc, 44, 200, 30*time.Second, time.Second))
	as, e := runPackets(t, ttlRule, EngineConfig{}, pkts)
	if got := ttlAlerts(as); len(got) != 1 {
		t.Errorf("got %d alerts, want 1:%s", len(got), alertLines(as))
	}
	d := e.ruleState[0].ttl
	if got := establishedDists(d, netip.MustParseAddr(ttlSrc)); !slices.Equal(got, []int{14, 20}) {
		t.Errorf("established %v, want [14 20]", got)
	}
}

// TestTTLAnomalyBackwardsTime checks that a packet older than the engine
// clock counts at the clock time: a window is never stretched by time
// going backwards, and nothing panics.
func TestTTLAnomalyBackwardsTime(t *testing.T) {
	pkts := ttlPkts(ttlSrc, 50, 10, 100*time.Second, time.Second)
	// Anomalies at 200s, then four stamped at 0s (clock stays at 200s).
	pkts = append(pkts, ttlPkts(ttlSrc, 60, 1, 200*time.Second, 0)...)
	pkts = append(pkts, ttlPkts(ttlSrc, 60, 4, 0, 0)...)
	as, _ := runPackets(t, ttlRule, EngineConfig{}, pkts)
	got := ttlAlerts(as)
	if len(got) != 1 {
		t.Fatalf("got %d alerts, want 1:%s", len(got), alertLines(as))
	}
	if got[0].Details["window"] != "0s" {
		t.Errorf("window %q, want 0s", got[0].Details["window"])
	}
}

// TestTTLAnomalySlots checks the per-source slot limit: a fifth distance
// replaces the least recently seen unestablished one, and established
// distances are kept while an unestablished one can go.
func TestTTLAnomalySlots(t *testing.T) {
	rs := mustParse(t, ttlRule)
	r := rs.rules[0]
	var st tableStat
	d := newTTLAnomaly(r, 10, &st)
	src := netip.MustParseAddr(ttlSrc)
	ts := t0
	send := func(ttl uint8, n int) {
		for range n {
			ts = ts.Add(time.Second)
			d.observe(src, ttl, ts)
		}
	}
	send(50, 10) // 14, established
	send(40, 10) // 24, established
	send(60, 1)  // 4
	send(61, 1)  // 3
	send(62, 1)  // 2: replaces 4, the older unestablished slot
	s := d.srcs[src].Value.(*ttlSource)
	var dists []int
	for _, sl := range s.slots {
		dists = append(dists, int(sl.dist))
	}
	slices.Sort(dists)
	if !slices.Equal(dists, []int{2, 3, 14, 24}) {
		t.Errorf("slots %v, want [2 3 14 24]", dists)
	}
	// With every slot established, the least recently seen goes.
	send(61, 9)
	send(62, 9)
	send(20, 1) // 12: replaces 14, the least recently seen
	dists = dists[:0]
	for _, sl := range s.slots {
		dists = append(dists, int(sl.dist))
	}
	slices.Sort(dists)
	if !slices.Equal(dists, []int{2, 3, 12, 24}) {
		t.Errorf("slots %v, want [2 3 12 24]", dists)
	}
}

// TestTTLAnomalyEviction checks the source cap: the least recently seen
// source is evicted, counted, and loses its history.
func TestTTLAnomalyEviction(t *testing.T) {
	var pkts []tpkt
	pkts = append(pkts, ttlPkts(ttlSrc, 50, 10, 0, time.Second)...)
	for i := range 3 {
		pkts = append(pkts, ttlPkts("198.51.100."+string(rune('1'+i)), 50, 1, 20*time.Second, 0)...)
	}
	pkts = append(pkts, ttlPkts(ttlSrc, 60, 5, 30*time.Second, time.Second)...)
	as, e := runPackets(t, ttlRule, EngineConfig{MaxKeys: 3}, pkts)
	if got := ttlAlerts(as); len(got) != 0 {
		t.Errorf("evicted source alerted:%s", alertLines(as))
	}
	ts := e.Stats().Tables[TableTTLAnomaly]
	if ts.Keys != 3 || ts.Evictions < 1 {
		t.Errorf("table stats %+v, want 3 keys and evictions", ts)
	}
	// Without the cap, the same packets alert.
	as, _ = runPackets(t, ttlRule, EngineConfig{}, pkts)
	if got := ttlAlerts(as); len(got) != 1 {
		t.Errorf("uncapped: got %d alerts:%s", len(got), alertLines(as))
	}
}

// TestTTLAnomalyWhitelistPass checks that whitelisted sources and packets
// a pass rule matches are not tracked.
func TestTTLAnomalyWhitelistPass(t *testing.T) {
	pkts := slices.Concat(ttlPkts(ttlSrc, 50, 10, 0, time.Second), ttlPkts(ttlSrc, 60, 5, 20*time.Second, time.Second))
	as, _ := runPackets(t, ttlRule, EngineConfig{Whitelist: []netip.Prefix{netip.MustParsePrefix(ttlSrc + "/32")}}, pkts)
	if got := ttlAlerts(as); len(got) != 0 {
		t.Errorf("whitelisted:%s", alertLines(as))
	}
	as, _ = runPackets(t, ttlRule+"\npass udp "+ttlSrc+" any -> any any (msg:\"p\"; sid:10;)", EngineConfig{}, pkts)
	if got := ttlAlerts(as); len(got) != 0 {
		t.Errorf("passed:%s", alertLines(as))
	}
}

// TestTTLAnomalyReload checks that an unchanged rule keeps its history
// across a reload and a changed one starts over.
func TestTTLAnomalyReload(t *testing.T) {
	e := NewEngine(mustParse(t, ttlRule), EngineConfig{})
	for _, tp := range ttlPkts(ttlSrc, 50, 10, 0, time.Second) {
		e.Process(tp.p.parsed(t, tp.ts))
	}
	e.next.Store(mustParse(t, ttlRule+"\nalert tcp any any -> any 1 (msg:\"x\"; sid:11;)"))
	var out []Alert
	for _, tp := range ttlPkts(ttlSrc, 60, 5, 20*time.Second, time.Second) {
		out = append(out, e.Process(tp.p.parsed(t, tp.ts))...)
	}
	if len(ttlAlerts(out)) != 1 {
		t.Errorf("history lost on reload:%s", alertLines(out))
	}
	e.next.Store(mustParse(t, strings.Replace(ttlRule, "max_hop_diff:3", "max_hop_diff:2", 1)))
	out = out[:0]
	for _, tp := range ttlPkts(ttlSrc, 70, 5, 40*time.Second, time.Second) {
		out = append(out, e.Process(tp.p.parsed(t, tp.ts))...)
	}
	if len(ttlAlerts(out)) != 0 {
		t.Errorf("changed rule kept history:%s", alertLines(out))
	}
}

// establishedDists returns the established distances of src, sorted.
func establishedDists(d *ttlAnomaly, src netip.Addr) []int {
	el, ok := d.srcs[src]
	if !ok {
		return nil
	}
	var out []int
	for _, sl := range el.Value.(*ttlSource).slots {
		if sl.samples >= uint32(d.rule.minSamples) {
			out = append(out, int(sl.dist))
		}
	}
	slices.Sort(out)
	return out
}

// tcpConn returns the packets of one TCP connection from client:cport to
// ttlSrc:443 starting at start, 10 ms apart: SYN, SYN-ACK and (if
// complete) the client's ACK, then n data segments from the server. The
// server's packets have serverTTL, the client's SYN synTTL (0 means 64).
func tcpConn(cport uint16, start time.Duration, synTTL, serverTTL uint8, complete bool, n int) []tpkt {
	const client = ttlDst
	ms := 10 * time.Millisecond
	var out []tpkt
	add := func(p pkt) { out = append(out, tpkt{at(start + time.Duration(len(out))*ms), p}) }
	add(pkt{proto: "tcp", src: client, dst: ttlSrc, sport: cport, dport: 443, flags: "S", seq: 100, ttl: synTTL})
	add(pkt{proto: "tcp", src: ttlSrc, dst: client, sport: 443, dport: cport, flags: "SA", seq: 500, ack: 101, ttl: serverTTL})
	if !complete {
		return out
	}
	add(pkt{proto: "tcp", src: client, dst: ttlSrc, sport: cport, dport: 443, flags: "A", seq: 101, ack: 501})
	for i := range n {
		add(pkt{proto: "tcp", src: ttlSrc, dst: client, sport: 443, dport: cport, flags: "PA", seq: 501 + uint32(i)*10, ack: 101, payload: "0123456789", ttl: serverTTL})
	}
	return out
}

// TestTTLAnomalyCompletedFlows is the eth0.pcap false positive: one
// server, a different path per connection, every connection completed.
// Nothing counts as anomalous, but the packets are still samples (every
// distance gets established), and the flows are remembered.
func TestTTLAnomalyCompletedFlows(t *testing.T) {
	var pkts []tpkt
	ttls := []uint8{50, 43, 57, 36}
	for i, ttl := range ttls {
		pkts = append(pkts, tcpConn(40000+uint16(i), time.Duration(i)*5*time.Second, 0, ttl, true, 12)...)
	}
	as, e := runPackets(t, ttlRule, EngineConfig{}, pkts)
	if got := ttlAlerts(as); len(got) != 0 {
		t.Errorf("completed connections alerted:%s", alertLines(as))
	}
	d := e.ruleState[0].ttl
	if got := establishedDists(d, netip.MustParseAddr(ttlSrc)); !slices.Equal(got, []int{7, 14, 21, 28}) {
		t.Errorf("established %v, want [7 14 21 28]: completed flows must still be samples", got)
	}
	if ts := e.Stats().Tables[TableTCPFlows]; ts.Keys != int64(len(ttls)) {
		t.Errorf("tcp_flows keys %d, want %d", ts.Keys, len(ttls))
	}
	if len(d.pending) != 0 {
		t.Errorf("%d held handshakes left after completion", len(d.pending))
	}

	// The same server packets without the handshakes (the IDS started
	// mid-connection) are checked at once: 13 anomalous packets from the
	// second connection on.
	var mid []tpkt
	for _, tp := range pkts {
		if tp.p.src == ttlSrc && tp.p.flags == "PA" {
			mid = append(mid, tp)
		}
	}
	as, _ = runPackets(t, ttlRule, EngineConfig{}, mid)
	if got := ttlAlerts(as); len(got) != 1 {
		t.Errorf("mid-connection packets: got %d alerts, want 1:%s", len(got), alertLines(as))
	}
}

// TestTTLAnomalyHeldHandshakes checks anomalies of pending handshakes:
// they are held until the outcome, dropped when the handshake completes
// and counted at the outcome time when it does not.
func TestTTLAnomalyHeldHandshakes(t *testing.T) {
	// ttlSrc establishes distance 14 over UDP. Then five connections that
	// ttlSrc opens to ttlDst:80 with SYN and ACK at TTL 60 (distance 4, an
	// anomaly), one per second from 20s.
	est := ttlPkts(ttlSrc, 50, 10, 0, time.Second)
	conns := func(complete bool) []tpkt {
		var out []tpkt
		for i := range 5 {
			ts := 20*time.Second + time.Duration(i)*time.Second
			cport := 41000 + uint16(i)
			out = append(out,
				tpkt{at(ts), pkt{proto: "tcp", src: ttlSrc, dst: ttlDst, sport: cport, dport: 80, flags: "S", seq: 100, ttl: 60}},
				tpkt{at(ts + time.Millisecond), pkt{proto: "tcp", src: ttlDst, dst: ttlSrc, sport: 80, dport: cport, flags: "SA", seq: 500, ack: 101}})
			if complete {
				out = append(out, tpkt{at(ts + 2*time.Millisecond), pkt{proto: "tcp", src: ttlSrc, dst: ttlDst, sport: cport, dport: 80, flags: "A", seq: 101, ack: 501, ttl: 60}})
			}
		}
		return out
	}

	as, e := runPackets(t, ttlRule, EngineConfig{}, slices.Concat(est, conns(true)))
	if got := ttlAlerts(as); len(got) != 0 {
		t.Errorf("completed handshakes alerted:%s", alertLines(as))
	}
	if n := len(e.ruleState[0].ttl.pending); n != 0 {
		t.Errorf("%d held handshakes left", n)
	}

	as, _ = runPackets(t, ttlRule, EngineConfig{}, slices.Concat(est, conns(false)))
	got := ttlAlerts(as)
	if len(got) != 1 {
		t.Fatalf("incomplete handshakes: got %d alerts, want 1:%s", len(got), alertLines(as))
	}
	// The fifth SYN was sent at 24s; its handshake times out 3s later.
	if want := at(27 * time.Second); !got[0].Time.Equal(want) {
		t.Errorf("alert at %v, want the fifth handshake's timeout %v", got[0].Time, want)
	}
	if got[0].SrcIP != ttlSrc || got[0].DstPort != 80 || got[0].SrcPort != 41004 {
		t.Errorf("alert %s, want the fifth SYN (%s:41004 -> port 80)", alertLine(got[0]), ttlSrc)
	}
}

// TestTTLAnomalyHeldCap checks the per-rule bound on held handshakes: at
// the cap the oldest is dropped and counted as an eviction.
func TestTTLAnomalyHeldCap(t *testing.T) {
	r := mustParse(t, ttlRule).rules[0]
	var st tableStat
	d := newTTLAnomaly(r, 2, &st)
	src := netip.MustParseAddr(ttlSrc)
	k := func(p uint16) hsKey { return hsKey{client: src, server: src, cport: p, sport: 1} }
	for p := range uint16(3) {
		d.hold(k(p), ttlHeld{src: src})
	}
	for range ttlMaxHeld + 2 {
		d.hold(k(2), ttlHeld{src: src})
	}
	if _, ok := d.pending[k(0)]; ok || len(d.pending) != 2 || st.evictions.Load() != 1 || st.keys.Load() != 2 {
		t.Errorf("pending %d (oldest kept %v), stats keys %d evictions %d; want 2, false, 2, 1", len(d.pending), ok, st.keys.Load(), st.evictions.Load())
	}
	if h := d.resolve(&hsEvent{key: k(2)}); len(h) != ttlMaxHeld {
		t.Errorf("held %d anomalies for one handshake, want the cap %d", len(h), ttlMaxHeld)
	}
	if h := d.resolve(&hsEvent{key: k(1), complete: true}); h != nil || len(d.pending) != 0 || st.keys.Load() != 0 {
		t.Errorf("complete handshake returned %d anomalies, %d left, keys %d", len(h), len(d.pending), st.keys.Load())
	}
}

// TestFlowSet checks the completed-flow set: refresh, idle expiry,
// eviction at the cap, and times earlier than the newest.
func TestFlowSet(t *testing.T) {
	var st tableStat
	f := newFlowSet(2, &st)
	a := netip.MustParseAddr("192.0.2.1")
	k := func(p uint16) hsKey { return hsKey{client: a, server: a, cport: p, sport: 80} }
	f.add(k(1), t0)
	f.add(k(2), t0.Add(time.Minute))
	if !f.touch(k(1), t0.Add(2*time.Minute)) { // k(1) is now the most recent
		t.Fatal("k1 not found")
	}
	f.add(k(3), t0.Add(3*time.Minute)) // evicts k(2)
	if f.touch(k(2), t0.Add(3*time.Minute)) || st.evictions.Load() != 1 || st.keys.Load() != 2 {
		t.Errorf("eviction: k2 kept or stats keys %d evictions %d", st.keys.Load(), st.evictions.Load())
	}
	// An earlier time does not move last back.
	f.touch(k(1), t0)
	if !f.touch(k(1), t0.Add(2*time.Minute+flowIdle)) {
		t.Error("k1 expired exactly at the idle limit")
	}
	if f.touch(k(3), t0.Add(3*time.Minute+flowIdle+time.Second)) || st.keys.Load() != 1 {
		t.Errorf("k3 not expired after idle, keys %d", st.keys.Load())
	}
	f.clear()
	if st.keys.Load() != 0 || len(f.m) != 0 {
		t.Errorf("clear left keys %d", st.keys.Load())
	}
}
