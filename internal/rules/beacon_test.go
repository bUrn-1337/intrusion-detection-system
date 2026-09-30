package rules

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

const (
	beaconHost = "10.0.0.5"
	beaconC2   = "203.0.113.9"
)

const beaconRule = `alert ip 10.0.0.0/8 any -> any any (msg:"beacon"; sid:1; detect:beacon;)`

// beaconSYNs returns one SYN per offset from beaconHost to beaconC2:443,
// each from a new source port.
func beaconSYNs(offsets []time.Duration) []timedPkt {
	var out []timedPkt
	for i, o := range offsets {
		out = append(out, timedPkt{o, pkt{proto: "tcp", src: beaconHost, dst: beaconC2, sport: uint16(40000 + i), dport: 443, flags: "S", seq: uint32(1000 * (i + 1))}})
	}
	return out
}

// every returns n offsets step apart.
func every(n int, step time.Duration) []time.Duration {
	var out []time.Duration
	for i := range n {
		out = append(out, time.Duration(i)*step)
	}
	return out
}

func TestBeaconScore(t *testing.T) {
	s := time.Second
	tests := []struct {
		name  string
		ivals []time.Duration
		med   time.Duration
		frac  float64
	}{
		{"fixed", []time.Duration{60 * s, 60 * s, 60 * s}, 60 * s, 1},
		{"even count takes the lower middle", []time.Duration{80 * s, 50 * s, 70 * s, 60 * s}, 60 * s, 0.75},
		{"half skipped", []time.Duration{60 * s, 120 * s, 60 * s, 120 * s}, 60 * s, 1},
		// One long gap moves the mean to 330s but not the median.
		{"median not mean", []time.Duration{60 * s, 60 * s, 60 * s, 60 * s, 60 * s, 60 * s, 60 * s, 60 * s, 60 * s, 2760 * s}, 60 * s, 0.9},
		{"skip counts", []time.Duration{60 * s, 120 * s, 60 * s, 60 * s}, 60 * s, 1},
		// Band edges: [45s, 75s] and [90s, 150s] around 60s.
		{"band edges in", []time.Duration{45 * s, 60 * s, 60 * s, 75 * s, 90 * s, 150 * s, 60 * s}, 60 * s, 1},
		{"band edges out", []time.Duration{44 * s, 60 * s, 60 * s, 76 * s, 89 * s, 151 * s, 60 * s}, 60 * s, 3.0 / 7},
		{"empty", nil, 0, 0},
	}
	for _, tt := range tests {
		med, frac := beaconScore(tt.ivals, 0.25)
		if med != tt.med || frac != tt.frac {
			t.Errorf("%s: median %v fraction %v, want %v %v", tt.name, med, frac, tt.med, tt.frac)
		}
	}
}

func TestBeaconFires(t *testing.T) {
	// Checks at connections 10, 16, 24 and 32 all pass: persistence 4
	// fires at the 32nd.
	pkts := beaconSYNs(every(34, time.Minute))
	if i := firesAt(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), pkts, 1); i != 31 {
		t.Fatalf("fired at %d, want 31 (the 32nd connection)", i)
	}
	as := sidAlerts(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), pkts, 1)
	if len(as) != 1 {
		t.Fatalf("%d alerts, want 1 (the rest are deduplicated)", len(as))
	}
	a := as[0]
	d := a.Details
	if a.SrcIP != beaconHost || a.DstIP != beaconC2 || a.DstPort != 443 || a.Proto != "TCP" {
		t.Errorf("alert %s", alertLine(a))
	}
	want := map[string]string{"detector": "beacon", "median": "1m0s", "fraction": "1.00", "count": "32", "events": "32", "name": "",
		"jitter": "0.25", "min_fraction": "0.7", "checks": "4", "intervals": strings.TrimSuffix(strings.Repeat("1m0s,", 8), ",")}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s = %q, want %q", k, d[k], v)
		}
	}

	// 20% jitter still fires by the 32nd connection.
	r := rand.New(rand.NewPCG(3, 4))
	var jit []time.Duration
	var tj time.Duration
	for range 32 {
		jit = append(jit, tj)
		tj += time.Duration(float64(time.Minute) * (0.8 + 0.4*r.Float64()))
	}
	if i := firesAt(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), beaconSYNs(jit), 1); i != 31 {
		t.Errorf("20%% jitter fired at %d, want 31", i)
	}

	// Outside [min_interval, max_interval]: every 5s and every 2h.
	for _, step := range []time.Duration{5 * time.Second, 2 * time.Hour} {
		if i := firesAt(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), beaconSYNs(every(12, step)), 1); i >= 0 {
			t.Errorf("every %v fired at %d", step, i)
		}
	}
	// Tuned options.
	tuned := `alert tcp 10.0.0.0/8 any -> any any (msg:"b"; sid:1; detect:beacon; min_events:4; persistence:1; min_interval:1; max_interval:10;)`
	if i := firesAt(t, NewEngine(mustParse(t, tuned), EngineConfig{}), beaconSYNs(every(6, 5*time.Second)), 1); i != 3 {
		t.Errorf("min_events:4 fired at %d, want 3", i)
	}
	// persistence:2 fires at the second checkpoint, 16.
	p2 := `alert tcp 10.0.0.0/8 any -> any any (msg:"b"; sid:1; detect:beacon; persistence:2;)`
	if i := firesAt(t, NewEngine(mustParse(t, p2), EngineConfig{}), beaconSYNs(every(20, time.Minute)), 1); i != 15 {
		t.Errorf("persistence:2 fired at %d, want 15", i)
	}
}

// randomOffsets returns n connection times with gaps drawn by gap.
func randomOffsets(n int, gap func() time.Duration) []time.Duration {
	var out []time.Duration
	var t time.Duration
	for range n {
		out = append(out, t)
		t += gap()
	}
	return out
}

func TestBeaconRandomIntervals(t *testing.T) {
	// Look-alikes: 100 connections with uniformly random 1-60s gaps and
	// with exponential gaps (mean 30s). These seeds pass a single check
	// (persistence:1 fires), as random traffic does by chance; four
	// checks in a row do not.
	r := rand.New(rand.NewPCG(210, 2))
	uniform := randomOffsets(100, func() time.Duration { return time.Second + time.Duration(r.Int64N(int64(59*time.Second))) })
	exp := randomOffsets(100, func() time.Duration { return time.Duration(r.ExpFloat64() * float64(30*time.Second)) })
	once := `alert ip 10.0.0.0/8 any -> any any (msg:"b"; sid:1; detect:beacon; persistence:1;)`
	for name, offs := range map[string][]time.Duration{"uniform": uniform, "exponential": exp} {
		if i := firesAt(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), beaconSYNs(offs), 1); i >= 0 {
			t.Errorf("%s: fired at %d", name, i)
		}
		if i := firesAt(t, NewEngine(mustParse(t, once), EngineConfig{}), beaconSYNs(offs), 1); i < 0 {
			t.Errorf("%s: persistence:1 did not fire; pick a seed that shows the difference", name)
		}
	}
}

func TestBeaconPersistenceReset(t *testing.T) {
	// Regular for the checks at 10, erratic for the check at 16, then
	// regular again: the failed check restarts the count, so the four in
	// a row are 24, 32, 40 and 48 (without the reset: 40).
	offs := every(10, time.Minute)
	last := offs[len(offs)-1]
	for _, g := range []int{7, 150, 20, 80, 3, 200} {
		last += time.Duration(g) * time.Second
		offs = append(offs, last)
	}
	for range 40 {
		last += time.Minute
		offs = append(offs, last)
	}
	e := NewEngine(mustParse(t, beaconRule), EngineConfig{})
	if i := firesAt(t, e, beaconSYNs(offs), 1); i != 47 {
		t.Errorf("fired at %d, want 47 (the 48th connection)", i)
	}
}

func TestBeaconCheckpoints(t *testing.T) {
	var got []uint64
	for n := uint64(1); n <= 50; n++ {
		if isCheckpoint(n, 10) {
			got = append(got, n)
		}
	}
	if fmt.Sprint(got) != "[10 16 24 32 40 48]" {
		t.Errorf("min_events 10: checkpoints %v", got)
	}
	got = nil
	for n := uint64(1); n <= 30; n++ {
		if isCheckpoint(n, 20) {
			got = append(got, n)
		}
	}
	if fmt.Sprint(got) != "[20 24]" {
		t.Errorf("min_events 20: checkpoints %v", got)
	}
}

func TestBeaconSkips(t *testing.T) {
	// Every third beat is missed: a third of the intervals are 2m.
	var offs []time.Duration
	for i := range 48 {
		if i%3 != 2 {
			offs = append(offs, time.Duration(i)*time.Minute)
		}
	}
	as := sidAlerts(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), beaconSYNs(offs), 1)
	if len(as) != 1 || as[0].Details["median"] != "1m0s" || as[0].Details["fraction"] != "1.00" {
		t.Fatalf("alerts %v", alertLines(as))
	}
}

func TestBeaconConnectionStart(t *testing.T) {
	// Each SYN is retransmitted 1s and 3s later with the same sequence
	// number; retransmissions are not connection starts.
	var pkts []timedPkt
	for _, p := range beaconSYNs(every(32, time.Minute)) {
		pkts = append(pkts, p, timedPkt{p.t + time.Second, p.p}, timedPkt{p.t + 3*time.Second, p.p})
	}
	if i := firesAt(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), pkts, 1); i != 93 {
		t.Errorf("with retransmissions fired at %d, want 93 (the 32nd original SYN)", i)
	}

	// A keepalive every minute on one connection is one event.
	pkts = beaconSYNs(every(1, 0))
	for i := 1; i < 40; i++ {
		pkts = append(pkts, timedPkt{time.Duration(i) * time.Minute, pkt{proto: "tcp", src: beaconHost, dst: beaconC2, sport: 40000, dport: 443, flags: "A", seq: 1001, ack: 1}})
	}
	if i := firesAt(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), pkts, 1); i >= 0 {
		t.Errorf("keepalives fired at %d", i)
	}
	// SYN-ACKs from a server are not starts either, even all to one
	// client port (one key) every minute.
	pkts = nil
	for i, o := range every(34, time.Minute) {
		pkts = append(pkts, timedPkt{o, pkt{proto: "tcp", src: beaconHost, dst: beaconC2, sport: 443, dport: 40000, flags: "SA", seq: uint32(i)}})
	}
	if i := firesAt(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), pkts, 1); i >= 0 {
		t.Errorf("SYN-ACKs fired at %d", i)
	}
}

func TestBeaconUDP(t *testing.T) {
	udpEvery := func(n int, step time.Duration, dport uint16, reply bool) []timedPkt {
		var out []timedPkt
		for i := range n {
			o := time.Duration(i) * step
			out = append(out, timedPkt{o, udpPkt(beaconHost, 50000, beaconC2, dport, "ping")})
			if reply {
				out = append(out, timedPkt{o + 10*time.Millisecond, udpPkt(beaconC2, dport, beaconHost, 50000, "pong")})
			}
		}
		return out
	}
	// One 4-tuple, idle 60s between packets: each is a new flow.
	as := sidAlerts(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), udpEvery(34, time.Minute, 4444, true), 1)
	if len(as) != 1 || as[0].Proto != "UDP" || as[0].DstPort != 4444 {
		t.Fatalf("alerts %v", alertLines(as))
	}
	// Every 20s the flow never goes idle: one event.
	if i := firesAt(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), udpEvery(110, 20*time.Second, 4444, false), 1); i >= 0 {
		t.Errorf("20s packets fired at %d", i)
	}
	// The server's packets keep the flow alive: the client sends every
	// 60s, the server every 20s in between.
	var pkts []timedPkt
	for i := range 110 {
		o := time.Duration(i) * 20 * time.Second
		if i%3 == 0 {
			pkts = append(pkts, timedPkt{o, udpPkt(beaconHost, 50000, beaconC2, 4444, "ping")})
		} else {
			pkts = append(pkts, timedPkt{o, udpPkt(beaconC2, 4444, beaconHost, 50000, "push")})
		}
	}
	if i := firesAt(t, NewEngine(mustParse(t, `alert ip any any -> any any (msg:"b"; sid:1; detect:beacon;)`), EngineConfig{}), pkts, 1); i >= 0 {
		t.Errorf("flow kept alive by the server fired at %d", i)
	}
	// DNS to port 53 and NTP (allow_ports default) never count.
	for _, port := range []uint16{53, 123} {
		if i := firesAt(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), udpEvery(34, time.Minute, port, true), 1); i >= 0 {
			t.Errorf("port %d fired at %d", port, i)
		}
	}
	// allow_ports replaces the default.
	r := `alert ip 10.0.0.0/8 any -> any any (msg:"b"; sid:1; detect:beacon; allow_ports:[4444];)`
	if i := firesAt(t, NewEngine(mustParse(t, r), EngineConfig{}), udpEvery(34, time.Minute, 123, true), 1); i < 0 {
		t.Error("port 123 with allow_ports:[4444] did not fire")
	}
	if i := firesAt(t, NewEngine(mustParse(t, r), EngineConfig{}), udpEvery(34, time.Minute, 4444, true), 1); i >= 0 {
		t.Errorf("allowed port 4444 fired at %d", i)
	}
}

func TestBeaconAllow(t *testing.T) {
	syns := beaconSYNs(every(34, time.Minute))
	rule := func(opt string) string {
		return `var OK [updates.example.com]
var OK_NETS [203.0.113.0/28]
alert ip 10.0.0.0/8 any -> any any (msg:"b"; sid:1; detect:beacon; ` + opt + `)`
	}
	if i := firesAt(t, NewEngine(mustParse(t, rule("allow_addrs:$OK_NETS;")), EngineConfig{}), syns, 1); i >= 0 {
		t.Errorf("allowed address fired at %d", i)
	}
	// Names come from the HTTP Host of the key's connections.
	var web []timedPkt
	for i, o := range every(34, time.Minute) {
		sport := uint16(40000 + i)
		web = append(web,
			timedPkt{o, pkt{proto: "tcp", src: beaconHost, dst: beaconC2, sport: sport, dport: 80, flags: "S", seq: uint32(i) * 1000}},
			timedPkt{o + 100*time.Millisecond, pkt{proto: "tcp", src: beaconHost, dst: beaconC2, sport: sport, dport: 80, flags: "PA", seq: uint32(i)*1000 + 1, ack: 1,
				payload: "GET /poll HTTP/1.1\r\nHost: Updates.Example.com:80\r\n\r\n"}})
	}
	if i := firesAt(t, NewEngine(mustParse(t, rule("allow:$OK;")), EngineConfig{}), web, 1); i >= 0 {
		t.Errorf("allowed name fired at %d", i)
	}
	as := sidAlerts(t, NewEngine(mustParse(t, rule("allow:[other.example.org];")), EngineConfig{}), web, 1)
	if len(as) != 1 || as[0].Details["name"] != "updates.example.com" {
		t.Fatalf("alerts %v", alertLines(as))
	}
	// A source outside the rule's source addresses is not a key.
	if i := firesAt(t, NewEngine(mustParse(t, `alert ip 192.168.0.0/16 any -> any any (msg:"b"; sid:1; detect:beacon;)`), EngineConfig{}), syns, 1); i >= 0 {
		t.Errorf("source outside the rule fired at %d", i)
	}
}

func TestBeaconTable(t *testing.T) {
	e := NewEngine(mustParse(t, beaconRule), EngineConfig{MaxKeys: 3})
	// Four destinations at the cap of 3 keys.
	for i, dst := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"} {
		e.Process(pkt{proto: "tcp", src: beaconHost, dst: dst, sport: 40000, dport: 443, flags: "S", seq: 1}.parsed(t, at(time.Duration(i)*time.Second)))
	}
	st := e.Stats().Tables[TableBeacon]
	if st.Keys != 3 || st.Evictions != 1 {
		t.Errorf("table %+v, want 3 keys, 1 eviction", st)
	}
	// A key without an event for 6h is dropped.
	e.Process(pkt{proto: "tcp", src: beaconHost, dst: "203.0.113.5", sport: 40001, dport: 443, flags: "S", seq: 1}.parsed(t, at(6*time.Hour+4*time.Second)))
	if st := e.Stats().Tables[TableBeacon]; st.Keys != 1 {
		t.Errorf("after 6h: %d keys, want 1", st.Keys)
	}
	// The ring keeps the last 32 events: 40 events 1m apart then a
	// change to 5m are still judged on the last 32 only.
	// A key alerts once while periodic, and again after a failed check:
	// 40 events 1m apart, then 50 events 5m apart. The check at 56 fails
	// (half the ring is 1m, half 5m), and 64, 72, 80 and 88 pass.
	offs := every(40, time.Minute)
	for i := range 50 {
		offs = append(offs, 39*time.Minute+time.Duration(i+1)*5*time.Minute)
	}
	as := sidAlerts(t, NewEngine(mustParse(t, beaconRule), EngineConfig{}), beaconSYNs(offs), 1)
	if len(as) != 2 || as[0].Details["median"] != "1m0s" || as[1].Details["median"] != "5m0s" || as[1].Details["count"] != "32" {
		t.Fatalf("alerts %v", alertLines(as))
	}
}

func TestBeaconParse(t *testing.T) {
	tests := []struct{ opts, want string }{
		{"min_events:2;", "min_events: 2: at least 3 (two intervals)"},
		{"min_events:33;", "min_events"},
		{"jitter:0.5;", `jitter "0.5": want a number above 0 and below 0.5`},
		{"min_fraction:0;", `min_fraction "0"`},
		{"min_interval:60; max_interval:30;", "min_interval 1m0s is above max_interval 30s"},
		{"allow_addrs:[foo];", "allow_addrs"},
		{"allow_ports:[x];", "allow_ports"},
		{"count:5;", "option count is not valid with detect:beacon"},
		{"persistence:0;", "persistence"},
		{"persistence:9;", "persistence"},
	}
	for _, tt := range tests {
		errs := loadErrors(t, `alert ip any any -> any any (msg:"b"; sid:1; detect:beacon; `+tt.opts+`)`)
		if len(errs) == 0 || !strings.Contains(errs[0], tt.want) {
			t.Errorf("%s: errors %q, want %q", tt.opts, errs, tt.want)
		}
	}
	for _, rule := range []string{
		`alert icmp any any -> any any (msg:"b"; sid:1; detect:beacon;)`,
		`alert ip any any <> any any (msg:"b"; sid:1; detect:beacon;)`,
	} {
		if errs := loadErrors(t, rule); len(errs) == 0 {
			t.Errorf("%s: no error", rule)
		}
	}
	errs := loadErrors(t, `alert tcp any any -> any any (msg:"b"; sid:1; min_events:3;)`)
	if len(errs) == 0 || !strings.Contains(errs[0], "only valid with detect:beacon") {
		t.Errorf("errors %q", errs)
	}
	rs := mustParse(t, beaconRule)
	r := rs.Rules()[0]
	if r.minEvents != 10 || r.persistence != 4 || r.minInterval != 10*time.Second || r.maxInterval != time.Hour || r.jitter != 0.25 || r.minFraction != 0.7 ||
		!r.allowPorts.match(123) || r.allowPorts.match(443) || r.hasAllowAddrs {
		t.Errorf("defaults %+v", r)
	}
}

func TestBeaconLearnName(t *testing.T) {
	tests := []struct {
		fields map[string]string
		want   string
	}{
		{map[string]string{"sni": "C2.Example.NET", "host": "x.example"}, "c2.example.net"},
		{map[string]string{"host": "poll.example.com:8080"}, "poll.example.com"},
		{map[string]string{"qname": "a.example.org"}, "a.example.org"},
		{map[string]string{"qname": "a.example.org", "is_response": "true"}, ""},
		{nil, ""},
	}
	for _, tt := range tests {
		var b beaconEntry
		learnName(&b, tt.fields)
		if b.name != tt.want {
			t.Errorf("%v: %q, want %q", tt.fields, b.name, tt.want)
		}
	}
	// The first name stays.
	b := beaconEntry{name: "first.example"}
	learnName(&b, map[string]string{"sni": "second.example"})
	if b.name != "first.example" {
		t.Errorf("name %q", b.name)
	}
}
