package rules

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

var (
	addrA = netip.MustParseAddr("10.0.0.1")
	addrB = netip.MustParseAddr("10.0.0.2")
	addrC = netip.MustParseAddr("10.0.0.3")
)

// feed adds one event per time and returns the indexes that fired.
func feed(w *windowCounter[netip.Addr], key netip.Addr, times ...time.Time) []int {
	var fired []int
	for i, ts := range times {
		if _, ok := w.add(key, ts, 0); ok {
			fired = append(fired, i)
		}
	}
	return fired
}

func repeat(n int, ts time.Time) []time.Time {
	out := make([]time.Time, n)
	for i := range out {
		out[i] = ts
	}
	return out
}

func spread(n int, start time.Time, step time.Duration) []time.Time {
	out := make([]time.Time, n)
	for i := range out {
		out[i] = start.Add(time.Duration(i) * step)
	}
	return out
}

func TestWindowCounter(t *testing.T) {
	sec := time.Second
	tests := []struct {
		name  string
		n     int
		span  time.Duration
		times []time.Time
		want  []int
	}{
		{"n-1 within span", 5, 10 * sec, spread(4, t0, sec), nil},
		{"n within span", 5, 10 * sec, spread(5, t0, sec), []int{4}},
		{"keeps firing while dense", 3, 10 * sec, spread(5, t0, sec), []int{2, 3, 4}},
		{"exactly span apart fires", 2, 10 * sec, []time.Time{t0, at(10 * sec)}, []int{1}},
		{"just over span", 2, 10 * sec, []time.Time{t0, at(10*sec + 1)}, nil},
		{"n spread over more than span", 5, 10 * sec, spread(5, t0, 3*sec), nil},
		{"slides: old events age out", 3, 10 * sec, []time.Time{t0, at(8 * sec), at(9 * sec), at(11 * sec), at(12 * sec)}, []int{2, 3, 4}},
		{"slides: gap then burst", 3, 2 * sec, []time.Time{t0, at(time.Second), at(5 * sec), at(5 * sec), at(5 * sec)}, []int{4}},
		{"n = 1", 1, sec, []time.Time{t0, at(time.Hour)}, []int{0, 1}},
		// 99 events at 0:59 and 99 at 1:01 with 100 per 2s: a fixed 1-minute
		// bucket sees 99 in each; the sliding window fires on the 100th.
		{"99 at 0:59, 99 at 1:01", 100, 2 * sec, append(repeat(99, at(59*sec)), repeat(99, at(61*sec))...), rangeInts(99, 198)},
		{"99 at 0:59, 99 at 1:01.001", 100, 2 * sec, append(repeat(99, at(59*sec)), repeat(99, at(61*sec+time.Millisecond))...), nil},
		// Events earlier than the key's newest are recorded at the newest
		// time, so going backwards never makes the window look longer.
		{"backwards timestamps", 3, 10 * sec, []time.Time{at(100 * sec), t0, t0}, []int{2}},
		{"backwards after a gap", 3, 10 * sec, []time.Time{t0, at(100 * sec), at(50 * sec), at(1 * sec)}, []int{3}},
		// Unclamped, the event at 0s would become the oldest and make
		// 100s..105s look like a 105s window.
		{"backwards event later oldest", 2, 10 * sec, []time.Time{at(100 * sec), t0, at(105 * sec)}, []int{1, 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var st tableStat
			w := newWindowCounter[netip.Addr](tt.n, tt.span, 100, &st)
			if got := feed(w, addrA, tt.times...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fired at %v, want %v", got, tt.want)
			}
		})
	}
}

func rangeInts(lo, hi int) []int {
	var out []int
	for i := lo; i < hi; i++ {
		out = append(out, i)
	}
	return out
}

func TestWindowCounterKeysAreSeparate(t *testing.T) {
	var st tableStat
	w := newWindowCounter[netip.Addr](2, time.Second, 100, &st)
	if feed(w, addrA, t0) != nil || feed(w, addrB, t0) != nil {
		t.Fatal("fired on first event")
	}
	if got := feed(w, addrA, t0); !reflect.DeepEqual(got, []int{0}) {
		t.Errorf("second event for A: %v", got)
	}
}

func TestWindowCounterEviction(t *testing.T) {
	var st tableStat
	w := newWindowCounter[netip.Addr](2, time.Hour, 2, &st)
	w.add(addrA, t0, 0)
	w.add(addrB, t0, 0)
	w.add(addrA, at(time.Second), 0) // A is now the most recently seen
	w.add(addrC, at(time.Second), 0) // evicts B, the least recently seen
	if st.keys.Load() != 2 || st.evictions.Load() != 1 || w.len() != 2 {
		t.Fatalf("keys %d evictions %d", st.keys.Load(), st.evictions.Load())
	}
	if _, ok := w.keys[addrB]; ok {
		t.Error("B not evicted")
	}
	// B starts again from scratch: one event does not fire.
	if _, ok := w.add(addrB, at(time.Second), 0); ok {
		t.Error("evicted key kept its events")
	}
	if st.evictions.Load() != 2 {
		t.Errorf("evictions %d", st.evictions.Load())
	}
}

func TestWindowCounterPrunesStaleKeys(t *testing.T) {
	var st tableStat
	w := newWindowCounter[netip.Addr](2, time.Second, 10, &st)
	w.add(addrA, t0, 0)
	w.add(addrB, t0, 0)
	w.add(addrC, at(5*time.Second), 0) // A and B can no longer fire
	if w.len() != 1 || st.keys.Load() != 1 || st.evictions.Load() != 0 {
		t.Errorf("len %d keys %d evictions %d", w.len(), st.keys.Load(), st.evictions.Load())
	}
	w.clear()
	if w.len() != 0 || st.keys.Load() != 0 {
		t.Errorf("after clear: len %d keys %d", w.len(), st.keys.Load())
	}
}

func TestWindowEntryHelpers(t *testing.T) {
	var st tableStat
	w := newWindowCounter[netip.Addr](4, time.Hour, 10, &st)
	for i, port := range []uint16{443, 80, 22, 80, 443, 22, 22} {
		w.add(addrA, at(time.Duration(i)*time.Second), port)
	}
	e := w.keys[addrA].Value.(*windowEntry[netip.Addr])
	// The last four events are 80, 443, 22, 22 at 3..6s.
	if e.size() != 4 || !e.oldest().Equal(at(3*time.Second)) || !e.newest().Equal(at(6*time.Second)) || e.topTag() != 22 {
		t.Errorf("size %d oldest %v newest %v top %d", e.size(), e.oldest().Sub(t0), e.newest().Sub(t0), e.topTag())
	}
	if got := w.countSince(addrA, at(5*time.Second)); got != 2 {
		t.Errorf("countSince = %d", got)
	}
	if got := w.countSince(addrB, t0); got != 0 {
		t.Errorf("countSince unknown key = %d", got)
	}
	// Ties go to the lower tag.
	w2 := newWindowCounter[netip.Addr](4, time.Hour, 10, &st)
	for _, port := range []uint16{443, 80, 443, 80} {
		w2.add(addrA, t0, port)
	}
	if top := w2.keys[addrA].Value.(*windowEntry[netip.Addr]).topTag(); top != 80 {
		t.Errorf("tie topTag = %d", top)
	}
}

// Handshake tracker.

type hsStep struct {
	at    time.Duration
	seg   tcpSegment
	check bool // run expire(at) before observing
}

var (
	cli = netip.MustParseAddr("10.0.0.1")
	srv = netip.MustParseAddr("10.0.0.2")
)

func syn(seq uint32) tcpSegment {
	return tcpSegment{src: cli, dst: srv, sport: 40000, dport: 80, flags: tcpSYN, seq: seq}
}
func synAck(seq, ack uint32) tcpSegment {
	return tcpSegment{src: srv, dst: cli, sport: 80, dport: 40000, flags: tcpSYN | tcpACK, seq: seq, ack: ack}
}
func finalAck(seq, ack uint32) tcpSegment {
	return tcpSegment{src: cli, dst: srv, sport: 40000, dport: 80, flags: tcpACK, seq: seq, ack: ack}
}
func rstFrom(fromServer bool) tcpSegment {
	if fromServer {
		return tcpSegment{src: srv, dst: cli, sport: 80, dport: 40000, flags: tcpRST | tcpACK}
	}
	return tcpSegment{src: cli, dst: srv, sport: 40000, dport: 80, flags: tcpRST}
}

// runHS drives a tracker (3s timeout) and returns the outcomes as
// "complete@t" or "reason@t".
func runHS(t *testing.T, max int, steps []hsStep, end time.Duration) ([]string, *handshakeTracker, *tableStat) {
	t.Helper()
	var st tableStat
	h := newHandshakeTracker(3*time.Second, max, &st)
	var evs []hsEvent
	for _, s := range steps {
		now := at(s.at)
		evs = h.expire(now, evs)
		evs = h.observe(&s.seg, now, evs)
	}
	evs = h.expire(at(end), evs)
	var out []string
	for _, ev := range evs {
		r := ev.reason
		if ev.complete {
			r = "complete"
		}
		out = append(out, r+"@"+ev.t.Sub(t0).String())
	}
	return out, h, &st
}

func TestHandshakeTracker(t *testing.T) {
	ms := time.Millisecond
	tests := []struct {
		name  string
		steps []hsStep
		end   time.Duration
		want  []string
	}{
		{"complete", []hsStep{{0, syn(100), false}, {ms, synAck(500, 101), false}, {2 * ms, finalAck(101, 501), false}}, time.Minute, []string{"complete@2ms"}},
		{"syn then server rst", []hsStep{{0, syn(100), false}, {ms, rstFrom(true), false}}, time.Minute, []string{"rst@1ms"}},
		{"syn-ack then client rst (half-open scan)", []hsStep{{0, syn(100), false}, {ms, synAck(500, 101), false}, {2 * ms, rstFrom(false), false}}, time.Minute, []string{"rst@2ms"}},
		{"syn timeout", []hsStep{{0, syn(100), false}}, time.Minute, []string{"timeout@3s"}},
		{"not yet timed out", []hsStep{{0, syn(100), false}}, 3*time.Second - 1, nil},
		{"answered but no final ack times out", []hsStep{{0, syn(100), false}, {ms, synAck(500, 101), false}}, time.Minute, []string{"timeout@3s"}},
		{"retransmitted syn not counted again", []hsStep{{0, syn(100), false}, {time.Second, syn(100), false}, {2 * time.Second, syn(100), false}}, time.Minute, []string{"timeout@3s"}},
		{"retransmitted syn then completes", []hsStep{{0, syn(100), false}, {time.Second, syn(100), false}, {time.Second + ms, synAck(500, 101), false}, {time.Second + 2*ms, finalAck(101, 501), false}}, time.Minute, []string{"complete@1.002s"}},
		{"new syn with other seq abandons the old one", []hsStep{{0, syn(100), false}, {time.Second, syn(900), false}}, time.Minute, []string{"reused@1s", "timeout@4s"}},
		{"syn-ack with wrong ack is not an answer", []hsStep{{0, syn(100), false}, {ms, synAck(500, 100), false}, {2 * ms, finalAck(101, 501), false}}, time.Minute, []string{"timeout@3s"}},
		{"syn-ack with ack = seq+2 is not an answer", []hsStep{{0, syn(100), false}, {ms, synAck(500, 102), false}, {2 * ms, finalAck(101, 501), false}}, time.Minute, []string{"timeout@3s"}},
		{"final ack with wrong ack does not complete", []hsStep{{0, syn(100), false}, {ms, synAck(500, 101), false}, {2 * ms, finalAck(101, 999), false}}, time.Minute, []string{"timeout@3s"}},
		{"seq wraps", []hsStep{{0, syn(0xffffffff), false}, {ms, synAck(0xffffffff, 0), false}, {2 * ms, finalAck(0, 0), false}}, time.Minute, []string{"complete@2ms"}},
		{"stray syn-ack, ack and rst are ignored", []hsStep{{0, synAck(1, 2), false}, {0, finalAck(1, 2), false}, {0, rstFrom(true), false}}, time.Minute, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, h, st := runHS(t, 100, tt.steps, tt.end)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("outcomes %v, want %v", got, tt.want)
			}
			if tt.end == time.Minute && (h.len() != 0 || st.keys.Load() != 0) {
				t.Errorf("%d entries left, keys stat %d", h.len(), st.keys.Load())
			}
		})
	}
}

func TestHandshakeTrackerEviction(t *testing.T) {
	var steps []hsStep
	for i := range 4 {
		s := syn(100)
		s.sport = uint16(1000 + i)
		steps = append(steps, hsStep{at: time.Duration(i) * time.Millisecond, seg: s})
	}
	got, h, st := runHS(t, 3, steps, 0)
	if want := []string{"evicted@3ms"}; !reflect.DeepEqual(got, want) {
		t.Errorf("outcomes %v, want %v", got, want)
	}
	if h.len() != 3 || st.keys.Load() != 3 || st.evictions.Load() != 1 {
		t.Errorf("len %d keys %d evictions %d", h.len(), st.keys.Load(), st.evictions.Load())
	}
	if _, ok := h.m[hsKey{client: cli, cport: 1000, server: srv, sport: 80}]; ok {
		t.Error("oldest entry not evicted")
	}
	evs := h.expireAll(nil)
	if len(evs) != 3 || h.len() != 0 || st.keys.Load() != 0 || !evs[0].t.Equal(at(3*time.Second+time.Millisecond)) {
		t.Errorf("expireAll: %+v", evs)
	}
}

// Dedup, through the engine.

func TestDedup(t *testing.T) {
	rs := mustParse(t, `alert udp any any -> any any (msg:"m"; sid:1;)`)
	e := NewEngine(rs, EngineConfig{DedupWindow: 10 * time.Second})
	a := pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.9", sport: 1, dport: 2}
	b := pkt{proto: "udp", src: "10.0.0.2", dst: "10.0.0.9", sport: 1, dport: 2}
	var got []Alert
	for i := range 5 {
		got = append(got, e.Process(a.parsed(t, at(time.Duration(i)*time.Second)))...)
	}
	got = append(got, e.Process(b.parsed(t, at(5*time.Second)))...)
	if len(got) != 2 || got[0].Kind != KindAlert || got[0].Count != 1 || got[0].SrcIP != "10.0.0.1" || got[1].SrcIP != "10.0.0.2" {
		t.Fatalf("first alerts: %s", alertLines(got))
	}
	// The window for A closes at 10s: one summary with the total count.
	got = e.Process(b.parsed(t, at(10*time.Second)))
	want := got0(got)
	if len(got) != 1 || want.Kind != KindSummary || want.Count != 5 || want.SrcIP != "10.0.0.1" ||
		!want.Time.Equal(at(10*time.Second)) || !want.FirstSeen.Equal(t0) || !want.LastSeen.Equal(at(4*time.Second)) {
		t.Fatalf("summary: %s", alertLines(got))
	}
	// A new match for A after the window alerts again.
	got = e.Process(a.parsed(t, at(11*time.Second)))
	if len(got) != 1 || got[0].Kind != KindAlert {
		t.Fatalf("after window: %s", alertLines(got))
	}
	// Flush: B has count 2 (5s and 10s), A has count 1 (no summary).
	got = e.Flush()
	if len(got) != 1 || got[0].Kind != KindSummary || got[0].SrcIP != "10.0.0.2" || got[0].Count != 2 || !got[0].LastSeen.Equal(at(10*time.Second)) {
		t.Fatalf("flush: %s", alertLines(got))
	}
	if again := e.Flush(); len(again) != 0 {
		t.Errorf("second flush: %s", alertLines(again))
	}
	s := e.Stats()
	if s.Alerts != 3 || s.Summaries != 2 || s.Suppressed != 5 || s.Tables[TableDedup].Keys != 0 {
		t.Errorf("stats %+v", s)
	}
}

func got0(as []Alert) Alert {
	if len(as) == 0 {
		return Alert{}
	}
	return as[0]
}

func TestDedupEviction(t *testing.T) {
	rs := mustParse(t, `alert udp any any -> any any (msg:"m"; sid:1;)`)
	e := NewEngine(rs, EngineConfig{MaxKeys: 2})
	var got []Alert
	for _, src := range []string{"10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		got = append(got, e.Process(pkt{proto: "udp", src: src, dst: "10.0.0.9", sport: 1, dport: 2}.parsed(t, t0))...)
	}
	// The third source evicts the first, whose summary (count 2) is emitted
	// before the new alert.
	var kinds []string
	for _, a := range got {
		kinds = append(kinds, a.Kind+" "+a.SrcIP)
	}
	want := []string{"alert 10.0.0.1", "alert 10.0.0.2", "summary 10.0.0.1", "alert 10.0.0.3"}
	if !reflect.DeepEqual(kinds, want) {
		t.Errorf("got %v, want %v", kinds, want)
	}
	if s := e.Stats().Tables[TableDedup]; s.Keys != 2 || s.Evictions != 1 {
		t.Errorf("dedup stats %+v", s)
	}
}

// TestClockClamp checks that the engine clock is packet time and never
// goes backwards.
func TestClockClamp(t *testing.T) {
	rs := mustParse(t, `alert udp any any -> any any (msg:"m"; sid:1;)`)
	e := NewEngine(rs, EngineConfig{DedupWindow: 10 * time.Second})
	a := pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.9", sport: 1, dport: 2}
	b := pkt{proto: "udp", src: "10.0.0.2", dst: "10.0.0.9", sport: 1, dport: 2}
	e.Process(a.parsed(t, at(100*time.Second)))
	// A packet from the past is treated as arriving at 100s.
	got := e.Process(b.parsed(t, at(time.Second)))
	if len(got) != 1 || !got[0].Time.Equal(at(100*time.Second)) {
		t.Fatalf("backwards packet: %s", alertLines(got))
	}
	// A backwards jump cannot close or reopen A's window: still suppressed.
	if got := e.Process(a.parsed(t, at(50*time.Second))); len(got) != 0 {
		t.Errorf("A alerted again: %s", alertLines(got))
	}
	// Forward time closes both windows at 110s.
	got = e.Process(pkt{proto: "icmp", src: "10.0.0.3", dst: "10.0.0.9"}.parsed(t, at(110*time.Second)))
	if len(got) != 1 || got[0].Kind != KindSummary || got[0].Count != 2 || !got[0].LastSeen.Equal(at(100*time.Second)) {
		t.Errorf("summary: %s", alertLines(got))
	}
}
