package rules

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

const baselineRule = `alert ip 10.0.0.0/8 any <> any any (msg:"baseline"; sid:1; detect:baseline; interval:10; learn_intervals:6;%s)`

func baselineEngine(t *testing.T, extra string) *Engine {
	t.Helper()
	return NewEngine(mustParse(t, fmt.Sprintf(baselineRule, extra)), EngineConfig{})
}

// traffic returns n packets per interval for intervals intervals of
// 10s from start, evenly spaced, from 10.0.0.5 to dsts distinct
// destinations (192.0.2.x, 198.51.100.x, ...) on UDP port 5000.
func traffic(start time.Duration, intervals, n, dsts int) []timedPkt {
	var out []timedPkt
	iv := 10 * time.Second
	for i := range intervals {
		for j := range n {
			off := start + time.Duration(i)*iv + time.Duration(j)*iv/time.Duration(n)
			k := j % dsts
			dst := fmt.Sprintf("192.0.%d.%d", 2+k/250, 1+k%250)
			out = append(out, timedPkt{off, udpPkt("10.0.0.5", 40000, dst, 5000, "x")})
		}
	}
	return out
}

// concat joins packet lists.
func concat(ps ...[]timedPkt) []timedPkt {
	var out []timedPkt
	for _, p := range ps {
		out = append(out, p...)
	}
	return out
}

func TestEWMALearning(t *testing.T) {
	p := baselineParams{learn: 4, threshold: 4, sustain: 3, maxStep: 0.2}
	var m ewma
	for _, x := range []float64{10, 20, 30, 40} {
		if v := m.update(x, 1, 0, false, &p); v.fire || v.score != 0 {
			t.Fatalf("learning interval %v: %+v", x, v)
		}
	}
	// Cumulative: mean 25; deviations 10 (20 vs 10), 15 (30 vs 15), 20
	// (40 vs 20): mean 15.
	if m.mean != 25 || m.dev != 15 || m.n != 4 {
		t.Fatalf("after learning mean %v dev %v n %d, want 25 15 4", m.mean, m.dev, m.n)
	}
}

func TestEWMAStep(t *testing.T) {
	p := baselineParams{learn: 1, threshold: 4, sustain: 3, maxStep: 0.2}
	m := ewma{mean: 100, dev: 10, n: 1}
	// Score (130-100)/10 = 3: normal, alpha 0.1 moves the mean 3 and the
	// deviation 0.1*(30-10) = 2.
	v := m.update(130, 1, 0, false, &p)
	if v.score != 3 || math.Abs(m.mean-103) > 1e-9 || math.Abs(m.dev-12) > 1e-9 {
		t.Fatalf("score %v mean %v dev %v, want 3 103 12", v.score, m.mean, m.dev)
	}
	// A noisy metric: dev 100, x 450 scores 3.5 (normal); alpha would
	// move the mean 35 and the deviation 25, max_step caps both at 20.
	m = ewma{mean: 100, dev: 100, n: 1}
	m.update(450, 1, 0, false, &p)
	if m.mean != 120 || m.dev != 120 {
		t.Fatalf("max_step: mean %v dev %v, want 120 120", m.mean, m.dev)
	}
	// From zero the step is a fraction of the floor: mean 0, floor 10,
	// alpha*30 = 3 is capped at 0.2*10 = 2 (30 scores 3: normal).
	m = ewma{n: 1}
	m.update(30, 10, 0, false, &p)
	if m.mean != 2 {
		t.Fatalf("floor step: mean %v, want 2", m.mean)
	}
}

func TestEWMAMinLevel(t *testing.T) {
	// A metric learned at 0 (DNS floor 0.2/s): 0.9/s scores 4.5, which
	// is anomalous, but below min_level 1 it never fires.
	p := baselineParams{learn: 1, threshold: 4, sustain: 3, maxStep: 0.2}
	for _, tc := range []struct {
		x, level float64
		fire     bool
	}{{0.9, 1, false}, {0.9, 0, true}, {1, 1, true}} {
		m := ewma{n: 1}
		var v verdict
		for range 3 {
			v = m.update(tc.x, 0.2, tc.level, false, &p)
		}
		if v.fire != tc.fire {
			t.Errorf("x %v level %v: fire %v, want %v (%+v)", tc.x, tc.level, v.fire, tc.fire, v)
		}
	}
}

func TestEWMAFreezeAndSustain(t *testing.T) {
	p := baselineParams{learn: 1, threshold: 4, sustain: 3, maxStep: 0.2}
	m := ewma{mean: 100, dev: 10, n: 1}
	var fired []int
	for i := range 5 {
		if v := m.update(200, 1, 0, false, &p); v.fire {
			fired = append(fired, i)
		}
		if m.mean != 100 || m.dev != 10 {
			t.Fatalf("interval %d: baseline moved to %v/%v while anomalous", i, m.mean, m.dev)
		}
	}
	if len(fired) != 1 || fired[0] != 2 {
		t.Fatalf("fired at %v, want [2] (the third anomalous interval, once)", fired)
	}
	// A normal interval ends the episode; the next one alerts again.
	m.update(100, 1, 0, false, &p)
	if m.run != 0 || m.alerted {
		t.Fatalf("after a normal interval run %d alerted %v", m.run, m.alerted)
	}
	fired = nil
	for i := range 3 {
		if m.update(200, 1, 0, false, &p).fire {
			fired = append(fired, i)
		}
	}
	if len(fired) != 1 || fired[0] != 2 {
		t.Fatalf("second episode fired at %v, want [2]", fired)
	}
	// Two anomalous intervals, a normal one, two more: never sustained.
	m = ewma{mean: 100, dev: 10, n: 1}
	for _, x := range []float64{200, 200, 100, 200, 200} {
		if m.update(x, 1, 0, false, &p).fire {
			t.Fatalf("fired without %d intervals in a row", p.sustain)
		}
	}
}

func TestEWMAAdaptAfter(t *testing.T) {
	p := baselineParams{learn: 1, threshold: 4, sustain: 3, maxStep: 0.2}
	m := ewma{mean: 100, dev: 10, n: 1}
	for i := 1; i <= baselineAdaptAfter; i++ {
		m.update(1000, 1, 0, false, &p)
	}
	if m.mean != 100 {
		t.Fatalf("mean %v after %d anomalous intervals, want frozen at 100", m.mean, baselineAdaptAfter)
	}
	m.update(1000, 1, 0, false, &p)
	if m.mean != 120 {
		t.Fatalf("mean %v after %d, want 120 (one max_step)", m.mean, baselineAdaptAfter+1)
	}
}

func TestEWMADrop(t *testing.T) {
	p := baselineParams{learn: 1, threshold: 4, sustain: 1, maxStep: 0.2}
	m := ewma{mean: 100, dev: 10, n: 1}
	if v := m.update(5, 10, 0, false, &p); v.fire {
		t.Fatal("a drop fired without drop")
	}
	m = ewma{mean: 100, dev: 10, n: 1}
	if v := m.update(5, 10, 0, true, &p); !v.fire || !v.down {
		t.Fatalf("drop to 5%% of the mean: %+v, want a down alert", v)
	}
	m = ewma{mean: 100, dev: 10, n: 1}
	if v := m.update(20, 10, 0, true, &p); v.fire {
		t.Fatal("a drop to 20% fired (the limit is 10%)")
	}
	// A mean under the floor is too quiet for a drop to mean anything.
	m = ewma{mean: 5, dev: 1, n: 1}
	if v := m.update(0, 10, 0, true, &p); v.fire {
		t.Fatal("a drop from a mean under the floor fired")
	}
}

func TestBitmapEstimate(t *testing.T) {
	for _, tc := range []struct{ bits, n int }{{baselineGlobalBits, 100}, {baselineGlobalBits, 5000}, {baselineGlobalBits, 50000},
		{baselineHostBits, 10}, {baselineHostBits, 500}, {baselineHostBits, 3000}} {
		b := make(bitmap, tc.bits/64)
		for i := range tc.n {
			a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
			b.add(a)
			b.add(a) // duplicates do not count
		}
		est := b.estimate()
		if math.Abs(est-float64(tc.n)) > 0.05*float64(tc.n)+1 {
			t.Errorf("%d bits, %d addresses: estimate %.0f", tc.bits, tc.n, est)
		}
		b.reset()
		if b.estimate() != 0 {
			t.Errorf("estimate %v after reset", b.estimate())
		}
	}
	// Saturated: a finite estimate.
	b := make(bitmap, 1)
	for i := range 10000 {
		b.add(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}))
	}
	if e := b.estimate(); math.IsInf(e, 0) || math.IsNaN(e) || e < 64 {
		t.Errorf("saturated estimate %v", e)
	}
}

func TestBaselineFires(t *testing.T) {
	e := baselineEngine(t, " metrics:packets;")
	// 8 steady intervals of 50 packets (5/s), then 4 of 1000 (100/s),
	// then one packet to close the last one.
	pkts := concat(traffic(0, 8, 50, 3), traffic(80*time.Second, 4, 1000, 3), traffic(120*time.Second, 1, 1, 1))
	res := runPkts(t, e, pkts)
	var as []Alert
	fireAt := -1
	for i, r := range res {
		for _, a := range r {
			if a.SID == 1 && a.Kind == KindAlert {
				as = append(as, a)
				if fireAt < 0 {
					fireAt = i
				}
			}
		}
	}
	if len(as) != 1 {
		t.Fatalf("%d alerts, want 1:%s", len(as), alertLines(as))
	}
	// The third anomalous interval (80s-110s) ends at 110s: the first
	// packet at or after it fires.
	if got := pkts[fireAt].t; got != 110*time.Second {
		t.Errorf("fired at %v, want 1m50s", got)
	}
	d := as[0].Details
	want := map[string]string{"detector": "baseline", "metric": "packets", "value": "100.0", "baseline": "5.0", "deviation": "0.0",
		"score": "9.5", "threshold": "4", "sustained": "3", "interval": "10s", "direction": "up", "unit": "packets/s"}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("details[%s] = %q, want %q (%v)", k, d[k], v, d)
		}
	}
	if _, ok := d["host"]; ok || as[0].SrcIP != "" {
		t.Errorf("a global metric names a host: %s", alertLine(as[0]))
	}
	ns := e.TakeNotices()
	if len(ns) != 2 || !strings.HasPrefix(ns[0].Message, "baseline learning until 2026-") || !strings.HasPrefix(ns[1].Message, "baseline active") {
		t.Fatalf("notices %+v", ns)
	}
	if !strings.Contains(ns[0].Message, fmt.Sprintf("until %s", at(60*time.Second).UTC().Format(time.RFC3339))) {
		t.Errorf("learning notice %q, want the end of the 6th interval", ns[0].Message)
	}
	if ns[1].Time != at(60*time.Second) {
		t.Errorf("active at %v, want the first packet of the 7th interval", ns[1].Time)
	}
	if len(e.TakeNotices()) != 0 {
		t.Error("TakeNotices returned the notices twice")
	}
	s := e.BaselineStatus()
	if s == nil || !s.Active || s.Until != at(60*time.Second) || s.Learned != 6 || s.Learn != 6 || s.SID != 1 || s.Interval != 10*time.Second || s.Anomalous != 1 {
		t.Errorf("status %+v", s)
	}
}

func TestBaselineNoFire(t *testing.T) {
	tests := []struct {
		name string
		pkts []timedPkt
	}{
		// A spike while learning is learned, not reported.
		{"learning", concat(traffic(0, 2, 50, 3), traffic(20*time.Second, 4, 1000, 3), traffic(60*time.Second, 1, 1, 1))},
		// Two anomalous intervals are not sustained.
		{"short spike", concat(traffic(0, 8, 50, 3), traffic(80*time.Second, 2, 1000, 3), traffic(100*time.Second, 4, 50, 3))},
		// Steady traffic.
		{"steady", traffic(0, 20, 50, 3)},
		// 10x within the floor: 5/s to 40/s is 3.5 floors of 10.
		{"within floor", concat(traffic(0, 8, 50, 3), traffic(80*time.Second, 5, 400, 3))},
	}
	for _, tt := range tests {
		e := baselineEngine(t, " metrics:packets;")
		if as := sidAlerts(t, e, tt.pkts, 1); len(as) != 0 {
			t.Errorf("%s: %s", tt.name, alertLines(as))
		}
	}
	e := baselineEngine(t, "")
	runPkts(t, e, traffic(0, 3, 10, 1))
	if s := e.BaselineStatus(); s.Active || s.Learned != 2 || s.Until != at(60*time.Second) {
		t.Errorf("learning status %+v", s)
	}
	if NewEngine(mustParse(t, beaconRule), EngineConfig{}).BaselineStatus() != nil {
		t.Error("status without a baseline rule")
	}
}

func TestBaselineFanout(t *testing.T) {
	e := baselineEngine(t, " metrics:fanout;")
	// 3 destinations per interval, then 200.
	pkts := concat(traffic(0, 8, 30, 3), traffic(80*time.Second, 3, 200, 200), traffic(110*time.Second, 1, 1, 1))
	as := sidAlerts(t, e, pkts, 1)
	if len(as) != 1 {
		t.Fatalf("%d alerts, want 1:%s", len(as), alertLines(as))
	}
	d := as[0].Details
	if d["metric"] != "fanout" || d["host"] != "10.0.0.5" || as[0].SrcIP != "10.0.0.5" || d["baseline"] != "3.0" {
		t.Errorf("alert %s %v", alertLine(as[0]), d)
	}
	if v, err := strconv.ParseFloat(d["value"], 64); err != nil || v < 190 || v > 210 {
		t.Errorf("value %s, want about 200", d["value"])
	}
	// Destinations are not internal hosts: only 10.0.0.5 is tracked.
	if n := e.Stats().Tables[TableBaselineHosts].Keys; n != 1 {
		t.Errorf("%d hosts, want 1", n)
	}
	// A host whose normal fan-out is high does not fire at that level.
	e = baselineEngine(t, " metrics:fanout;")
	if as := sidAlerts(t, e, traffic(0, 12, 200, 200), 1); len(as) != 0 {
		t.Errorf("steady high fan-out: %s", alertLines(as))
	}
}

func TestBaselineGlobalDsts(t *testing.T) {
	e := baselineEngine(t, " metrics:dsts;")
	pkts := concat(traffic(0, 8, 30, 3), traffic(80*time.Second, 3, 200, 200), traffic(110*time.Second, 1, 1, 1))
	as := sidAlerts(t, e, pkts, 1)
	if len(as) != 1 || as[0].Details["metric"] != "dsts" {
		t.Fatalf("alerts:%s", alertLines(as))
	}
}

func TestBaselineDrop(t *testing.T) {
	// Steady 5/s, then one packet per interval.
	var quiet []timedPkt
	for i := range 5 {
		quiet = append(quiet, traffic(80*time.Second+time.Duration(i)*10*time.Second, 1, 1, 1)...)
	}
	pkts := concat(traffic(0, 8, 500, 3), quiet)
	if as := sidAlerts(t, baselineEngine(t, " metrics:packets;"), pkts, 1); len(as) != 0 {
		t.Errorf("drop without drop:packets: %s", alertLines(as))
	}
	as := sidAlerts(t, baselineEngine(t, " metrics:packets; drop:packets;"), pkts, 1)
	if len(as) != 1 || as[0].Details["direction"] != "down" || as[0].Details["value"] != "0.1" {
		t.Fatalf("alerts:%s", alertLines(as))
	}
}

func TestBaselineEmptyIntervals(t *testing.T) {
	// Learned at 5/s. A 40s silence is 4 intervals of zeros (not
	// anomalous upwards); they pull the mean down by at most max_step
	// each, so normal traffic after them does not fire.
	pkts := concat(traffic(0, 8, 50, 3), traffic(120*time.Second, 6, 50, 3))
	if as := sidAlerts(t, baselineEngine(t, " metrics:packets;"), pkts, 1); len(as) != 0 {
		t.Errorf("after a silence: %s", alertLines(as))
	}
	// A silence far longer than baselineMaxEmpty intervals: at most
	// baselineMaxEmpty zeros are fed and the clock jumps.
	e := baselineEngine(t, " metrics:packets;")
	runPkts(t, e, concat(traffic(0, 2, 5, 1), traffic(10*time.Hour, 1, 1, 1)))
	d := e.ruleState[0].base
	if d.learned != 6 || d.start != at(10*time.Hour) {
		t.Errorf("learned %d start %v, want 6 and the new packet's interval", d.learned, d.start.Sub(t0))
	}
}

func TestBaselineHostTable(t *testing.T) {
	e := NewEngine(mustParse(t, fmt.Sprintf(baselineRule, " metrics:fanout;")), EngineConfig{MaxKeys: 3})
	var pkts []timedPkt
	for i := range 5 {
		pkts = append(pkts, timedPkt{time.Duration(i) * time.Second, udpPkt(fmt.Sprintf("10.0.0.%d", i+1), 1, "192.0.2.1", 2, "x")})
	}
	runPkts(t, e, pkts)
	ts := e.Stats().Tables[TableBaselineHosts]
	if ts.Keys != 3 || ts.Evictions != 2 {
		t.Errorf("hosts %d evictions %d, want 3 2", ts.Keys, ts.Evictions)
	}
	// Idle hosts are dropped at the next interval close after 24h.
	runPkts(t, e, []timedPkt{{25 * time.Hour, udpPkt("192.0.2.9", 1, "192.0.2.1", 2, "x")}})
	if n := e.Stats().Tables[TableBaselineHosts].Keys; n != 0 {
		t.Errorf("%d hosts after 25h idle, want 0", n)
	}
	// Reload with other rules clears the table.
	e = NewEngine(mustParse(t, fmt.Sprintf(baselineRule, " metrics:fanout;")), EngineConfig{})
	runPkts(t, e, pkts)
	e.activate(mustParse(t, beaconRule))
	if n := e.Stats().Tables[TableBaselineHosts].Keys; n != 0 || e.BaselineStatus() != nil {
		t.Errorf("%d hosts after the rule went away", n)
	}
}

func TestBaselineParse(t *testing.T) {
	rs := mustParse(t, `alert ip any any -> any any (msg:"b"; sid:1; detect:baseline;)`)
	r := rs.rules[0]
	if r.interval != time.Minute || r.learnIntervals != 10 || r.threshold != 4 || r.sustain != 3 || r.maxStep != 0.2 || r.metrics != allMetrics || r.drop != 0 {
		t.Errorf("defaults: %v %d %v %d %v %b %b", r.interval, r.learnIntervals, r.threshold, r.sustain, r.maxStep, r.metrics, r.drop)
	}
	rs = mustParse(t, `alert tcp any any <> any any (msg:"b"; sid:1; detect:baseline; interval:30; learn_intervals:20; threshold:5.5; sustain:2; max_step:0.1; metrics:packets, conns; drop:packets;)`)
	r = rs.rules[0]
	if r.interval != 30*time.Second || r.learnIntervals != 20 || r.threshold != 5.5 || r.sustain != 2 || r.maxStep != 0.1 ||
		r.metrics != 1<<metricPackets|1<<metricConns || r.drop != 1<<metricPackets {
		t.Errorf("options not applied")
	}
	if r.minLevel != [numMetrics]float64{10, 10000, 2, 1, 20, 20} {
		t.Errorf("default min_level %v", r.minLevel)
	}
	rs = mustParse(t, `alert ip any any -> any any (msg:"b"; sid:1; detect:baseline; min_level:dns=0.5, fanout=100;)`)
	if got := rs.rules[0].minLevel; got != [numMetrics]float64{10, 10000, 2, 0.5, 20, 100} {
		t.Errorf("min_level %v", got)
	}
	for _, tc := range []struct{ opts, want string }{
		{"min_level:dns;", "want METRIC=N"},
		{"min_level:pps=3;", "unknown metric"},
		{"min_level:dns=1, dns=2;", "given twice"},
		{"min_level:dns=-1;", "from 0 to 1e12"},
		{"min_level:dns=x;", "from 0 to 1e12"},
		{"min_level:dns=1; min_level:dns=2;", "more than once"},
		{"interval:0;", "interval"},
		{"interval:3601;", "interval"},
		{"learn_intervals:1;", "learn_intervals: 1: at least 2"},
		{"sustain:61;", "sustain"},
		{"threshold:0.5;", "threshold \"0.5\""},
		{"max_step:0;", "max_step"},
		{"max_step:1.5;", "max_step"},
		{"metrics:pps;", "unknown metric \"pps\""},
		{"drop:bytes;", "only packets"},
		{"metrics:bytes; drop:packets;", "drop lists a metric that metrics leaves out"},
		{"interval:10; interval:20;", "more than once"},
	} {
		errs := loadErrors(t, `alert ip any any -> any any (msg:"b"; sid:1; detect:baseline; `+tc.opts+`)`)
		if len(errs) == 0 || !strings.Contains(strings.Join(errs, "\n"), tc.want) {
			t.Errorf("%s: errors %q, want %q", tc.opts, errs, tc.want)
		}
	}
	if errs := loadErrors(t, `alert arp any any -> any any (msg:"b"; sid:1; detect:baseline;)`); len(errs) == 0 {
		t.Error("arp accepted")
	}
	if errs := loadErrors(t, `alert ip any any -> any any (msg:"b"; sid:1; detect:beacon; sustain:3;)`); len(errs) == 0 {
		t.Error("sustain accepted by beacon")
	}
}
