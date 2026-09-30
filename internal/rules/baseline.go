package rules

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Traffic baseline: detect:baseline.
//
// The detector learns what normal traffic volume looks like and fires
// when a metric stays far above it. Time is cut into intervals (interval,
// default 60s of packet time, aligned to multiples of the interval). For
// each interval it measures, over the packets the rule's header matches:
//
//	packets  packets per second
//	bytes    bytes per second (wire length)
//	conns    new TCP connections per second (SYN without ACK)
//	dns      DNS queries per second
//	dsts     distinct destination addresses
//	fanout   per internal host (a source the rule's source address
//	         matches): distinct destinations it sent to. Each host has
//	         its own baseline; at most baselineMaxHosts hosts are kept.
//
// Distinct addresses are counted with linear counting: each address sets
// one bit of a bitmap (baselineGlobalBits for dsts, baselineHostBits per
// host) and the count is estimated from the fraction of bits still clear,
// n = -m ln(zeros/m). Memory is fixed whatever the traffic, and the
// estimate is within a few percent well past m/2 distinct addresses.
//
// Each metric keeps an exponentially weighted moving average (EWMA) of
// its value and an EWMA of the absolute deviation from it:
//
//	mean += alpha (x - mean)
//	dev  += alpha (|x - mean_before| - dev)
//
// The score of a value is (x - mean) / max(dev, floor), in deviations.
// The absolute deviation is used rather than the standard deviation (the
// EWMA of squared deviations) because traffic volume is heavy-tailed:
// one burst squared dominates a variance estimate for many intervals and
// hides the next burst, while it moves the absolute deviation only in
// proportion. It needs no square root and has the same units as the
// metric. The floor (per metric, baselineFloors) keeps a very steady
// metric from alerting on a tiny absolute change.
//
// Learning: for the first learn_intervals intervals the mean and
// deviation are plain cumulative averages, so each interval weighs the
// same, and nothing fires. The engine then records a notice ("baseline
// learning until <time>", then "baseline active") that the IDS logs as
// an event. Fan-out baselines learn per host, from the host's first
// interval.
//
// Firing: an interval is anomalous when its score is at least threshold
// and the value is at least the metric's min_level (baselineMinLevels
// unless the rule sets it): a metric learned at zero, such as DNS on a
// link that was idle while learning, would otherwise alert on a handful
// of queries, since its deviation is only the floor. For metrics listed
// in drop, an interval is also anomalous when the value falls below
// baselineDropFraction of a mean above the floor: the link went quiet).
// The rule fires when a metric has been anomalous for sustain intervals
// in a row, once per episode; a normal interval ends the episode.
//
// Poisoning: an attacker who can raise traffic slowly could teach the
// baseline that the attack level is normal. Two things limit that. An
// anomalous interval does not update the baseline (it is frozen while
// anomalous), and one update moves the mean or deviation by at most
// max_step (default 20%) of its value (or of the floor, if higher). A
// ramp that stays below threshold at every step is still learned: that
// is the boiling frog (docs/ARCHITECTURE.md). A metric anomalous for
// baselineAdaptAfter intervals in a row starts updating again (still
// at most max_step per interval), so a lasting change of the network
// is eventually learned instead of hiding the metric for good; it has
// alerted by then.
//
// Intervals close on the first packet after their end, since the engine
// clock is packet time. Intervals without packets count as zeros, at
// most baselineMaxEmpty in a row; after a longer silence the next
// interval starts at the new packet.

const (
	baselineGlobalBits   = 65536
	baselineHostBits     = 4096
	baselineMaxHosts     = 10000
	baselineHostIdle     = 24 * time.Hour
	baselineAlpha        = 0.1
	baselineMaxEmpty     = 60
	baselineAdaptAfter   = 60
	baselineDropFraction = 0.1

	defaultBaselineInterval  = 60 * time.Second
	defaultBaselineLearn     = 10
	defaultBaselineThreshold = 4.0
	defaultBaselineSustain   = 3
	defaultBaselineMaxStep   = 0.2
)

// Baseline metrics.
const (
	metricPackets = iota
	metricBytes
	metricConns
	metricDNS
	metricDsts
	metricFanout
	numMetrics
)

var metricNames = [numMetrics]string{"packets", "bytes", "conns", "dns", "dsts", "fanout"}

// metricUnits describes each metric's value in alert details.
var metricUnits = [numMetrics]string{"packets/s", "bytes/s", "connections/s", "queries/s", "addresses/interval", "addresses/interval"}

// baselineFloors is the smallest deviation each metric's score divides
// by.
var baselineFloors = [numMetrics]float64{10, 10000, 0.5, 0.2, 10, 10}

// baselineMinLevels are the default min_level values: the smallest value
// (in the metric's unit) an interval needs to be anomalous upwards.
var baselineMinLevels = [numMetrics]float64{10, 10000, 2, 1, 20, 20}

// parseMinLevels parses a min_level value, METRIC=N[,METRIC=N...]. Metrics
// not listed keep their default.
func parseMinLevels(v string) ([numMetrics]float64, error) {
	lv := baselineMinLevels
	seen := metricSet(0)
	for _, item := range strings.Split(v, ",") {
		name, num, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok {
			return lv, fmt.Errorf("%q: want METRIC=N", item)
		}
		s, err := parseMetrics(name)
		if err != nil {
			return lv, err
		}
		if seen&s != 0 {
			return lv, fmt.Errorf("metric %s given twice", strings.TrimSpace(name))
		}
		seen |= s
		f, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
		if err != nil || !(f >= 0 && f <= 1e12) {
			return lv, fmt.Errorf("%q: want a number from 0 to 1e12", strings.TrimSpace(num))
		}
		for m := range numMetrics {
			if s.has(m) {
				lv[m] = f
			}
		}
	}
	return lv, nil
}

// metricSet is a bit set of metrics.
type metricSet uint8

func (s metricSet) has(m int) bool { return s&(1<<m) != 0 }

const allMetrics = metricSet(1<<numMetrics - 1)

// parseMetrics parses a comma-separated list of metric names.
func parseMetrics(v string) (metricSet, error) {
	var s metricSet
	for _, name := range strings.Split(v, ",") {
		name = strings.TrimSpace(name)
		i := -1
		for j, n := range metricNames {
			if n == name {
				i = j
			}
		}
		if i < 0 {
			return 0, fmt.Errorf("unknown metric %q: want packets, bytes, conns, dns, dsts or fanout", name)
		}
		s |= 1 << i
	}
	if s == 0 {
		return 0, fmt.Errorf("empty list")
	}
	return s, nil
}

// ewma is one metric's baseline.
type ewma struct {
	mean, dev float64
	n         int  // intervals learned, up to the learning length
	run       int  // anomalous intervals in a row
	alerted   bool // fired in the current episode
}

// baselineParams are a rule's settings, as update needs them.
type baselineParams struct {
	learn     int
	threshold float64
	sustain   int
	maxStep   float64
}

// verdict is the outcome of one interval of a metric.
type verdict struct {
	value, mean, dev, score float64
	down                    bool // anomalous by falling (drop)
	fire                    bool
}

// update feeds one interval's value x of a metric with the given floor
// and minimum level. drop enables anomalies downwards.
func (m *ewma) update(x, floor, level float64, drop bool, p *baselineParams) verdict {
	if m.n < p.learn {
		m.n++
		if m.n == 1 {
			m.mean, m.dev = x, 0
		} else {
			d := math.Abs(x - m.mean)
			m.mean += (x - m.mean) / float64(m.n)
			m.dev += (d - m.dev) / float64(m.n-1)
		}
		return verdict{value: x, mean: m.mean, dev: m.dev}
	}
	v := verdict{value: x, mean: m.mean, dev: m.dev, score: (x - m.mean) / max(m.dev, floor)}
	up := v.score >= p.threshold && x >= level
	v.down = drop && m.mean >= floor && x <= baselineDropFraction*m.mean
	if !up && !v.down {
		m.run, m.alerted = 0, false
		m.step(x, floor, p.maxStep)
		return v
	}
	m.run++
	if m.run > baselineAdaptAfter {
		m.step(x, floor, p.maxStep)
	}
	if m.run >= p.sustain && !m.alerted {
		m.alerted, v.fire = true, true
	}
	return v
}

// step moves the baseline towards x by alpha, by at most maxStep of the
// current value (or of floor, if higher).
func (m *ewma) step(x, floor, maxStep float64) {
	d := math.Abs(x - m.mean)
	lim := maxStep * max(m.mean, floor)
	m.mean += clampAbs(baselineAlpha*(x-m.mean), lim)
	lim = maxStep * max(m.dev, floor)
	m.dev += clampAbs(baselineAlpha*(d-m.dev), lim)
}

func clampAbs(x, lim float64) float64 {
	return min(max(x, -lim), lim)
}

// bitmap is a linear-counting bitmap of n bits (a multiple of 64).
type bitmap []uint64

func (b bitmap) add(a netip.Addr) {
	h := addrHash(a) % uint64(len(b)*64)
	b[h/64] |= 1 << (h % 64)
}

// estimate returns the estimated number of distinct addresses added.
func (b bitmap) estimate() float64 {
	m := float64(len(b) * 64)
	set := 0
	for _, w := range b {
		set += bits.OnesCount64(w)
	}
	zeros := m - float64(set)
	if zeros == 0 {
		zeros = 1 // saturated: the largest estimate the bitmap can give
	}
	return -m * math.Log(zeros/m)
}

func (b bitmap) reset() { clear(b) }

// addrHash is a fixed (seedless) hash, so estimates are reproducible.
func addrHash(a netip.Addr) uint64 {
	b := a.As16()
	return mix64(binary.BigEndian.Uint64(b[:8]) ^ mix64(binary.BigEndian.Uint64(b[8:])))
}

// mix64 is the splitmix64 finalizer.
func mix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ x>>30) * 0xbf58476d1ce4e5b9
	x = (x ^ x>>27) * 0x94d049bb133111eb
	return x ^ x>>31
}

// baselineHost is one internal host's fan-out baseline.
type baselineHost struct {
	addr  netip.Addr
	dsts  bitmap
	dirty bool // dsts has bits set in the current interval
	m     ewma
	last  time.Time
}

// BaselineStatus is a baseline rule's state, for the dashboard.
type BaselineStatus struct {
	SID      int
	Interval time.Duration
	Learned  int       // intervals learned so far, up to Learn
	Learn    int       // learn_intervals
	Until    time.Time // packet time learning ends (zero before the first packet)
	Active   bool
	// Anomalous counts the metrics (fan-out: hosts) anomalous in the
	// last interval.
	Anomalous int
}

// baseline is the detector for one rule.
type baseline struct {
	rule   *Rule
	params baselineParams
	groups [numGroups]bool // packet groups the rule's protocol covers

	start    time.Time // start of the current interval; zero before the first packet
	learned  int       // intervals closed, up to params.learn
	activeAt time.Time // end of the last learning interval, once learned
	counts   [metricDsts]float64
	dsts     bitmap
	global   [metricFanout]ewma

	hosts    map[netip.Addr]*list.Element // Value is *baselineHost
	lru      list.List                    // front = least recently seen
	maxHosts int
	stat     *tableStat

	status atomic.Pointer[BaselineStatus]
}

func newBaseline(r *Rule, maxKeys int, stat *tableStat) *baseline {
	d := &baseline{
		rule:   r,
		params: baselineParams{learn: r.learnIntervals, threshold: r.threshold, sustain: r.sustain, maxStep: r.maxStep},
		dsts:   make(bitmap, baselineGlobalBits/64),
		hosts:  make(map[netip.Addr]*list.Element), maxHosts: min(maxKeys, baselineMaxHosts), stat: stat,
	}
	for _, g := range groupsFor(r.Proto) {
		d.groups[g] = true
	}
	d.publish(0)
	return d
}

// publish stores the status for the dashboard.
func (d *baseline) publish(anomalous int) {
	s := &BaselineStatus{SID: d.rule.SID, Interval: d.rule.interval, Learned: d.learned, Learn: d.params.learn,
		Active: d.learned >= d.params.learn, Anomalous: anomalous}
	switch {
	case s.Active:
		s.Until = d.activeAt
	case !d.start.IsZero():
		s.Until = d.learnEnd()
	}
	d.status.Store(s)
}

// learnEnd is the packet time learning will end.
func (d *baseline) learnEnd() time.Time {
	return d.start.Add(time.Duration(d.params.learn-d.learned) * d.rule.interval)
}

// baselineFire is an alert due at the end of an interval.
type baselineFire struct {
	metric int
	host   netip.Addr // fanout only
	v      verdict
	run    int
}

// advance closes the intervals that ended by t. It returns the alerts
// due and appends notices.
func (d *baseline) advance(t time.Time, fires []baselineFire, notices []Notice) ([]baselineFire, []Notice) {
	iv := d.rule.interval
	if d.start.IsZero() {
		d.start = t.Truncate(iv)
		d.publish(0)
		notices = append(notices, Notice{Time: t, SID: d.rule.SID, Message: fmt.Sprintf(
			"baseline learning until %s (sid %d: %d intervals of %v)", d.learnEnd().UTC().Format(time.RFC3339), d.rule.SID, d.params.learn, iv)})
		return fires, notices
	}
	if t.Sub(d.start) < iv {
		return fires, notices
	}
	k := int64(t.Sub(d.start) / iv) // intervals ended: the current one and k-1 empty ones
	var anomalous int
	for i := int64(0); i < k && i <= baselineMaxEmpty; i++ {
		fires, anomalous = d.close(t, fires)
		if d.learned < d.params.learn {
			if d.learned++; d.learned == d.params.learn {
				d.activeAt = d.start.Add(time.Duration(i+1) * iv)
				notices = append(notices, Notice{Time: t, SID: d.rule.SID, Message: fmt.Sprintf(
					"baseline active (sid %d: learned from %d intervals of %v)", d.rule.SID, d.params.learn, iv)})
			}
		}
	}
	if k > baselineMaxEmpty+1 {
		d.start = t.Truncate(iv)
	} else {
		d.start = d.start.Add(time.Duration(k) * iv)
	}
	d.publish(anomalous)
	return fires, notices
}

// close ends the current interval: every metric's value is fed to its
// baseline and the counters are reset.
func (d *baseline) close(t time.Time, fires []baselineFire) ([]baselineFire, int) {
	r := d.rule
	secs := r.interval.Seconds()
	var vals [metricFanout]float64
	for m := range metricDsts {
		vals[m] = d.counts[m] / secs
	}
	vals[metricDsts] = d.dsts.estimate()
	d.counts = [metricDsts]float64{}
	d.dsts.reset()
	anomalous := 0
	for m := range metricFanout {
		if !r.metrics.has(m) {
			continue
		}
		g := &d.global[m]
		v := g.update(vals[m], baselineFloors[m], r.minLevel[m], r.drop.has(m), &d.params)
		if g.run > 0 {
			anomalous++
		}
		if v.fire {
			fires = append(fires, baselineFire{metric: m, v: v, run: g.run})
		}
	}
	// Hosts are visited least recently seen first: map order would make
	// the order of alerts in one interval random.
	for el := d.lru.Front(); el != nil; {
		next := el.Next()
		h := el.Value.(*baselineHost)
		if t.Sub(h.last) > baselineHostIdle {
			d.removeHost(el)
			el = next
			continue
		}
		x := 0.0
		if h.dirty {
			x = h.dsts.estimate()
			h.dsts.reset()
			h.dirty = false
		}
		v := h.m.update(x, baselineFloors[metricFanout], r.minLevel[metricFanout], false, &d.params)
		if h.m.run > 0 {
			anomalous++
		}
		if v.fire {
			fires = append(fires, baselineFire{metric: metricFanout, host: h.addr, v: v, run: h.m.run})
		}
		el = next
	}
	return fires, anomalous
}

// count adds one packet to the current interval.
func (d *baseline) count(v *view, p *packet.ParsedPacket, t time.Time) {
	r := d.rule
	if !d.groups[v.g] || !r.matchAddrs(v) {
		return
	}
	d.counts[metricPackets]++
	n := p.WireLen
	if n == 0 {
		n = p.CaptureLen
	}
	d.counts[metricBytes] += float64(n)
	if v.g == gTCP && v.flags&(tcpSYN|tcpACK) == tcpSYN {
		d.counts[metricConns]++
	}
	if p.AppProtocol == packet.AppDNS && p.AppFields["qname"] != "" && p.AppFields["is_response"] != "true" {
		d.counts[metricDNS]++
	}
	if !v.dst.IsValid() {
		return
	}
	d.dsts.add(v.dst)
	if r.metrics.has(metricFanout) && v.src.IsValid() && r.src.match(v.src) {
		h := d.host(v.src, t)
		h.dsts.add(v.dst)
		h.dirty = true
	}
}

// host returns a's entry, creating it (and evicting the least recently
// seen host at the cap) if needed.
func (d *baseline) host(a netip.Addr, t time.Time) *baselineHost {
	if el, ok := d.hosts[a]; ok {
		d.lru.MoveToBack(el)
		h := el.Value.(*baselineHost)
		h.last = t
		return h
	}
	if len(d.hosts) >= d.maxHosts {
		d.removeHost(d.lru.Front())
		d.stat.evictions.Add(1)
	}
	h := &baselineHost{addr: a, dsts: make(bitmap, baselineHostBits/64), last: t}
	d.hosts[a] = d.lru.PushBack(h)
	d.stat.keys.Add(1)
	return h
}

func (d *baseline) removeHost(el *list.Element) {
	delete(d.hosts, d.lru.Remove(el).(*baselineHost).addr)
	d.stat.keys.Add(-1)
}

func (d *baseline) clear() {
	d.stat.keys.Add(-int64(len(d.hosts)))
	clear(d.hosts)
	d.lru.Init()
}

// details returns the alert details of f.
func (d *baseline) details(f baselineFire) func() map[string]string {
	r := d.rule
	return func() map[string]string {
		dir := "up"
		if f.v.down {
			dir = "down"
		}
		m := map[string]string{
			"detector":  DetectBaseline,
			"metric":    metricNames[f.metric],
			"unit":      metricUnits[f.metric],
			"value":     strconv.FormatFloat(f.v.value, 'f', 1, 64),
			"baseline":  strconv.FormatFloat(f.v.mean, 'f', 1, 64),
			"deviation": strconv.FormatFloat(f.v.dev, 'f', 1, 64),
			"score":     strconv.FormatFloat(f.v.score, 'f', 1, 64),
			"threshold": strconv.FormatFloat(r.threshold, 'g', -1, 64),
			"min_level": strconv.FormatFloat(r.minLevel[f.metric], 'g', -1, 64),
			"sustained": strconv.Itoa(f.run),
			"interval":  r.interval.String(),
			"direction": dir,
		}
		if f.host.IsValid() {
			m["host"] = f.host.String()
		}
		return m
	}
}

// Notice is something the engine wants logged that is not an alert: a
// baseline that started learning or became active. Time is packet time.
type Notice struct {
	Time    time.Time
	SID     int
	Message string
}

// TakeNotices returns the notices recorded since the last call. Like
// Process, it must be called from the packet pipeline's goroutine.
func (e *Engine) TakeNotices() []Notice {
	n := e.notices
	e.notices = nil
	return n
}

// BaselineStatus returns the state of the first detect:baseline rule,
// or nil if there is none. It is safe to call from any goroutine.
func (e *Engine) BaselineStatus() *BaselineStatus {
	d := e.baselineShown.Load()
	if d == nil {
		return nil
	}
	return d.status.Load()
}

// baselineTick closes the intervals of every baseline rule that ended by
// the engine clock. It runs for every packet, whether or not it counts.
func (e *Engine) baselineTick(rs *RuleSet, out []Alert) []Alert {
	for _, r := range rs.baseline {
		d := e.ruleState[r.idx].base
		var fires []baselineFire
		fires, e.notices = d.advance(e.now, fires, e.notices)
		for _, f := range fires {
			v := view{g: gNone}
			dk := dedupKey{sid: r.SID, port: uint16(f.metric), hasPort: true}
			if f.host.IsValid() {
				v.src, dk.addr = f.host, f.host
			}
			out = e.emit(r, dk, &v, d.details(f), out)
		}
	}
	return out
}

// baselineCount adds a packet that is not whitelisted or passed to the
// baseline rules' current intervals.
func (e *Engine) baselineCount(rs *RuleSet, p *packet.ParsedPacket, v *view) {
	for _, r := range rs.baseline {
		e.ruleState[r.idx].base.count(v, p, e.now)
	}
}
