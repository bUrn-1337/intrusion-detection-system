package logging

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

// Aggregator defaults.
const (
	DefaultMaxIPs       = 10000
	DefaultRecentAlerts = 200
	TopN                = 10
	// RateHistory is how many one-second samples the rolling averages use.
	RateHistory = 60
	// TalkerWindow is the length of each of the two rolling windows the
	// top-N tables are computed over, so they cover the last 30-60s.
	TalkerWindow = 30 * time.Second
)

// Labels for packets without an L4 or application protocol.
const (
	LabelARP   = "ARP"
	LabelNonIP = "NON-IP"
	LabelNoL4  = "NO-L4" // IP without a parsed L4 header (e.g. a later fragment)
	LabelNone  = "NONE"  // no application protocol
)

// AggregatorConfig configures an Aggregator. Zero values select defaults.
type AggregatorConfig struct {
	MaxIPs       int // source addresses tracked per window
	RecentAlerts int // size of the recent alerts ring
}

// Count is one row of a protocol breakdown.
type Count struct {
	Name    string
	Packets uint64
}

// Talker is one row of a top-N table.
type Talker struct {
	IP      string
	Packets uint64
	Bytes   uint64
	Alerts  uint64
}

// Snapshot is the Aggregator's published state. A snapshot is never
// modified after it is published, so readers may keep it.
type Snapshot struct {
	Time    time.Time // of the Tick that published it
	Started time.Time

	Packets, Bytes uint64  // since start
	PPS, BPS       float64 // over the last second (tick interval)
	AvgPPS, AvgBPS float64 // over the last RateHistory seconds

	ByL4, ByApp []Count // since start, most packets first

	TopPackets, TopBytes, TopAlerts []Talker // over the talker windows
	TrackedIPs                      int      // distinct sources in the windows
	Untracked                       uint64   // packets from sources over the cap

	Alerts       uint64        // alert records seen (alerts, summaries and incidents)
	RecentAlerts []rules.Alert // oldest first

	// Incidents are the active incidents, most severe first (see
	// SortIncidents). AlertClock is the newest alert time, the clock
	// incidents age by in a pcap replay.
	Incidents  []Incident
	AlertClock time.Time
}

// Totals returns the traffic counters for a stats record.
func (s Snapshot) Totals() TrafficTotals {
	t := TrafficTotals{Packets: s.Packets, Bytes: s.Bytes, ByL4: map[string]uint64{}, ByApp: map[string]uint64{}}
	for _, c := range s.ByL4 {
		t.ByL4[c.Name] = c.Packets
	}
	for _, c := range s.ByApp {
		t.ByApp[c.Name] = c.Packets
	}
	return t
}

type talkerStats struct{ packets, bytes, alerts uint64 }

type talkerWindow struct {
	ips       map[netip.Addr]*talkerStats
	untracked uint64
}

func newTalkerWindow() *talkerWindow {
	return &talkerWindow{ips: make(map[netip.Addr]*talkerStats)}
}

type rateSample struct {
	packets, bytes uint64
	secs           float64
}

// Aggregator computes traffic statistics. Packet, Alert and Tick must all
// be called from one goroutine (the pipeline); Snapshot may be called from
// any goroutine. The per-packet path takes no lock: Tick publishes a new
// Snapshot under a mutex once per call.
type Aggregator struct {
	cfg AggregatorConfig

	started  time.Time
	lastTick time.Time

	packets, bytes   uint64
	secPkts, secByts uint64
	hist             []rateSample // ring of the last RateHistory samples
	histNext         int

	byL4, byApp map[string]uint64

	win      [2]*talkerWindow // [0] current, [1] previous
	winStart time.Time

	alerts   uint64
	ring     []rules.Alert
	ringNext int
	ringFull bool

	incidents  map[string]*Incident // by incident id
	alertClock time.Time

	mu   sync.Mutex
	snap Snapshot
}

// NewAggregator returns an Aggregator whose clock starts at now.
func NewAggregator(cfg AggregatorConfig, now time.Time) *Aggregator {
	if cfg.MaxIPs <= 0 {
		cfg.MaxIPs = DefaultMaxIPs
	}
	if cfg.RecentAlerts <= 0 {
		cfg.RecentAlerts = DefaultRecentAlerts
	}
	a := &Aggregator{
		cfg: cfg, started: now, lastTick: now, winStart: now,
		byL4: make(map[string]uint64), byApp: make(map[string]uint64),
		win:       [2]*talkerWindow{newTalkerWindow(), newTalkerWindow()},
		ring:      make([]rules.Alert, cfg.RecentAlerts),
		incidents: make(map[string]*Incident),
	}
	a.snap = Snapshot{Time: now, Started: now}
	return a
}

// Packet counts one processed packet.
func (a *Aggregator) Packet(p *packet.ParsedPacket) {
	n := uint64(p.WireLen)
	a.packets++
	a.bytes += n
	a.secPkts++
	a.secByts += n
	a.byL4[l4Label(p)]++
	app := p.AppProtocol
	if app == "" {
		app = LabelNone
	}
	a.byApp[app]++

	src, ok := netip.AddrFromSlice(p.IPSrc)
	if !ok {
		return
	}
	if t := a.talker(src.Unmap()); t != nil {
		t.packets++
		t.bytes += n
	} else {
		a.win[0].untracked++
	}
}

func l4Label(p *packet.ParsedPacket) string {
	switch {
	case p.L4Proto != "":
		return p.L4Proto
	case p.EthType == packet.EthTypeARP:
		return LabelARP
	case p.IPSrc == nil:
		return LabelNonIP
	}
	return LabelNoL4
}

// talker returns the current window's entry for ip, creating it unless
// the window is at its cap, in which case it returns nil.
func (a *Aggregator) talker(ip netip.Addr) *talkerStats {
	w := a.win[0]
	if t, ok := w.ips[ip]; ok {
		return t
	}
	if len(w.ips) >= a.cfg.MaxIPs {
		return nil
	}
	t := &talkerStats{}
	w.ips[ip] = t
	return t
}

// Alert records one alert, summary or incident: it goes into the recent
// alerts ring and counts against its source (a summary adds the matches
// its first alert did not already count). Incidents are tracked by id
// instead of counting against a source.
func (a *Aggregator) Alert(al rules.Alert) {
	a.alerts++
	a.ring[a.ringNext] = al
	a.ringNext = (a.ringNext + 1) % len(a.ring)
	if a.ringNext == 0 {
		a.ringFull = true
	}
	if IsIncident(&al) {
		a.incident(&al)
		return
	}
	if al.Time.After(a.alertClock) {
		a.alertClock = al.Time
	}

	n := uint64(1)
	if al.Kind == rules.KindSummary {
		if al.Count <= 1 {
			return
		}
		n = uint64(al.Count - 1)
	}
	src, err := netip.ParseAddr(al.SrcIP)
	if err != nil {
		return
	}
	if t := a.talker(src.Unmap()); t != nil {
		t.alerts += n
	}
}

// Tick closes the current rate interval, rolls the talker windows, and
// publishes a new Snapshot. Call it about once a second with the wall
// clock.
func (a *Aggregator) Tick(now time.Time) {
	secs := now.Sub(a.lastTick).Seconds()
	a.lastTick = now
	var pps, bps float64
	if secs > 0 {
		pps, bps = float64(a.secPkts)/secs, float64(a.secByts)/secs
		s := rateSample{packets: a.secPkts, bytes: a.secByts, secs: secs}
		if len(a.hist) < RateHistory {
			a.hist = append(a.hist, s)
		} else {
			a.hist[a.histNext] = s
			a.histNext = (a.histNext + 1) % RateHistory
		}
		a.secPkts, a.secByts = 0, 0
	}
	var hp, hb uint64
	var hs float64
	for _, s := range a.hist {
		hp += s.packets
		hb += s.bytes
		hs += s.secs
	}

	if el := now.Sub(a.winStart); el >= TalkerWindow {
		if el >= 2*TalkerWindow {
			a.win[1] = newTalkerWindow() // the current window is stale too
		} else {
			a.win[1] = a.win[0]
		}
		a.win[0] = newTalkerWindow()
		a.winStart = now
	}

	s := Snapshot{
		Time: now, Started: a.started,
		Packets: a.packets, Bytes: a.bytes, PPS: pps, BPS: bps,
		ByL4: sortedCounts(a.byL4), ByApp: sortedCounts(a.byApp),
		Alerts: a.alerts, RecentAlerts: a.recent(),
		Incidents: a.activeIncidents(), AlertClock: a.alertClock,
	}
	if hs > 0 {
		s.AvgPPS, s.AvgBPS = float64(hp)/hs, float64(hb)/hs
	}
	s.TopPackets, s.TopBytes, s.TopAlerts, s.TrackedIPs, s.Untracked = a.top()

	a.mu.Lock()
	a.snap = s
	a.mu.Unlock()
}

// Snapshot returns the most recently published snapshot.
func (a *Aggregator) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.snap
}

func sortedCounts(m map[string]uint64) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Packets != out[j].Packets {
			return out[i].Packets > out[j].Packets
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (a *Aggregator) recent() []rules.Alert {
	if !a.ringFull {
		return append([]rules.Alert(nil), a.ring[:a.ringNext]...)
	}
	out := make([]rules.Alert, 0, len(a.ring))
	out = append(out, a.ring[a.ringNext:]...)
	return append(out, a.ring[:a.ringNext]...)
}

// top merges the two talker windows and ranks them three ways.
func (a *Aggregator) top() (byPkts, byBytes, byAlerts []Talker, tracked int, untracked uint64) {
	merged := make(map[netip.Addr]talkerStats, len(a.win[0].ips)+len(a.win[1].ips))
	for _, w := range a.win {
		for ip, t := range w.ips {
			m := merged[ip]
			m.packets += t.packets
			m.bytes += t.bytes
			m.alerts += t.alerts
			merged[ip] = m
		}
		untracked += w.untracked
	}
	all := make([]Talker, 0, len(merged))
	for ip, t := range merged {
		all = append(all, Talker{IP: ip.String(), Packets: t.packets, Bytes: t.bytes, Alerts: t.alerts})
	}
	rank := func(key func(Talker) uint64) []Talker {
		sort.Slice(all, func(i, j int) bool {
			ki, kj := key(all[i]), key(all[j])
			if ki != kj {
				return ki > kj
			}
			return all[i].IP < all[j].IP
		})
		var out []Talker
		for _, t := range all {
			if len(out) == TopN || key(t) == 0 {
				break
			}
			out = append(out, t)
		}
		return out
	}
	byPkts = rank(func(t Talker) uint64 { return t.Packets })
	byBytes = rank(func(t Talker) uint64 { return t.Bytes })
	byAlerts = rank(func(t Talker) uint64 { return t.Alerts })
	return byPkts, byBytes, byAlerts, len(merged), untracked
}

// Totals returns the traffic counters since start. Unlike Snapshot it is
// current to the last Packet, but it must be called from the goroutine
// that feeds the Aggregator.
func (a *Aggregator) Totals() TrafficTotals {
	t := TrafficTotals{Packets: a.packets, Bytes: a.bytes, ByL4: make(map[string]uint64, len(a.byL4)), ByApp: make(map[string]uint64, len(a.byApp))}
	for k, v := range a.byL4 {
		t.ByL4[k] = v
	}
	for k, v := range a.byApp {
		t.ByApp[k] = v
	}
	return t
}
