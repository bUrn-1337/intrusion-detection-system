package rules

import (
	"container/list"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Beacon detection: detect:beacon.
//
// Malware that polls a command-and-control server starts a new
// connection on a timer: every minute, say, with some random jitter so
// that the intervals are not exactly equal. The detector looks for that
// regularity in connection starts, whatever the connections carry.
//
// A key is (source, destination, destination port, TCP or UDP), for
// sources the rule's source address matches ($HOME_NET in rules.conf).
// An event is the start of a connection:
//
//   - TCP: a SYN without ACK that is not a retransmission (the same
//     4-tuple and sequence number seen within beaconSYNMemory);
//   - UDP: the first packet of a 4-tuple, or the first after the flow
//     was idle for beaconUDPIdle (30s). Packets of the reverse direction
//     of a flow keep it alive and are never events.
//
// Packets within a connection are never events, so a long-lived
// connection with keepalives is one event however regular its packets.
//
// Each key keeps the times of its last beaconRing (32) events. The
// intervals between consecutive stored events are checked at
// checkpoints: when the key's event count reaches min_events, then at
// every multiple of beaconCheckEvery (8) from 16 on (10, 16, 24, 32, 40,
// ... with the defaults). A check passes when
//
//   - the median interval is within [min_interval, max_interval], and
//   - at least min_fraction of the intervals are within jitter (a
//     fraction of the band's center) of the median or of twice the
//     median: [m(1-j), m(1+j)] or [2m(1-j), 2m(1+j)].
//
// The rule fires when persistence (4) checks in a row pass. One check
// is not enough: random intervals (a person browsing, a poller with no
// timer) pass a single check by chance far too often, because with the
// 2x band about half the range of a uniform distribution fits (a
// simulation of uniform 1-60s gaps passed a check on every event about
// 45% of the time within 100 connections). Checking only at checkpoints
// makes consecutive checks see mostly new intervals, so the chances
// multiply instead of repeating one lucky window; four in a row bring
// random traffic below 1% while a real beacon, whose every check passes,
// fires at its 32nd connection (docs/RULES.md has the numbers).
//
// The median, not the mean, is the center: one long gap (the laptop
// slept) or a burst of retries moves the mean arbitrarily far but
// leaves the median alone. The 2x band counts a missed beat (a
// connection that failed, or a beacon that skipped a round on purpose)
// as regular instead of as two misses.
//
// A key alerts once while it stays periodic: a beacon slower than the
// dedup window would otherwise alert on every beat. A check that fails
// (the median leaves the range or too few intervals fit) resets the run
// of passed checks and re-arms it.
//
// Allowed traffic is never counted: destination ports in allow_ports
// (default 123, NTP clients poll on a timer by design), destinations in
// allow_addrs, and keys whose learned name is in allow. The name is the
// TLS server name, HTTP Host or DNS query name of a packet of the key's
// flows; it is checked when the rule would fire, since it is usually
// seen after the first event. UDP to port 53 is never counted: a
// resolver serves every name the host looks up, and stub resolvers and
// caches re-query names as their TTLs expire, so queries to it are
// periodic without saying anything about one destination. Beacons over
// DNS are dns_tunnel's job.
//
// Keys are held in an LRU table capped at the engine's MaxKeys, and a
// key without an event for beaconIdle (6h of engine time) is dropped.

const (
	beaconRing      = 32
	beaconIdle      = 6 * time.Hour
	beaconUDPIdle   = 30 * time.Second
	beaconSYNMemory = 60 * time.Second
	beaconShown     = 8 // intervals listed in alert details
	// beaconCheckEvery is the spacing of checkpoints after min_events.
	beaconCheckEvery = 8

	defaultBeaconMinEvents   = 10
	defaultBeaconPersistence = 4
	defaultBeaconMinInterval = 10 * time.Second
	defaultBeaconMaxInterval = 3600 * time.Second
	defaultBeaconJitter      = 0.25
	defaultBeaconMinFraction = 0.7
	defaultBeaconAllowPorts  = "123"
)

type beaconKey struct {
	src, dst netip.Addr
	dport    uint16
	g        group // gTCP or gUDP
}

type beaconEntry struct {
	key   beaconKey
	times [beaconRing]time.Time // ring; times[next] is the oldest once full
	n     int                   // stored times, at most beaconRing
	next  int
	total uint64 // events ever, for details
	name  string // learned SNI, Host or query name
	last  time.Time
	// passed counts the checks in a row that passed.
	passed int
	// alerted is set when the rule fires for the key and cleared when a
	// check fails, so a beacon alerts once while it stays periodic.
	alerted bool
}

// isCheckpoint reports whether a key with total events is checked.
func isCheckpoint(total uint64, minEvents int) bool {
	return total == uint64(minEvents) || total > uint64(minEvents) && total >= 2*beaconCheckEvery && total%beaconCheckEvery == 0
}

// ordered appends the stored times, oldest first, to buf.
func (b *beaconEntry) ordered(buf []time.Time) []time.Time {
	start := 0
	if b.n == beaconRing {
		start = b.next
	}
	for i := 0; i < b.n; i++ {
		buf = append(buf, b.times[(start+i)%beaconRing])
	}
	return buf
}

type synKey struct {
	src, dst     netip.Addr
	sport, dport uint16
	seq          uint32
}

type flowKey4 struct {
	src, dst     netip.Addr
	sport, dport uint16
}

// beacon is the detector for one rule.
type beacon struct {
	rule  *Rule
	keys  map[beaconKey]*list.Element // Value is *beaconEntry
	lru   list.List                   // front = least recent event
	max   int
	stat  *tableStat
	syns  *recentSet[synKey]
	flows *recentSet[flowKey4]
	times []time.Time     // scratch
	ivals []time.Duration // scratch
}

func newBeacon(r *Rule, max int, stat, conns *tableStat) *beacon {
	return &beacon{
		rule: r, keys: make(map[beaconKey]*list.Element), max: max, stat: stat,
		syns:  newRecentSet[synKey](beaconSYNMemory, max, conns),
		flows: newRecentSet[flowKey4](beaconUDPIdle, max, conns),
	}
}

// isStart reports whether the packet starts a connection (see the file
// comment). It updates the retransmission and UDP flow memory.
func (d *beacon) isStart(v *view, seq uint32, t time.Time) bool {
	switch v.g {
	case gTCP:
		if v.flags&(tcpSYN|tcpACK) != tcpSYN {
			return false
		}
		k := synKey{v.src, v.dst, v.sport, v.dport, seq}
		retrans := d.syns.has(k, t)
		d.syns.add(k, t)
		return !retrans
	case gUDP:
		rev := flowKey4{v.dst, v.src, v.dport, v.sport}
		if d.flows.has(rev, t) {
			d.flows.add(rev, t)
			return false
		}
		k := flowKey4{v.src, v.dst, v.sport, v.dport}
		fresh := !d.flows.has(k, t)
		d.flows.add(k, t)
		return fresh
	}
	return false
}

// observe feeds one TCP or UDP packet that matches the rule's addresses
// and protocol. It returns the dedup key and a details function when the
// rule fires.
func (d *beacon) observe(v *view, p *packet.ParsedPacket, t time.Time) (dedupKey, func() map[string]string, bool) {
	r := d.rule
	if v.g == gUDP && v.dport == 53 || r.allowPorts.match(v.dport) || r.hasAllowAddrs && r.allowAddrs.match(v.dst) {
		return dedupKey{}, nil, false
	}
	d.prune(t)
	k := beaconKey{v.src, v.dst, v.dport, v.g}
	if !d.isStart(v, p.TCPSeq, t) {
		if el, ok := d.keys[k]; ok {
			learnName(el.Value.(*beaconEntry), p.AppFields)
		}
		return dedupKey{}, nil, false
	}
	b := d.entry(k, t)
	learnName(b, p.AppFields)
	b.times[b.next] = t
	b.next = (b.next + 1) % beaconRing
	b.n = min(b.n+1, beaconRing)
	b.total++
	if b.n < r.minEvents || !isCheckpoint(b.total, r.minEvents) || b.name != "" && inDomains(b.name, r.allow) {
		return dedupKey{}, nil, false
	}
	d.times = b.ordered(d.times[:0])
	d.ivals = intervals(d.times, d.ivals[:0])
	shown := slices.Clone(d.ivals[max(0, len(d.ivals)-beaconShown):])
	med, frac := beaconScore(d.ivals, r.jitter)
	if med < r.minInterval || med > r.maxInterval || frac < r.minFraction {
		b.passed, b.alerted = 0, false
		return dedupKey{}, nil, false
	}
	b.passed++
	if b.passed < r.persistence || b.alerted {
		return dedupKey{}, nil, false
	}
	b.alerted = true
	count, total, name, passed := b.n, b.total, b.name, b.passed
	details := func() map[string]string {
		s := make([]string, len(shown))
		for i, x := range shown {
			s[i] = x.Round(100 * time.Millisecond).String()
		}
		return map[string]string{
			"detector":     DetectBeacon,
			"median":       med.Round(100 * time.Millisecond).String(),
			"fraction":     strconv.FormatFloat(frac, 'f', 2, 64),
			"count":        strconv.Itoa(count),
			"events":       strconv.FormatUint(total, 10),
			"name":         name,
			"jitter":       strconv.FormatFloat(r.jitter, 'g', -1, 64),
			"min_fraction": strconv.FormatFloat(r.minFraction, 'g', -1, 64),
			"checks":       strconv.Itoa(passed),
			"intervals":    strings.Join(s, ","),
		}
	}
	return dedupKey{sid: r.SID, addr: v.src, peer: v.dst, port: v.dport, hasPort: true}, details, true
}

// learnName keeps the first server name a packet of the key carries.
func learnName(b *beaconEntry, fields map[string]string) {
	if b.name != "" || fields == nil {
		return
	}
	switch {
	case fields["sni"] != "":
		b.name = strings.ToLower(fields["sni"])
	case fields["host"] != "":
		b.name = strings.ToLower(stripPort(fields["host"]))
	case fields["qname"] != "" && fields["is_response"] != "true":
		b.name = strings.ToLower(fields["qname"])
	}
}

// intervals appends the gaps between consecutive times to buf.
func intervals(times []time.Time, buf []time.Duration) []time.Duration {
	for i := 1; i < len(times); i++ {
		buf = append(buf, times[i].Sub(times[i-1]))
	}
	return buf
}

// beaconScore returns the median of ivals and the fraction of ivals
// within jitter of the median or of twice the median. It reorders ivals.
// For an even count the median is the lower middle interval, so it is
// always an interval that occurred: with as many skipped beats (2m) as
// regular ones (1m), the mean of the middle two (1.5m) would fit
// neither band.
func beaconScore(ivals []time.Duration, jitter float64) (time.Duration, float64) {
	if len(ivals) == 0 {
		return 0, 0
	}
	slices.Sort(ivals)
	n := len(ivals)
	med := ivals[(n-1)/2]
	m := float64(med)
	in := 0
	for _, x := range ivals {
		f := float64(x)
		if f >= m*(1-jitter) && f <= m*(1+jitter) || f >= 2*m*(1-jitter) && f <= 2*m*(1+jitter) {
			in++
		}
	}
	return med, float64(in) / float64(n)
}

// entry returns k's entry, creating it (and evicting the key with the
// oldest event at the cap) if needed.
func (d *beacon) entry(k beaconKey, t time.Time) *beaconEntry {
	if el, ok := d.keys[k]; ok {
		d.lru.MoveToBack(el)
		b := el.Value.(*beaconEntry)
		b.last = t
		return b
	}
	if len(d.keys) >= d.max {
		d.remove(d.lru.Front())
		d.stat.evictions.Add(1)
	}
	b := &beaconEntry{key: k, last: t}
	d.keys[k] = d.lru.PushBack(b)
	d.stat.keys.Add(1)
	return b
}

// prune drops keys without an event for beaconIdle.
func (d *beacon) prune(now time.Time) {
	for el := d.lru.Front(); el != nil; el = d.lru.Front() {
		if now.Sub(el.Value.(*beaconEntry).last) <= beaconIdle {
			return
		}
		d.remove(el)
	}
}

func (d *beacon) remove(el *list.Element) {
	delete(d.keys, d.lru.Remove(el).(*beaconEntry).key)
	d.stat.keys.Add(-1)
}

func (d *beacon) clear() {
	d.stat.keys.Add(-int64(len(d.keys)))
	clear(d.keys)
	d.lru.Init()
	d.syns.clear()
	d.flows.clear()
}

// beacons feeds one TCP or UDP packet that is not whitelisted or passed
// to the beacon rules.
func (e *Engine) beacons(rs *RuleSet, p *packet.ParsedPacket, v *view, out []Alert) []Alert {
	for _, r := range rs.beacon {
		if r.Proto == ProtoTCP && v.g != gTCP || r.Proto == ProtoUDP && v.g != gUDP {
			continue
		}
		// Forward direction only: the key's source is the rule's source.
		if !r.src.match(v.src) || !r.sport.match(v.sport) || !r.dst.match(v.dst) || !r.dport.match(v.dport) {
			continue
		}
		if dk, details, fired := e.ruleState[r.idx].beacon.observe(v, p, e.now); fired {
			out = e.emit(r, dk, v, details, out)
		}
	}
	return out
}
