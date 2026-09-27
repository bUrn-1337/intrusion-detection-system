package rules

import (
	"container/list"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// TTL anomaly detection: detect:ttl_anomaly.
//
// Every stack starts packets at one of a few TTLs (hop limits for IPv6):
// 32, 64, 128 or 255. The initial TTL of a packet is taken to be the
// smallest of these that is at least the observed TTL, and the hop
// distance is initial - observed. Packets from one address normally
// arrive over the same path, so their distance is stable; a spoofer
// elsewhere in the network cannot know the right TTL to use.
//
// Per source address the detector keeps up to ttlSlots distinct
// distances, each with a sample count and a last-seen time. A distance is
// established once it has min_samples samples. When a source has at
// least one established distance, a packet whose distance differs from
// every established one by more than max_hop_diff is anomalous (it still
// counts as a sample of its own distance, so a lasting route change
// becomes established and stops being anomalous). The rule fires when a
// source has count anomalous packets within seconds.
//
// Stacks with different initial TTLs behind one NAT address give the
// same distance, since the distance does not depend on the initial TTL.
// Observed TTLs of 5 or less are ignored: they come from traceroute and
// other TTL-limited probes, not from a stable path.
//
// With scope:external (the default) only sources outside $HOME_NET are
// tracked. Sources are held in an LRU table capped at the engine's
// MaxKeys, and a source unseen for ttlIdle is dropped.
//
// TCP flows that completed their handshake (per the handshake tracker)
// never count as anomalous: load balancers, anycast and per-flow ECMP
// hashing send each connection from one server address over its own
// path, so the distance is stable within a connection but differs
// between connections. A spoofer cannot complete a handshake from an
// address it does not receive traffic for. The engine therefore passes
// each packet in one of three modes (ttlMode):
//
//   - packets of a completed flow are samples only;
//   - packets of a handshake still pending in the tracker (the SYN and
//     SYN-ACK, and their retransmissions) are samples, and an anomaly is
//     held back per handshake until the tracker reports its outcome:
//     dropped if it completed, counted at the outcome time otherwise;
//   - every other packet (UDP, ICMP, TCP of flows the tracker never saw
//     open) is checked at once.

const (
	ttlSlots    = 4
	ttlMinTTL   = 5 // observed TTLs at or below this are ignored
	ttlIdle     = time.Hour
	ttlMaxShown = 8 // sample TTLs listed in alert details
)

type hopSlot struct {
	dist    uint8
	samples uint32
	last    time.Time
}

type ttlSource struct {
	key   netip.Addr
	slots []hopSlot // at most ttlSlots
	last  time.Time
}

// initialTTL returns the initial TTL a packet with this TTL most likely
// started with.
func initialTTL(ttl uint8) uint8 {
	switch {
	case ttl <= 32:
		return 32
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	}
	return 255
}

// ttlMode is how a packet's TTL is used; see the file comment.
type ttlMode uint8

const (
	ttlNow        ttlMode = iota // sample, and count an anomaly at once
	ttlOnlySample                // sample only: a completed TCP flow
	ttlHold                      // sample, and hold an anomaly until the handshake ends
)

// ttlMaxHeld bounds the anomalies held per handshake (SYN and SYN-ACK
// retransmissions); further ones are dropped.
const ttlMaxHeld = 4

// ttlHeld is an anomalous packet of a pending handshake.
type ttlHeld struct {
	src, dst     netip.Addr
	sport, dport uint16
	tag          uint16 // ttl<<8 | distance
}

type ttlPending struct {
	key  hsKey
	held []ttlHeld
}

// ttlAnomaly is the detector for one rule.
type ttlAnomaly struct {
	rule      *Rule
	srcs      map[netip.Addr]*list.Element // Value is *ttlSource
	lru       list.List                    // front = least recently seen
	max       int
	stat      *tableStat
	anomalies *windowCounter[netip.Addr] // tag = ttl<<8 | distance
	// pending holds anomalies of handshakes still in the tracker, oldest
	// first, capped at max like srcs. Every entry is resolved by the
	// tracker's outcome for its handshake (which always comes: completion,
	// reset, timeout or eviction); one evicted here is dropped.
	pending    map[hsKey]*list.Element // Value is *ttlPending
	pendingLRU list.List
}

func newTTLAnomaly(r *Rule, max int, stat *tableStat) *ttlAnomaly {
	return &ttlAnomaly{
		rule: r, srcs: make(map[netip.Addr]*list.Element), max: max, stat: stat,
		anomalies: newWindowCounter[netip.Addr](r.detect.count, r.detect.span(), max, stat),
		pending:   make(map[hsKey]*list.Element),
	}
}

// observe records a packet from src with the given TTL at engine time t
// and checks it at once (mode ttlNow). It returns the dedup key and a
// details function when the rule fires. The caller has checked the
// rule's addresses and the packet's group.
func (d *ttlAnomaly) observe(src netip.Addr, ttl uint8, t time.Time) (dedupKey, func() map[string]string, bool) {
	tag, anomalous := d.sample(src, ttl, t, ttlNow)
	if !anomalous {
		return dedupKey{}, nil, false
	}
	return d.count(src, tag, t)
}

// sample records a packet from src with the given TTL at engine time t.
// It reports whether the packet is anomalous (never in mode ttlOnlySample),
// with its tag for count.
func (d *ttlAnomaly) sample(src netip.Addr, ttl uint8, t time.Time, mode ttlMode) (uint16, bool) {
	if ttl <= ttlMinTTL || d.rule.external && d.rule.homeNet.match(src) {
		return 0, false
	}
	d.prune(t)
	dist := initialTTL(ttl) - ttl
	s := d.source(src, t)
	anomalous, established := false, false
	for _, sl := range s.slots {
		if sl.samples < uint32(d.rule.minSamples) {
			continue
		}
		if !established {
			established, anomalous = true, true
		}
		if absDiff(sl.dist, dist) <= d.rule.maxHopDiff {
			anomalous = false
			break
		}
	}
	d.record(s, dist, t)
	return uint16(ttl)<<8 | uint16(dist), anomalous && mode != ttlOnlySample
}

// hold keeps an anomaly of the pending handshake k until resolve.
func (d *ttlAnomaly) hold(k hsKey, h ttlHeld) {
	if el, ok := d.pending[k]; ok {
		p := el.Value.(*ttlPending)
		if len(p.held) < ttlMaxHeld {
			p.held = append(p.held, h)
		}
		return
	}
	if len(d.pending) >= d.max {
		d.removePending(d.pendingLRU.Front())
		d.stat.evictions.Add(1)
	}
	d.pending[k] = d.pendingLRU.PushBack(&ttlPending{key: k, held: []ttlHeld{h}})
	d.stat.keys.Add(1)
}

// resolve ends the handshake of ev: its held anomalies are dropped if it
// completed and returned otherwise, to be counted at ev.t.
func (d *ttlAnomaly) resolve(ev *hsEvent) []ttlHeld {
	el, ok := d.pending[ev.key]
	if !ok {
		return nil
	}
	p := el.Value.(*ttlPending)
	d.removePending(el)
	if ev.complete {
		return nil
	}
	return p.held
}

func (d *ttlAnomaly) removePending(el *list.Element) {
	delete(d.pending, d.pendingLRU.Remove(el).(*ttlPending).key)
	d.stat.keys.Add(-1)
}

// count adds one anomaly with the given tag for src at t. It returns the
// dedup key and a details function when the rule fires.
func (d *ttlAnomaly) count(src netip.Addr, tag uint16, t time.Time) (dedupKey, func() map[string]string, bool) {
	ent, fired := d.anomalies.add(src, t, tag)
	if !fired {
		return dedupKey{}, nil, false
	}
	details := func() map[string]string {
		var est []string
		if el, ok := d.srcs[src]; ok {
			for _, sl := range el.Value.(*ttlSource).slots {
				if sl.samples >= uint32(d.rule.minSamples) {
					est = append(est, strconv.Itoa(int(sl.dist))+"("+strconv.FormatUint(uint64(sl.samples), 10)+")")
				}
			}
		}
		var dists, ttls []int
		for _, ev := range ent.ring {
			dists = append(dists, int(ev.tag&0xff))
			ttls = append(ttls, int(ev.tag>>8))
		}
		return map[string]string{
			"detector":              DetectTTLAnomaly,
			"track":                 TrackBySrc.String(),
			"tracked_addr":          src.String(),
			"count":                 strconv.Itoa(ent.size()),
			"seconds":               strconv.Itoa(d.rule.detect.seconds),
			"window":                ent.newest().Sub(ent.oldest()).Round(time.Millisecond).String(),
			"established_distances": strings.Join(est, ","),
			"anomalous_distances":   joinInts(dists, ttlSlots*4),
			"sample_ttls":           joinInts(ttls, ttlMaxShown),
			"max_hop_diff":          strconv.Itoa(d.rule.maxHopDiff),
		}
	}
	return dedupKey{sid: d.rule.SID, addr: src}, details, true
}

// source returns src's entry, creating it (and evicting the least
// recently seen source at the cap) if needed.
func (d *ttlAnomaly) source(src netip.Addr, t time.Time) *ttlSource {
	if el, ok := d.srcs[src]; ok {
		d.lru.MoveToBack(el)
		s := el.Value.(*ttlSource)
		s.last = t
		return s
	}
	if len(d.srcs) >= d.max {
		d.remove(d.lru.Front())
		d.stat.evictions.Add(1)
	}
	s := &ttlSource{key: src, last: t}
	d.srcs[src] = d.lru.PushBack(s)
	d.stat.keys.Add(1)
	return s
}

// record counts one sample of dist. With every slot in use by other
// distances, the least recently seen slot that is not established is
// replaced, or failing that the least recently seen one.
func (d *ttlAnomaly) record(s *ttlSource, dist uint8, t time.Time) {
	for i := range s.slots {
		if s.slots[i].dist == dist {
			s.slots[i].samples++
			s.slots[i].last = t
			return
		}
	}
	fresh := hopSlot{dist: dist, samples: 1, last: t}
	if len(s.slots) < ttlSlots {
		s.slots = append(s.slots, fresh)
		return
	}
	victim := -1
	for pass := 0; pass < 2 && victim < 0; pass++ {
		for i, sl := range s.slots {
			if pass == 0 && sl.samples >= uint32(d.rule.minSamples) {
				continue
			}
			if victim < 0 || sl.last.Before(s.slots[victim].last) {
				victim = i
			}
		}
	}
	s.slots[victim] = fresh
}

// prune drops sources not seen for ttlIdle.
func (d *ttlAnomaly) prune(now time.Time) {
	for el := d.lru.Front(); el != nil; el = d.lru.Front() {
		if now.Sub(el.Value.(*ttlSource).last) <= ttlIdle {
			return
		}
		d.remove(el)
	}
}

func (d *ttlAnomaly) remove(el *list.Element) {
	delete(d.srcs, d.lru.Remove(el).(*ttlSource).key)
	d.stat.keys.Add(-1)
}

func (d *ttlAnomaly) clear() {
	d.stat.keys.Add(-int64(len(d.srcs) + len(d.pending)))
	clear(d.srcs)
	d.lru.Init()
	clear(d.pending)
	d.pendingLRU.Init()
	d.anomalies.clear()
}

func absDiff(a, b uint8) int {
	if a > b {
		return int(a - b)
	}
	return int(b - a)
}
