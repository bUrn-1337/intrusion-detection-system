package rules

import (
	"container/list"
	"maps"
	"net/netip"
	"time"
)

// deduper folds repeated matches of the same rule for the same address
// into one alert plus one summary.
//
// The first match for a key emits a Kind "alert" alert and opens a window
// of length window from that time. Further matches before the window
// closes only bump the count. When it closes (at first + window, on the
// engine clock) an entry with Count > 1 emits one Kind "summary" alert
// with the total count and the first and last match times. The window is
// fixed from the first match, not extended by later ones, so a steady
// attack produces one summary per window.
//
// Entries are kept in creation order, which is also closing order because
// the engine clock never goes backwards. At the cap, the oldest entry is
// closed early (its summary is emitted) and counted as an eviction.
type deduper struct {
	window time.Duration
	max    int
	m      map[dedupKey]*list.Element // Value is *dedupEntry
	order  list.List
	stat   *tableStat
}

// dedupKey is (sid, tracked address), plus the port for detectors that
// alert per port (host_sweep), the MAC for arp_spoof kinds that alert
// per MAC (unsolicited_reply, multi_ip), and a second address for
// detectors that alert per address pair (icmp_tunnel).
type dedupKey struct {
	sid     int
	addr    netip.Addr
	peer    netip.Addr
	port    uint16
	hasPort bool
	mac     mac6
	hasMAC  bool
}

type dedupEntry struct {
	key    dedupKey
	first  Alert
	last   time.Time
	count  int
	closes time.Time
}

func newDeduper(window time.Duration, max int, stat *tableStat) *deduper {
	return &deduper{window: window, max: max, m: make(map[dedupKey]*list.Element), stat: stat}
}

// seen records a match at now. If the key has an open window it only
// bumps the count. Otherwise it opens one and appends mk() (the alert to
// emit), after the summary of any entry evicted to make room. It reports
// whether a new alert was appended.
func (d *deduper) seen(k dedupKey, now time.Time, mk func() Alert, out []Alert) ([]Alert, bool) {
	if el, ok := d.m[k]; ok {
		e := el.Value.(*dedupEntry)
		e.count++
		e.last = now
		return out, false
	}
	if len(d.m) >= d.max {
		out = d.close(d.order.Front(), now, out)
		d.stat.evictions.Add(1)
	}
	a := mk()
	e := &dedupEntry{key: k, first: a, last: now, count: 1, closes: now.Add(d.window)}
	d.m[k] = d.order.PushBack(e)
	d.stat.keys.Add(1)
	return append(out, a), true
}

// expire closes every window that closes at or before now.
func (d *deduper) expire(now time.Time, out []Alert) []Alert {
	for el := d.order.Front(); el != nil; el = d.order.Front() {
		e := el.Value.(*dedupEntry)
		if now.Before(e.closes) {
			break
		}
		out = d.close(el, e.closes, out)
	}
	return out
}

// flush closes every open window at time now.
func (d *deduper) flush(now time.Time, out []Alert) []Alert {
	for el := d.order.Front(); el != nil; el = d.order.Front() {
		out = d.close(el, now, out)
	}
	return out
}

func (d *deduper) close(el *list.Element, at time.Time, out []Alert) []Alert {
	e := d.order.Remove(el).(*dedupEntry)
	delete(d.m, e.key)
	d.stat.keys.Add(-1)
	if e.count <= 1 {
		return out
	}
	s := e.first
	s.Kind = KindSummary
	s.Time = at
	s.LastSeen = e.last
	s.Count = e.count
	s.Details = maps.Clone(e.first.Details)
	return append(out, s)
}
