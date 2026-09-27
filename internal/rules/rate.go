package rules

import (
	"container/list"
	"time"
)

// rateCounter answers "how much arrived within the last S seconds?" per
// key, as sums of values rather than counts of events: bytes, or packets
// counted by adding 1. Each key keeps up to rateSeries sums side by side
// (udp_flood sums forward packets, forward bytes and reply packets for the
// same key), all over the same window.
//
// Each key has rateSlots sub-buckets of span/rateSlots each, in a ring.
// A value is added to the bucket of its time; buckets that fall out of
// the window are zeroed as time moves on. The sum is over all buckets, so
// it covers from the start of the oldest live bucket to now: between 90%
// and 100% of span. A value is never counted once it is more than span
// old, but one up to a bucket (10% of span) younger than that may already
// be gone, so a threshold is reached up to 10% of the window late, or not
// at all when the rate sits just at count/span. Buckets are aligned to the
// key's first value, not to the wall clock.
//
// windowCounter's exact deque of event times is not used because its
// memory grows with count: a flood threshold of 10000 packets would keep
// 10000 timestamps per key (hundreds of kilobytes, times up to MaxKeys
// keys), and a byte threshold of 100 MB cannot be stored as events at
// all. Here every key costs the same small fixed size whatever the count.
//
// Keys are capped at max like windowCounter: at the cap the least
// recently updated key is evicted and counted in stat, and keys whose
// newest value is more than span old are dropped (not counted) as they
// reach the front of the recency list.
//
// Times must come from the engine clock. A time earlier than the key's
// newest time is recorded at the newest time.
type rateCounter[K comparable] struct {
	span, slot time.Duration
	max        int
	keys       map[K]*list.Element // Value is *rateEntry[K]
	lru        list.List           // front = least recently updated
	stat       *tableStat
}

const (
	rateSlots  = 10
	rateSeries = 3
	// rateTags is how many tags an entry tracks to find the most common
	// one (Misra-Gries): a tag that is more than 1/(rateTags+1) of the
	// values is always among them.
	rateTags = 4
)

type rateEntry[K comparable] struct {
	key       K
	buckets   [rateSlots][rateSeries]uint64
	head      int       // bucket of headStart
	headStart time.Time // start of the newest bucket
	newest    time.Time
	tags      [rateTags]rateTag
}

type rateTag struct {
	tag uint16
	n   uint64
}

func newRateCounter[K comparable](span time.Duration, max int, stat *tableStat) *rateCounter[K] {
	return &rateCounter[K]{span: span, slot: span / rateSlots, max: max, keys: make(map[K]*list.Element), stat: stat}
}

// add adds vals to key's sums at t and returns the key's entry, valid
// until the next call.
func (r *rateCounter[K]) add(key K, t time.Time, vals [rateSeries]uint64) *rateEntry[K] {
	r.prune(t)
	el, ok := r.keys[key]
	if ok {
		r.lru.MoveToBack(el)
	} else {
		if len(r.keys) >= r.max {
			r.remove(r.lru.Front())
			r.stat.evictions.Add(1)
		}
		el = r.lru.PushBack(&rateEntry[K]{key: key, headStart: t, newest: t})
		r.keys[key] = el
		r.stat.keys.Add(1)
	}
	e := el.Value.(*rateEntry[K])
	if t.Before(e.newest) {
		t = e.newest
	}
	e.newest = t
	e.advance(t, r.slot)
	for i, v := range vals {
		e.buckets[e.head][i] += v
	}
	return e
}

// advance moves the ring forward so that the head bucket holds t, zeroing
// the buckets that left the window. When every bucket is zeroed, the
// entry starts over and its tag counts are reset too.
func (e *rateEntry[K]) advance(t time.Time, slot time.Duration) {
	steps := t.Sub(e.headStart) / slot
	if steps <= 0 {
		return
	}
	if steps >= rateSlots {
		e.buckets = [rateSlots][rateSeries]uint64{}
		e.tags = [rateTags]rateTag{}
		e.head, e.headStart = 0, t
		return
	}
	for range steps {
		e.head = (e.head + 1) % rateSlots
		e.buckets[e.head] = [rateSeries]uint64{}
	}
	e.headStart = e.headStart.Add(steps * slot)
}

// countTag counts one sighting of tag for topTag. It is one Misra-Gries
// step: count tag if it is tracked or a slot is free, else decrement
// every tracked count.
func (e *rateEntry[K]) countTag(tag uint16) {
	free := -1
	for i := range e.tags {
		switch {
		case e.tags[i].n > 0 && e.tags[i].tag == tag:
			e.tags[i].n++
			return
		case e.tags[i].n == 0 && free < 0:
			free = i
		}
	}
	if free >= 0 {
		e.tags[free] = rateTag{tag: tag, n: 1}
		return
	}
	for i := range e.tags {
		e.tags[i].n--
	}
}

// sum returns series i summed over the window.
func (e *rateEntry[K]) sum(i int) uint64 {
	var s uint64
	for b := range e.buckets {
		s += e.buckets[b][i]
	}
	return s
}

// topTag returns the tag with the highest Misra-Gries count, the smallest
// on ties. It is the most common tag when one tag is a large share of
// the sightings since the entry last started over.
func (e *rateEntry[K]) topTag() uint16 {
	var best rateTag
	for _, x := range e.tags {
		if x.n > best.n || x.n == best.n && x.n > 0 && x.tag < best.tag {
			best = x
		}
	}
	return best.tag
}

// prune drops keys at the front of the recency list whose newest value is
// more than span before now.
func (r *rateCounter[K]) prune(now time.Time) {
	for el := r.lru.Front(); el != nil; el = r.lru.Front() {
		if now.Sub(el.Value.(*rateEntry[K]).newest) <= r.span {
			return
		}
		r.remove(el)
	}
}

func (r *rateCounter[K]) remove(el *list.Element) {
	delete(r.keys, r.lru.Remove(el).(*rateEntry[K]).key)
	r.stat.keys.Add(-1)
}

// clear drops every key, for example when the rule that owns the counter
// is removed by a reload.
func (r *rateCounter[K]) clear() {
	r.stat.keys.Add(-int64(len(r.keys)))
	clear(r.keys)
	r.lru.Init()
}

func (r *rateCounter[K]) len() int { return len(r.keys) }
