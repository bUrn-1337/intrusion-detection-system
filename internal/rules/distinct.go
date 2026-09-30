package rules

import (
	"container/list"
	"time"
)

// distinctCounter answers "were N distinct values seen within S seconds?"
// per key, for example distinct ports per scanning source.
//
// Each key keeps at most n+1 distinct values with the time each was last
// seen. One more than the threshold is kept so that "more than n" can be
// told apart from "exactly n" (syn_flood's max_distinct_ports asks the
// first question, the scan detectors the second). A value not seen for
// more than span is dropped the next time its key is updated; at n+1
// values, a new value replaces the least recently seen one. Values are
// kept in a slice and searched linearly, so n is capped at maxDistinct by
// the rule parser.
//
// Keys are capped at max like windowCounter: at the cap the least
// recently updated key is evicted and counted in stat, and keys whose
// newest value is older than span are dropped (not counted) as they reach
// the front of the recency list.
//
// Times must come from the engine clock. A time earlier than the key's
// newest time is recorded at the newest time.
type distinctCounter[K, V comparable] struct {
	n    int
	span time.Duration
	max  int
	keys map[K]*list.Element // Value is *distinctEntry[K, V]
	lru  list.List           // front = least recently updated
	stat *tableStat
}

type distinctEntry[K, V comparable] struct {
	key    K
	vals   []distinctVal[V] // len <= n+1, in no particular order
	newest time.Time
}

// distinctVal is one value, when it was last seen, and caller-defined
// bits ORed over every sighting (the scan detectors store the probe kinds
// and whether the port answered).
type distinctVal[V comparable] struct {
	v    V
	t    time.Time
	bits uint8
}

func newDistinctCounter[K, V comparable](n int, span time.Duration, max int, stat *tableStat) *distinctCounter[K, V] {
	return &distinctCounter[K, V]{n: n, span: span, max: max, keys: make(map[K]*list.Element), stat: stat}
}

// add records v for key at t, ORing bits into the value's bits, and
// returns the key's entry. entry.size() is then the number of distinct
// values seen within span of t, capped at n+1. The entry is valid until
// the next call.
func (d *distinctCounter[K, V]) add(key K, v V, t time.Time, bits uint8) *distinctEntry[K, V] {
	d.prune(t)
	el, ok := d.keys[key]
	if ok {
		d.lru.MoveToBack(el)
	} else {
		if len(d.keys) >= d.max {
			d.remove(d.lru.Front())
			d.stat.evictions.Add(1)
		}
		el = d.lru.PushBack(&distinctEntry[K, V]{key: key})
		d.keys[key] = el
		d.stat.keys.Add(1)
	}
	e := el.Value.(*distinctEntry[K, V])
	if t.Before(e.newest) {
		t = e.newest
	}
	e.newest = t

	// Drop expired values, remembering where v is and which value is the
	// least recently seen.
	found, lru := -1, -1
	kept := e.vals[:0]
	for _, x := range e.vals {
		if t.Sub(x.t) > d.span {
			continue
		}
		if x.v == v {
			found = len(kept)
		}
		if lru < 0 || x.t.Before(kept[lru].t) {
			lru = len(kept)
		}
		kept = append(kept, x)
	}
	clear(e.vals[len(kept):]) // release values that hold pointers
	e.vals = kept

	switch {
	case found >= 0:
		e.vals[found].t = t
		e.vals[found].bits |= bits
	case len(e.vals) <= d.n:
		e.vals = append(e.vals, distinctVal[V]{v: v, t: t, bits: bits})
	default:
		e.vals[lru] = distinctVal[V]{v: v, t: t, bits: bits}
	}
	return e
}

// prune drops keys at the front of the recency list whose newest value is
// more than span before now.
func (d *distinctCounter[K, V]) prune(now time.Time) {
	for el := d.lru.Front(); el != nil; el = d.lru.Front() {
		if now.Sub(el.Value.(*distinctEntry[K, V]).newest) <= d.span {
			return
		}
		d.remove(el)
	}
}

func (d *distinctCounter[K, V]) remove(el *list.Element) {
	delete(d.keys, d.lru.Remove(el).(*distinctEntry[K, V]).key)
	d.stat.keys.Add(-1)
}

// clear drops every key, for example when the rule that owns the counter
// is removed by a reload.
func (d *distinctCounter[K, V]) clear() {
	d.stat.keys.Add(-int64(len(d.keys)))
	clear(d.keys)
	d.lru.Init()
}

func (d *distinctCounter[K, V]) len() int { return len(d.keys) }

// size returns the number of distinct values stored, at most n+1.
func (e *distinctEntry[K, V]) size() int { return len(e.vals) }

// oldest returns the earliest last-seen time among the stored values.
func (e *distinctEntry[K, V]) oldest() time.Time {
	var t time.Time
	for i, x := range e.vals {
		if i == 0 || x.t.Before(t) {
			t = x.t
		}
	}
	return t
}
