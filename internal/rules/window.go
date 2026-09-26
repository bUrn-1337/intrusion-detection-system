package rules

import (
	"container/list"
	"time"
)

// windowCounter answers "did N events happen within S seconds?" per key.
//
// Each key keeps a deque (ring) of at most n event times. add reports a
// hit when the deque is full and newest - oldest <= span, so the window
// slides with every event and has no bucket edges. Keys are capped at max;
// when a new key arrives at the cap, the least recently seen key is
// evicted and counted in stat. Keys whose newest event is older than span
// can never contribute to a hit again and are dropped as they reach the
// front of the recency list (not counted as evictions).
//
// Times must come from the engine clock. An event earlier than the key's
// newest event is recorded at the newest time (zero elapsed).
type windowCounter[K comparable] struct {
	n    int
	span time.Duration
	max  int
	keys map[K]*list.Element // Value is *windowEntry[K]
	lru  list.List           // front = least recently seen
	stat *tableStat
}

type windowEntry[K comparable] struct {
	key  K
	ring []windowEvent // len <= n; when len == n, head is the oldest
	head int
}

// windowEvent is one event time plus a small caller-defined tag (the SYN
// flood detector stores the destination port).
type windowEvent struct {
	t   time.Time
	tag uint16
}

func newWindowCounter[K comparable](n int, span time.Duration, max int, stat *tableStat) *windowCounter[K] {
	return &windowCounter[K]{n: n, span: span, max: max, keys: make(map[K]*list.Element), stat: stat}
}

// add records an event for key at t and reports whether the last n events
// of key, including this one, fall within span. The returned entry is
// valid until the next call.
func (w *windowCounter[K]) add(key K, t time.Time, tag uint16) (*windowEntry[K], bool) {
	w.prune(t)
	el, ok := w.keys[key]
	if ok {
		w.lru.MoveToBack(el)
	} else {
		if len(w.keys) >= w.max {
			w.remove(w.lru.Front())
			w.stat.evictions.Add(1)
		}
		el = w.lru.PushBack(&windowEntry[K]{key: key})
		w.keys[key] = el
		w.stat.keys.Add(1)
	}
	e := el.Value.(*windowEntry[K])
	if len(e.ring) > 0 {
		if newest := e.newest(); t.Before(newest) {
			t = newest
		}
	}
	ev := windowEvent{t: t, tag: tag}
	if len(e.ring) < w.n {
		e.ring = append(e.ring, ev)
	} else {
		e.ring[e.head] = ev
		e.head = (e.head + 1) % w.n
	}
	return e, len(e.ring) == w.n && t.Sub(e.oldest()) <= w.span
}

// countSince returns how many of key's stored events are at or after t.
// It is at most n.
func (w *windowCounter[K]) countSince(key K, t time.Time) int {
	el, ok := w.keys[key]
	if !ok {
		return 0
	}
	c := 0
	for _, ev := range el.Value.(*windowEntry[K]).ring {
		if !ev.t.Before(t) {
			c++
		}
	}
	return c
}

// prune drops keys at the front of the recency list whose newest event is
// more than span before now.
func (w *windowCounter[K]) prune(now time.Time) {
	for el := w.lru.Front(); el != nil; el = w.lru.Front() {
		if now.Sub(el.Value.(*windowEntry[K]).newest()) <= w.span {
			return
		}
		w.remove(el)
	}
}

func (w *windowCounter[K]) remove(el *list.Element) {
	delete(w.keys, w.lru.Remove(el).(*windowEntry[K]).key)
	w.stat.keys.Add(-1)
}

// clear drops every key, for example when the rule that owns the counter
// is removed by a reload.
func (w *windowCounter[K]) clear() {
	w.stat.keys.Add(-int64(len(w.keys)))
	clear(w.keys)
	w.lru.Init()
}

func (w *windowCounter[K]) len() int { return len(w.keys) }

func (e *windowEntry[K]) oldest() time.Time {
	return e.ring[e.head].t
}

func (e *windowEntry[K]) newest() time.Time {
	i := e.head - 1
	if i < 0 {
		i = len(e.ring) - 1
	}
	return e.ring[i].t
}

// size returns the number of stored events.
func (e *windowEntry[K]) size() int { return len(e.ring) }

// topTag returns the most common tag among the stored events; ties go to
// the smallest tag so the result is deterministic.
func (e *windowEntry[K]) topTag() uint16 {
	counts := make(map[uint16]int, 4)
	var best uint16
	bestN := 0
	for _, ev := range e.ring {
		counts[ev.tag]++
		if n := counts[ev.tag]; n > bestN || n == bestN && ev.tag < best {
			best, bestN = ev.tag, n
		}
	}
	return best
}
