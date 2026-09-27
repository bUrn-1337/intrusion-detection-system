package rules

import (
	"container/list"
	"time"
)

// recentSet remembers keys seen within the last idle, for example the UDP
// flows a udp_flood rule counted or the echo requests waiting for a
// reply. Every add refreshes a key; a key not added for more than idle is
// gone, and at the cap of max keys the least recently added one is
// evicted and counted in stat. Keys past idle are dropped (not counted)
// as they reach the front of the recency list.
//
// Times must come from the engine clock. A time earlier than a key's
// last time does not move it back.
type recentSet[K comparable] struct {
	idle time.Duration
	max  int
	m    map[K]*list.Element // Value is *recentEntry[K]
	lru  list.List           // front = least recently added
	stat *tableStat
}

type recentEntry[K comparable] struct {
	key  K
	last time.Time
}

func newRecentSet[K comparable](idle time.Duration, max int, stat *tableStat) *recentSet[K] {
	return &recentSet[K]{idle: idle, max: max, m: make(map[K]*list.Element), stat: stat}
}

// add records k at t.
func (s *recentSet[K]) add(k K, t time.Time) {
	s.prune(t)
	if el, ok := s.m[k]; ok {
		s.lru.MoveToBack(el)
		if e := el.Value.(*recentEntry[K]); t.After(e.last) {
			e.last = t
		}
		return
	}
	if len(s.m) >= s.max {
		s.remove(s.lru.Front())
		s.stat.evictions.Add(1)
	}
	s.m[k] = s.lru.PushBack(&recentEntry[K]{key: k, last: t})
	s.stat.keys.Add(1)
}

// has reports whether k was added within idle of t. It does not refresh k.
func (s *recentSet[K]) has(k K, t time.Time) bool {
	s.prune(t)
	_, ok := s.m[k]
	return ok
}

func (s *recentSet[K]) prune(now time.Time) {
	for el := s.lru.Front(); el != nil; el = s.lru.Front() {
		if now.Sub(el.Value.(*recentEntry[K]).last) <= s.idle {
			return
		}
		s.remove(el)
	}
}

func (s *recentSet[K]) remove(el *list.Element) {
	delete(s.m, s.lru.Remove(el).(*recentEntry[K]).key)
	s.stat.keys.Add(-1)
}

func (s *recentSet[K]) clear() {
	s.stat.keys.Add(-int64(len(s.m)))
	clear(s.m)
	s.lru.Init()
}

func (s *recentSet[K]) len() int { return len(s.m) }
