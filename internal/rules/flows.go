package rules

import (
	"container/list"
	"time"
)

// flowSet remembers TCP flows whose handshake the tracker saw complete,
// for ttl_anomaly (see ttl.go). A flow is keyed like a handshake (client
// = the sender of the SYN). Entries are kept in least recently seen
// order: every packet of the flow refreshes its entry, one unseen for
// flowIdle is dropped, and at the cap the least recently seen is evicted
// and counted. Times come from the engine clock.
type flowSet struct {
	max  int
	m    map[hsKey]*list.Element // Value is *flowEntry
	lru  list.List               // front = least recently seen
	stat *tableStat
}

type flowEntry struct {
	key  hsKey
	last time.Time
}

// flowIdle is how long a completed flow is remembered without packets.
// It matches ttlIdle: a source's history outlives none of its flows.
const flowIdle = time.Hour

func newFlowSet(max int, stat *tableStat) *flowSet {
	return &flowSet{max: max, m: make(map[hsKey]*list.Element), stat: stat}
}

// add records the completed flow k at t.
func (f *flowSet) add(k hsKey, t time.Time) {
	f.prune(t)
	if el, ok := f.m[k]; ok {
		f.lru.MoveToBack(el)
		el.Value.(*flowEntry).last = t
		return
	}
	if len(f.m) >= f.max {
		f.remove(f.lru.Front())
		f.stat.evictions.Add(1)
	}
	f.m[k] = f.lru.PushBack(&flowEntry{key: k, last: t})
	f.stat.keys.Add(1)
}

// touch reports whether k is a completed flow and, if so, refreshes it.
func (f *flowSet) touch(k hsKey, t time.Time) bool {
	f.prune(t)
	el, ok := f.m[k]
	if ok {
		f.lru.MoveToBack(el)
		if e := el.Value.(*flowEntry); t.After(e.last) {
			e.last = t
		}
	}
	return ok
}

func (f *flowSet) prune(now time.Time) {
	for el := f.lru.Front(); el != nil; el = f.lru.Front() {
		if now.Sub(el.Value.(*flowEntry).last) <= flowIdle {
			return
		}
		f.remove(el)
	}
}

func (f *flowSet) remove(el *list.Element) {
	delete(f.m, f.lru.Remove(el).(*flowEntry).key)
	f.stat.keys.Add(-1)
}

func (f *flowSet) clear() {
	f.stat.keys.Add(-int64(len(f.m)))
	clear(f.m)
	f.lru.Init()
}
