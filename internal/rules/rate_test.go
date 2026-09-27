package rules

import (
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

// unit is a value of 1 in series 0.
var unit = [rateSeries]uint64{1}

func TestRateCounterWindow(t *testing.T) {
	sec, ms := time.Second, time.Millisecond
	type add struct {
		at time.Duration // after t0
		v  uint64
	}
	tests := []struct {
		name string
		span time.Duration
		adds []add
		want uint64 // series 0 after the last add
	}{
		{"one", 10 * sec, []add{{0, 5}}, 5},
		{"sums", 10 * sec, []add{{0, 5}, {sec, 7}, {9 * sec, 1}}, 13},
		// Buckets are 1s, aligned to the first value at t0.
		{"last bucket still in", 10 * sec, []add{{0, 5}, {10*sec - 1, 1}}, 6},
		{"exactly span later: first bucket out", 10 * sec, []add{{0, 5}, {10 * sec, 1}}, 1},
		// The boundary error: 900ms is in bucket 0 (aligned by the 0 at
		// t0), which leaves the window at 10s although the value is only
		// 9.1s old.
		{"up to one bucket early", 10 * sec, []add{{0, 0}, {900 * ms, 5}, {10 * sec, 1}}, 1},
		{"aligned to the first value", 10 * sec, []add{{900 * ms, 5}, {10 * sec, 1}}, 6},
		{"bucket 1 still in at 10s", 10 * sec, []add{{0, 1}, {sec, 5}, {10 * sec, 1}}, 6},
		{"bucket 1 out at 11s", 10 * sec, []add{{0, 1}, {sec, 5}, {11 * sec, 1}}, 1},
		{"long gap clears all", 10 * sec, []add{{0, 5}, {sec, 5}, {time.Hour, 1}}, 1},
		// A value earlier than the newest is added at the newest time.
		{"backwards time", 10 * sec, []add{{100 * sec, 5}, {0, 7}}, 12},
		{"backwards then forward", 10 * sec, []add{{100 * sec, 5}, {0, 7}, {110 * sec, 1}}, 1},
		{"backwards value lives at the newest time", 10 * sec, []add{{100 * sec, 5}, {0, 7}, {109 * sec, 1}}, 13},
		// Small spans: 1s span, 100ms buckets.
		{"1s span", sec, []add{{0, 1}, {500 * ms, 1}, {999 * ms, 1}}, 3},
		{"1s span rolls", sec, []add{{0, 1}, {500 * ms, 1}, {1100 * ms, 1}}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var st tableStat
			r := newRateCounter[netip.Addr](tt.span, 100, &st)
			var e *rateEntry[netip.Addr]
			for _, a := range tt.adds {
				e = r.add(addrA, at(a.at), [rateSeries]uint64{a.v})
			}
			if got := e.sum(0); got != tt.want {
				t.Errorf("sum %d, want %d", got, tt.want)
			}
		})
	}
}

// TestRateCounterBound checks the documented error against an exact
// sliding window on random input: the sum never includes a value more
// than span old, and never misses one less than span*9/10 old.
func TestRateCounterBound(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	span := 5 * time.Second
	var st tableStat
	r := newRateCounter[netip.Addr](span, 100, &st)
	type ev struct {
		t time.Time
		v uint64
	}
	var evs []ev
	now := t0
	for i := range 6000 {
		now = now.Add(time.Duration(rng.IntN(20)) * time.Millisecond)
		if rng.IntN(500) == 0 {
			now = now.Add(time.Duration(rng.IntN(8000)) * time.Millisecond) // occasional gap
		}
		v := uint64(rng.IntN(1500))
		evs = append(evs, ev{now, v})
		got := r.add(addrA, now, [rateSeries]uint64{v}).sum(0)
		var upper, lower uint64 // exact sums over span and over 9/10 of it
		for _, x := range evs {
			age := now.Sub(x.t)
			if age < span {
				upper += x.v
			}
			if age < span*9/10 {
				lower += x.v
			}
		}
		if got > upper || got < lower {
			t.Fatalf("event %d at %v: sum %d outside [%d, %d]", i, now.Sub(t0), got, lower, upper)
		}
	}
}

func TestRateCounterSeries(t *testing.T) {
	var st tableStat
	r := newRateCounter[netip.Addr](time.Second, 100, &st)
	r.add(addrA, t0, [rateSeries]uint64{1, 100, 0})
	r.add(addrA, t0, [rateSeries]uint64{1, 200, 0})
	e := r.add(addrA, t0, [rateSeries]uint64{0, 0, 1})
	if e.sum(0) != 2 || e.sum(1) != 300 || e.sum(2) != 1 {
		t.Errorf("sums %d %d %d", e.sum(0), e.sum(1), e.sum(2))
	}
	if e := r.add(addrB, t0, unit); e.sum(0) != 1 || e.sum(1) != 0 {
		t.Errorf("keys share sums: %d %d", e.sum(0), e.sum(1))
	}
}

func TestRateCounterTopTag(t *testing.T) {
	var st tableStat
	r := newRateCounter[netip.Addr](time.Hour, 100, &st)
	e := r.add(addrA, t0, unit)
	if e.topTag() != 0 {
		t.Errorf("empty topTag %d", e.topTag())
	}
	// 53 is 40% of the tags, among many others.
	for i := range 1000 {
		tag := uint16(1000 + i)
		if i%5 < 2 {
			tag = 53
		}
		e = r.add(addrA, t0, unit)
		e.countTag(tag)
	}
	if e.topTag() != 53 {
		t.Errorf("topTag %d, want 53", e.topTag())
	}
	// Ties go to the smallest tag.
	e = r.add(addrB, t0, unit)
	e.countTag(9)
	e.countTag(7)
	if e.topTag() != 7 {
		t.Errorf("tie topTag %d, want 7", e.topTag())
	}
	// Starting over (every bucket expired) resets the tags.
	e = r.add(addrB, at(2*time.Hour), unit)
	e.countTag(99)
	if e.topTag() != 99 {
		t.Errorf("after reset topTag %d, want 99", e.topTag())
	}
	// Exactly one span later every bucket has expired too.
	e.countTag(99)
	e = r.add(addrB, at(3*time.Hour), unit)
	e.countTag(98)
	if e.topTag() != 98 || e.sum(0) != 1 {
		t.Errorf("one span later: topTag %d sum %d, want 98 and 1", e.topTag(), e.sum(0))
	}
}

func TestRateCounterEviction(t *testing.T) {
	var st tableStat
	r := newRateCounter[netip.Addr](time.Hour, 2, &st)
	r.add(addrA, t0, unit)
	r.add(addrB, t0, unit)
	r.add(addrA, at(time.Second), unit) // A is now the most recently updated
	r.add(addrC, at(time.Second), unit) // evicts B
	if st.keys.Load() != 2 || st.evictions.Load() != 1 || r.len() != 2 {
		t.Fatalf("keys %d evictions %d len %d", st.keys.Load(), st.evictions.Load(), r.len())
	}
	if _, ok := r.keys[addrB]; ok {
		t.Error("B not evicted")
	}
	if e := r.add(addrA, at(time.Second), unit); e.sum(0) != 3 {
		t.Errorf("A lost its sum: %d", e.sum(0))
	}
	if e := r.add(addrB, at(time.Second), unit); e.sum(0) != 1 {
		t.Errorf("evicted key kept its sum: %d", e.sum(0))
	}
}

func TestRateCounterPrunesStaleKeys(t *testing.T) {
	var st tableStat
	r := newRateCounter[netip.Addr](time.Second, 10, &st)
	r.add(addrA, t0, unit)
	r.add(addrB, t0, unit)
	r.add(addrC, at(time.Second+1), unit)
	if r.len() != 1 || st.keys.Load() != 1 || st.evictions.Load() != 0 {
		t.Errorf("len %d keys %d evictions %d", r.len(), st.keys.Load(), st.evictions.Load())
	}
	r.add(addrA, at(2*time.Second), unit) // exactly span after C: C stays
	if r.len() != 2 {
		t.Errorf("len %d, want 2", r.len())
	}
	r.clear()
	if r.len() != 0 || st.keys.Load() != 0 {
		t.Errorf("after clear: len %d keys %d", r.len(), st.keys.Load())
	}
}

func TestRecentSet(t *testing.T) {
	var st tableStat
	s := newRecentSet[netip.Addr](10*time.Second, 2, &st)
	s.add(addrA, t0)
	if !s.has(addrA, at(10*time.Second)) || s.has(addrA, at(10*time.Second+1)) {
		t.Error("idle boundary")
	}
	s.add(addrA, at(20*time.Second))
	s.add(addrA, at(5*time.Second)) // backwards: does not move A back
	if !s.has(addrA, at(30*time.Second)) {
		t.Error("backwards add moved A back")
	}
	s.add(addrB, at(30*time.Second))
	s.add(addrA, at(30*time.Second)) // B is now the least recently added
	s.add(addrC, at(30*time.Second))
	if s.has(addrB, at(30*time.Second)) || !s.has(addrA, at(30*time.Second)) || st.evictions.Load() != 1 || st.keys.Load() != 2 {
		t.Errorf("eviction: keys %d evictions %d", st.keys.Load(), st.evictions.Load())
	}
	s.clear()
	if s.len() != 0 || st.keys.Load() != 0 {
		t.Errorf("after clear: len %d keys %d", s.len(), st.keys.Load())
	}
}
