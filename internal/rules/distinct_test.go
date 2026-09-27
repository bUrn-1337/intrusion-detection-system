package rules

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"
)

// sighting is one value at one time.
type sighting struct {
	v int
	t time.Time
}

// feedDistinct adds each sighting for addrA and returns the indexes at
// which the key held at least n distinct values.
func feedDistinct(d *distinctCounter[netip.Addr, int], ss ...sighting) []int {
	var fired []int
	for i, s := range ss {
		if d.add(addrA, s.v, s.t, 0).size() >= d.n {
			fired = append(fired, i)
		}
	}
	return fired
}

// distinctValues returns v0, v0+1, ... one per step from start.
func distinctValues(n int, start time.Time, step time.Duration) []sighting {
	out := make([]sighting, n)
	for i := range out {
		out[i] = sighting{v: i, t: start.Add(time.Duration(i) * step)}
	}
	return out
}

func TestDistinctCounter(t *testing.T) {
	sec := time.Second
	tests := []struct {
		name string
		n    int
		span time.Duration
		ss   []sighting
		want []int
	}{
		{"n-1 distinct", 5, 10 * sec, distinctValues(4, t0, sec), nil},
		{"n distinct", 5, 10 * sec, distinctValues(5, t0, sec), []int{4}},
		{"keeps firing past n", 3, 10 * sec, distinctValues(6, t0, sec), []int{2, 3, 4, 5}},
		{"repeats do not count", 3, 10 * sec, []sighting{{1, t0}, {1, t0}, {2, t0}, {2, t0}, {1, t0}}, nil},
		{"exactly span apart counts", 2, 10 * sec, []sighting{{1, t0}, {2, at(10 * sec)}}, []int{1}},
		{"just over span", 2, 10 * sec, []sighting{{1, t0}, {2, at(10*sec + 1)}}, nil},
		{"n spread over more than span", 5, 10 * sec, distinctValues(5, t0, 3*sec), nil},
		// A value seen again is refreshed, so it stays in the window.
		{"refresh keeps a value", 3, 10 * sec, []sighting{{1, t0}, {2, at(5 * sec)}, {1, at(9 * sec)}, {3, at(14 * sec)}}, []int{3}},
		{"no refresh, value ages out", 3, 10 * sec, []sighting{{1, t0}, {2, at(5 * sec)}, {2, at(9 * sec)}, {3, at(14 * sec)}}, nil},
		{"n = 1", 1, sec, []sighting{{1, t0}, {1, at(time.Hour)}}, []int{0, 1}},
		// Backwards times are recorded at the key's newest time, so an old
		// timestamp cannot make a value expire early or late.
		{"backwards times", 3, 10 * sec, []sighting{{1, at(100 * sec)}, {2, t0}, {3, t0}}, []int{2}},
		{"backwards then forward", 2, 10 * sec, []sighting{{1, at(100 * sec)}, {2, t0}, {3, at(111 * sec)}}, []int{1}},
		// 2 is recorded at 100s, not 0, so it is still fresh at 105s.
		{"backwards value counts at the newest time", 3, 10 * sec, []sighting{{1, at(100 * sec)}, {2, t0}, {3, at(105 * sec)}}, []int{2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var st tableStat
			d := newDistinctCounter[netip.Addr, int](tt.n, tt.span, 100, &st)
			if got := feedDistinct(d, tt.ss...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fired at %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDistinctCounterBounded checks that a key holds at most n+1 values
// and that the least recently seen one is replaced.
func TestDistinctCounterBounded(t *testing.T) {
	var st tableStat
	d := newDistinctCounter[netip.Addr, int](3, time.Hour, 100, &st)
	for i := range 100 {
		if e := d.add(addrA, i, at(time.Duration(i)*time.Second), 0); e.size() > 4 {
			t.Fatalf("size %d after %d values", e.size(), i+1)
		}
	}
	d.add(addrA, 97, at(200*time.Second), 0) // refresh 97; 96 is now the least recently seen
	e := d.add(addrA, 1000, at(201*time.Second), 0)
	var got []int
	for _, x := range e.vals {
		got = append(got, x.v)
	}
	slices.Sort(got)
	if want := []int{97, 98, 99, 1000}; !reflect.DeepEqual(got, want) {
		t.Errorf("values %v, want %v", got, want)
	}
	if !e.oldest().Equal(at(98 * time.Second)) {
		t.Errorf("oldest %v", e.oldest())
	}
}

func TestDistinctCounterBits(t *testing.T) {
	var st tableStat
	d := newDistinctCounter[netip.Addr, int](5, time.Hour, 100, &st)
	d.add(addrA, 1, t0, 1)
	e := d.add(addrA, 1, t0, 4)
	if e.size() != 1 || e.vals[0].bits != 5 {
		t.Errorf("size %d bits %d", e.size(), e.vals[0].bits)
	}
}

func TestDistinctCounterEviction(t *testing.T) {
	var st tableStat
	d := newDistinctCounter[netip.Addr, int](2, time.Hour, 2, &st)
	d.add(addrA, 1, t0, 0)
	d.add(addrB, 1, t0, 0)
	d.add(addrA, 2, at(time.Second), 0) // A is now the most recently updated
	d.add(addrC, 1, at(time.Second), 0) // evicts B
	if st.keys.Load() != 2 || st.evictions.Load() != 1 || d.len() != 2 {
		t.Fatalf("keys %d evictions %d len %d", st.keys.Load(), st.evictions.Load(), d.len())
	}
	if _, ok := d.keys[addrB]; ok {
		t.Error("B not evicted")
	}
	if e := d.add(addrA, 3, at(time.Second), 0); e.size() != 3 {
		t.Errorf("A lost its values: size %d", e.size())
	}
	if e := d.add(addrB, 2, at(time.Second), 0); e.size() != 1 {
		t.Errorf("evicted key kept its values: size %d", e.size())
	}
	if st.evictions.Load() != 2 {
		t.Errorf("evictions %d", st.evictions.Load())
	}
}

func TestDistinctCounterPrunesStaleKeys(t *testing.T) {
	var st tableStat
	d := newDistinctCounter[netip.Addr, int](2, time.Second, 10, &st)
	d.add(addrA, 1, t0, 0)
	d.add(addrB, 1, t0, 0)
	d.add(addrC, 1, at(5*time.Second), 0)
	if d.len() != 1 || st.keys.Load() != 1 || st.evictions.Load() != 0 {
		t.Errorf("len %d keys %d evictions %d", d.len(), st.keys.Load(), st.evictions.Load())
	}
	d.clear()
	if d.len() != 0 || st.keys.Load() != 0 {
		t.Errorf("after clear: len %d keys %d", d.len(), st.keys.Load())
	}
}
