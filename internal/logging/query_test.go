package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

// line encodes one alert record.
func line(t *testing.T, a rules.Alert) string {
	t.Helper()
	b, err := json.Marshal(alertRecord{Type: TypeAlert, Alert: a})
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func writeFile(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatal(err)
	}
}

// query runs Query and returns the matched records' SIDs (0 for
// non-alert records) and the stats.
func query(t *testing.T, path string, f Filter) ([]int, QueryStats) {
	t.Helper()
	var sids []int
	st, err := Query(path, f, func(r Record) error {
		if r.Alert != nil {
			sids = append(sids, r.Alert.SID)
		} else {
			sids = append(sids, 0)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sids, st
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestQueryFilters(t *testing.T) {
	now := time.Now().UTC()
	mk := func(sid int, sev, cat, kind, src, dst string, age time.Duration) rules.Alert {
		a := testAlert(sid)
		a.Severity, a.Category, a.Kind, a.SrcIP, a.DstIP = sev, cat, kind, src, dst
		a.Time = now.Add(-age)
		return a
	}
	path := filepath.Join(t.TempDir(), "log.jsonl")
	stats, _ := json.Marshal(StatsRecord{Type: TypeStats, Time: now.Add(-30 * time.Minute), Reason: StatsPeriodic})
	event, _ := json.Marshal(EventRecord{Type: TypeEvent, Time: now.Add(-20 * time.Minute), Event: EventReload, OK: true})
	writeFile(t, path,
		line(t, mk(1, "low", "dns", "alert", "10.0.0.1", "192.168.1.1", 3*time.Hour)),
		line(t, mk(2, "medium", "credential", "alert", "10.0.0.2", "192.168.1.2", 2*time.Hour)),
		string(stats)+"\n",
		line(t, mk(3, "high", "dos", "alert", "10.1.0.3", "192.168.2.1", time.Hour)),
		string(event)+"\n",
		line(t, mk(3, "high", "dos", "summary", "10.1.0.3", "192.168.2.1", 50*time.Minute)),
		line(t, mk(4, "critical", "Web-Attack", "alert", "2001:db8::1", "2001:db8::2", 10*time.Minute)),
		line(t, mk(5, "medium", "dos", "alert", "10.0.0.1", "192.168.1.1", time.Minute)),
	)
	tests := []struct {
		name string
		f    Filter
		want []int
	}{
		{"default: alerts only", Filter{}, []int{1, 2, 3, 3, 4, 5}},
		{"type stats", Filter{Type: TypeStats}, []int{0}},
		{"type event", Filter{Type: TypeEvent}, []int{0}},
		{"type all", Filter{Type: TypeAll}, []int{1, 2, 0, 3, 0, 3, 4, 5}},
		{"min severity medium", Filter{MinSeverity: "medium"}, []int{2, 3, 3, 4, 5}},
		{"min severity high", Filter{MinSeverity: "high"}, []int{3, 3, 4}},
		{"min severity critical", Filter{MinSeverity: "critical"}, []int{4}},
		{"since 90m", Filter{Since: 90 * time.Minute}, []int{3, 3, 4, 5}},
		{"since, all types", Filter{Since: 25 * time.Minute, Type: TypeAll}, []int{0, 4, 5}},
		{"from/to", Filter{From: now.Add(-150 * time.Minute), To: now.Add(-30 * time.Minute)}, []int{2, 3, 3}},
		{"src IP", Filter{Src: mustPrefix(t, "10.0.0.1")}, []int{1, 5}},
		{"src CIDR", Filter{Src: mustPrefix(t, "10.0.0.0/16")}, []int{1, 2, 5}},
		{"src IPv6 CIDR", Filter{Src: mustPrefix(t, "2001:db8::/32")}, []int{4}},
		{"dst CIDR", Filter{Dst: mustPrefix(t, "192.168.2.0/24")}, []int{3, 3}},
		{"src and dst", Filter{Src: mustPrefix(t, "10.0.0.0/8"), Dst: mustPrefix(t, "192.168.1.2")}, []int{2}},
		{"sid", Filter{SID: 3}, []int{3, 3}},
		{"category (case-insensitive)", Filter{Category: "web-attack"}, []int{4}},
		{"kind summary", Filter{Kind: rules.KindSummary}, []int{3}},
		{"kind alert", Filter{Kind: rules.KindAlert}, []int{1, 2, 3, 4, 5}},
		{"alert filter excludes other types", Filter{Type: TypeAll, SID: 5}, []int{5}},
		{"combined", Filter{MinSeverity: "medium", Category: "dos", Kind: rules.KindAlert, Since: 2 * time.Hour}, []int{3, 5}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, st := query(t, path, tc.f)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			if st.Invalid != 0 || st.Matched != len(tc.want) {
				t.Errorf("stats %+v", st)
			}
		})
	}

	for _, bad := range []Filter{{Type: "x"}, {MinSeverity: "urgent"}, {Kind: "x"}, {Since: -1}} {
		if _, err := Query(path, bad, func(Record) error { return nil }); err == nil {
			t.Errorf("filter %+v accepted", bad)
		}
	}
	if _, err := Query(filepath.Join(t.TempDir(), "none"), Filter{}, func(Record) error { return nil }); err == nil {
		t.Error("missing log accepted")
	}
}

func TestQueryRotatedOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	writeFile(t, RotatedName(path, 3), line(t, testAlert(1)), line(t, testAlert(2)))
	writeFile(t, RotatedName(path, 2), line(t, testAlert(3)))
	writeFile(t, RotatedName(path, 1), line(t, testAlert(4)), line(t, testAlert(5)))
	writeFile(t, path, line(t, testAlert(6)))
	got, _ := query(t, path, Filter{})
	if want := []int{1, 2, 3, 4, 5, 6}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	// Rotated files are read even when the current file is missing (just
	// rotated, not yet reopened).
	os.Remove(path)
	got, _ = query(t, path, Filter{})
	if want := []int{1, 2, 3, 4, 5}; !reflect.DeepEqual(got, want) {
		t.Errorf("without current file: got %v, want %v", got, want)
	}
}

func TestQueryPartialTrailingLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	full := line(t, testAlert(2))
	writeFile(t, path, line(t, testAlert(1)), full[:len(full)/2])
	got, st := query(t, path, Filter{})
	if !reflect.DeepEqual(got, []int{1}) || st.Invalid != 0 {
		t.Errorf("got %v %+v, want [1] and no invalid lines", got, st)
	}

	// The same truncation in a rotated file is damage, and is counted.
	writeFile(t, RotatedName(path, 1), line(t, testAlert(0)), full[:len(full)/2])
	got, st = query(t, path, Filter{})
	if !reflect.DeepEqual(got, []int{0, 1}) || st.Invalid != 1 {
		t.Errorf("got %v %+v, want [0 1] and 1 invalid line", got, st)
	}
}

func TestQueryGarbageCounted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	writeFile(t, path,
		line(t, testAlert(1)),
		"not json at all\n",
		"{\"type\":\"weird\",\"time\":\"2026-09-26T12:00:00Z\"}\n",
		"{\"type\":\"alert\",\"sid\":\"not a number\"}\n",
		"{\"sid\":4}\n",
		"\x00\x01\x02\n",
		"\n",
		line(t, testAlert(2)),
		"{\"type\":\"alert\",\"time\":\"yesterday\"}\n",
	)
	got, st := query(t, path, Filter{Type: TypeAll})
	if !reflect.DeepEqual(got, []int{1, 2}) || st.Invalid != 6 {
		t.Errorf("got %v %+v, want [1 2] and 6 invalid", got, st)
	}
}

func TestPrinter(t *testing.T) {
	a := testAlert(1000001)
	a.Msg = "evil\x1b[2Jmsg"
	rec, err := ParseRecord([]byte(strings.TrimSuffix(line(t, a), "\n")))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	p := NewPrinter(&b, false)
	p.Print(rec)
	p.Print(rec)
	out := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if len(out) != 3 || !strings.HasPrefix(out[0], "TIME ") {
		t.Fatalf("table:\n%s", b.String())
	}
	for _, want := range []string{"alert", "high", "1000001", "10.0.0.1:40000", "10.0.0.2:80", "evil?[2Jmsg"} {
		if !strings.Contains(out[1], want) {
			t.Errorf("row %q lacks %q", out[1], want)
		}
	}
	if strings.Index(out[0], "SOURCE") != strings.Index(out[1], "10.0.0.1") {
		t.Errorf("columns not aligned:\n%s", b.String())
	}

	b.Reset()
	p = NewPrinter(&b, true)
	p.Print(rec)
	if b.String() != string(rec.Raw)+"\n" {
		t.Errorf("json output %q", b.String())
	}
}

// follower collects Follow's output.
type collector struct {
	mu   sync.Mutex
	sids []int
}

func (c *collector) add(r Record) error {
	c.mu.Lock()
	c.sids = append(c.sids, r.Alert.SID)
	c.mu.Unlock()
	return nil
}

func (c *collector) waitFor(t *testing.T, n int) []int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		got := append([]int(nil), c.sids...)
		c.mu.Unlock()
		if len(got) >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func seq(from, to int) []int {
	var out []int
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

func TestFollowAppendAndPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	writeFile(t, path, line(t, testAlert(1)))
	ctx, cancel := context.WithCancel(context.Background())
	var c collector
	res := make(chan QueryStats)
	go func() {
		st, err := Follow(ctx, path, Filter{}, c.add, 5*time.Millisecond)
		if err != nil {
			t.Error(err)
		}
		res <- st
	}()
	if got := c.waitFor(t, 1); !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("history: %v", got)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(line(t, testAlert(2)))
	full := line(t, testAlert(3))
	f.WriteString(full[:10]) // a record being written
	time.Sleep(50 * time.Millisecond)
	f.WriteString(full[10:])
	f.WriteString("garbage\n")
	f.WriteString(line(t, testAlert(4)))
	got := c.waitFor(t, 4)
	cancel()
	st := <-res
	if !reflect.DeepEqual(got, []int{1, 2, 3, 4}) {
		t.Errorf("got %v, want [1 2 3 4]", got)
	}
	if st.Invalid != 1 {
		t.Errorf("invalid %d, want 1 (the garbage line only)", st.Invalid)
	}
}

// TestFollowSurvivesRotation follows a log while a Writer with a tiny
// MaxSize rotates it many times, including several times between polls.
func TestFollowSurvivesRotation(t *testing.T) {
	for _, poll := range []time.Duration{time.Millisecond, 30 * time.Millisecond} {
		t.Run(poll.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "log.jsonl")
			size := int64(len(line(t, testAlert(100))))
			w, err := NewWriter(WriterConfig{Path: path, MaxSize: 2 * size, MaxFiles: 20})
			if err != nil {
				t.Fatal(err)
			}
			for i := 100; i < 105; i++ {
				w.WriteAlert(testAlert(i))
			}
			// Let the history land on disk first.
			for w.Stats().Written < 5 {
				time.Sleep(time.Millisecond)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var c collector
			go Follow(ctx, path, Filter{}, c.add, poll)
			for i := 105; i < 160; i++ {
				w.WriteAlert(testAlert(i))
				if i%7 == 0 {
					time.Sleep(3 * time.Millisecond)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			got := c.waitFor(t, 60)
			if want := seq(100, 159); !reflect.DeepEqual(got, want) {
				t.Errorf("got %v\nwant %v", got, want)
			}
			if w.Stats().Rotations < 20 {
				t.Errorf("only %d rotations", w.Stats().Rotations)
			}
		})
	}
}

func TestFollowWaitsForFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var c collector
	go Follow(ctx, path, Filter{}, c.add, 5*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	writeFile(t, path, line(t, testAlert(1)))
	if got := c.waitFor(t, 1); !reflect.DeepEqual(got, []int{1}) {
		t.Errorf("got %v", got)
	}
}
