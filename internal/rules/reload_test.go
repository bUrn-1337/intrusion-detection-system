package rules

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeRules(tb testing.TB, path, text string) {
	tb.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		tb.Fatal(err)
	}
}

const (
	reloadA = `alert udp any any -> any 53 (msg:"dns"; sid:1;)
alert udp any any -> any any (msg:"burst"; detection_filter:track by_src, count 3, seconds 10; sid:2;)
`
	reloadB = `alert udp any any -> any 123 (msg:"ntp"; sid:3;)
alert udp any any -> any any (msg:"burst"; detection_filter:track by_src, count 3, seconds 10; sid:2;)
`
)

func TestReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.conf")
	writeRules(t, path, reloadA)
	rs, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(rs, EngineConfig{})
	src := func(n int) string { return "10.0.0." + string(rune('0'+n)) }
	dns := func(n int) pkt { return pkt{proto: "udp", src: src(n), dst: "10.9.9.9", sport: 5000, dport: 53} }
	ntp := func(n int) pkt { return pkt{proto: "udp", src: src(n), dst: "10.9.9.9", sport: 5000, dport: 123} }
	sids := func(as []Alert) []int {
		var out []int
		for _, a := range as {
			out = append(out, a.SID)
		}
		return out
	}

	// Two packets from source 1: sid 1 fires, sid 2 has counted 2 of 3.
	if got := sids(e.Process(dns(1).parsed(t, t0))); len(got) != 1 || got[0] != 1 {
		t.Fatalf("before reload: %v", got)
	}
	e.Process(dns(1).parsed(t, at(time.Second)))

	// A valid reload: sid 1 is gone, sid 3 is new, sid 2 is unchanged and
	// keeps its count, so the third packet from source 1 fires it.
	writeRules(t, path, reloadB)
	if err := e.Reload(path); err != nil {
		t.Fatal(err)
	}
	if s := e.Stats(); s.Rules != 2 || s.Reloads != 1 {
		t.Errorf("stats %+v", s)
	}
	if got := sids(e.Process(ntp(1).parsed(t, at(2*time.Second)))); len(got) != 2 || got[0] != 3 || got[1] != 2 {
		t.Fatalf("after reload: %v", got)
	}
	if got := sids(e.Process(dns(2).parsed(t, at(3*time.Second)))); len(got) != 0 {
		t.Fatalf("removed rule still fires: %v", got)
	}

	// A reload with errors keeps the old rules.
	writeRules(t, path, reloadA+"alert udp any any -> any any (msg:\"typo\"; sid:4; severty:high;)\n")
	err = e.Reload(path)
	var le *LoadError
	if !errors.As(err, &le) || len(le.Errors) != 1 {
		t.Fatalf("Reload error = %v", err)
	}
	if s := e.Stats(); s.Rules != 2 || s.Reloads != 1 || s.ReloadFails != 1 {
		t.Errorf("stats %+v", s)
	}
	if got := sids(e.Process(ntp(3).parsed(t, at(4*time.Second)))); len(got) != 1 || got[0] != 3 {
		t.Fatalf("after failed reload: %v", got)
	}
	if err := e.Reload(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file reloaded")
	}

	// Changing a stateful rule resets its state: the new sid 2 needs
	// three fresh packets.
	writeRules(t, path, `alert udp any any -> any any (msg:"burst"; detection_filter:track by_src, count 3, seconds 20; sid:2;)`)
	if err := e.Reload(path); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if got := e.Process(ntp(4).parsed(t, at(time.Duration(5+i)*time.Second))); len(got) != 0 {
			t.Fatalf("changed rule kept old state: %s", alertLines(got))
		}
	}
	if got := sids(e.Process(ntp(4).parsed(t, at(7*time.Second)))); len(got) != 1 || got[0] != 2 {
		t.Fatalf("changed rule: %v", got)
	}
	if s := e.Stats(); s.Tables[TableDetectionFilter].Keys != 1 {
		t.Errorf("old rule's keys not released: %+v", s.Tables)
	}
}

// TestReloadConcurrent reloads and reads stats from other goroutines while
// packets are processed. Run with -race.
func TestReloadConcurrent(t *testing.T) {
	dir := t.TempDir()
	good1, good2, bad := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")
	writeRules(t, good1, reloadA+`alert tcp any any -> any any (msg:"f"; detect:syn_flood; track:by_dst; count:50; seconds:5; sid:10;)
alert tcp any any -> any any (msg:"f"; detect:syn_flood; track:by_src; count:50; seconds:5; sid:11;)
`)
	writeRules(t, good2, reloadB)
	writeRules(t, bad, "alert udp nonsense\n")
	rs, err := Load(good1)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(rs, EngineConfig{})

	var frames []frame
	for i := range 200 {
		ts := at(time.Duration(i) * time.Millisecond)
		frames = append(frames, flow(t, spoofed(i), uint16(10000+i), ts, "synack")...)
		frames = append(frames, frame{ts, pkt{proto: "udp", src: spoofed(i), dst: "10.9.9.9", sport: 5000, dport: 53}.bytes(t)})
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var reloadErrs, badErrs int
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			switch i % 3 {
			case 0:
				if e.Reload(good2) != nil {
					reloadErrs++
				}
			case 1:
				if e.Reload(bad) == nil {
					badErrs++
				}
			case 2:
				if e.Reload(good1) != nil {
					reloadErrs++
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			s := e.Stats()
			if s.Rules != 2 && s.Rules != 4 {
				t.Errorf("Rules = %d", s.Rules)
				return
			}
		}
	}()
	for range 20 {
		for _, f := range frames {
			e.Process(parseFrame(f.b, f.ts))
		}
	}
	e.Flush()
	close(stop)
	wg.Wait()
	if reloadErrs != 0 || badErrs != 0 {
		t.Errorf("valid reloads failed %d times, invalid ones succeeded %d times", reloadErrs, badErrs)
	}
	s := e.Stats()
	if s.Reloads == 0 || s.ReloadFails == 0 || s.Packets != uint64(20*len(frames)) {
		t.Errorf("stats %+v", s)
	}
}
