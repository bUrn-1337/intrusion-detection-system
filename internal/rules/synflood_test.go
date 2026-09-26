package rules

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// SYN flood scenarios, replayed from synthetic pcaps through the whole
// pipeline: capture -> lower -> upper -> app -> engine.

const synFloodRules = `
alert tcp any any -> any any (msg:"SYN flood against one destination"; detect:syn_flood; track:by_dst; count:100; seconds:5; min_incomplete_ratio:0.8; sid:1; severity:high; category:dos;)
alert tcp any any -> any any (msg:"SYN flood from one source"; detect:syn_flood; track:by_src; count:100; seconds:5; min_incomplete_ratio:0.8; sid:2; severity:high; category:dos;)
`

const (
	victim   = "192.168.1.10"
	attacker = "203.0.113.7"
)

// flow builds the frames of one connection attempt from client:cport to
// victim:80 starting at ts. kind is "syn" (SYN only), "synack" (SYN,
// SYN-ACK, never finished), "rst" (SYN answered by RST, a closed port) or
// "full" (a completed handshake followed by a request).
func flow(tb testing.TB, client string, cport uint16, ts time.Time, kind string) []frame {
	tb.Helper()
	cseq, sseq := uint32(cport)*1000, uint32(cport)*7000
	c2s := pkt{proto: "tcp", src: client, dst: victim, sport: cport, dport: 80}
	s2c := pkt{proto: "tcp", src: victim, dst: client, sport: 80, dport: cport}
	mk := func(p pkt, flags string, seq, ack uint32, d time.Duration, payload string) frame {
		p.flags, p.seq, p.ack, p.payload = flags, seq, ack, payload
		return frame{ts: ts.Add(d), b: p.bytes(tb)}
	}
	out := []frame{mk(c2s, "S", cseq, 0, 0, "")}
	switch kind {
	case "syn":
	case "synack":
		out = append(out, mk(s2c, "SA", sseq, cseq+1, time.Millisecond/2, ""))
	case "rst":
		out = append(out, mk(s2c, "RA", 0, cseq+1, time.Millisecond/2, ""))
	case "full":
		out = append(out,
			mk(s2c, "SA", sseq, cseq+1, time.Millisecond/4, ""),
			mk(c2s, "A", cseq+1, sseq+1, time.Millisecond/2, ""),
			mk(c2s, "PA", cseq+1, sseq+1, 3*time.Millisecond/4, "GET / HTTP/1.1\r\nHost: v\r\n\r\n"))
	default:
		tb.Fatalf("bad flow kind %q", kind)
	}
	return out
}

// spoofed returns the i-th fake source address.
func spoofed(i int) string {
	return fmt.Sprintf("198.18.%d.%d", i/250, i%250+1)
}

func runScenario(t *testing.T, cfg EngineConfig, frames []frame) ([]Alert, *Engine) {
	t.Helper()
	e := NewEngine(mustParse(t, synFloodRules), cfg)
	return replay(t, writePcap(t, frames), e), e
}

func TestSYNFloodScenarios(t *testing.T) {
	step := 10 * time.Millisecond // 500 attempts over 5s

	t.Run("a: one source floods", func(t *testing.T) {
		var frames []frame
		for i := range 500 {
			kind := "synack" // the victim answers, the attacker never finishes
			if i%2 == 1 {
				kind = "syn" // and some SYNs go unanswered
			}
			frames = append(frames, flow(t, attacker, uint16(10000+i), at(time.Duration(i)*step), kind)...)
		}
		got, e := runScenario(t, EngineConfig{}, frames)
		want := map[string]int{"1/alert": 1, "2/alert": 1, "1/summary": 1, "2/summary": 1}
		if !reflect.DeepEqual(bySID(got), want) {
			t.Fatalf("got %v, want %v:%s", bySID(got), want, alertLines(got))
		}
		// Handshakes time out 3s after their SYN, so the 100th
		// incomplete is the SYN sent at 0.99s, timing out at 3.99s.
		for _, a := range got {
			tracked := victim
			if a.SID == 2 {
				tracked = attacker
			}
			switch a.Kind {
			case KindAlert:
				d := a.Details
				if !a.Time.Equal(at(3990*time.Millisecond)) || a.SrcIP != attacker || a.DstIP != victim || a.DstPort != 80 ||
					d["tracked_addr"] != tracked || d["incomplete"] != "100" || d["completed"] != "0" ||
					d["ratio"] != "1.00" || d["top_dst_port"] != "80" || d["window"] != "990ms" || a.Proto != "TCP" {
					t.Errorf("alert: %s", alertLine(a))
				}
			case KindSummary:
				// 401 firings: the 100th to the 500th incomplete.
				if a.Count != 401 || !a.FirstSeen.Equal(at(3990*time.Millisecond)) || !a.LastSeen.Equal(at(7990*time.Millisecond)) {
					t.Errorf("summary: %s", alertLine(a))
				}
			}
		}
		s := e.Stats()
		if s.Suppressed != 800 || s.Tables[TableHandshake].Keys != 0 || s.Evictions != 0 {
			t.Errorf("stats %+v", s)
		}
	})

	t.Run("b: spoofed sources", func(t *testing.T) {
		var frames []frame
		for i := range 500 {
			frames = append(frames, flow(t, spoofed(i), uint16(10000+i), at(time.Duration(i)*step), "synack")...)
		}
		got, _ := runScenario(t, EngineConfig{}, frames)
		want := map[string]int{"1/alert": 1, "1/summary": 1}
		if !reflect.DeepEqual(bySID(got), want) {
			t.Fatalf("got %v, want %v:%s", bySID(got), want, alertLines(got))
		}
		if d := got[0].Details; d["tracked_addr"] != victim || d["track"] != "by_dst" || d["top_dst_port"] != "80" {
			t.Errorf("details %v", d)
		}
	})

	t.Run("c: completed handshakes", func(t *testing.T) {
		var frames []frame
		for i := range 500 {
			frames = append(frames, flow(t, attacker, uint16(10000+i), at(time.Duration(i)*step), "full")...)
		}
		got, e := runScenario(t, EngineConfig{}, frames)
		if len(got) != 0 {
			t.Fatalf("alerts on normal traffic:%s", alertLines(got))
		}
		if s := e.Stats(); s.Packets != 2000 || s.Tables[TableHandshake].Keys != 0 {
			t.Errorf("stats %+v", s)
		}
	})

	t.Run("d: whitelisted source", func(t *testing.T) {
		var frames []frame
		for i := range 500 {
			frames = append(frames, flow(t, attacker, uint16(10000+i), at(time.Duration(i)*step), "synack")...)
		}
		wl := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
		got, e := runScenario(t, EngineConfig{Whitelist: wl}, frames)
		if len(got) != 0 {
			t.Fatalf("whitelisted source alerted:%s", alertLines(got))
		}
		if s := e.Stats(); s.Whitelisted != 500 {
			t.Errorf("whitelisted %d, want 500 (the SYNs)", s.Whitelisted)
		}
	})

	t.Run("e: determinism", func(t *testing.T) {
		var frames []frame
		for i := range 500 {
			frames = append(frames, flow(t, spoofed(i%50), uint16(10000+i), at(time.Duration(i)*step), []string{"syn", "synack", "rst", "full"}[i%4])...)
			frames = append(frames, flow(t, attacker, uint16(20000+i), at(time.Duration(i)*step+step/2), "rst")...)
		}
		path := writePcap(t, frames)
		first := replay(t, path, NewEngine(mustParse(t, synFloodRules), EngineConfig{}))
		second := replay(t, path, NewEngine(mustParse(t, synFloodRules), EngineConfig{}))
		if len(first) == 0 {
			t.Fatal("no alerts")
		}
		if !reflect.DeepEqual(first, second) {
			t.Errorf("replays differ:%s\nvs%s", alertLines(first), alertLines(second))
		}
	})
}

// TestSYNFloodRatio interleaves refused and completed handshakes from one
// source: with enough completions the source looks like a busy client,
// not a flood.
func TestSYNFloodRatio(t *testing.T) {
	step := 10 * time.Millisecond
	run := func(pattern func(i int) string, n int) []Alert {
		var frames []frame
		for i := range n {
			frames = append(frames, flow(t, attacker, uint16(10000+i), at(time.Duration(i)*step), pattern(i))...)
		}
		got, _ := runScenario(t, EngineConfig{}, frames)
		return got
	}
	// 150 refused + 100 completed, evenly mixed: ratio 0.6 < 0.8.
	busy := run(func(i int) string { return []string{"rst", "rst", "rst", "full", "full"}[i%5] }, 250)
	if len(busy) != 0 {
		t.Errorf("ratio 0.6 alerted:%s", alertLines(busy))
	}
	// 150 refused + 10 completed: the last 100 refusals span at most ~7
	// completions, ratio >= 0.93.
	flood := run(func(i int) string {
		if i%16 == 15 {
			return "full"
		}
		return "rst"
	}, 160)
	if got := bySID(flood); got["1/alert"] != 1 || got["2/alert"] != 1 {
		t.Fatalf("ratio > 0.8 did not alert: %v", got)
	}
	d := flood[0].Details
	if d["incomplete"] != "100" || d["completed"] != "6" || d["ratio"] != "0.94" {
		t.Errorf("details %v", d)
	}
}

// TestSYNFloodChecksums checks that invalid checksums alone never alert:
// 500 completed handshakes whose every TCP checksum is wrong, as seen on
// the sending host with checksum offload.
func TestSYNFloodChecksums(t *testing.T) {
	var frames []frame
	for i := range 500 {
		for _, f := range flow(t, attacker, uint16(10000+i), at(time.Duration(i)*10*time.Millisecond), "full") {
			f.b[14+20+16] ^= 0xff // TCP checksum, after Ethernet and a 20-byte IPv4 header
			frames = append(frames, f)
		}
	}
	if p := parseFrame(frames[0].b, t0); p.L4ChecksumStatus != packet.L4ChecksumInvalid {
		t.Fatalf("checksum status %d, test frames not corrupted", p.L4ChecksumStatus)
	}
	rs := mustParse(t, synFloodRules)
	def, err := Load("../../rules.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, rs := range []*RuleSet{rs, def} {
		if got := replay(t, writePcap(t, frames), NewEngine(rs, EngineConfig{})); len(got) != 0 {
			t.Errorf("bad checksums alerted:%s", alertLines(got))
		}
	}
}

// TestSYNFloodRuleScope checks that a detector counts only handshakes its
// addresses and ports match, and that pass rules exclude handshakes.
func TestSYNFloodRuleScope(t *testing.T) {
	var frames []frame
	for i := range 200 {
		frames = append(frames, flow(t, attacker, uint16(10000+i), at(time.Duration(i)*10*time.Millisecond), "rst")...)
	}
	path := writePcap(t, frames)
	tests := []struct {
		name  string
		rules string
		want  int
	}{
		{"port matches", `alert tcp any any -> any 80 (msg:"f"; detect:syn_flood; track:by_src; count:100; seconds:5; sid:1;)`, 1},
		{"other port", `alert tcp any any -> any 443 (msg:"f"; detect:syn_flood; track:by_src; count:100; seconds:5; sid:1;)`, 0},
		{"other source net", `alert tcp 10.0.0.0/8 any -> any any (msg:"f"; detect:syn_flood; track:by_src; count:100; seconds:5; sid:1;)`, 0},
		{"reverse direction does not match", `alert tcp any 80 -> any any (msg:"f"; detect:syn_flood; track:by_src; count:100; seconds:5; sid:1;)`, 0},
		{"bidirectional matches", `alert tcp any 80 <> any any (msg:"f"; detect:syn_flood; track:by_src; count:100; seconds:5; sid:1;)`, 1},
		{"pass rule for the source", `pass tcp 203.0.113.7 any -> any any (msg:"p"; sid:2;)
alert tcp any any -> any any (msg:"f"; detect:syn_flood; track:by_src; count:100; seconds:5; sid:1;)`, 0},
		{"pass rule for data only", `pass tcp any any -> any any (msg:"p"; flags:PA; sid:2;)
alert tcp any any -> any any (msg:"f"; detect:syn_flood; track:by_src; count:100; seconds:5; sid:1;)`, 1},
		{"count not reached", `alert tcp any any -> any any (msg:"f"; detect:syn_flood; track:by_src; count:201; seconds:5; sid:1;)`, 0},
		{"too slow", `alert tcp any any -> any any (msg:"f"; detect:syn_flood; track:by_src; count:150; seconds:1; sid:1;)`, 0},
		{"fast enough", `alert tcp any any -> any any (msg:"f"; detect:syn_flood; track:by_src; count:100; seconds:1; sid:1;)`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := replay(t, path, NewEngine(mustParse(t, tt.rules), EngineConfig{}))
			if n := bySID(got)["1/alert"]; n != tt.want {
				t.Errorf("alerts %d, want %d:%s", n, tt.want, alertLines(got))
			}
		})
	}
}

// TestSYNFloodRatioBoundary checks the ratio test at exactly
// min_incomplete_ratio, and that completions before the oldest counted
// incomplete do not count.
func TestSYNFloodRatioBoundary(t *testing.T) {
	rs := mustParse(t, `alert tcp any any -> any any (msg:"f"; detect:syn_flood; track:by_dst; count:4; seconds:5; min_incomplete_ratio:0.8; sid:1;)`)
	run := func(outcomes string) (fired bool, details map[string]string) {
		var st tableStat
		d := newSYNFlood(rs.Rules()[0], 100, &st)
		for i, c := range outcomes {
			ev := hsEvent{key: hsKey{client: addrA, server: addrB, cport: uint16(i), sport: 80}, t: at(time.Duration(i) * time.Millisecond), complete: c == 'c'}
			if _, mk, ok := d.observe(ev); ok {
				return true, mk()
			}
		}
		return false, nil
	}
	tests := []struct {
		outcomes string
		fired    bool
		ratio    string
	}{
		{"iiii", true, "1.00"},
		{"icii", false, ""},         // only 3 incomplete
		{"iciii", true, "0.80"},     // 4 / (4+1)
		{"icciii", false, ""},       // 4 / (4+2)
		{"ccccciiii", true, "1.00"}, // completions before the window
		{"icciiii", true, "1.00"},   // the window slides past both completions
	}
	for _, tt := range tests {
		fired, d := run(tt.outcomes)
		if fired != tt.fired || (fired && d["ratio"] != tt.ratio) {
			t.Errorf("%s: fired %v details %v, want %v ratio %s", tt.outcomes, fired, d, tt.fired, tt.ratio)
		}
	}
}
