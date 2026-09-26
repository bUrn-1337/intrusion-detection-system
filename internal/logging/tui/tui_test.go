package tui

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/bUrn-1337/intrusion-detection-system/internal/logging"
	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

var t0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func newScreen(t *testing.T) tcell.SimulationScreen {
	t.Helper()
	s := tcell.NewSimulationScreen("UTF-8")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(160, 50)
	return s
}

// screenText returns the screen as lines of text.
func screenText(s tcell.SimulationScreen) []string {
	cells, w, h := s.GetContents()
	lines := make([]string, h)
	for y := 0; y < h; y++ {
		var b strings.Builder
		for x := 0; x < w; x++ {
			c := cells[y*w+x]
			if len(c.Runes) == 0 {
				b.WriteByte(' ')
			} else {
				b.WriteString(string(c.Runes))
			}
		}
		lines[y] = b.String()
	}
	return lines
}

// find returns the position of the first occurrence of sub on screen.
func find(s tcell.SimulationScreen, sub string) (x, y int, ok bool) {
	return findIn(screenText(s), sub)
}

func findIn(lines []string, sub string) (x, y int, ok bool) {
	for y, l := range lines {
		if i := strings.Index(l, sub); i >= 0 {
			return len([]rune(l[:i])), y, true
		}
	}
	return 0, 0, false
}

// col returns the screen column of sub in line, searching the 40 cells
// from column x (the first or, with last, the last occurrence).
func col(line string, x int, sub string, last bool) int {
	r := []rune(line)
	seg := string(r[x:min(x+40, len(r))])
	i := strings.Index(seg, sub)
	if last {
		i = strings.LastIndex(seg, sub)
	}
	if i < 0 {
		return -1
	}
	return x + len([]rune(seg[:i]))
}

func fgAt(s tcell.SimulationScreen, x, y int) tcell.Color {
	cells, w, _ := s.GetContents()
	fg, _, _ := cells[y*w+x].Style.Decompose()
	return fg
}

func fixedModel() *Model {
	return &Model{
		Now: t0.Add(83 * time.Second),
		Header: Header{Source: "interface lo", Started: t0, Rules: 8,
			Reload: "FAILED, kept 8 rules: rules.conf:58: bad option", ReloadOK: false, ReloadAt: t0.Add(80 * time.Second)},
		Health: Health{Captured: 123456, KernelDropped: 0, QueueDropped: 42, QueueDepth: 7, LogDropped: 0},
		Snap: logging.Snapshot{
			Packets: 123000, Bytes: 45 << 20, PPS: 1500, BPS: 2 << 20, AvgPPS: 750, AvgBPS: 1 << 20, Alerts: 3,
			ByL4:       []logging.Count{{Name: "TCP", Packets: 100000}, {Name: "UDP", Packets: 23000}},
			ByApp:      []logging.Count{{Name: "NONE", Packets: 90000}, {Name: "HTTP", Packets: 33000}},
			TopPackets: []logging.Talker{{IP: "10.0.0.66", Packets: 9000, Bytes: 540000}, {IP: "10.0.0.7", Packets: 12}},
			TopBytes:   []logging.Talker{{IP: "10.0.0.99", Packets: 10, Bytes: 3 << 20}},
			TopAlerts:  []logging.Talker{{IP: "203.0.113.5", Alerts: 301}},
		},
		Feed: []rules.Alert{
			{Time: t0.Add(81 * time.Second), SID: 1000001, Msg: "SYN flood against one destination", Severity: "high",
				SrcIP: "203.0.113.5", DstIP: "127.0.0.1", SrcPort: 4000, DstPort: 9, Count: 1, Kind: rules.KindAlert},
			{Time: t0.Add(82 * time.Second), SID: 1000102, Msg: "Malformed DNS [red]message", Severity: "low",
				SrcIP: "10.0.0.7", DstIP: "10.0.0.53", SrcPort: 5353, DstPort: 53, Count: 4, Kind: rules.KindSummary},
		},
	}
}

func TestRenderPanels(t *testing.T) {
	s := newScreen(t)
	defer s.Fini()
	Draw(s, fixedModel())
	text := strings.Join(screenText(s), "\n")
	for _, want := range []string{
		// Header.
		"interface lo", "00:01:23", "Rules loaded: 8", "FAILED, kept 8 rules: rules.conf:58",
		"q quit", "p pause", "r reload",
		// Traffic.
		"Traffic", "1.50k", "750", "2.00 MiB", "1.00 MiB", "123000", "45.00 MiB",
		// Health.
		"Capture health", "123456", "Kernel drops", "Queue drops", "Queue depth", "Log records drop",
		// Protocols.
		"TCP", "100000", "81.3%", "UDP", "HTTP", "NONE",
		// Talkers and alerting sources.
		"10.0.0.66", "9000", "10.0.0.99", "3.00 MiB", "203.0.113.5", "301",
		// Alert feed; the message's tag-like text is shown, not applied.
		"SYN flood against one destination", "203.0.113.5:4000 -> 127.0.0.1:9", "(summary)",
		`"Malformed DNS [red]message"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("screen lacks %q", want)
		}
	}
	if t.Failed() {
		t.Log("\n" + text)
	}

	// Drop counters: non-zero red, zero green.
	x, y, ok := find(s, "Queue drops")
	if !ok {
		t.Fatal("no Queue drops row")
	}
	nx := col(screenText(s)[y], x, "42", false)
	if fg := fgAt(s, nx, y); fg != tcell.ColorRed {
		t.Errorf("queue drop count color %v, want red", fg)
	}
	x, y, _ = find(s, "Kernel drops")
	zx := col(screenText(s)[y], x, "0", true)
	if fg := fgAt(s, zx, y); fg != tcell.ColorGreen {
		t.Errorf("zero kernel drop color %v, want green", fg)
	}
	// Failed reload in red, severities colored.
	if x, y, _ := find(s, "FAILED"); fgAt(s, x, y) != tcell.ColorRed {
		t.Errorf("failed reload not red")
	}
	if x, y, _ := find(s, "SYN flood against"); fgAt(s, x, y) != tcell.ColorRed {
		t.Errorf("high alert not red: %v", fgAt(s, x, y))
	}
	if x, y, _ := find(s, "Malformed DNS"); fgAt(s, x, y) != tcell.ColorAqua {
		t.Errorf("low alert not aqua: %v", fgAt(s, x, y))
	}

	// No drops at all: nothing red in the health panel.
	m := fixedModel()
	m.Health.QueueDropped = 0
	Draw(s, m)
	x, y, _ = find(s, "Queue drops")
	zx = col(screenText(s)[y], x, "0", true)
	if fg := fgAt(s, zx, y); fg != tcell.ColorGreen {
		t.Errorf("zero queue drop color %v, want green", fg)
	}
}

// fakeSources serves a snapshot the test can change.
type fakeSources struct {
	mu      sync.Mutex
	snap    logging.Snapshot
	reloads int
}

func (f *fakeSources) sources() Sources {
	return Sources{
		Snapshot: func() logging.Snapshot { f.mu.Lock(); defer f.mu.Unlock(); return f.snap },
		Header:   func() Header { return Header{Source: "file x.pcap", Started: t0, Rules: 8} },
		Health:   func() Health { return Health{Captured: 10} },
		Reload:   func() { f.mu.Lock(); f.reloads++; f.mu.Unlock() },
	}
}

// liveText reads a running dashboard's screen on its event loop, so the
// read does not race with drawing.
func liveText(d *Dashboard, s tcell.SimulationScreen) []string {
	var out []string
	d.app.QueueUpdate(func() { out = screenText(s) })
	return out
}

func waitScreen(t *testing.T, d *Dashboard, s tcell.SimulationScreen, what string, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, ok := findIn(liveText(d, s), what); ok == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("screen: %q present=%v, want %v\n%s", what, !want, want, strings.Join(liveText(d, s), "\n"))
}

// startDashboard runs d on a 160x50 simulation screen.
func startDashboard(t *testing.T, d *Dashboard) (tcell.SimulationScreen, chan error) {
	t.Helper()
	s := tcell.NewSimulationScreen("UTF-8")
	d.app.SetScreen(s) // initializes the screen
	s.SetSize(160, 50)
	done := make(chan error, 1)
	go func() { done <- d.Run(nil) }()
	return s, done
}

func alert(sid int, msg string) rules.Alert {
	return rules.Alert{Time: t0, SID: sid, Msg: msg, Severity: "medium", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Kind: rules.KindAlert, Count: 1}
}

func TestDashboardKeys(t *testing.T) {
	fs := &fakeSources{}
	d := New(fs.sources(), 0)
	d.refresh = 10 * time.Millisecond
	s, done := startDashboard(t, d)

	d.SendAlert(alert(1, "first alert"))
	waitScreen(t, d, s, "first alert", true)

	// p pauses: new alerts stay off the feed.
	s.InjectKey(tcell.KeyRune, 'p', tcell.ModNone)
	waitScreen(t, d, s, "PAUSED", true)
	d.SendAlert(alert(2, "second alert"))
	time.Sleep(100 * time.Millisecond) // several refreshes
	waitScreen(t, d, s, "second alert", false)
	if len(d.feedCh) != 0 {
		t.Errorf("feed channel not drained while paused: %d queued", len(d.feedCh))
	}

	// p again resumes, refilling the feed from the recent alerts ring.
	fs.mu.Lock()
	fs.snap.RecentAlerts = []rules.Alert{alert(1, "first alert"), alert(2, "second alert")}
	fs.mu.Unlock()
	s.InjectKey(tcell.KeyRune, 'p', tcell.ModNone)
	waitScreen(t, d, s, "PAUSED", false)
	waitScreen(t, d, s, "second alert", true)

	// r asks for a reload.
	s.InjectKey(tcell.KeyRune, 'r', tcell.ModNone)
	deadline := time.Now().Add(5 * time.Second)
	for {
		fs.mu.Lock()
		n := fs.reloads
		fs.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reloads %d, want 1", n)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// q quits.
	s.InjectKey(tcell.KeyRune, 'q', tcell.ModNone)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("q did not stop the dashboard")
	}
}

// TestSendAlertNeverBlocks fills the feed channel of a dashboard that is
// not running (nothing drains it) and checks senders are not blocked.
func TestSendAlertNeverBlocks(t *testing.T) {
	d := New(Sources{}, 8)
	done := make(chan int)
	go func() {
		ok := 0
		for i := 0; i < 10000; i++ {
			if d.SendAlert(alert(i, "x")) {
				ok++
			}
		}
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok != 8 || d.FeedDropped() != 10000-8 {
			t.Errorf("accepted %d dropped %d, want 8 and %d", ok, d.FeedDropped(), 10000-8)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendAlert blocked on a full channel")
	}
}

func TestStopFromOtherGoroutine(t *testing.T) {
	d := New(Sources{}, 0)
	d.refresh = 5 * time.Millisecond
	_, done := startDashboard(t, d)
	time.Sleep(50 * time.Millisecond)
	d.Stop()
	d.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not end Run")
	}
}
