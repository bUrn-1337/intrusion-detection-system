package logging

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

var t0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func testAlert(sid int) rules.Alert {
	return rules.Alert{
		Time: t0.Add(time.Duration(sid) * time.Second), FirstSeen: t0, LastSeen: t0,
		SID: sid, Rev: 1, Msg: "test alert", Severity: rules.SeverityHigh, Category: "dos", Proto: "TCP",
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 80, Count: 1, Kind: rules.KindAlert,
		Details: map[string]string{"k": "v"},
	}
}

// readLines returns the lines of a file.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func sidOf(t *testing.T, line string) int {
	t.Helper()
	var r struct {
		Type string `json:"type"`
		SID  int    `json:"sid"`
	}
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatalf("bad line %q: %v", line, err)
	}
	return r.SID
}

func TestWriterOrderAndFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	w, err := NewWriter(WriterConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 1000; i++ {
		if !w.WriteAlert(testAlert(i)) {
			t.Fatalf("record %d dropped", i)
		}
	}
	w.WriteStats(StatsRecord{Time: t0, Reason: StatsShutdown})
	w.WriteEvent(EventRecord{Time: t0, Event: EventReload, OK: true, Rules: 3})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, path)
	if len(lines) != 1002 {
		t.Fatalf("got %d lines, want 1002", len(lines))
	}
	for i := 0; i < 1000; i++ {
		if got := sidOf(t, lines[i]); got != i+1 {
			t.Fatalf("line %d has sid %d, want %d", i, got, i+1)
		}
	}

	// An alert record is the rules.Alert JSON plus "type" and nothing else.
	var got, want map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(testAlert(1))
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	want["type"] = "alert"
	if !reflect.DeepEqual(got, want) {
		t.Errorf("alert record\n got %v\nwant %v", got, want)
	}
	for i, typ := range map[int]string{1000: "stats", 1001: "event"} {
		var r map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &r); err != nil {
			t.Fatal(err)
		}
		if r["type"] != typ {
			t.Errorf("line %d type %v, want %s", i, r["type"], typ)
		}
	}
	if s := w.Stats(); s.Written != 1002 || s.Dropped != 0 || s.Errors != 0 {
		t.Errorf("stats %+v", s)
	}
}

func TestWriterPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.jsonl")
	w, err := NewWriter(WriterConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	w.WriteAlert(testAlert(1))
	w.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("new file mode %v, want 0600", fi.Mode().Perm())
	}

	// An existing, more open file is narrowed and appended to.
	old := filepath.Join(dir, "old.jsonl")
	if err := os.WriteFile(old, []byte("{\"type\":\"alert\",\"sid\":7}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chmod(old, 0o644)
	w, err = NewWriter(WriterConfig{Path: old})
	if err != nil {
		t.Fatal(err)
	}
	w.WriteAlert(testAlert(8))
	w.Close()
	if fi, _ := os.Stat(old); fi.Mode().Perm() != 0o600 {
		t.Errorf("existing file mode %v, want 0600", fi.Mode().Perm())
	}
	lines := readLines(t, old)
	if len(lines) != 2 || sidOf(t, lines[0]) != 7 || sidOf(t, lines[1]) != 8 {
		t.Errorf("appended file: %q", lines)
	}
}

func TestWriterRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	line, _ := json.Marshal(alertRecord{Type: TypeAlert, Alert: testAlert(100)})
	size := int64(len(line) + 1)
	// Three records fit per file.
	w, err := NewWriter(WriterConfig{Path: path, MaxSize: 3*size + size/2, MaxFiles: 3})
	if err != nil {
		t.Fatal(err)
	}
	const n = 20 // sids 100..119 all have the same length
	for i := 0; i < n; i++ {
		w.WriteAlert(testAlert(100 + i))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(RotatedName(path, 4)); err == nil {
		t.Errorf("%s exists, want at most 3 rotated files", RotatedName(path, 4))
	}
	files := []string{RotatedName(path, 3), RotatedName(path, 2), RotatedName(path, 1), path}
	var sids []int
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() > 3*size+size/2 {
			t.Errorf("%s is %d bytes, over MaxSize", f, fi.Size())
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
		for _, l := range readLines(t, f) {
			sids = append(sids, sidOf(t, l))
		}
	}
	// 20 records in files of 3: 7 files, the oldest 3 discarded; what is
	// left, oldest file first, is the last 11 records in order.
	var want []int
	for s := 100 + n - 11; s < 100+n; s++ {
		want = append(want, s)
	}
	if !reflect.DeepEqual(sids, want) {
		t.Errorf("records across files %v, want %v", sids, want)
	}
	if got := w.Stats().Rotations; got != 6 {
		t.Errorf("rotations %d, want 6", got)
	}
}

// TestWriterCloseLosesNothing checks that every accepted record is in the
// file after Close, with senders racing Close.
func TestWriterCloseLosesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	w, err := NewWriter(WriterConfig{Path: path, Buffer: 64})
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu       sync.Mutex
		accepted = map[int]bool{}
		wg       sync.WaitGroup
	)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				sid := g*100000 + i
				if w.WriteAlert(testAlert(sid)) {
					mu.Lock()
					accepted[sid] = true
					mu.Unlock()
				}
			}
		}(g)
	}
	time.Sleep(time.Millisecond)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	lines := readLines(t, path)
	if len(lines) != len(accepted) {
		t.Fatalf("%d lines in file, %d records accepted", len(lines), len(accepted))
	}
	for _, l := range lines {
		if !accepted[sidOf(t, l)] {
			t.Fatalf("record %d written but not accepted", sidOf(t, l))
		}
	}
	s := w.Stats()
	if s.Written != uint64(len(accepted)) || s.Written+s.Dropped != 16000 {
		t.Errorf("stats %+v, accepted %d", s, len(accepted))
	}
	if w.WriteAlert(testAlert(1)) {
		t.Error("record accepted after Close")
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestWriterDropsWhenFull stalls the writer goroutine and checks that
// senders are never blocked: records beyond the buffer are dropped and
// counted.
func TestWriterDropsWhenFull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	release := make(chan struct{})
	stalled := make(chan struct{}, 1)
	w, err := newWriter(WriterConfig{Path: path, Buffer: 4}, func() {
		select {
		case stalled <- struct{}{}:
		default:
		}
		<-release
	})
	if err != nil {
		t.Fatal(err)
	}
	w.WriteAlert(testAlert(0)) // taken by the writer, which then stalls
	<-stalled

	done := make(chan int)
	go func() {
		ok := 0
		for i := 1; i <= 104; i++ {
			if w.WriteAlert(testAlert(i)) {
				ok++
			}
		}
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok != 4 {
			t.Errorf("%d records accepted while stalled, want 4 (the buffer)", ok)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("WriteAlert blocked on a full buffer")
	}
	if got := w.Stats().Dropped; got != 100 {
		t.Errorf("dropped %d, want 100", got)
	}
	close(release)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, path)
	if len(lines) != 5 {
		t.Fatalf("%d lines, want 5", len(lines))
	}
	for i, l := range lines {
		if sidOf(t, l) != i {
			t.Errorf("line %d: sid %d", i, sidOf(t, l))
		}
	}
}

func TestWriterConcurrentSenders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	w, err := NewWriter(WriterConfig{Path: path, MaxSize: 64 << 10, MaxFiles: 50})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				switch i % 3 {
				case 0:
					w.WriteAlert(testAlert(g*1000 + i))
				case 1:
					w.WriteStats(StatsRecord{Time: t0, Reason: StatsPeriodic})
				default:
					w.WriteEvent(EventRecord{Time: t0, Event: EventReload})
				}
				_ = w.Stats()
			}
		}(g)
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	s := w.Stats()
	if s.Written+s.Dropped != 8000 || s.Errors != 0 {
		t.Errorf("stats %+v", s)
	}
	total := 0
	for _, f := range LogFiles(path) {
		total += len(readLines(t, f))
	}
	if uint64(total) != s.Written {
		t.Errorf("%d lines on disk, %d written", total, s.Written)
	}
}
