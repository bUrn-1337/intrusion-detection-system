package main

// Hostile and unusual pcap files, run through "ids run -r" end to end.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/bUrn-1337/intrusion-detection-system/internal/testutil/pcapgen"
)

type edgeResult struct {
	code           int
	stdout, stderr string
	alerts         []gotAlert
	captured       uint64 // from the final stats record
	stats          bool   // a final stats record was written
}

func runEdge(t *testing.T, pcap string, extra ...string) edgeResult {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "ids.jsonl")
	args := append([]string{"run", "-r", pcap, "-rules", rulesPath(t), "-log", logPath, "-no-tui"}, extra...)
	var r edgeResult
	r.code, r.stdout, r.stderr = runIDSTest(t, args...)
	if _, err := os.Stat(logPath); err != nil {
		return r
	}
	for _, rec := range readLogLenient(t, logPath) {
		switch rec.Type {
		case "alert":
			var g gotAlert
			json.Unmarshal(rec.Raw, &g)
			r.alerts = append(r.alerts, g)
		case "stats":
			var st struct{ Capture struct{ Captured uint64 } }
			json.Unmarshal(rec.Raw, &st)
			r.captured, r.stats = st.Capture.Captured, rec.Reason == "shutdown"
		}
	}
	return r
}

// readLogLenient is readLog that accepts an empty file.
func readLogLenient(t *testing.T, path string) []logRec {
	if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
		return nil
	}
	return readLog(t, path)
}

func countSID(as []gotAlert, sid int, kind string) int {
	n := 0
	for _, a := range as {
		if a.SID == sid && a.Kind == kind {
			n++
		}
	}
	return n
}

// floodFrames returns the frames of genSYNFloodSingleSource with their
// timestamps.
func floodFrames(t *testing.T) ([][]byte, []time.Time) {
	path := filepath.Join(t.TempDir(), "flood.pcap")
	w := pcapgen.Create(t, path)
	genSYNFloodSingleSource(w)
	w.Close()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	r, err := pcapgo.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	var frames [][]byte
	var ts []time.Time
	for {
		b, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		frames, ts = append(frames, b), append(ts, ci.Timestamp)
	}
	return frames, ts
}

func writeClassic(t *testing.T, path string, nanos bool, snaplen uint32, lt layers.LinkType, frames [][]byte, ts []time.Time) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if nanos {
		w = pcapgo.NewWriterNanos(f)
	}
	if err := w.WriteFileHeader(snaplen, lt); err != nil {
		t.Fatal(err)
	}
	for i, b := range frames {
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts[i], CaptureLength: len(b), Length: len(b)}, b); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPcapEdgeCases(t *testing.T) {
	frames, ts := floodFrames(t)
	dir := t.TempDir()
	full := filepath.Join(dir, "full.pcap")
	writeClassic(t, full, false, 262144, layers.LinkTypeEthernet, frames, ts)

	t.Run("truncated mid-record", func(t *testing.T) {
		b, _ := os.ReadFile(full)
		cut := filepath.Join(dir, "cut.pcap")
		os.WriteFile(cut, b[:len(b)*2/3+7], 0o600) // lands inside a record
		r := runEdge(t, cut)
		// Everything before the cut is inspected, the flood is still
		// detected and the final stats are written; the exit status and
		// message report the damaged file.
		if r.code != 1 || !strings.Contains(r.stderr, "is damaged after") || !strings.Contains(r.stderr, "truncated dump file") || !r.stats {
			t.Fatalf("exit %d stats=%v stderr:\n%s", r.code, r.stats, r.stderr)
		}
		if r.captured == 0 || r.captured >= uint64(len(frames)) {
			t.Errorf("captured %d of %d frames", r.captured, len(frames))
		}
		if countSID(r.alerts, 1000001, "alert") != 1 {
			t.Errorf("flood not detected before the cut: %v", r.alerts)
		}
	})

	t.Run("zero-length file", func(t *testing.T) {
		empty := filepath.Join(dir, "empty.pcap")
		os.WriteFile(empty, nil, 0o600)
		r := runEdge(t, empty)
		if r.code != 1 || !strings.Contains(r.stderr, "opening pcap file") || r.stats {
			t.Fatalf("exit %d stats=%v stderr:\n%s", r.code, r.stats, r.stderr)
		}
	})

	t.Run("header only", func(t *testing.T) {
		hdr := filepath.Join(dir, "hdr.pcap")
		writeClassic(t, hdr, false, 262144, layers.LinkTypeEthernet, nil, nil)
		r := runEdge(t, hdr)
		if r.code != 0 || !r.stats || r.captured != 0 || len(r.alerts) != 0 {
			t.Fatalf("exit %d stats=%v captured=%d stderr:\n%s", r.code, r.stats, r.captured, r.stderr)
		}
	})

	t.Run("pcapng", func(t *testing.T) {
		ng := filepath.Join(dir, "flood.pcapng")
		f, _ := os.Create(ng)
		w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatal(err)
		}
		for i, b := range frames {
			w.WritePacket(gopacket.CaptureInfo{Timestamp: ts[i], CaptureLength: len(b), Length: len(b)}, b)
		}
		w.Flush()
		f.Close()
		r := runEdge(t, ng)
		if r.code != 0 || r.captured != uint64(len(frames)) {
			t.Fatalf("exit %d captured=%d stderr:\n%s", r.code, r.captured, r.stderr)
		}
		if countSID(r.alerts, 1000001, "alert") != 1 || countSID(r.alerts, 1000002, "alert") != 1 {
			t.Errorf("alerts %v", r.alerts)
		}
	})

	t.Run("nanosecond timestamps", func(t *testing.T) {
		ns := filepath.Join(dir, "ns.pcap")
		nts := make([]time.Time, len(ts))
		for i := range ts {
			nts[i] = ts[i].Add(time.Duration(i%1000) * time.Nanosecond)
		}
		writeClassic(t, ns, true, 262144, layers.LinkTypeEthernet, frames, nts)
		logPath := filepath.Join(t.TempDir(), "ids.jsonl")
		code, _, stderr := runIDSTest(t, "run", "-r", ns, "-rules", rulesPath(t), "-log", logPath, "-no-tui")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		// The first flood alert is raised by the 100th refused SYN's RST;
		// its time keeps the nanoseconds.
		var first struct {
			Time time.Time `json:"time"`
		}
		for _, rec := range readLog(t, logPath) {
			if rec.Type == "alert" && rec.SID == 1000001 && rec.Kind == "alert" {
				json.Unmarshal(rec.Raw, &first)
			}
		}
		if first.Time.Nanosecond()%1000 == 0 {
			t.Errorf("alert time %s lost sub-microsecond precision", first.Time.Format(time.RFC3339Nano))
		}
	})

	t.Run("non-Ethernet", func(t *testing.T) {
		raw := filepath.Join(dir, "raw.pcap")
		ipOnly := make([][]byte, len(frames))
		for i, b := range frames {
			ipOnly[i] = b[14:]
		}
		writeClassic(t, raw, false, 262144, layers.LinkTypeRaw, ipOnly, ts)
		r := runEdge(t, raw)
		if r.code != 1 || !strings.Contains(r.stderr, "only Ethernet (EN10MB) captures are supported") || r.stats {
			t.Fatalf("exit %d stats=%v stderr:\n%s", r.code, r.stats, r.stderr)
		}
	})

	t.Run("262144-byte frames", func(t *testing.T) {
		// GRO/LRO can hand the capture a super-frame of up to 64 KiB of
		// TCP payload per IP packet; a 262144-byte record is the most
		// libpcap will accept. Build an HTTP request carrying Basic auth
		// in one such frame, and one that is cut at the snaplen.
		big := pcapgen.Pkt{Proto: "tcp", Src: "10.0.0.7", Dst: "192.0.2.80", Sport: 42000, Dport: 80, Flags: "PA", Seq: 1,
			Payload: []byte("GET /a HTTP/1.1\r\nHost: x\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\n\r\n")}.Bytes(t)
		frame := append(big, make([]byte, 262144-len(big))...) // padding after the IP packet
		p := filepath.Join(dir, "snap.pcap")
		f, _ := os.Create(p)
		w := pcapgo.NewWriter(f)
		w.WriteFileHeader(262144, layers.LinkTypeEthernet)
		w.WritePacket(gopacket.CaptureInfo{Timestamp: pcapgen.T0, CaptureLength: len(frame), Length: len(frame)}, frame)
		w.WritePacket(gopacket.CaptureInfo{Timestamp: pcapgen.T0.Add(time.Millisecond), CaptureLength: len(frame), Length: len(frame) + 5000}, frame)
		f.Close()
		r := runEdge(t, p)
		if r.code != 0 || r.captured != 2 {
			t.Fatalf("exit %d captured=%d stderr:\n%s", r.code, r.captured, r.stderr)
		}
		if countSID(r.alerts, 1000201, "alert") != 1 {
			t.Errorf("alerts %v", r.alerts)
		}
	})

	t.Run("timestamps going backwards", func(t *testing.T) {
		// Every 7th frame is stamped 2s early, and halfway through the
		// clock steps back an hour (as WSL2 does after a host sleep).
		bts := make([]time.Time, len(ts))
		for i := range ts {
			bts[i] = ts[i]
			if i%7 == 0 {
				bts[i] = bts[i].Add(-2 * time.Second)
			}
			if i >= len(ts)/2 {
				bts[i] = bts[i].Add(-time.Hour)
			}
		}
		back := filepath.Join(dir, "back.pcap")
		writeClassic(t, back, false, 262144, layers.LinkTypeEthernet, frames, bts)
		r := runEdge(t, back)
		if r.code != 0 || r.captured != uint64(len(frames)) {
			t.Fatalf("exit %d captured=%d stderr:\n%s", r.code, r.captured, r.stderr)
		}
		// The engine clock never goes backwards, so the flood is still
		// one burst: one alert per rule, no duplicates.
		if countSID(r.alerts, 1000001, "alert") != 1 || countSID(r.alerts, 1000002, "alert") != 1 {
			t.Errorf("alerts %v", r.alerts)
		}
	})

	t.Run("multi-hour gap", func(t *testing.T) {
		// The same flood twice, 3 hours apart: every window and dedup
		// entry expires in between, so each burst alerts on its own.
		var fs [][]byte
		var gts []time.Time
		for _, off := range []time.Duration{0, 3 * time.Hour} {
			for i := range frames {
				fs, gts = append(fs, frames[i]), append(gts, ts[i].Add(off))
			}
		}
		gap := filepath.Join(dir, "gap.pcap")
		writeClassic(t, gap, false, 262144, layers.LinkTypeEthernet, fs, gts)
		r := runEdge(t, gap)
		if r.code != 0 || r.captured != uint64(len(fs)) {
			t.Fatalf("exit %d captured=%d stderr:\n%s", r.code, r.captured, r.stderr)
		}
		for _, sid := range []int{1000001, 1000002} {
			if countSID(r.alerts, sid, "alert") != 2 || countSID(r.alerts, sid, "summary") != 2 {
				t.Errorf("sid %d: alerts %v", sid, r.alerts)
			}
		}
	})
}

// TestSpoofedFloodTableCap floods one server from 120,000 distinct spoofed
// sources, more than the engine's 50,000-key table cap. The tables must
// stay at the cap and count evictions, and the by_dst rule must still
// fire (evicted half-open handshakes count as incomplete). The 1M-source
// version of this, with peak RSS, is described in docs/ARCHITECTURE.md.
func TestSpoofedFloodTableCap(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 120k frames")
	}
	const n = 120_000
	path := filepath.Join(t.TempDir(), "spoofed.pcap")
	w := pcapgen.Create(t, path)
	w.Step = 10 * time.Microsecond
	for i := 0; i < n; i++ {
		src := fmt.Sprintf("198.%d.%d.%d", 18+i>>16, i>>8&0xff, i&0xff)
		w.Add(pcapgen.Pkt{Proto: "tcp", Src: src, Dst: "192.0.2.10", Sport: uint16(1024 + i%60000), Dport: 80, Flags: "S", Seq: uint32(i)})
	}
	w.Close()

	logPath := filepath.Join(t.TempDir(), "ids.jsonl")
	code, _, stderr := runIDSTest(t, "run", "-r", path, "-rules", rulesPath(t), "-log", logPath, "-no-tui")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var byDst, bySrc int
	var st struct {
		Engine struct {
			Evictions uint64
			Tables    map[string]struct {
				Keys      int64
				Evictions uint64
			}
		}
	}
	for _, rec := range readLog(t, logPath) {
		switch {
		case rec.Type == "alert" && rec.SID == 1000001 && rec.Kind == "alert":
			byDst++
		case rec.Type == "alert" && rec.SID == 1000002:
			bySrc++
		case rec.Type == "stats":
			json.Unmarshal(rec.Raw, &st)
		}
	}
	if byDst != 1 || bySrc != 0 {
		t.Errorf("by_dst alerts %d (want 1), by_src alerts %d (want 0)", byDst, bySrc)
	}
	hs, sf, ta := st.Engine.Tables["handshake"], st.Engine.Tables["syn_flood"], st.Engine.Tables["ttl_anomaly"]
	// The handshake table holds at most 50,000 open handshakes, so at
	// least n-50,000 were evicted. syn_flood holds one by_dst key plus at
	// most 50,000 by_src keys. ttl_anomaly tracks every (external) source
	// and holds at most 50,000.
	var sum uint64
	for _, tb := range st.Engine.Tables {
		sum += tb.Evictions
	}
	if hs.Evictions < n-50_000 || sf.Evictions < n-50_000 || sf.Keys > 50_001 || ta.Keys > 50_000 || ta.Evictions < n-50_000 || st.Engine.Evictions != sum {
		t.Errorf("engine stats %+v", st.Engine)
	}
}
