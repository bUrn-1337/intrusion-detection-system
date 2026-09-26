package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var t0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// tcpFrame builds an Ethernet/IPv4/TCP frame.
func tcpFrame(t testing.TB, src, dst string, sport, dport uint16, syn, ack, rst bool) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), Seq: 1000, SYN: syn, ACK: ack, RST: rst, Window: 64240}
	if ack {
		tcp.Ack = 1001
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func udpFrame(t testing.TB, src, dst string, sport, dport uint16, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// synFloodPcap writes n SYNs from 203.0.113.5 to a closed port on
// 192.0.2.10, each answered with RST/ACK, 5ms apart, with some normal UDP
// traffic mixed in.
func synFloodPcap(t testing.TB, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "flood.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	write := func(ts time.Time, b []byte) {
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(b), Length: len(b)}, b); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		ts := t0.Add(time.Duration(i) * 5 * time.Millisecond)
		sport := uint16(40000 + i)
		write(ts, tcpFrame(t, "203.0.113.5", "192.0.2.10", sport, 9, true, false, false))
		write(ts.Add(100*time.Microsecond), tcpFrame(t, "192.0.2.10", "203.0.113.5", 9, sport, false, true, true))
		if i%20 == 0 {
			write(ts.Add(200*time.Microsecond), udpFrame(t, "10.0.0.1", "10.0.0.2", 5000, 6000, []byte("hello")))
		}
	}
	return path
}

func runIDSTest(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(context.Background(), args, &o, &e)
	return code, o.String(), e.String()
}

type logRec struct {
	Type   string          `json:"type"`
	SID    int             `json:"sid"`
	Kind   string          `json:"kind"`
	Count  int             `json:"count"`
	Reason string          `json:"reason"`
	Raw    json.RawMessage `json:"-"`
}

func readLog(t *testing.T, path string) []logRec {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []logRec
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		var r logRec
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("bad log line %q: %v", l, err)
		}
		r.Raw = json.RawMessage(l)
		out = append(out, r)
	}
	return out
}

func rulesPath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../rules.conf")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPipelineSYNFlood(t *testing.T) {
	pcap := synFloodPcap(t, 300)
	var runs [][]string
	for i := 0; i < 2; i++ {
		logPath := filepath.Join(t.TempDir(), "ids.jsonl")
		code, stdout, stderr := runIDSTest(t, "run", "-r", pcap, "-rules", rulesPath(t), "-log", logPath, "-no-tui")
		if code != 0 {
			t.Fatalf("exit %d\nstderr: %s", code, stderr)
		}
		recs := readLog(t, logPath)

		var alerts []string
		var alertSIDs, summarySIDs []int
		for _, r := range recs {
			if r.Type == "alert" {
				alerts = append(alerts, string(r.Raw))
				if r.Kind == "alert" {
					alertSIDs = append(alertSIDs, r.SID)
				} else {
					summarySIDs = append(summarySIDs, r.SID)
					if r.Count < 100 {
						t.Errorf("summary count %d", r.Count)
					}
				}
			}
		}
		if !reflect.DeepEqual(alertSIDs, []int{1000001, 1000002}) {
			t.Errorf("alerts %v, want [1000001 1000002]", alertSIDs)
		}
		if len(summarySIDs) != 2 {
			t.Errorf("summaries %v, want one per flood rule", summarySIDs)
		}

		// Every alert went to stdout in the capturedump format.
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		if len(lines) != len(alerts) {
			t.Errorf("%d stdout lines, %d alert records:\n%s", len(lines), len(alerts), stdout)
		}
		for _, l := range lines {
			if !strings.HasPrefix(l, "ALERT [high] sid=100000") && !strings.HasPrefix(l, "SUMMARY [high] sid=100000") {
				t.Errorf("stdout line %q", l)
			}
		}

		// The last record is the final stats record, after every alert.
		last := recs[len(recs)-1]
		if last.Type != "stats" || last.Reason != "shutdown" {
			t.Fatalf("last record %s", last.Raw)
		}
		var st struct {
			Capture struct{ Captured uint64 }
			Engine  struct{ Alerts, Summaries uint64 }
			Traffic struct {
				Packets uint64
				ByL4    map[string]uint64 `json:"by_l4"`
			}
			Log struct{ Dropped uint64 }
		}
		json.Unmarshal(last.Raw, &st)
		if st.Capture.Captured != 615 || st.Traffic.Packets != 615 || st.Traffic.ByL4["TCP"] != 600 || st.Traffic.ByL4["UDP"] != 15 {
			t.Errorf("final stats %s", last.Raw)
		}
		if st.Engine.Alerts != 2 || st.Engine.Summaries != 2 || st.Log.Dropped != 0 {
			t.Errorf("final stats %s", last.Raw)
		}
		if fi, _ := os.Stat(logPath); fi.Mode().Perm() != 0o600 {
			t.Errorf("log mode %v", fi.Mode().Perm())
		}
		runs = append(runs, alerts)
	}
	// Alert records depend only on the packets, so two runs agree exactly.
	if !reflect.DeepEqual(runs[0], runs[1]) {
		t.Errorf("runs differ:\n%s\n---\n%s", strings.Join(runs[0], "\n"), strings.Join(runs[1], "\n"))
	}
}

func TestQuerySubcommand(t *testing.T) {
	pcap := synFloodPcap(t, 300)
	logPath := filepath.Join(t.TempDir(), "ids.jsonl")
	if code, _, stderr := runIDSTest(t, "-r", pcap, "-rules", rulesPath(t), "-log", logPath, "-no-tui"); code != 0 {
		t.Fatal(stderr)
	}
	code, out, stderr := runIDSTest(t, "query", "-log", logPath, "-severity", "high", "-kind", "summary", "-src", "203.0.113.0/24")
	if code != 0 {
		t.Fatal(stderr)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "TIME") || !strings.Contains(lines[1], "summary") || !strings.Contains(stderr, "2 matching") {
		t.Errorf("query table:\n%s\n%s", out, stderr)
	}
	code, out, _ = runIDSTest(t, "query", "-log", logPath, "-type", "stats", "-json")
	if code != 0 || !strings.HasPrefix(out, `{"type":"stats"`) || strings.Count(out, "\n") != 1 {
		t.Errorf("stats query: %q", out)
	}
	code, out, _ = runIDSTest(t, "query", "-log", logPath, "-src", "10.0.0.1")
	if code != 0 || strings.TrimSpace(out) != "" {
		t.Errorf("src filter: %q", out)
	}
	for _, bad := range [][]string{{"-severity", "urgent"}, {"-src", "300.1.1.1"}, {"-type", "x"}, {"-since", "1h", "-from", "2026-01-01"}} {
		if code, _, _ := runIDSTest(t, append([]string{"query", "-log", logPath}, bad...)...); code != 2 {
			t.Errorf("query %v: exit %d, want 2", bad, code)
		}
	}
}

func TestRunErrors(t *testing.T) {
	dir := t.TempDir()
	pcap := synFloodPcap(t, 1)
	bad := filepath.Join(dir, "bad.conf")
	os.WriteFile(bad, []byte("# comment\nalert tcp any any -> any any (msg:\"x\"; sid:1;)\nalert tcp any any -> any any (msg:\"y\"; sid:1;)\nalert bogus\nalert tcp any any -> any any (msg:\"z\"; sid:3; nosuch:1;)\n"), 0o600)
	tests := []struct {
		name string
		args []string
		code int
		want []string
	}{
		{"no source", []string{"-rules", rulesPath(t)}, 2, []string{"exactly one of -i"}},
		{"both sources", []string{"-i", "lo", "-r", pcap}, 2, []string{"exactly one of -i"}},
		{"missing rules", []string{"-r", pcap, "-rules", filepath.Join(dir, "none.conf")}, 1, []string{"rules file", "none.conf not found"}},
		{"bad rules", []string{"-r", pcap, "-rules", bad}, 1, []string{"bad rules", "bad.conf:3", "bad.conf:4", "bad.conf:5"}},
		{"missing pcap", []string{"-r", filepath.Join(dir, "none.pcap"), "-rules", rulesPath(t)}, 1, []string{"capture:", "none.pcap"}},
		{"bad interface", []string{"-i", "nosuchif0", "-rules", rulesPath(t)}, 1, []string{"capture:"}},
		{"bad size", []string{"-r", pcap, "-log-max-size", "lots"}, 2, []string{"bad size"}},
		{"bad whitelist", []string{"-r", pcap, "-whitelist", "10.0.0.0/8,nope"}, 2, []string{"bad whitelist"}},
		{"unknown subcommand", []string{"frobnicate"}, 2, []string{"unknown subcommand"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := tc.args
			if tc.name != "unknown subcommand" {
				args = append(append([]string{"run"}, tc.args...), "-log", filepath.Join(dir, "x.jsonl"))
			}
			code, _, stderr := runIDSTest(t, args...)
			if code != tc.code {
				t.Errorf("exit %d, want %d; stderr:\n%s", code, tc.code, stderr)
			}
			for _, w := range tc.want {
				if !strings.Contains(stderr, w) {
					t.Errorf("stderr lacks %q:\n%s", w, stderr)
				}
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"2048": 2048, "2K": 2048, "2kb": 2048, "100M": 100 << 20, "1GiB": 1 << 30} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "-5", "M", "12X", "99999999999G"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) accepted", in)
		}
	}
}

// TestShutdownOnCancel runs a live-like shutdown: the context is
// cancelled while a large pcap is still being read; ids must drain, flush
// and write the final stats record, and exit 0.
func TestShutdownOnCancel(t *testing.T) {
	pcap := synFloodPcap(t, 3000)
	logPath := filepath.Join(t.TempDir(), "ids.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	var o, e bytes.Buffer
	done := make(chan int)
	go func() {
		done <- run(ctx, []string{"-r", pcap, "-rules", rulesPath(t), "-log", logPath, "-no-tui"}, &o, &e)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d: %s", code, e.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no exit after cancel")
	}
	recs := readLog(t, logPath)
	if last := recs[len(recs)-1]; last.Type != "stats" || last.Reason != "shutdown" {
		t.Errorf("last record %s", last.Raw)
	}
}
