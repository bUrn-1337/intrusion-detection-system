package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

var baseTS = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

// testFrame is one record to write into a synthetic pcap file. If wireLen
// is 0 it defaults to len(data), i.e. an untruncated capture.
type testFrame struct {
	ts      time.Time
	data    []byte
	wireLen int
}

// writePcap writes frames to a new pcap file in t.TempDir and returns its
// path. Timestamps must be microsecond-aligned (classic pcap resolution).
func writePcap(t *testing.T, linkType layers.LinkType, frames []testFrame) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, linkType); err != nil {
		t.Fatal(err)
	}
	for _, fr := range frames {
		wire := fr.wireLen
		if wire == 0 {
			wire = len(fr.data)
		}
		ci := gopacket.CaptureInfo{Timestamp: fr.ts, CaptureLength: len(fr.data), Length: wire}
		if err := w.WritePacket(ci, fr.data); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// ethFrame builds an Ethernet II frame by hand: dst MAC, src MAC,
// EtherType, payload.
func ethFrame(etherType uint16, payload []byte) []byte {
	b := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x0b, // dst
		0x02, 0x00, 0x00, 0x00, 0x00, 0x0a, // src
	}
	b = binary.BigEndian.AppendUint16(b, etherType)
	return append(b, payload...)
}

// ipv4Frame builds an Ethernet frame holding a minimal 20-byte IPv4 header
// with the given protocol, followed by 8 bytes filled with marker. The IP
// checksum is left zero; nothing in Module 1 checks it.
func ipv4Frame(proto uint8, marker byte) []byte {
	ip := make([]byte, 28)
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8] = 64 // TTL
	ip[9] = proto
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	for i := 20; i < len(ip); i++ {
		ip[i] = marker
	}
	return ethFrame(packet.EthTypeIPv4, ip)
}

// arpFrame builds an Ethernet frame with a 28-byte ARP body (contents are
// irrelevant to capture, only the EtherType matters for BPF).
func arpFrame() []byte {
	return ethFrame(packet.EthTypeARP, make([]byte, 28))
}

// udpFrames returns n distinct IPv4/UDP frames, 1ms apart.
func udpFrames(n int) []testFrame {
	frames := make([]testFrame, n)
	for i := range frames {
		frames[i] = testFrame{
			ts:   baseTS.Add(time.Duration(i) * time.Millisecond),
			data: ipv4Frame(17, byte(i)),
		}
	}
	return frames
}

func newFileCapturer(t *testing.T, path string, cfg Config) *Capturer {
	t.Helper()
	cfg.PcapFile = path
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		// Bound Close so a capture bug fails the test instead of hanging it.
		done := make(chan struct{})
		go func() { c.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Close hung in cleanup: capture goroutine never exited")
		}
	})
	return c
}

// drain reads until the channel closes, failing the test if that takes
// longer than a few seconds (i.e. capture hung instead of closing).
func drain(t *testing.T, ch <-chan *packet.ParsedPacket) []*packet.ParsedPacket {
	t.Helper()
	var got []*packet.ParsedPacket
	timeout := time.After(5 * time.Second)
	for {
		select {
		case p, ok := <-ch:
			if !ok {
				return got
			}
			got = append(got, p)
		case <-timeout:
			t.Fatalf("channel not closed after 5s (received %d packets)", len(got))
		}
	}
}

func TestFileFramesAndTimestamps(t *testing.T) {
	frames := udpFrames(5)
	c := newFileCapturer(t, writePcap(t, layers.LinkTypeEthernet, frames), Config{})

	got := drain(t, c.Start(context.Background()))

	if len(got) != len(frames) {
		t.Fatalf("got %d packets, want %d", len(got), len(frames))
	}
	for i, p := range got {
		if !p.Timestamp.Equal(frames[i].ts) {
			t.Errorf("packet %d Timestamp = %v, want %v", i, p.Timestamp, frames[i].ts)
		}
		if !bytes.Equal(p.RawData, frames[i].data) {
			t.Errorf("packet %d RawData = %x, want %x", i, p.RawData, frames[i].data)
		}
		if p.L3Offset != -1 || p.L4Offset != -1 || p.PayloadOffset != -1 {
			t.Errorf("packet %d offsets set by capture: %d/%d/%d", i, p.L3Offset, p.L4Offset, p.PayloadOffset)
		}
	}
	if s := c.Stats(); s.Captured != uint64(len(frames)) || s.QueueDropped != 0 || s.KernelDropped != 0 {
		t.Errorf("Stats = %+v, want Captured=%d and no drops", s, len(frames))
	}
	if err := c.Err(); err != nil {
		t.Errorf("Err() = %v after EOF, want nil", err)
	}
}

func TestRawDataIsOwnedCopy(t *testing.T) {
	first := ipv4Frame(17, 0xAA)
	second := ipv4Frame(17, 0xBB)
	c := newFileCapturer(t, writePcap(t, layers.LinkTypeEthernet, []testFrame{
		{ts: baseTS, data: first},
		{ts: baseTS.Add(time.Millisecond), data: second},
	}), Config{})

	// Both packets sit in the queue together before either is inspected,
	// so a reused read buffer would make the first one look like the second.
	got := drain(t, c.Start(context.Background()))
	if len(got) != 2 {
		t.Fatalf("got %d packets, want 2", len(got))
	}
	a, b := got[0].RawData, got[1].RawData

	if !bytes.Equal(a, first) {
		t.Errorf("first RawData = %x, want %x (overwritten by a later frame?)", a, first)
	}
	if !bytes.Equal(b, second) {
		t.Errorf("second RawData = %x, want %x", b, second)
	}
	if &a[0] == &b[0] {
		t.Fatal("both packets share the same RawData backing array")
	}
	a[len(a)-1] ^= 0xFF
	if !bytes.Equal(b, second) {
		t.Error("modifying the first packet's RawData changed the second")
	}
}

func TestCaptureAndWireLen(t *testing.T) {
	full := ipv4Frame(17, 1)
	truncated := ipv4Frame(6, 2)[:20]

	tests := []struct {
		name        string
		frame       testFrame
		wantCapture uint32
		wantWire    uint32
	}{
		{"full frame", testFrame{ts: baseTS, data: full}, uint32(len(full)), uint32(len(full))},
		{"truncated frame", testFrame{ts: baseTS, data: truncated, wireLen: 1514}, 20, 1514},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFileCapturer(t, writePcap(t, layers.LinkTypeEthernet, []testFrame{tt.frame}), Config{})
			got := drain(t, c.Start(context.Background()))
			if len(got) != 1 {
				t.Fatalf("got %d packets, want 1", len(got))
			}
			p := got[0]
			if p.CaptureLen != tt.wantCapture || p.WireLen != tt.wantWire {
				t.Errorf("CaptureLen/WireLen = %d/%d, want %d/%d",
					p.CaptureLen, p.WireLen, tt.wantCapture, tt.wantWire)
			}
			if len(p.RawData) != int(p.CaptureLen) {
				t.Errorf("len(RawData) = %d, want CaptureLen %d", len(p.RawData), p.CaptureLen)
			}
		})
	}
}

func TestFileDoesNotDropByDefault(t *testing.T) {
	c := newFileCapturer(t, writePcap(t, layers.LinkTypeEthernet, udpFrames(1)), Config{})
	if c.dropWhenFull {
		t.Error("file capturer has dropWhenFull = true, want false (files wait for the consumer)")
	}
}

// TestLiveQueueDropsWhenConsumerStalls exercises the live-capture drop
// policy. Live capture needs root, so it forces that policy on file input.
func TestLiveQueueDropsWhenConsumerStalls(t *testing.T) {
	const total, queue = 50, 2
	c := newFileCapturer(t, writePcap(t, layers.LinkTypeEthernet, udpFrames(total)), Config{QueueSize: queue})
	c.dropWhenFull = true

	ch := c.Start(context.Background())

	// Don't read; wait for the capturer to get through the whole file.
	deadline := time.Now().Add(5 * time.Second)
	for c.Stats().Captured < total {
		if time.Now().After(deadline) {
			t.Fatalf("capture stalled: Stats = %+v", c.Stats())
		}
		time.Sleep(5 * time.Millisecond)
	}

	s := c.Stats()
	if s.QueueDropped != total-queue {
		t.Errorf("QueueDropped = %d, want %d", s.QueueDropped, total-queue)
	}
	if s.QueueDepth != queue {
		t.Errorf("QueueDepth = %d, want %d", s.QueueDepth, queue)
	}

	got := drain(t, ch)
	if len(got) != queue {
		t.Errorf("received %d packets, want the %d that fit in the queue", len(got), queue)
	}
	// The queued ones are the first frames, not arbitrary ones.
	if len(got) > 0 && !got[0].Timestamp.Equal(baseTS) {
		t.Errorf("first queued packet Timestamp = %v, want %v", got[0].Timestamp, baseTS)
	}
}

func TestFileDeliversEveryFrameToSlowConsumer(t *testing.T) {
	const total = 5000
	frames := udpFrames(total)
	c := newFileCapturer(t, writePcap(t, layers.LinkTypeEthernet, frames), Config{QueueSize: 1})

	ch := c.Start(context.Background())

	var got []*packet.ParsedPacket
	timeout := time.After(30 * time.Second)
	for done := false; !done; {
		select {
		case p, ok := <-ch:
			if !ok {
				done = true
				break
			}
			got = append(got, p)
			time.Sleep(10 * time.Microsecond)
		case <-timeout:
			t.Fatalf("channel not closed after 30s (received %d of %d)", len(got), total)
		}
	}

	if len(got) != total {
		t.Fatalf("received %d packets, want all %d", len(got), total)
	}
	for i, p := range got {
		if !p.Timestamp.Equal(frames[i].ts) {
			t.Fatalf("packet %d Timestamp = %v, want %v (out of order or missing)", i, p.Timestamp, frames[i].ts)
		}
	}
	if s := c.Stats(); s.Captured != total || s.QueueDropped != 0 {
		t.Errorf("Stats = %+v, want Captured=%d and QueueDropped=0", s, total)
	}
}

// startStalled starts a file capturer with QueueSize 1 whose consumer never
// reads, and returns once the capture goroutine is blocked on a full queue.
// It also returns the goroutine count from before Start.
func startStalled(t *testing.T, ctx context.Context) (*Capturer, <-chan *packet.ParsedPacket, int) {
	t.Helper()
	c := newFileCapturer(t, writePcap(t, layers.LinkTypeEthernet, udpFrames(100)), Config{QueueSize: 1})
	baseline := runtime.NumGoroutine()
	ch := c.Start(ctx)

	// One frame fills the queue; the second is read and then held in the
	// blocked send.
	deadline := time.Now().Add(5 * time.Second)
	for c.Stats().Captured < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("capturer never filled the queue: Stats = %+v", c.Stats())
		}
		time.Sleep(time.Millisecond)
	}
	if s := c.Stats(); s.QueueDropped != 0 {
		t.Fatalf("file capture dropped frames: Stats = %+v", s)
	}
	return c, ch, baseline
}

// assertStopped checks, without the consumer reading anything first, that
// the capture goroutine exits within 1s and the goroutine count returns to
// baseline. Only then does it read ch, which must already be closed. (Reading
// first would free a queue slot and let a send that ignores cancellation
// complete, hiding the bug.)
func assertStopped(t *testing.T, c *Capturer, ch <-chan *packet.ParsedPacket, baseline int) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("capture goroutine still blocked 1s after stop: the send ignores cancellation")
	}

	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: %d goroutines, want <= %d", runtime.NumGoroutine(), baseline)
		}
		time.Sleep(time.Millisecond)
	}

	// The goroutine has exited, so ch is closed; at most the one queued
	// frame can come out before that is observed.
	for i := 0; ; i++ {
		select {
		case _, ok := <-ch:
			if !ok {
				if err := c.Err(); err != nil {
					t.Errorf("Err() = %v after stop, want nil", err)
				}
				return
			}
			if i >= 1 {
				t.Fatalf("received %d frames after stop, want at most the 1 queued", i+1)
			}
		default:
			t.Fatal("capture goroutine exited but the channel is not closed")
		}
	}
}

func TestCancelUnblocksStalledFileCapture(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, ch, baseline := startStalled(t, ctx)

	cancel()
	assertStopped(t, c, ch, baseline)
}

func TestCloseUnblocksStalledFileCapture(t *testing.T) {
	c, ch, baseline := startStalled(t, context.Background())

	// Close waits for the capture goroutine, so run it separately: if the
	// blocked send ignored Close, this would deadlock rather than fail.
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not return within 1s")
	}

	assertStopped(t, c, ch, baseline)
}

func TestChannelClosesAtEOF(t *testing.T) {
	tests := []struct {
		name   string
		frames []testFrame
	}{
		{"empty file", nil},
		{"three frames", udpFrames(3)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFileCapturer(t, writePcap(t, layers.LinkTypeEthernet, tt.frames), Config{})
			if got := drain(t, c.Start(context.Background())); len(got) != len(tt.frames) {
				t.Errorf("got %d packets, want %d", len(got), len(tt.frames))
			}
		})
	}
}

func TestContextCancelStopsCapture(t *testing.T) {
	const total = 1000
	c := newFileCapturer(t, writePcap(t, layers.LinkTypeEthernet, udpFrames(total)), Config{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := drain(t, c.Start(ctx))
	if len(got) != 0 {
		t.Errorf("received %d packets after cancel, want 0", len(got))
	}
	if s := c.Stats(); s.Captured != 0 {
		t.Errorf("Captured = %d after cancel before start, want 0", s.Captured)
	}
	if err := c.Err(); err != nil {
		t.Errorf("Err() = %v after cancel, want nil", err)
	}
}

func TestCloseStopsCapture(t *testing.T) {
	c := newFileCapturer(t, writePcap(t, layers.LinkTypeEthernet, udpFrames(100)), Config{QueueSize: 1})
	ch := c.Start(context.Background())

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	drain(t, ch) // must close, not hang
	if err := c.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestBPFFilter(t *testing.T) {
	frames := []testFrame{
		{ts: baseTS, data: ipv4Frame(17, 1)},                           // UDP
		{ts: baseTS.Add(1 * time.Millisecond), data: ipv4Frame(6, 2)},  // TCP
		{ts: baseTS.Add(2 * time.Millisecond), data: arpFrame()},       // ARP
		{ts: baseTS.Add(3 * time.Millisecond), data: ipv4Frame(17, 3)}, // UDP
	}
	path := writePcap(t, layers.LinkTypeEthernet, frames)

	tests := []struct {
		filter string
		want   []time.Time
	}{
		{"udp", []time.Time{frames[0].ts, frames[3].ts}},
		{"arp", []time.Time{frames[2].ts}},
		{"", []time.Time{frames[0].ts, frames[1].ts, frames[2].ts, frames[3].ts}},
	}

	for _, tt := range tests {
		t.Run("filter="+tt.filter, func(t *testing.T) {
			c := newFileCapturer(t, path, Config{BPFFilter: tt.filter})
			got := drain(t, c.Start(context.Background()))
			if len(got) != len(tt.want) {
				t.Fatalf("got %d packets, want %d", len(got), len(tt.want))
			}
			for i, p := range got {
				if !p.Timestamp.Equal(tt.want[i]) {
					t.Errorf("packet %d Timestamp = %v, want %v", i, p.Timestamp, tt.want[i])
				}
			}
		})
	}
}

func TestInvalidBPFFilter(t *testing.T) {
	path := writePcap(t, layers.LinkTypeEthernet, udpFrames(1))
	_, err := New(Config{PcapFile: path, BPFFilter: "tcp port nope"})
	if err == nil {
		t.Fatal("New succeeded with an invalid BPF filter")
	}
	if !strings.Contains(err.Error(), "invalid BPF filter") {
		t.Errorf("error = %q, want it to mention the invalid BPF filter", err)
	}
}

func TestNonEthernetLinkTypeRejected(t *testing.T) {
	tests := []struct {
		name     string
		linkType layers.LinkType
	}{
		{"linux cooked capture", layers.LinkTypeLinuxSLL},
		{"BSD loopback", layers.LinkTypeNull},
		{"raw IP", layers.LinkTypeRaw},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePcap(t, tt.linkType, []testFrame{{ts: baseTS, data: make([]byte, 40)}})
			c, err := New(Config{PcapFile: path})
			if err == nil {
				c.Close()
				t.Fatal("New accepted a non-Ethernet capture")
			}
			if !strings.Contains(err.Error(), "only Ethernet") {
				t.Errorf("error = %q, want it to say only Ethernet is supported", err)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"neither source", Config{}, "neither"},
		{"both sources", Config{Interface: "eth0", PcapFile: "x.pcap"}, "both"},
		{"negative snaplen", Config{PcapFile: "x.pcap", Snaplen: -1}, "Snaplen"},
		{"negative queue", Config{PcapFile: "x.pcap", QueueSize: -1}, "QueueSize"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("New(%+v) error = %v, want one containing %q", tt.cfg, err, tt.wantErr)
			}
		})
	}
}

func TestMissingPcapFile(t *testing.T) {
	_, err := New(Config{PcapFile: filepath.Join(t.TempDir(), "missing.pcap")})
	if err == nil {
		t.Fatal("New succeeded on a missing file")
	}
}
