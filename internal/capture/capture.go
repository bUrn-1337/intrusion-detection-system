// Package capture implements Module 1: live and offline packet capture.
//
// It reads raw Ethernet frames from a network interface or a .pcap file and
// emits one packet.ParsedPacket per frame, with only the capture-stage
// fields (Timestamp, CaptureLen, WireLen, RawData) set. It does not parse
// any headers; that is Module 2's job.
//
// Backpressure depends on the source. When the output channel is full:
//   - Live interface: the frame is dropped and counted in
//     Stats.QueueDropped. Capture never blocks on a slow consumer, because
//     the kernel would drop frames anyway while we waited.
//   - Pcap file: capture waits for the consumer, so every frame in the file
//     is delivered in order and Stats.QueueDropped is always 0. Cancelling
//     the context or calling Close still stops a waiting capture promptly.
//
// Live capture uses libpcap through cgo, so building this package requires
// the libpcap development headers (libpcap-dev on Debian/Ubuntu).
//
// # Kernel ring and immediate mode
//
// Live capture runs with immediate mode off and a 32 MB kernel buffer.
// On Linux, immediate mode makes libpcap fall back from TPACKET_V3 to
// TPACKET_V2, whose ring has fixed-size slots, each big enough for a
// snaplen-sized frame (capped at the interface MTU). With the 262144-byte
// snaplen that GRO frames need, an 8 MB ring held only about 127 frames of
// any size, and a short scheduling stall during an 800-frame SYN burst
// overflowed it (kernel drops, measured in the soak test). TPACKET_V3
// packs frames by their real size into blocks, so the same memory holds
// tens of thousands of small packets.
//
// The cost is batching: a block is handed to us when it fills or when the
// 100 ms read timeout expires, so on a quiet link a packet can reach the
// dashboard up to about 100 ms late. Detection is not affected, because the
// rule engine's clock is the packet's capture timestamp, not arrival time.
package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Defaults applied by New when the corresponding Config field is zero.
const (
	DefaultSnaplen   = 262144
	DefaultQueueSize = 10000
)

const (
	// liveBufferSize is the kernel capture buffer for live interfaces.
	liveBufferSize = 32 << 20
	// liveImmediateMode must stay false: immediate mode forces fixed-size,
	// snaplen-sized ring slots and drops bursts. See the package doc and
	// TestImmediateModeStaysOff before changing it.
	liveImmediateMode = false
	// readTimeout bounds how long a live read blocks when no traffic
	// arrives, so the capture loop can notice context cancellation. It is
	// also the longest a partly filled ring block waits before delivery.
	readTimeout = 100 * time.Millisecond
	// statsInterval is how often the capture loop refreshes kernel drop
	// counters on a live handle.
	statsInterval = 500 * time.Millisecond
)

// setcapHint is the fix suggested when a live capture is not permitted.
const setcapHint = "run as root, or grant the binary capture rights with " +
	"`sudo setcap cap_net_raw,cap_net_admin=eip bin/ids`"

// Config selects and tunes the capture source. Exactly one of Interface or
// PcapFile must be set.
type Config struct {
	// Interface is the network interface for live capture. It must use
	// Ethernet framing. It is mutually exclusive with PcapFile.
	Interface string
	// PcapFile is the path of a .pcap file for offline input. The file must
	// have the Ethernet link type.
	PcapFile string
	// BPFFilter is an optional pcap filter expression, e.g. "tcp port 80".
	BPFFilter string
	// Snaplen is the maximum bytes captured per frame (live only; a file
	// keeps the snaplen it was recorded with). 0 means DefaultSnaplen.
	Snaplen int
	// QueueSize is the capacity of the output channel. 0 means
	// DefaultQueueSize. When it is full, live capture drops frames and
	// counts them in Stats.QueueDropped, so a slow consumer never stalls the
	// capture. File input waits for the consumer instead, so a replayed pcap
	// always delivers every frame.
	QueueSize int
	// Promisc enables promiscuous mode for live capture. Go cannot tell an
	// unset bool from false, so use DefaultConfig to get the default of
	// true. Ignored for files.
	Promisc bool
}

// DefaultConfig returns a Config with the documented defaults filled in,
// including Promisc = true. Set Interface or PcapFile on the result.
func DefaultConfig() Config {
	return Config{
		Snaplen:   DefaultSnaplen,
		QueueSize: DefaultQueueSize,
		Promisc:   true,
	}
}

// Stats is a snapshot of capture counters.
type Stats struct {
	// Captured is the number of frames read from the source, including
	// frames later dropped because the queue was full.
	Captured uint64
	// KernelDropped is the number of frames the kernel dropped before we
	// could read them, from pcap's ps_drop counter. Always 0 for files.
	KernelDropped uint64
	// QueueDropped is the number of frames dropped because the output
	// channel was full. Always 0 for files, which wait instead of dropping.
	QueueDropped uint64
	// QueueDepth is the number of frames currently waiting in the output
	// channel.
	QueueDepth int
}

// Capturer reads frames from one source and emits them on a channel.
type Capturer struct {
	handle *pcap.Handle
	live   bool
	file   string // the pcap file, when not live
	out    chan *packet.ParsedPacket

	// dropWhenFull selects the full-queue policy: drop (live) or wait
	// (file). It is separate from live so tests can exercise the drop path
	// with file input.
	dropWhenFull bool

	captured      atomic.Uint64
	kernelDropped atomic.Uint64
	queueDropped  atomic.Uint64

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{} // closed when the capture goroutine exits
	err     error         // fatal read error, guarded by mu
}

// New validates cfg and opens the capture source. It fails if the source
// does not use Ethernet framing.
func New(cfg Config) (*Capturer, error) {
	if err := validate(&cfg); err != nil {
		return nil, err
	}

	var (
		h   *pcap.Handle
		err error
	)
	if cfg.Interface != "" {
		h, err = openLive(cfg)
	} else {
		h, err = openFile(cfg.PcapFile)
	}
	if err != nil {
		return nil, err
	}

	if err := checkLinkType(h, cfg); err != nil {
		h.Close()
		return nil, err
	}

	if cfg.BPFFilter != "" {
		if err := h.SetBPFFilter(cfg.BPFFilter); err != nil {
			h.Close()
			return nil, fmt.Errorf("capture: invalid BPF filter %q: %w", cfg.BPFFilter, err)
		}
	}

	live := cfg.Interface != ""
	return &Capturer{
		handle:       h,
		live:         live,
		file:         cfg.PcapFile,
		out:          make(chan *packet.ParsedPacket, cfg.QueueSize),
		dropWhenFull: live,
	}, nil
}

func validate(cfg *Config) error {
	switch {
	case cfg.Interface != "" && cfg.PcapFile != "":
		return errors.New("capture: config sets both Interface and PcapFile; set exactly one")
	case cfg.Interface == "" && cfg.PcapFile == "":
		return errors.New("capture: config sets neither Interface nor PcapFile; set exactly one")
	case cfg.Snaplen < 0:
		return fmt.Errorf("capture: Snaplen must be >= 0, got %d", cfg.Snaplen)
	case cfg.QueueSize < 0:
		return fmt.Errorf("capture: QueueSize must be >= 0, got %d", cfg.QueueSize)
	}
	if cfg.Snaplen == 0 {
		cfg.Snaplen = DefaultSnaplen
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	return nil
}

func openLive(cfg Config) (*pcap.Handle, error) {
	// Check existence first: unprivileged, libpcap reports a missing
	// interface as "permission denied", which would send users to setcap
	// instead of to a typo.
	if names, err := interfaceNames(); err == nil && !slices.Contains(names, cfg.Interface) {
		return nil, fmt.Errorf("capture: interface %q does not exist; available interfaces: %s",
			cfg.Interface, formatInterfaces(names))
	}

	inactive, err := pcap.NewInactiveHandle(cfg.Interface)
	if err != nil {
		return nil, liveOpenError(cfg.Interface, err)
	}
	defer inactive.CleanUp()

	settings := []struct {
		name string
		set  func() error
	}{
		{"snaplen", func() error { return inactive.SetSnapLen(cfg.Snaplen) }},
		{"promiscuous mode", func() error { return inactive.SetPromisc(cfg.Promisc) }},
		{"read timeout", func() error { return inactive.SetTimeout(readTimeout) }},
		{"immediate mode", func() error { return inactive.SetImmediateMode(liveImmediateMode) }},
		{"buffer size", func() error { return inactive.SetBufferSize(liveBufferSize) }},
	}
	for _, s := range settings {
		if err := s.set(); err != nil {
			return nil, fmt.Errorf("capture: setting %s on %q: %w", s.name, cfg.Interface, err)
		}
	}

	h, err := inactive.Activate()
	if err != nil {
		return nil, liveOpenError(cfg.Interface, err)
	}
	return h, nil
}

// liveOpenError turns libpcap's open/activate errors into actionable ones.
// libpcap's activation error type is unexported, so this matches on text.
func liveOpenError(iface string, err error) error {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "permission denied"),
		strings.Contains(msg, "operation not permitted"),
		strings.Contains(msg, "don't have permission"):
		return fmt.Errorf("capture: permission denied opening %q: %w; %s", iface, err, setcapHint)
	case strings.Contains(msg, "no such device"),
		strings.Contains(msg, "doesn't exist"):
		names, lerr := interfaceNames()
		list := formatInterfaces(names)
		if lerr != nil {
			list = fmt.Sprintf("(could not list interfaces: %v)", lerr)
		}
		return fmt.Errorf("capture: interface %q does not exist (%w); available interfaces: %s",
			iface, err, list)
	}
	return fmt.Errorf("capture: opening interface %q: %w", iface, err)
}

// interfaceNames lists the devices libpcap can open. It works unprivileged.
func interfaceNames() ([]string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	names := make([]string, len(devs))
	for i, d := range devs {
		names[i] = d.Name
	}
	return names, nil
}

func formatInterfaces(names []string) string {
	if len(names) == 0 {
		return "(none found)"
	}
	return strings.Join(names, ", ")
}

func openFile(path string) (*pcap.Handle, error) {
	h, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("capture: opening pcap file %q: %w", path, err)
	}
	return h, nil
}

// checkLinkType rejects any source that does not produce Ethernet frames,
// since Module 2 only decodes Ethernet.
func checkLinkType(h *pcap.Handle, cfg Config) error {
	lt := h.LinkType()
	if lt == layers.LinkTypeEthernet {
		return nil
	}
	name := pcap.DatalinkValToName(int(lt))
	if cfg.Interface != "" {
		return fmt.Errorf("capture: interface %q has link type %s (DLT %d), but only Ethernet "+
			"(EN10MB) is supported; capture on a real Ethernet interface such as eth0 instead "+
			"(the Linux \"any\" device and macOS loopback are not Ethernet)",
			cfg.Interface, name, int(lt))
	}
	return fmt.Errorf("capture: pcap file %q has link type %s (DLT %d), but only Ethernet "+
		"(EN10MB) captures are supported; re-record it on a real Ethernet interface",
		cfg.PcapFile, name, int(lt))
}

// Start begins capturing in a new goroutine and returns the output channel.
// The channel is closed when ctx is cancelled, when a pcap file reaches
// EOF, on a fatal read error (see Err), or when Close is called.
//
// Start may be called only once. Later calls, or calls after Close, return
// an already-closed channel.
func (c *Capturer) Start(ctx context.Context) <-chan *packet.ParsedPacket {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started || c.closed {
		ch := make(chan *packet.ParsedPacket)
		close(ch)
		return ch
	}
	c.started = true

	ctx, c.cancel = context.WithCancel(ctx)
	c.done = make(chan struct{})
	go c.run(ctx)
	return c.out
}

func (c *Capturer) run(ctx context.Context) {
	defer close(c.done)
	defer close(c.out)

	lastStats := time.Now()
	for ctx.Err() == nil {
		if c.live && time.Since(lastStats) >= statsInterval {
			c.refreshKernelStats()
			lastStats = time.Now()
		}

		// ReadPacketData returns a freshly allocated slice for every
		// frame, so data is owned by this packet. Do not switch to
		// ZeroCopyReadPacketData: it reuses one buffer, and every queued
		// packet would be overwritten by later frames.
		data, ci, err := c.handle.ReadPacketData()
		switch {
		case err == nil:
		case errors.Is(err, pcap.NextErrorTimeoutExpired):
			continue
		case errors.Is(err, io.EOF):
			return
		default:
			if ctx.Err() == nil {
				c.setErr(c.readError(err))
			}
			return
		}

		c.captured.Add(1)
		p := packet.NewParsedPacket(ci.Timestamp, uint32(ci.CaptureLength), uint32(ci.Length))
		p.RawData = data

		if !c.send(ctx, p) {
			return
		}
	}
	if c.live {
		c.refreshKernelStats()
	}
}

// send delivers p according to the backpressure policy and reports whether
// capture should continue. With dropWhenFull it never blocks. Otherwise it
// waits for room in the channel until ctx is done. ctx is the context Start
// derived, and Close cancels it, so both a caller's cancel and Close unblock
// a waiting send.
func (c *Capturer) send(ctx context.Context, p *packet.ParsedPacket) bool {
	if c.dropWhenFull {
		select {
		case c.out <- p:
		default:
			c.queueDropped.Add(1)
		}
		return true
	}
	select {
	case c.out <- p:
		return true
	case <-ctx.Done():
		return false
	}
}

// readError describes a failed read. For a file, libpcap's own message
// (such as "truncated dump file; tried to read 60 captured bytes, only got
// 13") says what is wrong, where gopacket only says "Read Error".
func (c *Capturer) readError(err error) error {
	if !c.live && errors.Is(err, pcap.NextErrorReadError) {
		detail := err.Error()
		if herr := c.handle.Error(); herr != nil && herr.Error() != "" {
			detail = herr.Error()
		}
		return fmt.Errorf("capture: pcap file %q is damaged after %d frames: %s", c.file, c.captured.Load(), detail)
	}
	return fmt.Errorf("capture: read failed: %w", err)
}

// refreshKernelStats must only be called from the capture goroutine: pcap
// handles are not safe for concurrent use.
func (c *Capturer) refreshKernelStats() {
	s, err := c.handle.Stats()
	if err != nil {
		return
	}
	c.kernelDropped.Store(uint64(s.PacketsDropped))
}

func (c *Capturer) setErr(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
}

// Stats returns a snapshot of the capture counters. It is safe to call
// concurrently with capture. KernelDropped is refreshed about every 500ms
// and once more when capture stops.
func (c *Capturer) Stats() Stats {
	return Stats{
		Captured:      c.captured.Load(),
		KernelDropped: c.kernelDropped.Load(),
		QueueDropped:  c.queueDropped.Load(),
		QueueDepth:    len(c.out),
	}
}

// Err returns the fatal read error that stopped capture, or nil if capture
// is still running or stopped because of EOF, cancellation, or Close.
func (c *Capturer) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close stops capture, waits for the capture goroutine to exit (which
// closes the output channel), and releases the pcap handle. It is safe to
// call more than once.
func (c *Capturer) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	cancel, done := c.cancel, c.done
	c.mu.Unlock()

	if cancel != nil {
		cancel()
		<-done
	}
	c.handle.Close()
	return nil
}
