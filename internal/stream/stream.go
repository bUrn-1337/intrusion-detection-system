// Package stream reassembles TCP application messages, so that Module 4
// (parser/app) sees whole HTTP message heads, DNS-over-TCP messages, FTP
// lines and TLS ClientHellos however the sender split them into segments.
//
// A Reassembler runs in the pipeline goroutine after upper.Parse and before
// app.Parse. It only tracks TCP flows with a port in its set (by default 21
// FTP, 53 DNS, 80, 8000 and 8080 HTTP, 443 and 8443 TLS); for any other
// packet Process returns after two array lookups. For a tracked flow it
// sets FlowID and FlowStart on every packet, and StreamProto, AppData,
// StreamAnomaly and the HTTP state fields as described in package packet.
//
// # What is buffered
//
// Each direction of a flow keeps only the application message in progress,
// never bodies or bulk data:
//   - HTTP: the message head, up to MaxHTTPHead bytes. Bodies with a
//     Content-Length are skipped by sequence number. After a chunked or
//     close-delimited body, the direction waits for the next segment that
//     starts a message. A 101 or CONNECT 2xx response, or the HTTP/2
//     cleartext preface, hands both directions back to per-segment parsing.
//   - DNS: one length-prefixed message, up to MaxDNSMessage bytes.
//   - FTP: one line, up to MaxFTPLine bytes. A 234 reply (AUTH TLS
//     accepted) hands both directions back to per-segment parsing.
//   - TLS: the first record of each direction, if it is a handshake record
//     of up to MaxTLSRecord bytes. After it, or after any other first
//     record, the direction is handed back to per-segment parsing.
//
// # Sequence numbers
//
// Each direction tracks the next expected sequence number, compared with
// RFC 1982 serial arithmetic (seq.go). A segment wholly before it is a
// retransmission: if its bytes differ from bytes still held for that
// direction (the message in progress and the last delivered message), the
// packet gets StreamAnomaly "overlap_conflict", the message in progress is
// dropped and the direction desyncs, so the conflicting segment itself is
// parsed on its own (as without reassembly); otherwise it is ignored. Bytes
// that are no longer held (skipped bodies, older messages) cannot be
// compared, so a conflicting retransmission of them is not detected. A
// segment ahead of it is held (up to Config.MaxOOO per direction) until
// the gap closes. A gap still open after Config.OOOTimeout drops the
// message and desyncs the direction.
//
// # Desync and resync
//
// A desynced direction is not reassembled (StreamProto is "", so Module 4
// parses each segment on its own, as without reassembly) until a segment
// starts at a clean message boundary: an HTTP method or "HTTP/1.", a
// plausible DNS length prefix and header, a handshake record header, or
// for FTP the start of a line (after a line ending). A flow picked up
// mid-stream, without its SYN, starts desynced in both directions.
//
// # Limits and cleanup
//
// A flow is dropped after RST (in the sender's window), after both sides
// sent FIN, after Config.IdleTimeout without packets, and, least recently
// used first, when the memory charged to all flows passes
// Config.MaxBytes. A flow whose buffers pass Config.MaxFlowBytes has its
// buffers dropped and desyncs. Only a SYN or a segment with payload opens
// a flow.
//
// All times are engine time: packet timestamps, never going backwards.
package stream

import (
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Proto is an application protocol the reassembler understands.
type Proto uint8

// Protocols. None means a port is not reassembled.
const (
	None Proto = iota
	HTTP
	DNS
	FTP
	TLS
)

// String returns the packet.App* name of p, or "" for None.
func (p Proto) String() string {
	switch p {
	case HTTP:
		return packet.AppHTTP
	case DNS:
		return packet.AppDNS
	case FTP:
		return packet.AppFTP
	case TLS:
		return packet.AppTLS
	}
	return ""
}

// ParseProto returns the protocol named s (case-sensitive, as returned by
// String), and false if there is none.
func ParseProto(s string) (Proto, bool) {
	for _, p := range []Proto{HTTP, DNS, FTP, TLS} {
		if p.String() == s {
			return p, true
		}
	}
	return None, false
}

// Message caps. A message that would pass its cap is dropped and the
// direction desyncs; an HTTP head also sets StreamAnomaly
// "oversize_headers".
const (
	// MaxHTTPHead caps an HTTP message head, from the first byte of the
	// request or status line to the end of the blank line.
	MaxHTTPHead = 16 << 10
	// MaxDNSMessage is the largest DNS-over-TCP message: the 2-byte length
	// prefix plus 65535 bytes.
	MaxDNSMessage = 2 + 0xFFFF
	// MaxFTPLine caps an FTP line, including its line ending.
	MaxFTPLine = 8 << 10
	// MaxTLSRecord caps the first TLS record: a 5-byte header plus 16 KiB.
	MaxTLSRecord = 5 + 16<<10
)

// flowOverhead is charged against Config.MaxBytes for every tracked flow,
// on top of its buffers, so the cap also bounds the number of flows: the
// flow itself and its map slot (key, pointer, and about a quarter more
// for control bytes and the load factor).
const flowOverhead = int(unsafe.Sizeof(flow{}) + (unsafe.Sizeof(flowKey{})+unsafe.Sizeof(&flow{}))*5/4)

// rstWindow is how far from the next expected sequence number a RST may
// be and still close the flow. A RST outside it is ignored, so a blind
// injected RST cannot easily make the stage forget a flow.
const rstWindow = 1 << 20

// maxBodySkip is the largest Content-Length skipped by sequence number. A
// larger body is treated like a chunked one.
const maxBodySkip = 1 << 30

// DefaultPorts returns the default port set.
func DefaultPorts() map[uint16]Proto {
	return map[uint16]Proto{21: FTP, 53: DNS, 80: HTTP, 8000: HTTP, 8080: HTTP, 443: TLS, 8443: TLS}
}

// Config configures a Reassembler. Zero fields take their defaults.
type Config struct {
	// Ports maps a server port to the protocol spoken on it. nil means
	// DefaultPorts(); an empty non-nil map tracks nothing.
	Ports map[uint16]Proto
	// OOOTimeout is how long a gap may stay open while out-of-order
	// segments wait behind it. Default 5 s.
	OOOTimeout time.Duration
	// IdleTimeout drops a flow with no packets for this long. Default 2 min.
	IdleTimeout time.Duration
	// MaxOOO is how many out-of-order segments a direction holds. Default 16.
	MaxOOO int
	// MaxFlowBytes caps the bytes one flow buffers, in both directions,
	// out-of-order segments included. Default 256 KiB. It must allow one
	// full DNS message, so a smaller value is raised to 2*MaxDNSMessage.
	MaxFlowBytes int
	// MaxBytes caps the memory charged to all flows: their buffers plus
	// a fixed overhead per flow. Default 64 MiB.
	MaxBytes int
}

func (c *Config) setDefaults() {
	if c.Ports == nil {
		c.Ports = DefaultPorts()
	}
	if c.OOOTimeout <= 0 {
		c.OOOTimeout = 5 * time.Second
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 2 * time.Minute
	}
	if c.MaxOOO <= 0 {
		c.MaxOOO = 16
	}
	if c.MaxFlowBytes <= 0 {
		c.MaxFlowBytes = 256 << 10
	}
	c.MaxFlowBytes = max(c.MaxFlowBytes, 2*MaxDNSMessage)
	if c.MaxBytes <= 0 {
		c.MaxBytes = 64 << 20
	}
}

// Stats are the reassembler's counters. Counters only grow; Flows,
// Buffered and Charged are current values.
type Stats struct {
	Flows      int64  // flows tracked now
	FlowsTotal uint64 // flows opened since start
	Closed     uint64 // flows closed by FIN or RST
	IdleClosed uint64 // flows dropped after IdleTimeout
	// Evictions counts flows dropped, least recently used first, at
	// MaxBytes.
	Evictions uint64
	// Gaps counts gaps not filled within OOOTimeout.
	Gaps uint64
	// Desyncs counts directions that lost sync (gap, anomaly, cap or an
	// implausible message start). Picking up a flow mid-stream is not
	// counted.
	Desyncs uint64
	// Resyncs counts directions that found a clean boundary again after
	// a desync or a mid-stream pickup.
	Resyncs          uint64
	OverlapConflicts uint64 // StreamAnomaly overlap_conflict
	OversizeHeaders  uint64 // StreamAnomaly oversize_headers
	OOOOverflows     uint64 // StreamAnomaly too_many_ooo_segments
	// CapDrops counts messages dropped at a message cap or at
	// MaxFlowBytes.
	CapDrops uint64
	Messages uint64 // messages delivered in AppData
	// Buffered is the bytes held in buffers now (capacity, so a little
	// more than their content), and BufferedPeak its highest value.
	Buffered     int64
	BufferedPeak int64
	// Charged is what counts against MaxBytes: Buffered plus the fixed
	// per-flow overhead.
	Charged int64
}

type counters struct {
	flows, buffered, peak, charged                         atomic.Int64
	total, closed, idle, evictions, gaps, desyncs, resyncs atomic.Uint64
	overlaps, oversize, oooOverflows, capDrops, messages   atomic.Uint64
}

// flowKey identifies a TCP connection in both directions: the endpoint
// that sorts lower is a.
type flowKey struct {
	a, b   [16]byte
	pa, pb uint16
}

// Directions within a flow.
const (
	toServer = 0
	toClient = 1
)

type flow struct {
	key        flowKey
	id         uint64
	start      time.Time
	last       time.Time
	proto      Proto
	clientIsA  bool
	half       [2]half
	prev, next *flow // LRU list, most recent at the head
	mem        int   // buffer bytes charged (without flowOverhead)
	// pending remembers, for the HTTP requests whose responses have not
	// started, whether each was HEAD or CONNECT (bits, oldest first).
	pending    uint64
	pendingLen uint8
	closing    bool // RST seen, or both FINs; dropped after this packet
}

// Reassembler tracks TCP flows and reassembles their messages. It is not
// safe for concurrent use, except Stats, which may be called from any
// goroutine.
type Reassembler struct {
	cfg    Config
	ports  [65536]Proto
	now    time.Time
	flows  map[flowKey]*flow
	head   *flow
	tail   *flow
	free   *flow
	nextID uint64
	mem    int // buffers of all flows
	st     counters
}

// New returns a Reassembler for cfg.
func New(cfg Config) *Reassembler {
	cfg.setDefaults()
	r := &Reassembler{cfg: cfg, flows: make(map[flowKey]*flow)}
	for port, proto := range cfg.Ports {
		r.ports[port] = proto
	}
	return r
}

// Stats returns a snapshot of the counters.
func (r *Reassembler) Stats() Stats {
	s := &r.st
	return Stats{
		Flows: s.flows.Load(), FlowsTotal: s.total.Load(), Closed: s.closed.Load(), IdleClosed: s.idle.Load(),
		Evictions: s.evictions.Load(), Gaps: s.gaps.Load(), Desyncs: s.desyncs.Load(), Resyncs: s.resyncs.Load(),
		OverlapConflicts: s.overlaps.Load(), OversizeHeaders: s.oversize.Load(), OOOOverflows: s.oooOverflows.Load(),
		CapDrops: s.capDrops.Load(), Messages: s.messages.Load(),
		Buffered: s.buffered.Load(), BufferedPeak: s.peak.Load(), Charged: s.charged.Load(),
	}
}

// Process runs the stream stage on one packet. It must be called after
// upper.Parse and before app.Parse, for every packet in capture order.
func (r *Reassembler) Process(p *packet.ParsedPacket) {
	if p == nil || p.L4Proto != packet.L4TCP || p.PayloadOffset < 0 {
		return
	}
	if r.ports[p.SrcPort] == None && r.ports[p.DstPort] == None {
		return
	}
	if p.Timestamp.After(r.now) {
		r.now = p.Timestamp
	}
	key, fromA, ok := makeKey(p)
	if !ok {
		return
	}
	r.expireIdle(p)
	f := r.flows[key]
	fl := p.TCPFlags
	payload := p.Payload()

	if f != nil && fl.SYN && !fl.ACK && r.isNewConnection(f, fromA, p.TCPSeq) {
		r.remove(f, p)
		r.st.closed.Add(1)
		f = nil
	}
	if f == nil {
		if fl.RST || !fl.SYN && len(payload) == 0 {
			return
		}
		if f = r.open(key, fromA, p); f == nil {
			return
		}
	} else {
		r.touch(f)
	}
	f.last = r.now
	p.FlowID, p.FlowStart = f.id, f.start

	d := toServer
	if fromA != f.clientIsA {
		d = toClient
	}
	h := &f.half[d]
	h.completed = false
	seq := p.TCPSeq
	if fl.SYN {
		h.syn(seq)
		seq++
	}
	if len(payload) > 0 {
		if h.mode == modeSync {
			p.StreamProto = f.proto.String()
		}
		r.segment(f, d, seq, payload, p)
	}
	if f.proto == HTTP && d == toServer {
		h.setHTTPFields(p)
	}
	if fl.FIN && !fl.RST {
		h.fin = true
		if f.half[1-d].fin {
			f.closing = true
		}
	}
	if fl.RST && (!h.haveNxt || inWindow(p.TCPSeq, h.nxt)) {
		f.closing = true
	}
	if f.closing {
		r.remove(f, p)
		r.st.closed.Add(1)
		return
	}
	r.account(f, d, p)
}

func inWindow(seq, nxt uint32) bool {
	d := seq - nxt
	return d <= rstWindow || -d <= rstWindow
}

// makeKey builds the flow key and reports whether the sender is endpoint
// a. ok is false if the addresses are unusable.
func makeKey(p *packet.ParsedPacket) (k flowKey, fromA bool, ok bool) {
	src, dst := p.IPSrc.To16(), p.IPDst.To16()
	if src == nil || dst == nil {
		return k, false, false
	}
	var s, d [16]byte
	copy(s[:], src)
	copy(d[:], dst)
	c := compareAddr(s, d)
	if c < 0 || c == 0 && p.SrcPort <= p.DstPort {
		return flowKey{a: s, b: d, pa: p.SrcPort, pb: p.DstPort}, true, true
	}
	return flowKey{a: d, b: s, pa: p.DstPort, pb: p.SrcPort}, false, true
}

func compareAddr(a, b [16]byte) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// isNewConnection reports whether a SYN from the given side starts a new
// connection on the 4-tuple of f rather than retransmitting its SYN.
func (r *Reassembler) isNewConnection(f *flow, fromA bool, seq uint32) bool {
	h := &f.half[toServer]
	return fromA != f.clientIsA || !h.sawSYN || h.isn != seq
}

// open starts tracking a flow, or returns nil if it should not be
// tracked. The client is the SYN sender when there is a SYN; otherwise the
// side not on a port in the set, or the side on the higher port.
func (r *Reassembler) open(key flowKey, fromA bool, p *packet.ParsedPacket) *flow {
	fl := p.TCPFlags
	sp, dp := r.ports[p.SrcPort], r.ports[p.DstPort]
	var clientIsSrc bool
	var proto Proto
	switch {
	case fl.SYN && !fl.ACK:
		clientIsSrc, proto = true, dp
	case fl.SYN:
		clientIsSrc, proto = false, sp
	case dp != None && (sp == None || p.DstPort <= p.SrcPort):
		clientIsSrc, proto = true, dp
	default:
		clientIsSrc, proto = false, sp
	}
	if proto == None {
		return nil
	}
	f := r.free
	if f != nil {
		r.free = f.next
		*f = flow{}
	} else {
		f = new(flow)
	}
	r.nextID++
	f.key, f.id, f.start, f.last, f.proto = key, r.nextID, r.now, r.now, proto
	f.clientIsA = clientIsSrc == fromA
	// Both directions start desynced; a SYN syncs its direction.
	r.flows[key] = f
	r.pushFront(f)
	r.mem += flowOverhead
	r.st.flows.Add(1)
	r.st.total.Add(1)
	r.publishMem()
	return f
}

// remove stops tracking f and reports it in p.ClosedFlows.
func (r *Reassembler) remove(f *flow, p *packet.ParsedPacket) {
	delete(r.flows, f.key)
	r.unlink(f)
	r.mem -= f.mem + flowOverhead
	r.st.flows.Add(-1)
	r.publishMem()
	p.ClosedFlows = append(p.ClosedFlows, f.id)
	*f = flow{next: r.free}
	r.free = f
}

// expireIdle drops flows idle for longer than IdleTimeout, oldest first.
// It runs before the packet's own flow is looked up, so a packet on a
// flow idle that long opens a new one.
func (r *Reassembler) expireIdle(p *packet.ParsedPacket) {
	for f := r.tail; f != nil && r.now.Sub(f.last) > r.cfg.IdleTimeout; f = r.tail {
		r.remove(f, p)
		r.st.idle.Add(1)
	}
}

// account recharges f's buffers after a packet, enforces MaxFlowBytes on
// f and MaxBytes on all flows, evicting the least recently used flows
// other than f.
func (r *Reassembler) account(f *flow, d int, p *packet.ParsedPacket) {
	used := f.half[0].mem() + f.half[1].mem()
	if used > r.cfg.MaxFlowBytes {
		for _, i := range []int{d, 1 - d} {
			if used <= r.cfg.MaxFlowBytes {
				break
			}
			h := &f.half[i]
			if h.mem() > 0 {
				used -= h.mem()
				h.desync()
				if i == d {
					unstream(p)
				}
				r.st.capDrops.Add(1)
				r.st.desyncs.Add(1)
			}
		}
	}
	r.mem += used - f.mem
	f.mem = used
	for r.mem > r.cfg.MaxBytes && r.tail != nil && r.tail != f {
		victim := r.tail
		r.remove(victim, p)
		r.st.evictions.Add(1)
	}
	r.publishMem()
}

func (r *Reassembler) publishMem() {
	buf := int64(r.mem) - int64(len(r.flows)*flowOverhead)
	r.st.buffered.Store(buf)
	r.st.charged.Store(int64(r.mem))
	if buf > r.st.peak.Load() {
		r.st.peak.Store(buf)
	}
}

func (r *Reassembler) pushFront(f *flow) {
	f.prev, f.next = nil, r.head
	if r.head != nil {
		r.head.prev = f
	}
	r.head = f
	if r.tail == nil {
		r.tail = f
	}
}

func (r *Reassembler) unlink(f *flow) {
	if f.prev != nil {
		f.prev.next = f.next
	} else {
		r.head = f.next
	}
	if f.next != nil {
		f.next.prev = f.prev
	} else {
		r.tail = f.prev
	}
	f.prev, f.next = nil, nil
}

func (r *Reassembler) touch(f *flow) {
	if r.head != f {
		r.unlink(f)
		r.pushFront(f)
	}
}
