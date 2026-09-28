package stream

import (
	"bytes"
	"sort"
	"strconv"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Direction modes.
const (
	// modeDesync: not reassembling; each segment is checked for a clean
	// message boundary to resync at.
	modeDesync uint8 = iota
	// modeSync: reassembling from nxt.
	modeSync
	// modePass: handed back to per-segment parsing for good.
	modePass
)

// HTTP phases of a synced direction.
const (
	phIdle uint8 = iota // between messages
	phHead              // inside a message head
	phBody              // a Content-Length body not fully seen yet
)

// histWindow is how far behind nxt the last delivered message is still
// kept for comparing retransmissions.
const histWindow = 1 << 20

// seg is an out-of-order segment waiting for a gap to close. data is owned.
type seg struct {
	seq  uint32
	data []byte
}

// half is one direction of a flow.
type half struct {
	mode    uint8
	sawSYN  bool
	isn     uint32
	haveNxt bool
	nxt     uint32 // next byte needed
	fin     bool
	lastNL  bool // the last byte before nxt was '\n' (FTP resync)

	buf []byte // the message in progress; covers [nxt-len(buf), nxt)

	// hist is the last delivered message, at [histSeq, histSeq+len(hist)).
	hist    []byte
	histSeq uint32

	ooo      []seg // sorted by seq, all after nxt
	oooBytes int
	oooSince time.Time

	completed bool // the current packet completed a message

	// HTTP
	phase     uint8
	checked   bool // the message start has been checked for plausibility
	scan      int  // where the next search for the end of the head starts
	chunked   bool // desynced only to skip a body without a length
	msgSeq    uint32
	msgStart  time.Time
	lastHead  int // length of the last completed head
	bodyStart uint32
	bodyEnd   uint32
	bodyHigh  uint32 // highest body byte seen, +1
	bodyLen   uint64
}

// mem is what the direction holds: its buffers, and the whole AppData
// array its last message keeps alive.
func (h *half) mem() int { return cap(h.buf) + h.oooBytes + cap(h.hist) }

// syn records a SYN: the stream starts at isn+1. A retransmitted SYN
// changes nothing.
func (h *half) syn(isn uint32) {
	if h.sawSYN && h.isn == isn {
		return
	}
	*h = half{sawSYN: true, isn: isn, haveNxt: true, nxt: isn + 1, mode: modeSync, fin: h.fin}
}

// desync drops everything buffered and waits for a clean boundary.
func (h *half) desync() {
	h.mode = modeDesync
	h.buf, h.hist, h.ooo, h.oooBytes = nil, nil, nil, 0
	h.phase, h.checked, h.chunked = phIdle, false, false
}

// pass hands the direction back to per-segment parsing for good.
func (h *half) pass() {
	h.desync()
	h.mode = modePass
}

// segment handles a segment with payload starting at seq.
func (r *Reassembler) segment(f *flow, d int, seq uint32, data []byte, p *packet.ParsedPacket) {
	h := &f.half[d]
	switch h.mode {
	case modePass:
		return
	case modeDesync:
		r.desynced(f, d, seq, data, p)
		return
	}
	if len(h.ooo) > 0 && r.now.Sub(h.oooSince) > r.cfg.OOOTimeout {
		r.st.gaps.Add(1)
		r.st.desyncs.Add(1)
		h.desync()
		unstream(p)
		r.desynced(f, d, seq, data, p)
		return
	}
	end := seq + uint32(len(data))
	if seqLT(h.nxt, seq) {
		r.hold(f, d, seq, data, p)
		return
	}
	r.inOrder(f, d, seq, end, data, p)
	r.drain(f, d, p)
}

// inOrder handles a segment that starts at or before nxt: the part
// before nxt is checked against held bytes, the rest is fed.
func (r *Reassembler) inOrder(f *flow, d int, seq, end uint32, data []byte, p *packet.ParsedPacket) {
	h := &f.half[d]
	// Body bytes behind nxt were skipped by sequence number (nxt is then
	// bodyEnd); count them toward bodyHigh. Bytes from nxt on are fed.
	if h.phase == phBody && seqLT(h.bodyHigh, seqMin(end, h.nxt)) && seqLT(h.bodyStart, end) {
		h.bodyHigh = seqMin(end, h.nxt)
		if h.bodyHigh == h.bodyEnd {
			h.phase = phIdle
		}
	}
	old := data
	if seqLT(h.nxt, end) {
		old = data[:h.nxt-seq]
	}
	if len(old) > 0 && !h.matchesHeld(seq, old) {
		r.anomaly(h, p, packet.StreamOverlapConflict)
		return
	}
	if len(old) < len(data) {
		r.feed(f, d, data[len(old):], p)
	}
}

// matchesHeld reports whether b, at seq, agrees with every byte still held
// for the direction.
func (h *half) matchesHeld(seq uint32, b []byte) bool {
	if len(h.buf) > 0 && !overlapEqual(h.nxt-uint32(len(h.buf)), h.buf, seq, b) {
		return false
	}
	if len(h.hist) > 0 {
		if h.nxt-h.histSeq > histWindow {
			h.hist = nil
		} else if !overlapEqual(h.histSeq, h.hist, seq, b) {
			return false
		}
	}
	return true
}

// overlapEqual reports whether a (at seq as) and b (at seq bs) agree where
// they overlap.
func overlapEqual(as uint32, a []byte, bs uint32, b []byte) bool {
	lo := seqMax(as, bs)
	hi := seqMin(as+uint32(len(a)), bs+uint32(len(b)))
	if !seqLT(lo, hi) {
		return true
	}
	n := hi - lo
	return bytes.Equal(a[lo-as:][:n], b[lo-bs:][:n])
}

// hold keeps a segment that starts after nxt.
func (r *Reassembler) hold(f *flow, d int, seq uint32, data []byte, p *packet.ParsedPacket) {
	h := &f.half[d]
	i := sort.Search(len(h.ooo), func(i int) bool { return !seqLT(h.ooo[i].seq, seq) })
	if i < len(h.ooo) && h.ooo[i].seq == seq && len(h.ooo[i].data) == len(data) {
		if !bytes.Equal(h.ooo[i].data, data) {
			r.anomaly(h, p, packet.StreamOverlapConflict)
		}
		return
	}
	if len(h.ooo) >= r.cfg.MaxOOO {
		r.anomaly(h, p, packet.StreamTooManyOOO)
		return
	}
	if len(h.ooo) == 0 {
		h.oooSince = r.now
	}
	h.ooo = append(h.ooo, seg{})
	copy(h.ooo[i+1:], h.ooo[i:])
	h.ooo[i] = seg{seq: seq, data: bytes.Clone(data)}
	h.oooBytes += len(data)
}

// drain feeds held segments that the stream has caught up with.
func (r *Reassembler) drain(f *flow, d int, p *packet.ParsedPacket) {
	h := &f.half[d]
	moved := false
	for len(h.ooo) > 0 && h.mode == modeSync && !seqLT(h.nxt, h.ooo[0].seq) {
		s := h.ooo[0]
		h.ooo = h.ooo[1:]
		h.oooBytes -= len(s.data)
		moved = true
		r.inOrder(f, d, s.seq, s.seq+uint32(len(s.data)), s.data, p)
	}
	if len(h.ooo) == 0 {
		h.ooo = nil
	} else if moved {
		h.oooSince = r.now
	}
}

// anomaly marks the packet, drops the direction's message and desyncs it.
func (r *Reassembler) anomaly(h *half, p *packet.ParsedPacket, reason string) {
	if p.StreamAnomaly == "" {
		p.StreamAnomaly = reason
	}
	switch reason {
	case packet.StreamOverlapConflict:
		r.st.overlaps.Add(1)
	case packet.StreamOversizeHeaders:
		r.st.oversize.Add(1)
		r.st.capDrops.Add(1)
	case packet.StreamTooManyOOO:
		r.st.oooOverflows.Add(1)
	}
	r.st.desyncs.Add(1)
	h.desync()
	p.StreamProto = "" // the message in progress is dropped with it
	p.AppData = nil
}

// unstream hands the rest of p back to per-segment parsing after its
// direction desynced. Messages p already completed stay in AppData, and
// StreamProto stays set so that Module 4 parses them; the bytes after
// them are lost, as for any desync.
func unstream(p *packet.ParsedPacket) {
	if len(p.AppData) == 0 {
		p.StreamProto = ""
	}
}

// lose desyncs the direction without an anomaly (implausible message
// start, message cap).
func (r *Reassembler) lose(h *half, capDrop bool) {
	if capDrop {
		r.st.capDrops.Add(1)
	}
	r.st.desyncs.Add(1)
	h.desync()
}

// desynced handles a segment of a desynced direction: it resyncs if the
// segment starts at a clean boundary.
func (r *Reassembler) desynced(f *flow, d int, seq uint32, data []byte, p *packet.ParsedPacket) {
	h := &f.half[d]
	end := seq + uint32(len(data))
	if h.haveNxt && seqLEQ(end, h.nxt) {
		return
	}
	k := r.boundary(f, d, seq, data)
	if h.mode == modePass {
		return
	}
	if k < 0 {
		h.nxt, h.haveNxt = end, true
		h.lastNL = data[len(data)-1] == '\n'
		return
	}
	if !h.chunked {
		r.st.resyncs.Add(1)
	}
	h.mode, h.chunked = modeSync, false
	h.phase, h.checked = phIdle, false
	h.nxt, h.haveNxt = seq+uint32(k), true
	h.lastNL = k > 0 && data[k-1] == '\n'
	p.StreamProto = f.proto.String()
	r.feed(f, d, data[k:], p)
}

// boundary returns the offset in data of a clean message start, or -1. It
// may switch a TLS direction to modePass.
func (r *Reassembler) boundary(f *flow, d int, seq uint32, data []byte) int {
	h := &f.half[d]
	switch f.proto {
	case HTTP:
		if d == toServer && methodStart(data) || d == toClient && bytes.HasPrefix(data, httpSlash1) {
			return 0
		}
	case DNS:
		if plausibleDNS(data) {
			return 0
		}
	case FTP:
		if h.haveNxt && seq == h.nxt && h.lastNL {
			return 0
		}
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1
		}
	case TLS:
		switch tlsRecord(data) {
		case tlsHandshakeRecord:
			return 0
		case tlsOtherRecord:
			h.pass()
		}
	}
	return -1
}

// feed runs the protocol machine over bytes that start at nxt.
func (r *Reassembler) feed(f *flow, d int, data []byte, p *packet.ParsedPacket) {
	switch f.proto {
	case HTTP:
		r.feedHTTP(f, d, data, p)
	case DNS:
		r.feedDNS(f, d, data, p)
	case FTP:
		r.feedFTP(f, d, data, p)
	case TLS:
		r.feedTLS(f, d, data, p)
	}
	h := &f.half[d]
	if h.mode != modePass && len(data) > 0 {
		h.lastNL = data[len(data)-1] == '\n'
	}
}

// deliver appends a complete message to p.AppData. owned says msg is a
// buffer the direction gives up, which may become AppData without a copy.
// seq is where the message starts.
func (r *Reassembler) deliver(h *half, p *packet.ParsedPacket, msg []byte, seq uint32, owned bool) {
	if p.AppData == nil && owned {
		p.AppData = msg[:len(msg):len(msg)]
	} else {
		p.AppData = append(p.AppData, msg...)
	}
	h.hist = p.AppData[len(p.AppData)-len(msg):]
	h.histSeq = seq
	h.completed = true
	r.st.messages.Add(1)
}

// ---- HTTP ----

var (
	httpSlash1 = []byte("HTTP/1.")
	h2cPreface = []byte("PRI * HTTP/2.0\r\n")
)

// httpMethods are the methods a desynced client direction resyncs on.
var httpMethods = []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"}

func methodStart(b []byte) bool {
	for _, m := range httpMethods {
		if len(b) > len(m) && b[len(m)] == ' ' && string(b[:len(m)]) == m {
			return true
		}
	}
	return false
}

// plausibleHTTPStart checks the start of a message: a request must begin
// with a token of up to 20 uppercase letters, '-' or '_' and a space, a
// response with "HTTP/1.". decided is false while b is too short to tell.
func plausibleHTTPStart(b []byte, response bool) (ok, decided bool) {
	if response {
		n := min(len(b), len(httpSlash1))
		if !bytes.Equal(b[:n], httpSlash1[:n]) {
			return false, true
		}
		return true, n == len(httpSlash1)
	}
	for i := 0; i < len(b) && i <= 20; i++ {
		switch c := b[i]; {
		case c == ' ':
			return i > 0, true
		case 'A' <= c && c <= 'Z', c == '-', c == '_':
		default:
			return false, true
		}
	}
	return len(b) <= 20, len(b) > 20
}

// headEnd returns the index just past the blank line ending an HTTP head
// in b ("\n\r\n" or "\n\n"), searching from from, or -1.
func headEnd(b []byte, from int) int {
	for i := from; i < len(b); {
		j := bytes.IndexByte(b[i:], '\n')
		if j < 0 {
			return -1
		}
		k := i + j + 1
		if k < len(b) && b[k] == '\n' {
			return k + 1
		}
		if k+1 < len(b) && b[k] == '\r' && b[k+1] == '\n' {
			return k + 2
		}
		i = k
	}
	return -1
}

func (r *Reassembler) feedHTTP(f *flow, d int, data []byte, p *packet.ParsedPacket) {
	h := &f.half[d]
	for len(data) > 0 && h.mode == modeSync {
		switch h.phase {
		case phBody:
			rem := int(h.bodyEnd - h.nxt)
			if rem <= 0 || !seqLT(h.nxt, h.bodyEnd) {
				h.phase = phIdle
				continue
			}
			if len(data) >= rem {
				data = data[rem:]
				h.nxt, h.bodyHigh, h.phase = h.bodyEnd, h.bodyEnd, phIdle
				continue
			}
			// The rest of the body is skipped by sequence number: later
			// body segments are behind nxt and only move bodyHigh.
			h.bodyHigh = h.nxt + uint32(len(data))
			h.nxt = h.bodyEnd
			return
		case phIdle:
			n := 0
			for n < len(data) && (data[n] == '\r' || data[n] == '\n') {
				n++
			}
			h.nxt += uint32(n)
			data = data[n:]
			if len(data) == 0 {
				return
			}
			h.phase, h.checked, h.scan = phHead, false, 0
			h.msgSeq, h.msgStart = h.nxt, r.now
		case phHead:
			data = r.httpHead(f, d, data, p)
		}
	}
}

// httpHead consumes bytes of a message head and returns what is left
// after it.
func (r *Reassembler) httpHead(f *flow, d int, data []byte, p *packet.ParsedPacket) []byte {
	h := &f.half[d]
	room := MaxHTTPHead - len(h.buf)
	take := data[:min(len(data), room)]
	var msg []byte
	owned := false
	if len(h.buf) == 0 {
		msg = take
	} else {
		h.buf = append(h.buf, take...)
		msg = h.buf
		owned = true
	}
	if !h.checked {
		ok, decided := plausibleHTTPStart(msg, d == toClient)
		if !ok {
			r.lose(h, false)
			unstream(p)
			return nil
		}
		h.checked = decided
	}
	end := headEnd(msg, h.scan)
	if end < 0 {
		if len(data) > room {
			r.anomaly(h, p, packet.StreamOversizeHeaders)
			return nil
		}
		if !owned {
			h.buf = append(make([]byte, 0, max(512, 2*len(take))), take...)
		}
		h.scan = max(0, len(h.buf)-3)
		h.nxt += uint32(len(data))
		return nil
	}
	used := end - (len(msg) - len(take))
	h.nxt += uint32(used)
	h.buf = nil
	msg = msg[:end]
	r.deliver(h, p, msg, h.msgSeq, owned)
	h.lastHead = end
	r.httpComplete(f, d, msg)
	return data[used:]
}

// httpComplete sets up what follows a complete head: a body, the next
// message, or per-segment parsing.
func (r *Reassembler) httpComplete(f *flow, d int, head []byte) {
	h := &f.half[d]
	h.phase = phIdle
	cl, clOK, chunked := bodyHeaders(head)
	if d == toServer {
		if bytes.HasPrefix(head, h2cPreface) {
			f.half[0].pass()
			f.half[1].pass()
			return
		}
		var kind uint64
		switch {
		case bytes.HasPrefix(head, []byte("HEAD ")):
			kind = reqHEAD
		case bytes.HasPrefix(head, []byte("CONNECT ")):
			kind = reqCONNECT
		}
		f.pushRequest(kind)
	} else {
		code := statusCode(head)
		if code >= 100 && code < 200 {
			if code == 101 {
				f.half[0].pass()
				f.half[1].pass()
			}
			return // interim response: the final one follows
		}
		kind := f.popRequest()
		if kind == reqCONNECT && code >= 200 && code < 300 {
			f.half[0].pass()
			f.half[1].pass()
			return
		}
		if kind == reqHEAD || code == 204 || code == 304 {
			return
		}
		if !chunked && !clOK {
			chunked = true // read until close: wait for a boundary
		}
	}
	switch {
	case chunked || !clOK && cl != 0 || cl > maxBodySkip:
		h.desync()
		h.chunked = true
	case cl > 0:
		h.phase = phBody
		h.bodyStart, h.bodyEnd, h.bodyHigh = h.nxt, h.nxt+uint32(cl), h.nxt
		h.bodyLen = cl
	}
}

// Request kinds remembered for their responses.
const (
	reqOther   = 0
	reqHEAD    = 1
	reqCONNECT = 2
)

const maxPending = 32

func (f *flow) pushRequest(kind uint64) {
	if f.pendingLen == maxPending {
		f.pending >>= 2
		f.pendingLen--
	}
	f.pending |= kind << (2 * f.pendingLen)
	f.pendingLen++
}

func (f *flow) popRequest() uint64 {
	if f.pendingLen == 0 {
		return reqOther
	}
	k := f.pending & 3
	f.pending >>= 2
	f.pendingLen--
	return k
}

// bodyHeaders reads Content-Length and Transfer-Encoding from a head.
// clOK is false if Content-Length is absent (cl 0) or invalid or
// repeated with different values (cl 1).
func bodyHeaders(head []byte) (cl uint64, clOK bool, chunked bool) {
	seen, bad := false, false
	for line := range bytes.SplitSeq(head, []byte("\n")) {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		name = bytes.TrimRight(name, " \t")
		value = bytes.Trim(value, " \t\r")
		switch {
		case bytes.EqualFold(name, []byte("content-length")):
			n, err := strconv.ParseUint(string(value), 10, 64)
			if err != nil || seen && n != cl {
				bad = true
			}
			cl, seen = n, true
		case bytes.EqualFold(name, []byte("transfer-encoding")):
			if bytes.Contains(bytes.ToLower(value), []byte("chunked")) {
				chunked = true
			}
		}
	}
	if bad {
		return 1, false, chunked
	}
	return cl, seen, chunked
}

// statusCode returns the status code of a response head, or 0.
func statusCode(head []byte) int {
	if len(head) < 12 || head[8] != ' ' {
		return 0
	}
	n, err := strconv.Atoi(string(head[9:12]))
	if err != nil {
		return 0
	}
	return n
}

// setHTTPFields writes the http_* AppFields for a client-to-server packet.
func (h *half) setHTTPFields(p *packet.ParsedPacket) {
	var state string
	switch {
	case h.mode == modePass || h.mode == modeDesync && !h.chunked:
		return
	case h.mode == modeDesync:
		state = "body_partial"
	case h.phase == phHead:
		state = "headers_partial"
		p.SetAppField("http_hdr_bytes", strconv.FormatUint(uint64(h.nxt-h.msgSeq), 10))
	case h.phase == phBody:
		state = "body_partial"
		p.SetAppField("http_body_expected", strconv.FormatUint(h.bodyLen, 10))
		p.SetAppField("http_body_seen", strconv.FormatUint(uint64(h.bodyHigh-h.bodyStart), 10))
	case h.completed:
		state = "headers_complete"
		p.SetAppField("http_hdr_bytes", strconv.Itoa(h.lastHead))
	default:
		p.SetAppField("http_state", "idle")
		return
	}
	p.SetAppField("http_state", state)
	p.SetAppField("http_msg_start", strconv.FormatInt(h.msgStart.UnixNano(), 10))
}

// ---- DNS ----

const dnsHeaderLen = 12

// plausibleDNS reports whether b starts with a DNS-over-TCP message: a
// length prefix of at least a header, and a header with an assigned
// opcode and at most one question.
func plausibleDNS(b []byte) bool {
	if len(b) < 2+dnsHeaderLen {
		return false
	}
	n := int(b[0])<<8 | int(b[1])
	opcode := b[4] >> 3 & 0x0F
	qd := int(b[6])<<8 | int(b[7])
	return n >= dnsHeaderLen && opcode != 3 && opcode <= 6 && qd <= 1
}

func (r *Reassembler) feedDNS(f *flow, d int, data []byte, p *packet.ParsedPacket) {
	h := &f.half[d]
	for len(data) > 0 && h.mode == modeSync {
		if len(h.buf) == 0 && len(data) >= 2 {
			n := 2 + (int(data[0])<<8 | int(data[1]))
			if n < 2+dnsHeaderLen {
				r.lose(h, false)
				unstream(p)
				return
			}
			if len(data) >= n {
				r.deliver(h, p, data[:n], h.nxt, false)
				h.nxt += uint32(n)
				data = data[n:]
				continue
			}
			h.buf = append(make([]byte, 0, n), data...)
			h.nxt += uint32(len(data))
			return
		}
		if len(h.buf) < 2 {
			h.buf = append(h.buf, data[0])
			h.nxt++
			data = data[1:]
			if len(h.buf) < 2 {
				continue
			}
			n := 2 + (int(h.buf[0])<<8 | int(h.buf[1]))
			if n < 2+dnsHeaderLen {
				r.lose(h, false)
				unstream(p)
				return
			}
			h.buf = append(make([]byte, 0, n), h.buf...)
		}
		n := 2 + (int(h.buf[0])<<8 | int(h.buf[1]))
		take := min(len(data), n-len(h.buf))
		h.buf = append(h.buf, data[:take]...)
		h.nxt += uint32(take)
		data = data[take:]
		if len(h.buf) == n {
			start := h.nxt - uint32(n)
			msg := h.buf
			h.buf = nil
			r.deliver(h, p, msg, start, true)
		}
	}
}

// ---- FTP ----

var ftpAuthOK = []byte("234")

func (r *Reassembler) feedFTP(f *flow, d int, data []byte, p *packet.ParsedPacket) {
	h := &f.half[d]
	for len(data) > 0 && h.mode == modeSync {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			if len(h.buf)+len(data) > MaxFTPLine {
				r.lose(h, true)
				unstream(p)
				return
			}
			if len(h.buf) == 0 {
				h.buf = make([]byte, 0, max(128, 2*len(data)))
			}
			h.buf = append(h.buf, data...)
			h.nxt += uint32(len(data))
			return
		}
		line := data[:i+1]
		owned := false
		if len(h.buf) > 0 {
			line = append(h.buf, line...)
			owned = true
		}
		h.buf = nil
		if len(line) > MaxFTPLine {
			r.lose(h, true)
			unstream(p)
			return
		}
		r.deliver(h, p, line, h.nxt+uint32(i+1)-uint32(len(line)), owned)
		h.nxt += uint32(i + 1)
		data = data[i+1:]
		if d == toClient && bytes.HasPrefix(line, ftpAuthOK) && (len(line) == 3 || line[3] == ' ' || line[3] == '\r') {
			// AUTH TLS accepted: the rest of the connection is TLS.
			f.half[0].pass()
			f.half[1].pass()
			return
		}
	}
}

// ---- TLS ----

const (
	tlsNotRecord = iota
	tlsHandshakeRecord
	tlsOtherRecord
)

// tlsRecord classifies a record header at the start of b.
func tlsRecord(b []byte) int {
	if len(b) < 5 || b[1] != 3 || b[2] > 4 {
		return tlsNotRecord
	}
	n := int(b[3])<<8 | int(b[4])
	switch {
	case b[0] == 22 && n >= 1 && n <= MaxTLSRecord-5:
		return tlsHandshakeRecord
	case b[0] >= 20 && b[0] <= 24 && n >= 1:
		return tlsOtherRecord
	}
	return tlsNotRecord
}

func (r *Reassembler) feedTLS(f *flow, d int, data []byte, p *packet.ParsedPacket) {
	h := &f.half[d]
	if len(h.buf) < 5 {
		take := min(len(data), 5-len(h.buf))
		hdr := append(h.buf[:len(h.buf):len(h.buf)], data[:take]...)
		if len(hdr) < 5 {
			h.buf = hdr
			h.nxt += uint32(take)
			return
		}
		if tlsRecord(hdr) != tlsHandshakeRecord {
			h.pass()
			unstream(p)
			return
		}
		n := 5 + (int(hdr[3])<<8 | int(hdr[4]))
		if len(h.buf) == 0 && len(data) >= n {
			r.deliver(h, p, data[:n], h.nxt, false)
			h.pass()
			return
		}
		h.buf = append(make([]byte, 0, n), hdr...)
		h.nxt += uint32(take)
		data = data[take:]
	}
	n := 5 + (int(h.buf[3])<<8 | int(h.buf[4]))
	take := min(len(data), n-len(h.buf))
	h.buf = append(h.buf, data[:take]...)
	h.nxt += uint32(take)
	if len(h.buf) == n {
		msg := h.buf
		h.buf = nil
		r.deliver(h, p, msg, h.nxt-uint32(n), true)
		h.pass()
	}
}
