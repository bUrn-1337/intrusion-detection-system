package stream

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// conn drives one TCP connection through a Reassembler.
type conn struct {
	t          *testing.T
	r          *Reassembler
	now        time.Time
	cli, srv   string
	cport      uint16
	sport      uint16
	cseq, sseq uint32 // next byte each side sends
}

func newConn(t *testing.T, r *Reassembler, sport uint16) *conn {
	return &conn{t: t, r: r, now: t0, cli: "10.0.0.1", srv: "10.0.0.2", cport: 40000, sport: sport, cseq: 1000, sseq: 5000}
}

func mkpkt(ts time.Time, src, dst string, sp, dp uint16, flags string, seq uint32, payload []byte) *packet.ParsedPacket {
	p := packet.NewParsedPacket(ts, uint32(len(payload)), uint32(len(payload)))
	p.RawData = payload
	p.PayloadOffset = 0
	p.L4Offset = 0
	p.L4Proto = packet.L4TCP
	p.IPSrc, p.IPDst = net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	p.SrcPort, p.DstPort = sp, dp
	p.TCPSeq = seq
	p.TCPWindow = 64240
	for _, c := range flags {
		switch c {
		case 'S':
			p.TCPFlags.SYN = true
		case 'A':
			p.TCPFlags.ACK = true
		case 'F':
			p.TCPFlags.FIN = true
		case 'R':
			p.TCPFlags.RST = true
		case 'P':
			p.TCPFlags.PSH = true
		}
	}
	return p
}

// raw sends a segment at an explicit sequence number without moving the
// side's next sequence number.
func (c *conn) raw(fromClient bool, flags string, seq uint32, payload string) *packet.ParsedPacket {
	var p *packet.ParsedPacket
	if fromClient {
		p = mkpkt(c.now, c.cli, c.srv, c.cport, c.sport, flags, seq, []byte(payload))
	} else {
		p = mkpkt(c.now, c.srv, c.cli, c.sport, c.cport, flags, seq, []byte(payload))
	}
	c.r.Process(p)
	return p
}

// send sends payload in order from one side.
func (c *conn) send(fromClient bool, payload string) *packet.ParsedPacket {
	seq := &c.sseq
	if fromClient {
		seq = &c.cseq
	}
	p := c.raw(fromClient, "PA", *seq, payload)
	*seq += uint32(len(payload))
	return p
}

func (c *conn) handshake() {
	c.raw(true, "S", c.cseq-1, "")
	c.raw(false, "SA", c.sseq-1, "")
	c.raw(true, "A", c.cseq, "")
}

func (c *conn) wait(d time.Duration) { c.now = c.now.Add(d) }

func appData(p *packet.ParsedPacket) string { return string(p.AppData) }

func TestUntrackedPort(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 22)
	c.handshake()
	p := c.send(true, "SSH-2.0-x\r\n")
	if p.FlowID != 0 || p.StreamProto != "" || p.AppData != nil || !p.FlowStart.IsZero() {
		t.Fatalf("port 22 touched: %+v", p)
	}
	if r.Stats().FlowsTotal != 0 {
		t.Fatal("flow opened for port 22")
	}
}

func TestHTTPInOrderSplit(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 80)
	c.handshake()
	req := "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n"
	p1 := c.send(true, req[:10])
	p2 := c.send(true, req[10:30])
	p3 := c.send(true, req[30:])
	if p1.AppData != nil || p2.AppData != nil {
		t.Fatal("partial segment got AppData")
	}
	if p1.StreamProto != packet.AppHTTP || p2.StreamProto != packet.AppHTTP {
		t.Fatalf("StreamProto = %q", p1.StreamProto)
	}
	if appData(p3) != req {
		t.Fatalf("AppData = %q", p3.AppData)
	}
	if p1.FlowID == 0 || p1.FlowID != p3.FlowID || !p1.FlowStart.Equal(t0) {
		t.Fatalf("flow id/start: %d %d %v", p1.FlowID, p3.FlowID, p1.FlowStart)
	}
	if got := p1.AppFields["http_state"]; got != "headers_partial" {
		t.Errorf("p1 http_state = %q", got)
	}
	if got := p2.AppFields["http_hdr_bytes"]; got != "30" {
		t.Errorf("p2 http_hdr_bytes = %q", got)
	}
	if got := p3.AppFields["http_state"]; got != "headers_complete" {
		t.Errorf("p3 http_state = %q", got)
	}
	// Server packets never get http_* fields.
	resp := c.send(false, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	if resp.AppFields["http_state"] != "" {
		t.Error("server packet got http_state")
	}
	if !strings.HasPrefix(appData(resp), "HTTP/1.1 200 OK") || strings.Contains(appData(resp), "hello") {
		t.Errorf("response AppData = %q", resp.AppData)
	}
	idle := c.raw(true, "A", c.cseq, "")
	if got := idle.AppFields["http_state"]; got != "idle" {
		t.Errorf("idle http_state = %q", got)
	}
	if _, ok := idle.AppFields["http_msg_start"]; ok {
		t.Error("idle packet has http_msg_start")
	}
}

func TestHTTPOutOfOrder(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 80)
	c.handshake()
	req := "GET /a HTTP/1.1\r\nHost: h\r\n\r\n"
	base := c.cseq
	p2 := c.raw(true, "PA", base+10, req[10:20])
	p3 := c.raw(true, "PA", base+20, req[20:])
	if p2.AppData != nil || p3.AppData != nil {
		t.Fatal("AppData before the gap closed")
	}
	p1 := c.raw(true, "PA", base, req[:10])
	if appData(p1) != req {
		t.Fatalf("AppData = %q", p1.AppData)
	}
	if s := r.Stats(); s.Gaps != 0 || s.Desyncs != 0 {
		t.Fatalf("stats %+v", s)
	}
}

func TestHTTPGapTimeoutAndResync(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 80)
	c.handshake()
	base := c.cseq
	c.raw(true, "PA", base+10, "later")
	c.wait(4 * time.Second)
	c.raw(true, "PA", base+15, "more") // within the timeout: held
	if s := r.Stats(); s.Gaps != 0 {
		t.Fatal("gap timed out early")
	}
	c.wait(1500 * time.Millisecond)
	p := c.raw(true, "PA", base+19, "x")
	if s := r.Stats(); s.Gaps != 1 || s.Desyncs != 1 {
		t.Fatalf("after timeout: %+v", s)
	}
	if p.StreamProto != "" {
		t.Error("desynced packet has StreamProto")
	}
	if _, ok := p.AppFields["http_state"]; ok {
		t.Error("desynced packet has http_state")
	}
	// A segment starting with a method resyncs.
	req := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"
	q := c.raw(true, "PA", base+100, req)
	if appData(q) != req || q.StreamProto != packet.AppHTTP {
		t.Fatalf("resync AppData = %q", q.AppData)
	}
	if r.Stats().Resyncs != 1 {
		t.Fatal("resync not counted")
	}
}

func TestHTTPPipelinedAndBodies(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 80)
	c.handshake()
	a := "GET /1 HTTP/1.1\r\nHost: h\r\n\r\n"
	b := "POST /2 HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\n"
	body := "0123456789"
	d := "\r\nGET /3 HTTP/1.1\r\nHost: h\r\n\r\n"
	p := c.send(true, a+b+body+d)
	want := a + b + strings.TrimPrefix(d, "\r\n")
	if appData(p) != want {
		t.Fatalf("AppData = %q\nwant %q", p.AppData, want)
	}
	// A body split over segments is skipped by sequence number.
	e := "PUT /4 HTTP/1.1\r\nContent-Length: 20\r\n\r\n"
	p = c.send(true, e+"0123")
	if p.AppFields["http_state"] != "body_partial" || p.AppFields["http_body_expected"] != "20" || p.AppFields["http_body_seen"] != "4" {
		t.Fatalf("fields %v", p.AppFields)
	}
	if p.AppFields["http_msg_start"] != "1767225600000000000" {
		t.Errorf("msg_start %q", p.AppFields["http_msg_start"])
	}
	// A body that looks like a request is not parsed.
	p = c.send(true, "GET /x HTTP/1.")
	if p.AppData != nil || p.AppFields["http_body_seen"] != "18" {
		t.Fatalf("body parsed: %q %v", p.AppData, p.AppFields)
	}
	p = c.send(true, "12GET /5 HTTP/1.1\r\n\r\n")
	if appData(p) != "GET /5 HTTP/1.1\r\n\r\n" {
		t.Fatalf("after body: %q", p.AppData)
	}
	// A body in a segment of its own, not a message start.
	c.send(false, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n")
	c.send(false, "GIF89a")
	p = c.send(false, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	if appData(p) != "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" || r.Stats().Desyncs != 0 {
		t.Fatalf("after a body segment: %q %+v", p.AppData, r.Stats())
	}
}

func TestHTTPResponsesWithoutBodies(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 80)
	c.handshake()
	c.send(true, "HEAD / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n")
	c.send(false, "HTTP/1.1 100 Continue\r\n\r\n")
	p := c.send(false, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
	if p.AppData == nil {
		t.Fatal("HEAD response head not delivered")
	}
	// The HEAD response has no body, so this is the next response.
	p = c.send(false, "HTTP/1.1 304 Not Modified\r\n\r\n")
	if !strings.HasPrefix(appData(p), "HTTP/1.1 304") {
		t.Fatalf("second response: %q", p.AppData)
	}
}

func TestHTTPChunkedWaitsForBoundary(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 80)
	c.handshake()
	p := c.send(true, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
	if p.AppData == nil || p.AppFields["http_state"] != "body_partial" {
		t.Fatalf("chunked head: %q %v", p.AppData, p.AppFields)
	}
	p = c.send(true, "0\r\n\r\n")
	if p.AppData != nil || p.AppFields["http_state"] != "body_partial" {
		t.Fatalf("chunk end: %q %v", p.AppData, p.AppFields)
	}
	p = c.send(true, "GET / HTTP/1.1\r\n\r\n")
	if p.AppData == nil || p.AppFields["http_state"] != "headers_complete" {
		t.Fatalf("next request: %q %v", p.AppData, p.AppFields)
	}
	if s := r.Stats(); s.Desyncs != 0 || s.Resyncs != 0 {
		t.Fatalf("chunked body counted as desync: %+v", s)
	}
}

func TestHTTPUpgradePassesThrough(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 80)
	c.handshake()
	c.send(true, "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n")
	c.send(false, "HTTP/1.1 101 Switching Protocols\r\n\r\n")
	p := c.send(true, "GET frame that looks like http\r\n\r\n")
	if p.StreamProto != "" || p.AppData != nil {
		t.Fatal("upgraded flow still reassembled")
	}
	if _, ok := p.AppFields["http_state"]; ok {
		t.Fatal("upgraded flow has http_state")
	}
}

func TestHTTPImplausibleStartDesyncs(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 80)
	c.handshake()
	p := c.send(true, "\x16\x03\x01\x02\x00hello")
	if p.StreamProto != "" || r.Stats().Desyncs != 1 {
		t.Fatalf("TLS on port 80 kept in sync: %q %+v", p.StreamProto, r.Stats())
	}
	p = c.send(false, "garbage")
	if p.StreamProto != "" {
		t.Fatal("server garbage kept in sync")
	}
}

// A segment that completes a message and then desyncs keeps the message
// (found by FuzzStream: StreamProto was cleared with AppData set).
func TestDesyncAfterDeliveredMessage(t *testing.T) {
	for _, tc := range []struct {
		port    uint16
		payload string
		msg     string
	}{
		{80, "GET / HTTP/1.1\r\n\r\n\x16\x03", "GET / HTTP/1.1\r\n\r\n"},
		{53, string(prefixed(dnsMsg(1, 1, 0))) + "\x00\x01", string(prefixed(dnsMsg(1, 1, 0)))},
		{21, "USER a\r\n" + strings.Repeat("x", MaxFTPLine+1), "USER a\r\n"},
	} {
		r := New(Config{})
		c := newConn(t, r, tc.port)
		c.handshake()
		p := c.send(true, tc.payload)
		if p.StreamProto == "" || appData(p) != tc.msg || r.Stats().Desyncs != 1 {
			t.Errorf("port %d: proto %q AppData %q %+v", tc.port, p.StreamProto, appData(p), r.Stats())
		}
		if p = c.send(true, "more"); p.StreamProto != "" || p.AppData != nil {
			t.Errorf("port %d: next segment %q %q", tc.port, p.StreamProto, appData(p))
		}
	}
}

func TestHTTPMidstreamPickup(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 8080)
	p := c.send(true, "ody of something\r\n\r\n")
	if p.FlowID == 0 || p.StreamProto != "" || p.AppData != nil {
		t.Fatalf("midstream first segment: %+v", p)
	}
	req := "GET / HTTP/1.1\r\nHost: h\r\n\r\n"
	p = c.send(true, req)
	if appData(p) != req {
		t.Fatalf("resync: %q", p.AppData)
	}
	s := r.Stats()
	if s.Desyncs != 0 || s.Resyncs != 1 {
		t.Fatalf("stats %+v", s)
	}
	// The server is the side on the well-known port.
	p = c.send(false, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	if p.AppData == nil {
		t.Fatal("server direction not resynced")
	}
	if p.AppFields["http_state"] != "" {
		t.Fatal("server packet treated as client")
	}
}

// A head ends at a blank line, bare LF or CRLF; a CR not followed by LF
// does not end it.
func TestHTTPHeadTerminators(t *testing.T) {
	for _, req := range []string{
		"GET / HTTP/1.1\nHost: h\n\n",
		"GET / HTTP/1.1\r\nHost: h\r\n\n",
		"GET / HTTP/1.1\r\n\rX: y\r\nHost: h\r\n\r\n",
	} {
		r := New(Config{})
		c := newConn(t, r, 80)
		c.handshake()
		p := c.send(true, req+"GET /2 HTTP/1.1\r\n\r\n")
		if appData(p) != req+"GET /2 HTTP/1.1\r\n\r\n" || r.Stats().Messages != 2 {
			t.Errorf("%q: AppData %q, %d messages", req, p.AppData, r.Stats().Messages)
		}
	}
}

func TestOversizeHeaders(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 80)
	c.handshake()
	line := "X-Pad: " + strings.Repeat("a", 1000) + "\r\n"
	p := c.send(true, "GET / HTTP/1.1\r\n")
	for i := 0; i < 20 && p.StreamAnomaly == ""; i++ {
		p = c.send(true, line)
	}
	if p.StreamAnomaly != packet.StreamOversizeHeaders {
		t.Fatalf("anomaly = %q", p.StreamAnomaly)
	}
	if s := r.Stats(); s.OversizeHeaders != 1 || s.Buffered != 0 {
		t.Fatalf("stats %+v", s)
	}
	// Exactly at the cap is fine.
	c2 := newConn(t, r, 80)
	c2.cport = 40001
	c2.handshake()
	head := "GET / HTTP/1.1\r\nX: " + strings.Repeat("b", MaxHTTPHead-len("GET / HTTP/1.1\r\nX: ")-4) + "\r\n\r\n"
	if len(head) != MaxHTTPHead {
		t.Fatal(len(head))
	}
	c2.send(true, head[:100])
	p = c2.send(true, head[100:])
	if p.StreamAnomaly != "" || len(p.AppData) != MaxHTTPHead {
		t.Fatalf("head at cap: %q %d", p.StreamAnomaly, len(p.AppData))
	}
	// One byte over in a single segment is oversize too.
	c3 := newConn(t, r, 80)
	c3.cport = 40002
	c3.handshake()
	p = c3.send(true, head[:len(head)-4]+"x\r\n\r\n")
	if p.StreamAnomaly != packet.StreamOversizeHeaders {
		t.Fatalf("one over: %q", p.StreamAnomaly)
	}
}

func TestRetransmitAndOverlap(t *testing.T) {
	req := "GET /index.html HTTP/1.1\r\nHost: h\r\n\r\n"
	t.Run("identical", func(t *testing.T) {
		r := New(Config{})
		c := newConn(t, r, 80)
		c.handshake()
		base := c.cseq
		c.raw(true, "PA", base, req[:20])
		p := c.raw(true, "PA", base, req[:20])
		if p.StreamAnomaly != "" || p.AppData != nil {
			t.Fatal("identical retransmission flagged")
		}
		// Partial identical overlap straddling nxt.
		p = c.raw(true, "PA", base+10, req[10:])
		if p.StreamAnomaly != "" || appData(p) != req {
			t.Fatalf("straddle: %q %q", p.StreamAnomaly, p.AppData)
		}
		// Retransmission of the delivered message.
		p = c.raw(true, "PA", base+5, req[5:25])
		if p.StreamAnomaly != "" || p.AppData != nil {
			t.Fatal("retransmitted delivered bytes flagged")
		}
	})
	t.Run("identical held segment", func(t *testing.T) {
		r := New(Config{})
		c := newConn(t, r, 80)
		c.handshake()
		base := c.cseq
		c.raw(true, "PA", base+10, req[10:20])
		p := c.raw(true, "PA", base+10, req[10:20])
		if p.StreamAnomaly != "" {
			t.Fatal("identical retransmission of a held segment flagged")
		}
		c.raw(true, "PA", base, req[:10])
		p = c.raw(true, "PA", base+20, req[20:])
		if p.StreamAnomaly != "" || appData(p) != req {
			t.Fatalf("%q %q", p.StreamAnomaly, p.AppData)
		}
	})
	t.Run("conflict", func(t *testing.T) {
		r := New(Config{})
		c := newConn(t, r, 80)
		c.handshake()
		base := c.cseq
		c.raw(true, "PA", base, "GET /index.html HTTP/1.1\r\n")
		p := c.raw(true, "PA", base, "GET /admin.php. HTTP/1.1\r\n")
		if p.StreamAnomaly != packet.StreamOverlapConflict {
			t.Fatalf("anomaly = %q", p.StreamAnomaly)
		}
		p = c.raw(true, "PA", base+26, "Host: h\r\n\r\n")
		if p.AppData != nil {
			t.Fatalf("message parsed after conflict: %q", p.AppData)
		}
		if s := r.Stats(); s.OverlapConflicts != 1 || s.Desyncs != 1 {
			t.Fatalf("stats %+v", s)
		}
	})
	t.Run("partial conflict straddling", func(t *testing.T) {
		r := New(Config{})
		c := newConn(t, r, 80)
		c.handshake()
		base := c.cseq
		c.raw(true, "PA", base, req[:20])
		p := c.raw(true, "PA", base+18, "XX"+req[20:])
		if p.StreamAnomaly != packet.StreamOverlapConflict || p.AppData != nil {
			t.Fatalf("anomaly = %q data %q", p.StreamAnomaly, p.AppData)
		}
	})
	t.Run("conflict with held segment", func(t *testing.T) {
		r := New(Config{})
		c := newConn(t, r, 80)
		c.handshake()
		base := c.cseq
		c.raw(true, "PA", base+10, req[10:20])
		p := c.raw(true, "PA", base+10, "XXXXXXXXXX")
		if p.StreamAnomaly != packet.StreamOverlapConflict {
			t.Fatalf("anomaly = %q", p.StreamAnomaly)
		}
	})
	t.Run("conflict found when gap fills", func(t *testing.T) {
		r := New(Config{})
		c := newConn(t, r, 80)
		c.handshake()
		base := c.cseq
		c.raw(true, "PA", base+15, "YYYYY"+req[20:])
		p := c.raw(true, "PA", base, req[:20])
		if p.StreamAnomaly != packet.StreamOverlapConflict || p.AppData != nil {
			t.Fatalf("anomaly = %q data %q", p.StreamAnomaly, p.AppData)
		}
	})
	t.Run("conflict with delivered message", func(t *testing.T) {
		r := New(Config{})
		c := newConn(t, r, 80)
		c.handshake()
		base := c.cseq
		c.raw(true, "PA", base, req)
		p := c.raw(true, "PA", base+4, "/admin")
		if p.StreamAnomaly != packet.StreamOverlapConflict {
			t.Fatalf("anomaly = %q", p.StreamAnomaly)
		}
	})
}

func TestTooManyOOO(t *testing.T) {
	r := New(Config{MaxOOO: 4})
	c := newConn(t, r, 80)
	c.handshake()
	base := c.cseq
	var p *packet.ParsedPacket
	for i := range 5 {
		p = c.raw(true, "PA", base+10+uint32(i)*10, "0123456789")
	}
	if p.StreamAnomaly != packet.StreamTooManyOOO {
		t.Fatalf("anomaly = %q", p.StreamAnomaly)
	}
	if s := r.Stats(); s.OOOOverflows != 1 || s.Buffered != 0 {
		t.Fatalf("stats %+v", s)
	}
}

func TestSeqWraparound(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 80)
	c.cseq = 0xFFFFFFF6 // the request crosses 2^32
	c.handshake()
	req := "GET /wrap HTTP/1.1\r\nHost: h\r\n\r\n"
	p1 := c.send(true, req[:5])
	base := c.cseq
	p3 := c.raw(true, "PA", base+10, req[15:])
	p2 := c.raw(true, "PA", base, req[5:15])
	if p1.AppData != nil || p3.AppData != nil || appData(p2) != req {
		t.Fatalf("wrap: %q", p2.AppData)
	}
	p := c.raw(true, "PA", 0xFFFFFFF6, req[:5]) // retransmission from before the wrap
	if p.StreamAnomaly != "" {
		t.Fatal("pre-wrap retransmission flagged")
	}
}

func dnsMsg(id uint16, qd uint16, extra int) []byte {
	m := make([]byte, 12+extra)
	binary.BigEndian.PutUint16(m, id)
	binary.BigEndian.PutUint16(m[4:], qd)
	for i := 12; i < len(m); i++ {
		m[i] = byte(i)
	}
	return m
}

func prefixed(m []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(m))), m...)
}

func TestDNS(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 53)
	c.handshake()
	a := prefixed(dnsMsg(1, 1, 20))
	b := prefixed(dnsMsg(2, 1, 5))
	// Prefix split 1+1, then the rest.
	p1 := c.send(true, string(a[:1]))
	p2 := c.send(true, string(a[1:2]))
	p3 := c.send(true, string(a[2:]))
	if p1.AppData != nil || p2.AppData != nil || !bytes.Equal(p3.AppData, a) {
		t.Fatalf("split prefix: %x", p3.AppData)
	}
	// Two messages in one segment plus the start of a third.
	big := prefixed(dnsMsg(3, 0, 3000))
	p := c.send(true, string(a)+string(b)+string(big[:100]))
	if !bytes.Equal(p.AppData, append(append([]byte{}, a...), b...)) {
		t.Fatalf("two messages: %d bytes", len(p.AppData))
	}
	p = c.send(true, string(big[100:]))
	if !bytes.Equal(p.AppData, big) {
		t.Fatal("large message")
	}
	// A length below a header desyncs; a plausible message resyncs.
	p = c.send(true, "\x00\x05hello")
	if p.StreamProto != "" || r.Stats().Desyncs != 1 {
		t.Fatal("short length kept in sync")
	}
	p = c.send(true, "garbage garbage garbage")
	if p.AppData != nil {
		t.Fatal("garbage delivered")
	}
	p = c.send(true, string(b))
	if !bytes.Equal(p.AppData, b) || r.Stats().Resyncs != 1 {
		t.Fatalf("resync: %x", p.AppData)
	}
	// Two questions is not a resync boundary.
	c.send(true, "\x00\x05hello")
	p = c.send(true, string(prefixed(dnsMsg(4, 2, 0))))
	if p.AppData != nil {
		t.Fatal("resynced on qdcount 2")
	}
	// Neither is an unassigned opcode (3, or above 6).
	for _, op := range []byte{3, 7, 15} {
		m := dnsMsg(5, 1, 0)
		m[2] = op << 3
		if p = c.send(true, string(prefixed(m))); p.AppData != nil {
			t.Fatalf("resynced on opcode %d", op)
		}
	}
}

func TestFTP(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 21)
	c.handshake()
	p := c.send(false, "220 hi\r\n")
	if appData(p) != "220 hi\r\n" {
		t.Fatalf("%q", p.AppData)
	}
	c.send(true, "US")
	p = c.send(true, "ER alice\r\nPASS x\r\nSY")
	if appData(p) != "USER alice\r\nPASS x\r\n" {
		t.Fatalf("%q", p.AppData)
	}
	p = c.send(true, "ST\r\n")
	if appData(p) != "SYST\r\n" {
		t.Fatalf("%q", p.AppData)
	}
	// Line cap.
	c.send(true, strings.Repeat("a", MaxFTPLine-1))
	p = c.send(true, "bb")
	if p.StreamProto != "" || r.Stats().CapDrops != 1 {
		t.Fatalf("line cap: %+v", r.Stats())
	}
	// Resync after the next line ending.
	p = c.send(true, "tail\r\nNOOP\r\n")
	if appData(p) != "NOOP\r\n" {
		t.Fatalf("resync: %q", p.AppData)
	}
	// A line starting right after a desynced segment's line ending.
	c.raw(true, "PA", c.cseq+100, "junk\r\n") // leaves a gap
	c.wait(6 * time.Second)
	c.cseq += 106
	p = c.send(true, "x\r\n") // gap timeout desyncs; resync after "\n"
	if p.AppData != nil {
		t.Fatalf("mid-line data delivered: %q", p.AppData)
	}
	p = c.send(true, "QUIT\r\n")
	if appData(p) != "QUIT\r\n" {
		t.Fatalf("line after newline: %q", p.AppData)
	}
	// Line cap within one segment.
	p = c.send(true, "USER "+strings.Repeat("a", MaxFTPLine)+"\r\n")
	if p.AppData != nil || r.Stats().CapDrops != 2 {
		t.Fatalf("one-segment line cap: %q %+v", p.AppData, r.Stats())
	}
	c.send(true, "NOOP\r\n") // resyncs on the line ending
	// A gap filled only after the gap timeout: the late segment resyncs
	// at its start if the bytes before it ended a line, else after its
	// first line ending.
	for _, tc := range []struct{ before, late, want string }{
		{"NOOP\r\n", "SYST\r\n", "SYST\r\n"},
		{"NO", "OP\r\n", ""},
	} {
		c.send(true, tc.before)
		c.raw(true, "PA", c.cseq+uint32(len(tc.late)), "HELP\r\n")
		c.wait(6 * time.Second)
		p = c.send(true, tc.late)
		if appData(p) != tc.want {
			t.Fatalf("late gap fill after %q: %q, want %q", tc.before, p.AppData, tc.want)
		}
		c.send(true, "HELP\r\n") // the held segment again, now in order
		if p = c.send(true, "NOOP\r\n"); appData(p) != "NOOP\r\n" {
			t.Fatalf("after late gap fill: %q", p.AppData)
		}
	}
	// AUTH TLS accepted: per-segment parsing from now on.
	c.send(true, "AUTH TLS\r\n")
	c.send(false, "234 go ahead\r\n")
	p = c.send(true, "\x16\x03\x01\x00\x05hello")
	if p.StreamProto != "" || p.AppData != nil {
		t.Fatal("still reassembling after AUTH TLS")
	}
}

func tlsRec(n int) []byte {
	b := []byte{22, 3, 1, byte(n >> 8), byte(n)}
	for i := range n {
		b = append(b, byte(i))
	}
	return b
}

func TestTLS(t *testing.T) {
	r := New(Config{})
	c := newConn(t, r, 443)
	c.handshake()
	rec := tlsRec(1800)
	p1 := c.send(true, string(rec[:3]))
	p2 := c.send(true, string(rec[3:1400]))
	p3 := c.send(true, string(rec[1400:])+"\x14\x03\x03\x00\x01\x01")
	if p1.AppData != nil || p2.AppData != nil || !bytes.Equal(p3.AppData, rec) {
		t.Fatalf("split record: %d", len(p3.AppData))
	}
	p := c.send(true, "\x17\x03\x03\x00\x10encrypted.......")
	if p.StreamProto != "" || p.AppData != nil {
		t.Fatal("after the first record still reassembling")
	}
	// A first record that is not a handshake: per-segment parsing.
	c2 := newConn(t, r, 443)
	c2.cport = 40001
	c2.handshake()
	p = c2.send(true, "\x17\x03\x03\x00\x10encrypted.......")
	if p.StreamProto != "" {
		t.Fatal("non-handshake first record reassembled")
	}
	// Midstream: an application data record header passes through, a
	// handshake header resyncs.
	c3 := newConn(t, r, 443)
	c3.cport = 40002
	p = c3.send(true, string(tlsRec(10)))
	if !bytes.Equal(p.AppData, tlsRec(10)) {
		t.Fatalf("midstream handshake: %x", p.AppData)
	}
	// Midstream: after an application data record the direction passes
	// through, so a later handshake-looking header does not resync.
	c5 := newConn(t, r, 443)
	c5.cport = 40004
	c5.send(true, "\x17\x03\x03\x00\x10encrypted.......")
	if p = c5.send(true, string(tlsRec(10))); p.StreamProto != "" || p.AppData != nil {
		t.Fatalf("resynced after application data: %x", p.AppData)
	}
	// Record length over the cap.
	c4 := newConn(t, r, 443)
	c4.cport = 40003
	c4.handshake()
	p = c4.send(true, "\x16\x03\x01\x40\x01xxxx")
	if p.StreamProto != "" {
		t.Fatal("oversize record reassembled")
	}
}

func TestCleanup(t *testing.T) {
	t.Run("fin both sides", func(t *testing.T) {
		r := New(Config{})
		c := newConn(t, r, 80)
		c.handshake()
		p := c.send(true, "GET / HTTP/1.1\r\n\r\n")
		id := p.FlowID
		p = c.raw(true, "FA", c.cseq, "")
		if p.ClosedFlows != nil {
			t.Fatal("closed after one FIN")
		}
		p = c.raw(false, "FA", c.sseq, "")
		if len(p.ClosedFlows) != 1 || p.ClosedFlows[0] != id || p.FlowID != id {
			t.Fatalf("closed = %v", p.ClosedFlows)
		}
		if s := r.Stats(); s.Flows != 0 || s.Closed != 1 || s.Charged != 0 {
			t.Fatalf("stats %+v", s)
		}
		p = c.raw(true, "A", c.cseq+1, "")
		if p.FlowID != 0 {
			t.Fatal("final ACK reopened the flow")
		}
	})
	t.Run("rst", func(t *testing.T) {
		r := New(Config{})
		c := newConn(t, r, 80)
		c.handshake()
		c.send(true, "GET / HTTP/1.1\r\n")
		p := c.raw(false, "R", c.sseq+5<<20, "") // far outside the window
		if p.ClosedFlows != nil {
			t.Fatal("out-of-window RST closed the flow")
		}
		p = c.raw(false, "RA", c.sseq, "")
		if len(p.ClosedFlows) != 1 {
			t.Fatal("RST did not close")
		}
		if r.Stats().Buffered != 0 {
			t.Fatal("buffers not released")
		}
	})
	t.Run("idle", func(t *testing.T) {
		r := New(Config{IdleTimeout: time.Minute})
		c := newConn(t, r, 80)
		c.handshake()
		id := c.send(true, "GET / HTTP/1.1\r\n").FlowID
		other := newConn(t, r, 80)
		other.cport = 40001
		other.now = t0.Add(61 * time.Second)
		p := other.send(true, "GET / HTTP/1.1\r\n\r\n")
		if len(p.ClosedFlows) != 1 || p.ClosedFlows[0] != id {
			t.Fatalf("idle closed = %v", p.ClosedFlows)
		}
		if r.Stats().IdleClosed != 1 {
			t.Fatal("idle not counted")
		}
	})
	t.Run("new SYN on same tuple", func(t *testing.T) {
		r := New(Config{})
		c := newConn(t, r, 80)
		c.handshake()
		id := c.send(true, "GET / HTTP/1.1\r\n").FlowID
		p := c.raw(true, "S", c.cseq-1, "") // SYN retransmission: same flow? no: ISN differs
		if len(p.ClosedFlows) != 1 || p.ClosedFlows[0] != id || p.FlowID == id {
			t.Fatalf("new connection: closed %v id %d", p.ClosedFlows, p.FlowID)
		}
		p2 := c.raw(true, "S", c.cseq-1, "")
		if p2.ClosedFlows != nil || p2.FlowID != p.FlowID {
			t.Fatal("retransmitted SYN restarted the flow")
		}
	})
	t.Run("no flow for bare ack or rst", func(t *testing.T) {
		r := New(Config{})
		c := newConn(t, r, 80)
		if c.raw(true, "A", 1, "").FlowID != 0 || c.raw(true, "R", 1, "").FlowID != 0 || c.raw(true, "FA", 1, "").FlowID != 0 {
			t.Fatal("flow opened")
		}
	})
}

func TestBackwardsTime(t *testing.T) {
	r := New(Config{IdleTimeout: time.Minute})
	c := newConn(t, r, 80)
	c.now = t0.Add(time.Hour)
	c.handshake()
	c.send(true, "GET / HTTP/1.1\r\n")
	c.now = t0 // clock steps back
	p := c.send(true, "Host: h\r\n\r\n")
	if p.AppData == nil {
		t.Fatal("message lost")
	}
	if !p.FlowStart.Equal(t0.Add(time.Hour)) {
		t.Fatal("flow start moved")
	}
	// Engine time did not go back, so the flow is not idle-expired early
	// or late: 61 s after the latest time it is.
	other := newConn(t, r, 80)
	other.cport = 40001
	other.now = t0.Add(time.Hour + 30*time.Second)
	if p := other.send(true, "GET / HTTP/1.1\r\n\r\n"); p.ClosedFlows != nil {
		t.Fatal("expired early")
	}
	other.now = t0.Add(time.Hour + 61*time.Second)
	if p := other.send(true, "GET / HTTP/1.1\r\n\r\n"); len(p.ClosedFlows) != 1 {
		t.Fatal("not expired")
	}
	// A request timestamped in the past gets engine time as msg_start.
	c3 := newConn(t, r, 80)
	c3.cport = 40002
	c3.now = t0
	p = c3.send(true, "GET / HTTP/1.1\r\n")
	if p.AppFields["http_msg_start"] != "1767229261000000000" {
		t.Fatalf("msg_start %s", p.AppFields["http_msg_start"])
	}
}

func TestPerFlowCap(t *testing.T) {
	r := New(Config{MaxFlowBytes: 1}) // raised to 2*MaxDNSMessage
	c := newConn(t, r, 53)
	c.handshake()
	base := c.cseq
	// Out-of-order segments pile up past the per-flow cap.
	var p *packet.ParsedPacket
	for i := range 3 {
		p = c.raw(true, "PA", base+100+uint32(i)*60000, strings.Repeat("x", 60000))
	}
	if p.StreamProto != "" || r.Stats().CapDrops != 1 {
		t.Fatalf("stats %+v", r.Stats())
	}
	if s := r.Stats(); s.Buffered != 0 {
		t.Fatalf("buffered %d", s.Buffered)
	}
}

func TestGlobalCapEvictsLRU(t *testing.T) {
	r := New(Config{MaxBytes: 100 * flowOverhead})
	var first uint64
	for i := range 300 {
		c := newConn(t, r, 80)
		c.cport = uint16(10000 + i)
		c.now = t0.Add(time.Duration(i) * time.Millisecond)
		p := c.send(true, "GET / HTTP/1.1\r\n")
		if i == 0 {
			first = p.FlowID
		}
		if s := r.Stats(); s.Charged > 100*int64(flowOverhead) && s.Flows > 1 {
			t.Fatalf("over cap: %+v", s)
		}
	}
	s := r.Stats()
	if s.Evictions == 0 || s.Flows > 100 || s.Charged > 100*int64(flowOverhead) {
		t.Fatalf("stats %+v", s)
	}
	if len(r.flows) != int(s.Flows) {
		t.Fatal("flow count mismatch")
	}
	for _, f := range r.flows {
		if f.id == first {
			t.Fatal("oldest flow not evicted")
		}
	}
	// The most recently used flow survives: touch the oldest remaining,
	// add more, and it is still there.
	oldest := r.tail
	c := newConn(t, r, 80)
	c.cport = uint16(10000 + 300 - int(s.Flows))
	c.now = t0.Add(time.Second)
	if p := c.send(true, "Host: h\r\n\r\n"); p.FlowID != oldest.id {
		t.Fatalf("touched %d, oldest %d", p.FlowID, oldest.id)
	}
	d := newConn(t, r, 80)
	d.cport = 20000
	d.now = t0.Add(2 * time.Second)
	d.send(true, "GET / HTTP/1.1\r\n")
	if r.tail.id == oldest.id {
		t.Fatal("touched flow is still least recent")
	}
}
