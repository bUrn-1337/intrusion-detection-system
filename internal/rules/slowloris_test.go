package rules

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/app"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
	"github.com/bUrn-1337/intrusion-detection-system/internal/stream"
)

// streamHarness runs packets through lower -> upper -> stream -> app ->
// engine, as the ids pipeline does.
type streamHarness struct {
	tb  testing.TB
	e   *Engine
	rsm *stream.Reassembler
	out []Alert
}

func newStreamHarness(tb testing.TB, rules string, cfg EngineConfig) *streamHarness {
	return &streamHarness{tb: tb, e: NewEngine(mustParse(tb, rules), cfg), rsm: stream.New(stream.Config{})}
}

func (h *streamHarness) send(s pkt, d time.Duration) *packet.ParsedPacket {
	h.tb.Helper()
	b := s.bytes(h.tb)
	p := packet.NewParsedPacket(at(d), uint32(len(b)), uint32(len(b)))
	p.RawData = b
	lower.Parse(p)
	upper.Parse(p)
	h.rsm.Process(p)
	app.Parse(p)
	h.out = append(h.out, h.e.Process(p)...)
	return p
}

func (h *streamHarness) flush() { h.out = append(h.out, h.e.Flush()...) }

// fired returns the Kind "alert" alerts of sid.
func (h *streamHarness) fired(sid int) []Alert {
	var as []Alert
	for _, a := range h.out {
		if a.SID == sid && a.Kind == KindAlert {
			as = append(as, a)
		}
	}
	return as
}

// tconn is one TCP connection of a streamHarness.
type tconn struct {
	h              *streamHarness
	client, server string
	cport, sport   uint16
	cseq, sseq     uint32
}

func (h *streamHarness) conn(client, server string, cport, sport uint16) *tconn {
	return &tconn{h: h, client: client, server: server, cport: cport, sport: sport, cseq: 1000, sseq: 5000}
}

func (c *tconn) open(d time.Duration) *tconn {
	c.h.send(pkt{proto: "tcp", src: c.client, dst: c.server, sport: c.cport, dport: c.sport, flags: "S", seq: c.cseq}, d)
	c.cseq++
	c.h.send(pkt{proto: "tcp", src: c.server, dst: c.client, sport: c.sport, dport: c.cport, flags: "SA", seq: c.sseq, ack: c.cseq}, d)
	c.sseq++
	c.h.send(pkt{proto: "tcp", src: c.client, dst: c.server, sport: c.cport, dport: c.sport, flags: "A", seq: c.cseq, ack: c.sseq}, d)
	return c
}

// write sends data from the client.
func (c *tconn) write(d time.Duration, data string) *packet.ParsedPacket {
	p := c.h.send(pkt{proto: "tcp", src: c.client, dst: c.server, sport: c.cport, dport: c.sport, flags: "PA", seq: c.cseq, ack: c.sseq, payload: data}, d)
	c.cseq += uint32(len(data))
	return p
}

// reply sends data from the server.
func (c *tconn) reply(d time.Duration, data string) {
	c.h.send(pkt{proto: "tcp", src: c.server, dst: c.client, sport: c.sport, dport: c.cport, flags: "PA", seq: c.sseq, ack: c.cseq, payload: data}, d)
	c.sseq += uint32(len(data))
}

// ack sends a bare ACK from the client, with a zero window if zero.
func (c *tconn) ack(d time.Duration, zero bool) {
	c.h.send(pkt{proto: "tcp", src: c.client, dst: c.server, sport: c.cport, dport: c.sport, flags: "A", seq: c.cseq, ack: c.sseq, zeroWin: zero}, d)
}

// close sends a RST (rst) or a FIN from the client.
func (c *tconn) close(d time.Duration, rst bool) {
	flags := "FA"
	if rst {
		flags = "R"
	}
	c.h.send(pkt{proto: "tcp", src: c.client, dst: c.server, sport: c.cport, dport: c.sport, flags: flags, seq: c.cseq, ack: c.sseq}, d)
}

// tick sends an unrelated packet, only to advance the clock.
func (h *streamHarness) tick(d time.Duration) {
	h.send(pkt{proto: "udp", src: "192.0.2.250", dst: "192.0.2.251", sport: 9, dport: 9, payload: "x"}, d)
}

const slowRules = `
alert tcp any any -> any any (msg:"slow headers"; detect:slowloris; kind:slow_headers; track:by_src; count:20; sid:1; severity:high; category:dos;)
alert tcp any any -> any any (msg:"slow headers by dst"; detect:slowloris; kind:slow_headers; track:by_dst; count:20; sid:2; severity:high; category:dos;)
alert tcp any any -> any any (msg:"slow body"; detect:slowloris; kind:slow_body; track:by_src; count:10; sid:3; severity:high; category:dos;)
alert tcp any any -> any any (msg:"slow read"; detect:slowloris; kind:slow_read; track:by_src; count:10; sid:4; severity:high; category:dos;)
`

// slowHeaders opens n connections from client (one per source address
// when client is "", from 10.1.0.1..n) that start a request and then
// send one header line every 5s from t=1s through last.
func slowHeaders(h *streamHarness, client string, n int, last time.Duration) []*tconn {
	var cs []*tconn
	for i := range n {
		src := client
		if src == "" {
			src = fmt.Sprintf("10.1.0.%d", i+1)
		}
		c := h.conn(src, "10.0.0.80", uint16(40000+i), 80).open(0)
		c.write(time.Second, "GET / HTTP/1.1\r\nHost: x\r\n")
		cs = append(cs, c)
	}
	for d := 6 * time.Second; d <= last; d += 5 * time.Second {
		for _, c := range cs {
			c.write(d, "X-a: b\r\n")
		}
	}
	return cs
}

func TestSlowHeaders(t *testing.T) {
	h := newStreamHarness(t, slowRules, EngineConfig{})
	slowHeaders(h, "10.1.0.1", 20, 6*time.Second)
	// Heads started at 1s are older than 10s after 11s; the check is due
	// then, without waiting for the next header line.
	h.tick(11*time.Second + time.Millisecond)
	as := h.fired(1)
	if len(as) != 1 {
		t.Fatalf("by_src alerts %d:%s", len(as), alertLines(h.out))
	}
	a := as[0]
	if a.Time != at(11*time.Second+time.Millisecond) || a.SrcIP != "10.1.0.1" || a.DstIP != "10.0.0.80" || a.DstPort != 80 || a.Category != "dos" {
		t.Errorf("alert %s", alertLine(a))
	}
	for k, want := range map[string]string{
		"detector": "slowloris", "kind": "slow_headers", "track": "by_src", "tracked_addr": "10.1.0.1",
		"flows": "20", "count": "20", "oldest_age": "10.001s", "min_age": "10s", "seconds": "30",
		"targets": "10.0.0.80:80", "distinct_targets": "1", "clients": "1", "sample_flow_ids": "1,2,3,4,5",
	} {
		if a.Details[k] != want {
			t.Errorf("details[%s] = %q, want %q", k, a.Details[k], want)
		}
	}
	// One server: the by_dst rule sees the same 20 flows.
	if len(h.fired(2)) != 1 {
		t.Errorf("by_dst alerts %d", len(h.fired(2)))
	}
	if s := h.e.Stats().Tables[TableSlowFlows]; s.Keys != 20 {
		t.Errorf("slow flows %+v", s)
	}
}

func TestSlowHeadersBelowCount(t *testing.T) {
	h := newStreamHarness(t, slowRules, EngineConfig{})
	slowHeaders(h, "10.1.0.1", 19, 40*time.Second)
	h.flush()
	if len(h.out) != 0 {
		t.Fatalf("alerts:%s", alertLines(h.out))
	}
}

func TestSlowHeadersByDst(t *testing.T) {
	h := newStreamHarness(t, slowRules, EngineConfig{})
	slowHeaders(h, "", 20, 16*time.Second)
	h.flush()
	if len(h.fired(1)) != 0 {
		t.Errorf("by_src fired:%s", alertLines(h.out))
	}
	as := h.fired(2)
	if len(as) != 1 || as[0].Details["tracked_addr"] != "10.0.0.80" || as[0].Details["clients"] != "20" {
		t.Fatalf("by_dst:%s", alertLines(h.out))
	}
}

// Closing flows leave the count at once; a head that completes does too.
func TestSlowHeadersLeaveOnClose(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(c *tconn, d time.Duration)
	}{
		{"rst", func(c *tconn, d time.Duration) { c.close(d, true) }},
		{"fin", func(c *tconn, d time.Duration) { c.close(d, false) }},
		{"complete", func(c *tconn, d time.Duration) { c.write(d, "\r\n") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newStreamHarness(t, slowRules, EngineConfig{})
			cs := slowHeaders(h, "10.1.0.1", 20, 6*time.Second)
			tc.end(cs[7], 10*time.Second)
			h.tick(20 * time.Second)
			h.flush()
			if len(h.out) != 0 {
				t.Fatalf("alerts:%s", alertLines(h.out))
			}
			if s := h.e.Stats().Tables[TableSlowFlows]; s.Keys != 19 {
				t.Errorf("slow flows %+v", s)
			}
		})
	}
}

// A connection that went quiet for more than seconds is not an active
// slowloris connection.
func TestSlowHeadersNeedActivity(t *testing.T) {
	h := newStreamHarness(t, slowRules, EngineConfig{})
	slowHeaders(h, "10.1.0.1", 20, 1*time.Second)
	h.tick(31*time.Second + time.Millisecond) // old enough, but last data at 1s
	h.flush()
	if len(h.out) != 0 {
		t.Fatalf("alerts:%s", alertLines(h.out))
	}
	// Activity from 20 of them within 30s of each check.
	h = newStreamHarness(t, slowRules, EngineConfig{})
	cs := slowHeaders(h, "10.1.0.1", 20, 1*time.Second)
	for _, c := range cs {
		c.write(25*time.Second, "X-b: c\r\n")
	}
	if len(h.fired(1)) != 1 {
		t.Fatalf("alerts:%s", alertLines(h.out))
	}
}

// Keep-alive connections idle between requests never count, however long.
func TestKeepAliveNeverCounts(t *testing.T) {
	h := newStreamHarness(t, slowRules, EngineConfig{})
	for i := range 50 {
		c := h.conn("10.1.0.1", "10.0.0.80", uint16(40000+i), 80).open(0)
		c.write(time.Second, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		c.reply(time.Second, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		c.ack(time.Second, false)
		c.ack(50*time.Second, false) // TCP keep-alive
	}
	h.tick(100 * time.Second)
	h.flush()
	if len(h.out) != 0 {
		t.Fatalf("alerts:%s", alertLines(h.out))
	}
	if s := h.e.Stats().Tables[TableSlowFlows]; s.Keys != 0 {
		t.Errorf("slow flows %+v", s)
	}
}

func TestSlowBody(t *testing.T) {
	h := newStreamHarness(t, slowRules, EngineConfig{})
	var cs []*tconn
	for i := range 10 {
		c := h.conn("10.1.0.2", "10.0.0.80", uint16(41000+i), 80).open(0)
		c.write(time.Second, "POST /form HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n")
		cs = append(cs, c)
	}
	for d := 5 * time.Second; d <= 20*time.Second; d += 5 * time.Second {
		for _, c := range cs {
			c.write(d, "a=b&")
		}
	}
	h.tick(21*time.Second + time.Millisecond)
	as := h.fired(3)
	if len(as) != 1 {
		t.Fatalf("alerts:%s", alertLines(h.out))
	}
	if d := as[0].Details; d["kind"] != "slow_body" || d["flows"] != "10" || d["min_rate"] != "100" || d["min_remaining"] != "10240" {
		t.Errorf("details %v", d)
	}
	if len(h.fired(1)) != 0 {
		t.Errorf("slow_headers fired")
	}
}

// A slow but real upload moves more than min_rate: it never counts.
func TestSlowButLegitUpload(t *testing.T) {
	h := newStreamHarness(t, slowRules, EngineConfig{})
	chunk := strings.Repeat("x", 1000)
	for i := range 10 {
		c := h.conn("10.1.0.2", "10.0.0.80", uint16(41000+i), 80).open(0)
		c.write(0, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 200000\r\n\r\n")
		for d := time.Second; d <= 60*time.Second; d += time.Second {
			c.write(d, chunk) // 1000 B/s
		}
	}
	h.tick(61 * time.Second)
	h.flush()
	if len(h.out) != 0 {
		t.Fatalf("alerts:%s", alertLines(h.out))
	}
}

func TestSlowRead(t *testing.T) {
	h := newStreamHarness(t, slowRules, EngineConfig{})
	var cs []*tconn
	for i := range 10 {
		c := h.conn("10.1.0.3", "10.0.0.80", uint16(42000+i), 80).open(0)
		c.write(time.Second, "GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
		c.reply(time.Second, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
		c.ack(2*time.Second, true)
		cs = append(cs, c)
	}
	// Zero-window probes answered with zero windows.
	for _, c := range cs {
		c.ack(12*time.Second, true)
	}
	// Aged on an unrelated packet: nothing from these flows after 12s.
	h.tick(22*time.Second + time.Millisecond)
	as := h.fired(4)
	if len(as) != 1 || as[0].Details["oldest_age"] != "20.001s" || as[0].Details["seconds"] != "" {
		t.Fatalf("alerts:%s", alertLines(h.out))
	}
	// Opening the window leaves the count.
	cs[0].ack(23*time.Second, false)
	if n := len(h.e.slow.rules[3].groups[netip.MustParseAddr("10.1.0.3")]); n != 9 {
		t.Errorf("group size %d after the window opened", n)
	}
}

// Flush checks due flows at the clock it ends on.
func TestSlowFlush(t *testing.T) {
	h := newStreamHarness(t, `alert tcp any any -> any any (msg:"slow read"; detect:slowloris; kind:slow_read; track:by_src; count:1; min_age:1; sid:4;)
alert tcp any any -> any any (msg:"syn"; detect:syn_flood; track:by_dst; count:100; seconds:1; sid:9;)`, EngineConfig{HandshakeTimeout: 5 * time.Second})
	c := h.conn("10.1.0.3", "10.0.0.80", 42000, 80).open(0)
	c.write(0, "GET / HTTP/1.1\r\n\r\n")
	c.ack(0, true)
	// A pending handshake moves the clock to its deadline in Flush.
	h.send(pkt{proto: "tcp", src: "10.9.9.9", dst: "10.0.0.80", sport: 1, dport: 22, flags: "S"}, 0)
	h.flush()
	if len(h.fired(4)) != 1 {
		t.Fatalf("alerts:%s", alertLines(h.out))
	}
}

func TestSlowWhitelistAndPass(t *testing.T) {
	cidr := netip.MustParsePrefix("10.1.0.1/32")
	h := newStreamHarness(t, slowRules, EngineConfig{Whitelist: []netip.Prefix{cidr}})
	slowHeaders(h, "10.1.0.1", 20, 16*time.Second)
	h.flush()
	if len(h.out) != 0 {
		t.Fatalf("whitelisted:%s", alertLines(h.out))
	}
	h = newStreamHarness(t, "pass tcp 10.1.0.1 any -> any 80 (msg:\"ok\"; sid:99;)\n"+slowRules, EngineConfig{})
	slowHeaders(h, "10.1.0.1", 20, 16*time.Second)
	h.flush()
	if len(h.out) != 0 {
		t.Fatalf("passed:%s", alertLines(h.out))
	}
}

// Flows the stream stage reports closed leave the table: here one
// replaced by a new connection on its 4-tuple, then the rest when idle.
func TestSlowClosedFlows(t *testing.T) {
	h := newStreamHarness(t, slowRules, EngineConfig{})
	cs := slowHeaders(h, "10.1.0.1", 5, time.Second)
	if s := h.e.Stats().Tables[TableSlowFlows]; s.Keys != 5 {
		t.Fatalf("slow flows %+v", s)
	}
	c := cs[0]
	p := h.send(pkt{proto: "tcp", src: c.client, dst: c.server, sport: c.cport, dport: c.sport, flags: "S", seq: 777}, 2*time.Second)
	if len(p.ClosedFlows) != 1 {
		t.Fatalf("port reuse closed %v", p.ClosedFlows)
	}
	if s := h.e.Stats().Tables[TableSlowFlows]; s.Keys != 4 {
		t.Fatalf("slow flows after port reuse %+v", s)
	}
	p = h.send(pkt{proto: "tcp", src: "10.9.9.9", dst: "10.0.0.80", sport: 1, dport: 80, flags: "S"}, 3*time.Minute)
	// The SYN that reused the 4-tuple carried no data, so it opened no
	// flow: only the four remaining ones idle out.
	if len(p.ClosedFlows) != 4 {
		t.Fatalf("closed %v", p.ClosedFlows)
	}
	if s := h.e.Stats().Tables[TableSlowFlows]; s.Keys != 0 {
		t.Errorf("slow flows %+v", s)
	}
}

// Flows silent for slowIdle leave the table even when the stream stage
// never reports them closed (it only sees packets on its ports).
func TestSlowIdle(t *testing.T) {
	h := newStreamHarness(t, slowRules, EngineConfig{})
	slowHeaders(h, "10.1.0.1", 5, time.Second)
	h.tick(time.Second + slowIdle)
	if s := h.e.Stats().Tables[TableSlowFlows]; s.Keys != 0 {
		t.Errorf("slow flows %+v", s)
	}
}

func TestSlowTableCap(t *testing.T) {
	h := newStreamHarness(t, slowRules, EngineConfig{MaxKeys: 10})
	slowHeaders(h, "10.1.0.1", 15, time.Second)
	s := h.e.Stats().Tables[TableSlowFlows]
	if s.Keys != 10 || s.Evictions != 5 {
		t.Fatalf("slow flows %+v", s)
	}
	// A full table evicts nothing for a flow with no slow request.
	c := h.conn("10.1.0.2", "10.0.0.80", 41000, 80).open(2 * time.Second)
	c.write(2*time.Second, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if s := h.e.Stats().Tables[TableSlowFlows]; s.Keys != 10 || s.Evictions != 5 {
		t.Fatalf("slow flows after a complete request %+v", s)
	}
}

// A reload keeps the flows and recomputes their counts without alerting;
// removing the rules empties the table.
func TestSlowReload(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/r.conf"
	writeFile(t, path, slowRules)
	h := newStreamHarness(t, slowRules, EngineConfig{})
	cs := slowHeaders(h, "10.1.0.1", 20, 16*time.Second)
	h.flush()
	n := len(h.out)
	lower := strings.Replace(slowRules, "count:20; sid:1;", "count:5; sid:1;", 1)
	writeFile(t, path, lower)
	if err := h.e.Reload(path); err != nil {
		t.Fatal(err)
	}
	cs[0].write(17*time.Second, "X-c: d\r\n")
	if len(h.out) != n {
		t.Errorf("reload alerted:%s", alertLines(h.out[n:]))
	}
	if g := h.e.slow.rules[0].groups[netip.MustParseAddr("10.1.0.1")]; len(g) != 20 {
		t.Errorf("group %d after reload", len(g))
	}
	writeFile(t, path, "")
	if err := h.e.Reload(path); err != nil {
		t.Fatal(err)
	}
	h.tick(18 * time.Second)
	st := h.e.Stats().Tables
	if st[TableSlowFlows].Keys != 0 || st[TableSlowloris].Keys != 0 {
		t.Errorf("tables %+v %+v", st[TableSlowFlows], st[TableSlowloris])
	}
}

func writeFile(tb testing.TB, path, text string) {
	tb.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		tb.Fatal(err)
	}
}

// Per-packet rules see what the stream stage reassembled: content split
// over segments, one of several pipelined requests, and stream anomalies.
func TestStreamMatching(t *testing.T) {
	h := newStreamHarness(t, `
alert tcp any any -> any 80 (msg:"content"; content:"/etc/passwd"; sid:1;)
alert tcp any any -> any 80 (msg:"second request"; app_proto:http; app_field:method=DELETE; app_field:uri=/x; sid:2;)
alert tcp any any -> any 80 (msg:"fields of different requests"; app_field:method=DELETE; app_field:uri=/one; sid:3;)
alert tcp any any -> any 80 (msg:"any anomaly"; stream_anomaly; sid:4;)
alert tcp any any -> any 80 (msg:"overlap"; stream_anomaly:overlap_conflict; sid:5;)
alert tcp any any -> any 80 (msg:"oversize"; stream_anomaly:oversize_headers; sid:6;)
alert tcp any any -> any 80 (msg:"nocase content"; content:"ETC/PASS"; nocase; sid:7;)
`, EngineConfig{})
	c := h.conn("10.1.0.1", "10.0.0.80", 40000, 80).open(0)
	c.write(time.Second, "GET /etc/pa")
	if len(h.out) != 0 {
		t.Fatalf("early:%s", alertLines(h.out))
	}
	p := c.write(time.Second, "sswd HTTP/1.1\r\n\r\nGET /one HTTP/1.1\r\n\r\nDELETE /x HTTP/1.1\r\n\r\n")
	if len(p.AppMore) != 2 {
		t.Fatalf("AppMore %v", p.AppMore)
	}
	if got := bySID(h.out); got["1/alert"] != 1 || got["7/alert"] != 1 || got["2/alert"] != 1 || got["3/alert"] != 0 {
		t.Fatalf("alerts %v:%s", got, alertLines(h.out))
	}

	// Overlap conflict: the same sequence number with other bytes.
	h.out = nil
	c.write(2*time.Second, "GET /a")
	c.cseq -= 6
	c.write(2*time.Second, "PUT /b")
	if got := bySID(h.out); got["4/alert"] != 1 || got["5/alert"] != 1 || got["6/alert"] != 0 {
		t.Fatalf("overlap alerts %v:%s", got, alertLines(h.out))
	}

	// Oversize headers, on a new connection (dedup keys on the source).
	h.out = nil
	c2 := h.conn("10.1.0.2", "10.0.0.80", 40001, 80).open(3 * time.Second)
	c2.write(3*time.Second, "GET / HTTP/1.1\r\n")
	for range 20 {
		c2.write(3*time.Second, "X-Big: "+strings.Repeat("a", 1000)+"\r\n")
	}
	if got := bySID(h.out); got["4/alert"] != 1 || got["6/alert"] != 1 || got["5/alert"] != 0 {
		t.Fatalf("oversize alerts %v:%s", got, alertLines(h.out))
	}
}
