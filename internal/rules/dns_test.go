package rules

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/entropy"
)

const (
	dnsClient = "10.0.0.5"
	dnsServer = "192.0.2.53"
)

// dnsWire builds a DNS message with one question. A response gets rcode
// and, after the question, pad bytes standing in for its answers.
func dnsWire(id uint16, name string, qtype uint16, response bool, rcode int, pad int) string {
	flags := uint16(0x0100)
	if response {
		flags = 0x8180 | uint16(rcode)
	}
	b := binary.BigEndian.AppendUint16(nil, id)
	b = binary.BigEndian.AppendUint16(b, flags)
	b = append(b, 0, 1, 0, 0, 0, 0, 0, 0)
	if response && pad > 0 {
		b[7] = 1 // ancount
	}
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = append(b, make([]byte, pad)...)
	return string(b)
}

func dnsQ(client string, cport uint16, server string, id uint16, name string, qtype uint16) pkt {
	return udpPkt(client, cport, server, 53, dnsWire(id, name, qtype, false, 0, 0))
}

func dnsR(server string, client string, cport uint16, id uint16, name string, qtype uint16, rcode, pad int) pkt {
	return udpPkt(server, 53, client, cport, dnsWire(id, name, qtype, true, rcode, pad))
}

// tcpDNS frames a message for TCP.
func tcpDNS(src string, sport uint16, dst string, dport uint16, msg string) pkt {
	return pkt{proto: "tcp", src: src, dst: dst, sport: sport, dport: dport, flags: "PA", seq: 1, ack: 1,
		payload: string(binary.BigEndian.AppendUint16(nil, uint16(len(msg)))) + msg}
}

func TestDNSQueryTable(t *testing.T) {
	var stat tableStat
	q := newDNSQueries(3, &stat)
	c, s := netip.MustParseAddr(dnsClient), netip.MustParseAddr(dnsServer)
	tx := dnsTx{client: c, server: s, cport: 40000, id: 7}
	a := &dnsMsg{id: 7, qname: "a.example", qtype: 1, size: 30}
	b := &dnsMsg{id: 7, qname: "b.example", qtype: 1, size: 30}
	aaaa := &dnsMsg{id: 7, qname: "a.example", qtype: 28, size: 30}

	if o, _ := q.answer(tx, a, at(0)); o != dnsUnsolicited {
		t.Errorf("empty table: %d", o)
	}
	q.query(tx, a, at(0))
	if o, _ := q.answer(tx, b, at(time.Second)); o != dnsMismatch {
		t.Errorf("other name: %d, want mismatch", o)
	}
	if o, _ := q.answer(tx, aaaa, at(time.Second)); o != dnsMismatch {
		t.Errorf("other type: %d, want mismatch", o)
	}
	other := tx
	other.cport = 40001
	if o, _ := q.answer(other, a, at(time.Second)); o != dnsUnsolicited {
		t.Errorf("other port: %d, want unsolicited", o)
	}
	other = tx
	other.server = netip.MustParseAddr("192.0.2.54")
	if o, _ := q.answer(other, a, at(time.Second)); o != dnsUnsolicited {
		t.Errorf("other server: %d, want unsolicited", o)
	}
	if o, size := q.answer(tx, a, at(time.Second)); o != dnsMatched || size != 30 {
		t.Errorf("answer: %d size %d", o, size)
	}
	if o, _ := q.answer(tx, a, at(time.Second)); o != dnsUnsolicited {
		t.Errorf("second answer: %d, want unsolicited (the query was used up)", o)
	}
	if q.len() != 0 || stat.keys.Load() != 0 || len(q.names) != 0 {
		t.Errorf("table holds %d (stat %d, names %d) after the answer", q.len(), stat.keys.Load(), len(q.names))
	}

	// asked sees a question on any port and id of the same client and
	// server, until it is answered or forgotten.
	q.query(tx, a, at(0))
	other = tx
	other.cport, other.id = 40001, 9
	if !q.asked(other, "a.example") || q.asked(other, "b.example") {
		t.Errorf("asked: a %v b %v", q.asked(other, "a.example"), q.asked(other, "b.example"))
	}
	other.server = netip.MustParseAddr("192.0.2.54")
	if q.asked(other, "a.example") {
		t.Errorf("asked of another server")
	}
	q.query(tx, a, at(time.Second)) // a retransmission counts once
	q.answer(tx, a, at(2*time.Second))
	if q.asked(tx, "a.example") || len(q.names) != 0 {
		t.Errorf("asked after the answer: names %v", q.names)
	}

	// A question is forgotten 10s after it was sent; a retransmission
	// restarts that.
	q.query(tx, a, at(0))
	if o, _ := q.answer(tx, a, at(dnsQueryIdle+time.Millisecond)); o != dnsUnsolicited {
		t.Errorf("after 10s: %d, want unsolicited", o)
	}
	q.query(tx, a, at(20*time.Second))
	q.query(tx, a, at(28*time.Second))
	if o, _ := q.answer(tx, a, at(36*time.Second)); o != dnsMatched {
		t.Errorf("retransmitted: %d, want matched", o)
	}

	// A response without a question answers the oldest one.
	q.query(tx, a, at(40*time.Second))
	q.query(tx, b, at(41*time.Second))
	if o, _ := q.answer(tx, &dnsMsg{id: 7}, at(42*time.Second)); o != dnsMatched {
		t.Errorf("no question: %d", o)
	}
	if o, _ := q.answer(tx, a, at(42*time.Second)); o != dnsMismatch {
		t.Errorf("oldest not taken: %d", o)
	}

	// At most maxQuestionsPerTx per transaction; the oldest go first.
	q.clear()
	for i := range maxQuestionsPerTx + 1 {
		q.query(tx, &dnsMsg{id: 7, qname: fmt.Sprintf("n%d.example", i), qtype: 1}, at(time.Minute))
	}
	if o, _ := q.answer(tx, &dnsMsg{id: 7, qname: "n0.example", qtype: 1}, at(time.Minute)); o != dnsMismatch {
		t.Errorf("oldest question kept: %d", o)
	}

	// Transactions are capped; the least recently queried is evicted.
	q.clear()
	for i := range 4 {
		x := tx
		x.id = uint16(i)
		q.query(x, &dnsMsg{id: uint16(i), qname: "a.example", qtype: 1}, at(2*time.Minute))
	}
	if len(q.names) != 1 || q.names[q.nameKey(tx, "a.example")] != 3 {
		t.Errorf("names after eviction: %v", q.names)
	}
	if q.len() != 3 || stat.evictions.Load() != 1 || stat.keys.Load() != 3 {
		t.Errorf("len %d evictions %d keys %d", q.len(), stat.evictions.Load(), stat.keys.Load())
	}
	x := tx
	x.id = 0
	if o, _ := q.answer(x, &dnsMsg{id: 0, qname: "a.example", qtype: 1}, at(2*time.Minute)); o != dnsUnsolicited {
		t.Errorf("evicted transaction answered: %d", o)
	}
}

const spoofRules = `alert ip any any -> any any (msg:"u"; detect:dns_spoof; kind:unsolicited_response; count:10; seconds:10; sid:1;)
alert ip any any -> any any (msg:"r"; detect:dns_spoof; kind:id_race; count:10; seconds:2; sid:2;)
alert ip any any -> any any (msg:"m"; detect:dns_spoof; kind:qname_mismatch; sid:3;)
`

func TestDNSSpoofUnsolicited(t *testing.T) {
	var pkts []timedPkt
	for i := range 10 {
		pkts = append(pkts, timedPkt{time.Duration(i) * 500 * time.Millisecond,
			dnsR(dnsServer, dnsClient, uint16(40000+i), uint16(i), fmt.Sprintf("h%d.example.com", i), 1, 0, 40)})
	}
	if i := firesAt(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), pkts, 1); i != 9 {
		t.Fatalf("fired at %d, want 9", i)
	}
	as := sidAlerts(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), pkts, 1)
	if len(as) != 1 || as[0].Details["kind"] != SpoofUnsolicited || as[0].Details["client"] != dnsClient || as[0].Details["responses"] != "10" {
		t.Fatalf("alerts %+v", as)
	}
	// Nine, or ten spread over more than 10s, do not fire.
	if i := firesAt(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), pkts[:9], 1); i >= 0 {
		t.Errorf("9 responses fired")
	}
	spread := append([]timedPkt(nil), pkts...)
	for i := range spread {
		spread[i].t = time.Duration(i) * 1200 * time.Millisecond
	}
	if i := firesAt(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), spread, 1); i >= 0 {
		t.Errorf("responses 12s apart fired")
	}
	// Answered responses never count.
	var answered []timedPkt
	for i := range 20 {
		d := time.Duration(i) * 100 * time.Millisecond
		name := fmt.Sprintf("h%d.example.com", i)
		answered = append(answered,
			timedPkt{d, dnsQ(dnsClient, uint16(40000+i), dnsServer, uint16(i), name, 1)},
			timedPkt{d + time.Millisecond, dnsR(dnsServer, dnsClient, uint16(40000+i), uint16(i), name, 1, 0, 40)})
	}
	if as := flat(runPkts(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), answered)); len(as) != 0 {
		t.Errorf("answered lookups alerted: %+v", as)
	}
}

func TestDNSSpoofIDRace(t *testing.T) {
	// The client asks once; forged answers with guessed ids race the real
	// one. The real answer matches; the others answer nothing.
	pkts := []timedPkt{{0, dnsQ(dnsClient, 40000, dnsServer, 777, "www.bank.example", 1)}}
	for i := range 10 {
		pkts = append(pkts, timedPkt{time.Duration(i+1) * 10 * time.Millisecond,
			dnsR(dnsServer, dnsClient, 40000, uint16(1000+i), "www.bank.example", 1, 0, 40)})
	}
	e := NewEngine(mustParse(t, spoofRules), EngineConfig{})
	as := sidAlerts(t, e, pkts, 2)
	if len(as) != 1 || as[0].Details["distinct_ids"] != "10" || as[0].Details["qname"] != "www.bank.example" || as[0].Details["kind"] != SpoofIDRace {
		t.Fatalf("id_race alerts %+v", as)
	}
	// Nine ids, or ten repeats of one id, do not fire.
	if i := firesAt(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), pkts[:10], 2); i >= 0 {
		t.Errorf("9 ids fired")
	}
	same := append([]timedPkt(nil), pkts...)
	for i := 1; i < len(same); i++ {
		same[i].p = dnsR(dnsServer, dnsClient, 40000, 1000, "www.bank.example", 1, 0, 40)
	}
	if i := firesAt(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), same, 2); i >= 0 {
		t.Errorf("one repeated id fired")
	}
	// Ten ids over more than 2s do not fire.
	slow := append([]timedPkt(nil), pkts...)
	for i := range slow {
		slow[i].t = time.Duration(i) * 300 * time.Millisecond
	}
	if i := firesAt(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), slow, 2); i >= 0 {
		t.Errorf("ids 300ms apart fired")
	}
	// Ten ids spread over ten names do not fire.
	names := append([]timedPkt(nil), pkts...)
	for i := 1; i < len(names); i++ {
		names[i].p = dnsR(dnsServer, dnsClient, 40000, uint16(1000+i), fmt.Sprintf("n%d.bank.example", i), 1, 0, 40)
	}
	if i := firesAt(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), names, 2); i >= 0 {
		t.Errorf("ids over ten names fired")
	}
	// A client asking the same name with ten ids, every one answered, is
	// not a race.
	var repeat []timedPkt
	for i := range 10 {
		d := time.Duration(i) * 50 * time.Millisecond
		repeat = append(repeat,
			timedPkt{d, dnsQ(dnsClient, uint16(40000+i), dnsServer, uint16(i), "www.bank.example", 1)},
			timedPkt{d + time.Millisecond, dnsR(dnsServer, dnsClient, uint16(40000+i), uint16(i), "www.bank.example", 1, 0, 40)})
	}
	if as := flat(runPkts(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), repeat)); len(as) != 0 {
		t.Errorf("answered repeats alerted: %+v", as)
	}
	// Without the client's question (a reflection victim), or once the
	// real answer has arrived, the answers race nothing.
	if i := firesAt(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), pkts[1:], 2); i >= 0 {
		t.Errorf("answers without a question fired at %d", i)
	}
	late := append([]timedPkt(nil), pkts[0], timedPkt{5 * time.Millisecond, dnsR(dnsServer, dnsClient, 40000, 777, "www.bank.example", 1, 0, 40)})
	late = append(late, pkts[1:]...)
	if i := firesAt(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), late, 2); i >= 0 {
		t.Errorf("answers after the real one fired at %d", i)
	}
	// A question to another server does not count.
	elsewhere := append([]timedPkt{{0, dnsQ(dnsClient, 40000, "192.0.2.54", 777, "www.bank.example", 1)}}, pkts[1:]...)
	if i := firesAt(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), elsewhere, 2); i >= 0 {
		t.Errorf("question to another server fired at %d", i)
	}
}

func TestDNSSpoofQNameMismatch(t *testing.T) {
	pkts := []timedPkt{
		{0, dnsQ(dnsClient, 40000, dnsServer, 5, "www.example.org", 1)},
		{time.Millisecond, dnsR(dnsServer, dnsClient, 40000, 5, "evil.example.net", 1, 0, 40)},
	}
	as := sidAlerts(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), pkts, 3)
	if len(as) != 1 || as[0].Details["qname"] != "evil.example.net" || as[0].Details["client_port"] != "40000" {
		t.Fatalf("alerts %+v", as)
	}
	ok := []timedPkt{pkts[0], {time.Millisecond, dnsR(dnsServer, dnsClient, 40000, 5, "www.example.org", 1, 0, 40)}}
	if as := flat(runPkts(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), ok)); len(as) != 0 {
		t.Errorf("matching answer alerted: %+v", as)
	}
	// The resolver randomizes letter case (DNS 0x20); names are compared
	// lowercased.
	mixed := []timedPkt{{0, dnsQ(dnsClient, 40000, dnsServer, 5, "wWw.ExAmple.org", 1)},
		{time.Millisecond, dnsR(dnsServer, dnsClient, 40000, 5, "WwW.eXample.ORG", 1, 0, 40)}}
	if as := flat(runPkts(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), mixed)); len(as) != 0 {
		t.Errorf("0x20 case alerted: %+v", as)
	}
}

func TestDNSSpoofTCP(t *testing.T) {
	q := dnsWire(9, "big.example.com", 16, false, 0, 0)
	pkts := []timedPkt{
		{0, tcpDNS(dnsClient, 40000, dnsServer, 53, q)},
		{time.Millisecond, tcpDNS(dnsServer, 53, dnsClient, 40000, dnsWire(9, "other.example.com", 16, true, 0, 500))},
	}
	as := sidAlerts(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), pkts, 3)
	if len(as) != 1 {
		t.Fatalf("TCP mismatch: %+v", as)
	}
	pkts[1].p = tcpDNS(dnsServer, 53, dnsClient, 40000, dnsWire(9, "big.example.com", 16, true, 0, 500))
	if as := flat(runPkts(t, NewEngine(mustParse(t, spoofRules), EngineConfig{}), pkts)); len(as) != 0 {
		t.Errorf("TCP answer alerted: %+v", as)
	}
}

// TestDNSSpoofWhitelistedQuery checks that a query from a whitelisted
// client still enters the table, so its answer is not unsolicited.
func TestDNSSpoofWhitelistedQuery(t *testing.T) {
	rules := `alert ip any any -> any any (msg:"u"; detect:dns_spoof; kind:unsolicited_response; count:1; seconds:10; sid:1;)`
	pkts := []timedPkt{
		{0, dnsQ(dnsClient, 40000, dnsServer, 5, "www.example.org", 1)},
		{time.Millisecond, dnsR(dnsServer, dnsClient, 40000, 5, "www.example.org", 1, 0, 40)},
	}
	e := NewEngine(mustParse(t, rules), EngineConfig{Whitelist: []netip.Prefix{netip.MustParsePrefix(dnsClient + "/32")}})
	if as := flat(runPkts(t, e, pkts)); len(as) != 0 {
		t.Errorf("alerted: %+v", as)
	}
	if as := flat(runPkts(t, NewEngine(mustParse(t, rules), EngineConfig{}), pkts[1:])); len(as) != 1 {
		t.Errorf("unsolicited with count 1: %d alerts", len(as))
	}
}

const ampRule = `alert ip any any -> any any (msg:"a"; detect:dns_amplification; min_bytes:1000000; seconds:5; min_ratio:10; sid:1;)`

func TestDNSAmplification(t *testing.T) {
	const victim = "198.51.100.7"
	// Reflection: responses to queries the victim never sent.
	var refl []timedPkt
	for i := range 400 {
		refl = append(refl, timedPkt{time.Duration(i) * 5 * time.Millisecond,
			dnsR(fmt.Sprintf("192.0.2.%d", 1+i%50), victim, 4444, uint16(i), "example.com", 255, 0, 3000)})
	}
	e := NewEngine(mustParse(t, ampRule), EngineConfig{})
	as := sidAlerts(t, e, refl, 1)
	if len(as) != 1 || as[0].Details["reason"] != "unmatched" || as[0].Details["tracked_addr"] != victim || as[0].Details["top_qtype"] != "255" {
		t.Fatalf("reflection alerts %+v", as)
	}
	// 1 MB is about 330 of these 3 KB answers.
	if i := firesAt(t, NewEngine(mustParse(t, ampRule), EngineConfig{}), refl, 1); i < 320 || i > 340 {
		t.Errorf("fired at %d, want about 330", i)
	}

	// Answers to the victim's own small queries, 60 times their size:
	// the victim asked, but the ratio is still amplification (e.g. a
	// spoofed query stream it also sent). Ratio fires.
	var own []timedPkt
	for i := range 400 {
		d := time.Duration(i) * 5 * time.Millisecond
		own = append(own,
			timedPkt{d, dnsQ(victim, uint16(10000+i), dnsServer, uint16(i), "example.com", 255)},
			timedPkt{d + time.Millisecond, dnsR(dnsServer, victim, uint16(10000+i), uint16(i), "example.com", 255, 0, 3000)})
	}
	as = sidAlerts(t, NewEngine(mustParse(t, ampRule), EngineConfig{}), own, 1)
	if len(as) != 1 || as[0].Details["reason"] != "ratio" || as[0].Details["unmatched_bytes"] != "0" {
		t.Fatalf("ratio alerts %+v", as)
	}

	// Ordinary answers, 3 times their query, never fire however many.
	var normal []timedPkt
	for i := range 3000 {
		d := time.Duration(i) * time.Millisecond
		name := fmt.Sprintf("host%d.example.com", i)
		q := dnsQ(victim, uint16(10000+i%50000), dnsServer, uint16(i), name, 1)
		qlen := len(q.payload)
		normal = append(normal,
			timedPkt{d, q},
			timedPkt{d + 100*time.Microsecond, dnsR(dnsServer, victim, uint16(10000+i%50000), uint16(i), name, 1, 0, 2*qlen)})
	}
	if as := flat(runPkts(t, NewEngine(mustParse(t, ampRule), EngineConfig{}), normal)); len(as) != 0 {
		t.Errorf("ordinary answers alerted: %+v", as[0])
	}
	// Big answers the victim asked for at ratio 9 do not fire either,
	// though they pass min_bytes: 600 answers of about 2 KB in 3s.
	var nine []timedPkt
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60)
	for i := range 600 {
		d := time.Duration(i) * 5 * time.Millisecond
		name := fmt.Sprintf("h%d.%s.example.com", i, long)
		q := dnsQ(victim, uint16(10000+i), dnsServer, uint16(i), name, 16)
		// A response is 12 + question + pad; the query 12 + question.
		qlen := len(q.payload)
		nine = append(nine,
			timedPkt{d, q},
			timedPkt{d + time.Millisecond, dnsR(dnsServer, victim, uint16(10000+i), uint16(i), name, 16, 0, 8*qlen)})
	}
	if as := flat(runPkts(t, NewEngine(mustParse(t, ampRule), EngineConfig{}), nine)); len(as) != 0 {
		t.Errorf("ratio 9 alerted: %+v", as[0])
	}
	// The same at ratio 11 fires.
	eleven := append([]timedPkt(nil), nine...)
	for i := 1; i < len(eleven); i += 2 {
		q := eleven[i-1].p
		name := fmt.Sprintf("h%d.%s.example.com", i/2, long)
		eleven[i].p = dnsR(dnsServer, victim, uint16(10000+i/2), uint16(i/2), name, 16, 0, 10*len(q.payload))
	}
	as = flat(runPkts(t, NewEngine(mustParse(t, ampRule), EngineConfig{}), eleven))
	if len(as) != 1 || as[0].Details["reason"] != "ratio" {
		t.Errorf("ratio 11 alerts %+v", as)
	}
}

func TestRegisteredDomain(t *testing.T) {
	for _, tt := range []struct {
		name, domain, sub string
		ok                bool
	}{
		{"www.bbc.co.uk", "bbc.co.uk", "www", true},
		{"a.b.example.com", "example.com", "a.b", true},
		{"example.com.", "example.com", "", true},
		{"alice.github.io", "alice.github.io", "", true},
		{"x.alice.github.io", "alice.github.io", "x", true},
		// Private suffixes count: each CloudFront distribution is its own
		// domain.
		{"d1.cloudfront.net", "d1.cloudfront.net", "", true},
		{"co.uk", "", "", false},
		{"com", "", "", false},
		{"4.3.2.1.in-addr.arpa", "1.in-addr.arpa", "4.3.2", true},
	} {
		d, sub, ok := registeredDomain(tt.name)
		if d != tt.domain || sub != tt.sub || ok != tt.ok {
			t.Errorf("registeredDomain(%q) = %q, %q, %v", tt.name, d, sub, ok)
		}
	}
}

// base32Label returns n random base32 characters, as iodine or dnscat2
// encode data.
func base32Label(r *rand.Rand, n int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz234567"
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[r.IntN(len(alpha))]
	}
	return string(b)
}

const tunnelRules = `var ALLOW [in-addr.arpa,ip6.arpa,allowed.example]
alert ip any any -> any any (msg:"s"; detect:dns_tunnel; kind:subdomains; count:50; seconds:60; allow:$ALLOW; sid:1;)
alert ip any any -> any any (msg:"t"; detect:dns_tunnel; kind:txt; count:100; seconds:60; allow:$ALLOW; sid:2;)
`

func TestDNSTunnelSubdomains(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	queries := func(names []string, qtype uint16) []timedPkt {
		var out []timedPkt
		for i, n := range names {
			out = append(out, timedPkt{time.Duration(i) * 200 * time.Millisecond, dnsQ(dnsClient, uint16(30000+i), dnsServer, uint16(i), n, qtype)})
		}
		return out
	}
	var tunnel []string
	for range 80 {
		tunnel = append(tunnel, base32Label(r, 40)+"."+base32Label(r, 20)+".tunnel-test.example.com")
	}
	e := NewEngine(mustParse(t, tunnelRules), EngineConfig{})
	pk := queries(tunnel, 1)
	if i := firesAt(t, e, pk, 1); i != 49 {
		t.Fatalf("fired at %d, want 49 (the 50th name)", i)
	}
	as := sidAlerts(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), pk, 1)
	if len(as) != 1 {
		t.Fatalf("%d alerts", len(as))
	}
	d := as[0].Details
	if d["registered_domain"] != "example.com" || d["unique_subdomains"] != "50" || d["client"] != dnsClient || d["kind"] != TunnelSubdomains {
		t.Errorf("details %v", d)
	}
	if s := strings.Fields(d["sample_qnames"]); len(s) != 3 || s[2] != tunnel[49] || s[0] != tunnel[47] {
		t.Errorf("samples %q", d["sample_qnames"])
	}
	if d["avg_entropy"] < "4.5" || d["avg_length"] != "71.0" || d["txt_null_cname_mx"] != "0.00" {
		t.Errorf("stats %v", d)
	}

	// Short random names (entropy alone) fire; long word-like names
	// (length alone) fire.
	var short, long []string
	for range 60 {
		short = append(short, base32Label(r, 16)+".t.example.net")
		long = append(long, strings.Repeat("ab", 30)+base32Label(r, 2)+".example.net")
	}
	for _, names := range [][]string{short, long} {
		if i := firesAt(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), queries(names, 1), 1); i < 0 {
			t.Errorf("did not fire on %q...", names[0])
		}
	}

	// Many real hostnames of one domain do not: short, word-like.
	var real []string
	for _, h := range []string{"www", "mail", "api", "cdn", "static", "img", "login", "auth", "docs", "blog"} {
		for i := range 8 {
			real = append(real, fmt.Sprintf("%s%d.eu-west.example.com", h, i+1))
		}
	}
	if i := firesAt(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), queries(real, 1), 1); i >= 0 {
		t.Errorf("real hostnames fired at %d", i)
	}
	// Random names spread over many co.uk and github.io sites are many
	// registered domains, not one.
	var spread []string
	for i := range 80 {
		suffix := "co.uk"
		if i%2 == 1 {
			suffix = "github.io"
		}
		spread = append(spread, base32Label(r, 30)+"."+base32Label(r, 8)+"."+suffix)
	}
	if i := firesAt(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), queries(spread, 1), 1); i >= 0 {
		t.Errorf("co.uk/github.io names fired at %d", i)
	}
	// Allowed domains and their subdomains are skipped.
	var allowed []string
	for range 80 {
		allowed = append(allowed, base32Label(r, 40)+".x.allowed.example")
	}
	if i := firesAt(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), queries(allowed, 1), 1); i >= 0 {
		t.Errorf("allowed domain fired at %d", i)
	}
	// 49 names within the window do not fire; 50 over more than 60s do not.
	if i := firesAt(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), queries(tunnel[:49], 1), 1); i >= 0 {
		t.Errorf("49 names fired")
	}
	slow := queries(tunnel[:50], 1)
	for i := range slow {
		slow[i].t = time.Duration(i) * 1300 * time.Millisecond
	}
	if i := firesAt(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), slow, 1); i >= 0 {
		t.Errorf("names 1.3s apart fired")
	}
	// Repeating one name is one subdomain.
	var one []string
	for range 80 {
		one = append(one, tunnel[0])
	}
	if i := firesAt(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), queries(one, 1), 1); i >= 0 {
		t.Errorf("repeated name fired")
	}
	// Responses are not counted.
	var resp []timedPkt
	for i, n := range tunnel {
		resp = append(resp, timedPkt{time.Duration(i) * 100 * time.Millisecond, dnsR(dnsServer, dnsClient, 30000, uint16(i), n, 1, 0, 40)})
	}
	if i := firesAt(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), resp, 1); i >= 0 {
		t.Errorf("responses fired")
	}
	// The TXT/NULL/CNAME/MX share is reported.
	as = sidAlerts(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), queries(tunnel, qtypeCNAME), 1)
	if len(as) != 1 || as[0].Details["txt_null_cname_mx"] != "1.00" {
		t.Errorf("CNAME share %+v", as)
	}
}

func TestDNSTunnelTXT(t *testing.T) {
	var pkts []timedPkt
	for i := range 100 {
		qtype := uint16(qtypeTXT)
		if i%2 == 1 {
			qtype = qtypeNULL
		}
		pkts = append(pkts, timedPkt{time.Duration(i) * 500 * time.Millisecond, dnsQ(dnsClient, 30000, dnsServer, uint16(i), fmt.Sprintf("p%d.c2.example.org", i%3), qtype)})
	}
	if i := firesAt(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), pkts, 2); i != 99 {
		t.Fatalf("fired at %d, want 99", i)
	}
	as := sidAlerts(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), pkts, 2)
	if len(as) != 1 || as[0].Details["registered_domain"] != "example.org" || as[0].Details["txt_null_queries"] != "100" {
		t.Fatalf("alerts %+v", as)
	}
	// A queries do not count.
	for i := range pkts {
		pkts[i].p = dnsQ(dnsClient, 30000, dnsServer, uint16(i), "p.c2.example.org", 1)
	}
	if i := firesAt(t, NewEngine(mustParse(t, tunnelRules), EngineConfig{}), pkts, 2); i >= 0 {
		t.Errorf("A queries fired")
	}
}

const nxRule = `alert ip any any -> any any (msg:"n"; detect:dns_nxdomain_burst; count:30; seconds:60; sid:1;)`

func TestNXDomainBurst(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	nx := func(names []string, rcode int) []timedPkt {
		var out []timedPkt
		for i, n := range names {
			out = append(out, timedPkt{time.Duration(i) * 500 * time.Millisecond, dnsR(dnsServer, dnsClient, uint16(30000+i), uint16(i), n, 1, rcode, 0)})
		}
		return out
	}
	randName := func() string {
		const alpha = "abcdefghijklmnopqrstuvwxyz"
		b := make([]byte, 14)
		for i := range b {
			b[i] = alpha[r.IntN(len(alpha))]
		}
		return string(b) + ".com"
	}
	var dga []string
	for range 40 {
		dga = append(dga, randName())
	}
	if i := firesAt(t, NewEngine(mustParse(t, nxRule), EngineConfig{}), nx(dga, 3), 1); i != 29 {
		t.Fatalf("fired at %d, want 29", i)
	}
	as := sidAlerts(t, NewEngine(mustParse(t, nxRule), EngineConfig{}), nx(dga, 3), 1)
	if len(as) != 1 || as[0].Details["tracked_addr"] != dnsClient || as[0].Details["nxdomain_names"] != "30" {
		t.Fatalf("alerts %+v", as)
	}
	// Successful answers do not count.
	if i := firesAt(t, NewEngine(mustParse(t, nxRule), EngineConfig{}), nx(dga, 0), 1); i >= 0 {
		t.Errorf("NOERROR fired")
	}
	// Typos and a broken search domain: word-like names.
	var typos []string
	for _, w := range []string{"gooogle", "facebok", "yotube", "amazn", "wikipeda", "redit", "twiter", "gihub", "linkdin", "netflx"} {
		typos = append(typos, w+".com", "www."+w+".com", "mail."+w+".com")
	}
	for _, h := range []string{"printer", "nas", "router", "db", "ldap", "intranet", "wiki", "jira"} {
		typos = append(typos, h+".corp.example.com", h+".lan")
	}
	if len(typos) < 40 {
		t.Fatalf("only %d typos", len(typos))
	}
	if i := firesAt(t, NewEngine(mustParse(t, nxRule), EngineConfig{}), nx(typos, 3), 1); i >= 0 {
		t.Errorf("typos fired at %d", i)
	}
	// Half random, half words: fires; fewer than half random: does not.
	var half, third []string
	for i := range 30 {
		switch {
		case i%2 == 0:
			half = append(half, dga[i])
		default:
			half = append(half, typos[i])
		}
		if i%3 == 0 {
			third = append(third, dga[i])
		} else {
			third = append(third, typos[i])
		}
	}
	if i := firesAt(t, NewEngine(mustParse(t, nxRule), EngineConfig{}), nx(half, 3), 1); i != 29 {
		t.Errorf("half random fired at %d, want 29", i)
	}
	if i := firesAt(t, NewEngine(mustParse(t, nxRule), EngineConfig{}), nx(third, 3), 1); i >= 0 {
		t.Errorf("a third random fired at %d", i)
	}
}

func TestLeftLabelEntropy(t *testing.T) {
	// The thresholds rely on these: word-like labels below 3 bits per
	// character, random 12+ letter labels above.
	for _, w := range []string{"www", "mail", "gooogle", "facebok", "printer", "intranet"} {
		if e := entropyOf(w); e >= defaultNXEntropy {
			t.Errorf("%q entropy %.2f", w, e)
		}
	}
	for _, w := range []string{"xjwqpzkvhbrmta", "qmzkvwpxtrbhjc"} {
		if e := entropyOf(w); e < defaultNXEntropy {
			t.Errorf("%q entropy %.2f", w, e)
		}
	}
	if leftLabel("a.b.c") != "a" || leftLabel("abc") != "abc" {
		t.Error("leftLabel")
	}
}

func TestDNSDetectorParse(t *testing.T) {
	const hdr = "alert ip any any -> any any (msg:\"m\"; sid:1; "
	r := one(t, hdr+`detect:dns_amplification; min_bytes:1000; seconds:5;)`)
	if r.ampRatio != defaultAmpRatio || r.minBytes != 1000 {
		t.Errorf("amp defaults %v %v", r.ampRatio, r.minBytes)
	}
	r = one(t, hdr+`detect:dns_tunnel; kind:subdomains; count:50; seconds:60;)`)
	if r.minEntropy != defaultTunnelEntropy || r.minLength != defaultTunnelLength {
		t.Errorf("tunnel defaults %v %v", r.minEntropy, r.minLength)
	}
	r = one(t, hdr+`detect:dns_tunnel; kind:txt; count:5; seconds:60; allow:[Example.COM.,x.org];)`)
	if len(r.allow) != 2 || r.allow[0] != "example.com" {
		t.Errorf("allow %v", r.allow)
	}
	r = one(t, hdr+`detect:dns_nxdomain_burst; count:30; seconds:60;)`)
	if r.minEntropy != defaultNXEntropy {
		t.Errorf("nx default %v", r.minEntropy)
	}
	one(t, hdr+`detect:dns_spoof; kind:qname_mismatch;)`)

	tests := []struct{ line, want string }{
		{hdr + `detect:dns_spoof;)`, "needs kind"},
		{hdr + `detect:dns_spoof; kind:bogus;)`, `kind "bogus"`},
		{hdr + `detect:dns_spoof; kind:unsolicited_response;)`, "count"},
		{hdr + `detect:dns_spoof; kind:qname_mismatch; count:5; seconds:1;)`, "count"},
		{hdr + `detect:dns_spoof; kind:id_race; count:100000; seconds:1;)`, "count"},
		{hdr + `detect:dns_amplification; seconds:5;)`, "min_bytes"},
		{hdr + `detect:dns_amplification; min_bytes:1000; seconds:5; min_ratio:0.5;)`, "min_ratio"},
		{hdr + `detect:dns_tunnel; kind:txt; count:5; seconds:60; min_entropy:3;)`, "min_entropy"},
		{hdr + `detect:dns_tunnel; kind:subdomains; count:5; seconds:60; min_entropy:9;)`, "min_entropy"},
		{hdr + `detect:dns_tunnel; kind:subdomains; count:5; seconds:60; min_length:300;)`, "min_length"},
		{hdr + `detect:dns_tunnel; kind:subdomains; count:5; seconds:60; allow:"a b";)`, "allow"},
		{hdr + `detect:dns_nxdomain_burst; count:30;)`, "seconds"},
		{hdr + `min_bytes:5;)`, "min_bytes"},
		{`alert icmp any any -> any any (msg:"m"; sid:1; detect:dns_nxdomain_burst; count:30; seconds:60;)`, "ip, tcp or udp"},
	}
	for _, tt := range tests {
		errs := loadErrors(t, tt.line)
		if len(errs) != 1 || !strings.Contains(errs[0], tt.want) {
			t.Errorf("%s\n got %q\nwant one error with %q", tt.line, errs, tt.want)
		}
	}
}

func TestAppDomain(t *testing.T) {
	rules := `var DOH [dns.google,Cloudflare-DNS.com.]
alert tcp any any -> any 443 (msg:"m"; app_proto:tls; app_domain:sni,$DOH; sid:1;)
`
	rs := mustParse(t, rules)
	r := rs.Rules()[0]
	for _, tt := range []struct {
		sni  string
		want bool
	}{
		{"dns.google", true},
		{"DNS.Google.", true},
		{"cloudflare-dns.com", true},
		{"security.cloudflare-dns.com", true},
		{"evildns.google", false},
		{"google", false},
		{"cloudflare-dns.com.evil.example", false},
		{"", false},
	} {
		if got := r.matchApp(map[string]string{"sni": tt.sni}); got != tt.want {
			t.Errorf("sni %q: %v", tt.sni, got)
		}
	}
	if r.matchApp(map[string]string{}) {
		t.Error("missing field matched")
	}
	one(t, `alert tcp any any -> any any (msg:"m"; sid:1; app_domain:host,example.com;)`)
	// Name lists splice into other name lists.
	spliced := mustParse(t, "var A [a.com,b.com]\nvar B [$A,c.com]\n"+`alert tcp any any -> any any (msg:"m"; sid:1; app_domain:sni,$B;)`).Rules()[0]
	if !spliced.matchApp(map[string]string{"sni": "x.a.com"}) || !spliced.matchApp(map[string]string{"sni": "c.com"}) {
		t.Errorf("spliced list %+v", spliced.appDomains)
	}
	for _, tt := range []struct{ line, want string }{
		{`var N [a.com,b..c]` + "\n" + `alert tcp any any -> any any (msg:"m"; sid:1; app_domain:sni,$N;)`, "neither"},
		{`alert tcp any any -> any any (msg:"m"; sid:1; app_domain:sni;)`, "app_domain"},
		{`alert tcp any any -> any any (msg:"m"; sid:1; app_domain:sni,10.0.0.1;)`, "app_domain"},
		{`var P 80` + "\n" + `alert tcp any any -> any any (msg:"m"; sid:1; app_domain:sni,$P;)`, "holds ports"},
		{`alert icmp any any -> any any (msg:"m"; sid:1; app_domain:sni,a.com;)`, "ip, tcp or udp"},
		{`var N !a.com` + "\n" + `alert tcp any any -> any any (msg:"m"; sid:1; app_domain:sni,$N;)`, "neither"},
		{`var N a.com` + "\n" + `alert tcp any any -> any any (msg:"m"; sid:1; app_domain:sni,!$N;)`, "app_domain"},
	} {
		errs := loadErrors(t, tt.line)
		if len(errs) == 0 || !strings.Contains(strings.Join(errs, "\n"), tt.want) {
			t.Errorf("%s\n got %q\nwant %q", tt.line, errs, tt.want)
		}
	}
}

func TestParseNameList(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"example.com", "example.com", true},
		{"[A.com,b.org.]", "a.com b.org", true},
		{"[a.com, b.org]", "", false},
		{"_dmarc.example.com", "_dmarc.example.com", true},
		{"123", "", false},
		{"10.0.0.1", "", false},
		{"a..b", "", false},
		{"-", "", false},
		{"[a.com,]", "", false},
		{strings.Repeat("a", 64) + ".com", "", false},
		{"[]", "", false},
	} {
		got, err := parseNameList(tt.in)
		if (err == nil) != tt.ok || tt.ok && strings.Join(got, " ") != tt.want {
			t.Errorf("parseNameList(%q) = %q, %v", tt.in, got, err)
		}
	}
}

func entropyOf(s string) float64 { return entropy.Shannon([]byte(s)) }
