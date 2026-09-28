package rules

import (
	"container/list"
	"hash/maphash"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/bUrn-1337/intrusion-detection-system/internal/entropy"
	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// DNS detector defaults and limits. See docs/RULES.md for the reasoning.
const (
	// dnsQueryIdle is how long a query waits for its response in the
	// outstanding query table. Stub resolvers give up after about 5s.
	dnsQueryIdle = 10 * time.Second
	// maxQuestionsPerTx bounds the questions waiting under one (client,
	// port, server, id); a client reusing an id for different names
	// keeps the newest ones.
	maxQuestionsPerTx = 8
	// defaultAmpRatio is dns_amplification's min_ratio: response bytes
	// per matched query byte. Ordinary answers are 2 to 5 times their
	// query; ANY, DNSSEC and big TXT answers used for reflection are 30
	// to 100 times.
	defaultAmpRatio = 10
	// dns_tunnel kind:subdomains defaults: bits per character of the
	// subdomain part, and its length. Hostnames people pick average under
	// 3 bits (few distinct letters, many repeats); base32 or hex encoded
	// data is close to 5 or 4 bits once a label is long enough to show
	// it.
	defaultTunnelEntropy = 3.5
	defaultTunnelLength  = 50
	// defaultNXEntropy is dns_nxdomain_burst's min_entropy for the
	// leftmost label; nxHighShare of the names must reach it.
	defaultNXEntropy = 3.0
	nxHighShare      = 0.5
	// tunnelSamples is how many recent query names a dns_tunnel alert
	// shows.
	tunnelSamples = 3
)

var (
	spoofKinds  = []string{SpoofUnsolicited, SpoofIDRace, SpoofQNameMismatch}
	tunnelKinds = []string{TunnelSubdomains, TunnelTXT}
)

// DNS query types the detectors look at.
const (
	qtypeCNAME = 5
	qtypeNULL  = 10
	qtypeMX    = 15
	qtypeTXT   = 16
	rcodeNX    = 3
)

// dnsMsg is one DNS message of a packet, from its AppFields.
type dnsMsg struct {
	id       uint16
	qname    string // lowercased, "" without a question
	qtype    uint16
	response bool
	rcode    int
	size     uint64 // message bytes, without the TCP length prefix
}

// dnsMessages appends the DNS messages of p: the one in AppFields and,
// for a reassembled TCP segment, those in AppMore. Messages without an
// id (too short to have a header) are skipped.
func dnsMessages(p *packet.ParsedPacket, buf []dnsMsg) []dnsMsg {
	add := func(f map[string]string) {
		id, err := strconv.ParseUint(f["id"], 10, 16)
		if err != nil {
			return
		}
		m := dnsMsg{id: uint16(id), qname: f["qname"], response: f["is_response"] == "true"}
		if q, err := strconv.ParseUint(f["qtype"], 10, 16); err == nil {
			m.qtype = uint16(q)
		}
		m.rcode, _ = strconv.Atoi(f["rcode"])
		m.size, _ = strconv.ParseUint(f["dns_len"], 10, 64)
		buf = append(buf, m)
	}
	if p.AppFields != nil {
		add(p.AppFields)
	}
	for _, f := range p.AppMore {
		add(f)
	}
	return buf
}

// dnsTx identifies a DNS transaction: the client's address and port, the
// server's address, and the message id. The question is compared
// separately, so a response whose transaction matches but whose question
// does not can be told from one nobody asked for.
type dnsTx struct {
	client, server netip.Addr
	cport          uint16
	id             uint16
}

type dnsQuestion struct {
	qname string
	qtype uint16
	size  uint64
	t     time.Time
}

type dnsPending struct {
	tx   dnsTx
	qs   []dnsQuestion // oldest first
	last time.Time
}

// dnsQueries is the outstanding query table: the questions sent to a
// server and not answered yet, per transaction. A question is forgotten
// when answered or dnsQueryIdle after it was sent. Transactions are
// capped at max; at the cap the least recently queried is evicted and
// counted in stat. It sees every query, whitelisted or passed or not.
// names counts the outstanding questions per (client, server, name),
// whatever their port and id, for kind:id_race.
type dnsQueries struct {
	max   int
	m     map[dnsTx]*list.Element // Value is *dnsPending
	lru   list.List               // front = least recently queried
	names map[raceKey]int32
	seed  maphash.Seed
	stat  *tableStat
}

func newDNSQueries(max int, stat *tableStat) *dnsQueries {
	return &dnsQueries{max: max, m: make(map[dnsTx]*list.Element), names: make(map[raceKey]int32), seed: maphash.MakeSeed(), stat: stat}
}

func (q *dnsQueries) nameKey(tx dnsTx, qname string) raceKey {
	return raceKey{client: tx.client, server: tx.server, name: maphash.String(q.seed, qname)}
}

// count adds d to the outstanding questions for qname in tx.
func (q *dnsQueries) count(tx dnsTx, qname string, d int32) {
	k := q.nameKey(tx, qname)
	if n := q.names[k] + d; n > 0 {
		q.names[k] = n
	} else {
		delete(q.names, k)
	}
}

// asked reports whether the client of tx has a question for qname
// outstanding at the server of tx, on any port and id.
func (q *dnsQueries) asked(tx dnsTx, qname string) bool {
	return q.names[q.nameKey(tx, qname)] > 0
}

// Outcomes of dnsQueries.answer.
const (
	dnsMatched     = iota // the response answers an outstanding question
	dnsUnsolicited        // no question is outstanding for its transaction
	dnsMismatch           // its transaction has questions, none of them its own
)

// query records a question sent at t. A retransmission refreshes it.
func (q *dnsQueries) query(tx dnsTx, m *dnsMsg, t time.Time) {
	q.prune(t)
	el, ok := q.m[tx]
	if ok {
		q.lru.MoveToBack(el)
	} else {
		if len(q.m) >= q.max {
			q.remove(q.lru.Front())
			q.stat.evictions.Add(1)
		}
		el = q.lru.PushBack(&dnsPending{tx: tx})
		q.m[tx] = el
		q.stat.keys.Add(1)
	}
	pd := el.Value.(*dnsPending)
	if t.After(pd.last) {
		pd.last = t
	}
	for i := range pd.qs {
		if pd.qs[i].qname == m.qname && pd.qs[i].qtype == m.qtype {
			pd.qs[i].t, pd.qs[i].size = pd.last, m.size
			return
		}
	}
	if len(pd.qs) == maxQuestionsPerTx {
		q.count(tx, pd.qs[0].qname, -1)
		pd.qs = append(pd.qs[:0], pd.qs[1:]...)
	}
	pd.qs = append(pd.qs, dnsQuestion{qname: m.qname, qtype: m.qtype, size: m.size, t: pd.last})
	q.count(tx, m.qname, 1)
}

// answer looks up a response of transaction tx at t. A matching question
// is removed and its query size returned. A response without a question
// (a server may leave it out of an error) matches the oldest one.
func (q *dnsQueries) answer(tx dnsTx, m *dnsMsg, t time.Time) (int, uint64) {
	q.prune(t)
	el, ok := q.m[tx]
	if !ok {
		return dnsUnsolicited, 0
	}
	pd := el.Value.(*dnsPending)
	live := pd.qs[:0]
	for _, x := range pd.qs {
		if t.Sub(x.t) <= dnsQueryIdle {
			live = append(live, x)
		} else {
			q.count(tx, x.qname, -1)
		}
	}
	pd.qs = live
	found := -1
	for i, x := range pd.qs {
		if m.qname == "" || x.qname == m.qname && x.qtype == m.qtype {
			found = i
			break
		}
	}
	switch {
	case len(pd.qs) == 0:
		q.remove(el)
		return dnsUnsolicited, 0
	case found < 0:
		return dnsMismatch, 0
	}
	size := pd.qs[found].size
	q.count(tx, pd.qs[found].qname, -1)
	pd.qs = append(pd.qs[:found], pd.qs[found+1:]...)
	if len(pd.qs) == 0 {
		q.remove(el)
	}
	return dnsMatched, size
}

func (q *dnsQueries) prune(now time.Time) {
	for el := q.lru.Front(); el != nil; el = q.lru.Front() {
		if now.Sub(el.Value.(*dnsPending).last) <= dnsQueryIdle {
			return
		}
		q.remove(el)
	}
}

func (q *dnsQueries) remove(el *list.Element) {
	pd := q.lru.Remove(el).(*dnsPending)
	for _, x := range pd.qs {
		q.count(pd.tx, x.qname, -1)
	}
	delete(q.m, pd.tx)
	q.stat.keys.Add(-1)
}

func (q *dnsQueries) clear() {
	q.stat.keys.Add(-int64(len(q.m)))
	clear(q.m)
	clear(q.names)
	q.lru.Init()
}

func (q *dnsQueries) len() int { return len(q.m) }

// dnsSpoof is the detect:dns_spoof detector for one rule (see dns
// responses fed by Engine.dns).
//
//   - kind:unsolicited_response counts, per client, responses that answer
//     no outstanding query. One is common enough (a response arriving
//     after the query timed out, a server answering a retransmission
//     twice), so it takes count within seconds.
//   - kind:id_race counts, per (client, server, name), the distinct ids
//     of unanswered responses for a name the client has asked that server
//     and not had answered: a Kaminsky-style race floods the client with
//     forged answers for its pending question, guessing the id. A client
//     asking the same name repeatedly gets matched answers, and a
//     reflection victim asked nothing, so neither counts.
//   - kind:qname_mismatch fires on one response whose client, ports and
//     id match an outstanding query but whose question does not: an
//     answer forged for the wrong query, or a broken server.
type dnsSpoof struct {
	rule  *Rule
	unsol *windowCounter[netip.Addr]        // unsolicited_response, per client
	race  *distinctCounter[raceKey, uint16] // id_race: ids per (client, server, name)
	seed  maphash.Seed                      // hashes names for raceKey
}

type raceKey struct {
	client, server netip.Addr
	name           uint64 // qname hash
}

func newDNSSpoof(r *Rule, max int, stat *tableStat) *dnsSpoof {
	d := &dnsSpoof{rule: r, seed: maphash.MakeSeed()}
	switch r.dnsKind {
	case SpoofUnsolicited:
		d.unsol = newWindowCounter[netip.Addr](r.detect.count, r.detect.span(), max, stat)
	case SpoofIDRace:
		d.race = newDistinctCounter[raceKey, uint16](r.detect.count, r.detect.span(), max, stat)
	}
	return d
}

// response feeds one response, its outcome in the query table, and
// whether its name is asked by the client of the server on another
// transaction.
func (d *dnsSpoof) response(tx dnsTx, m *dnsMsg, outcome int, asked bool, t time.Time) (func() map[string]string, bool) {
	r := d.rule
	base := func(extra map[string]string) map[string]string {
		extra["detector"] = DetectDNSSpoof
		extra["kind"] = r.dnsKind
		extra["client"] = tx.client.String()
		extra["server"] = tx.server.String()
		extra["qname"] = m.qname
		extra["id"] = strconv.Itoa(int(m.id))
		return extra
	}
	switch r.dnsKind {
	case SpoofQNameMismatch:
		if outcome != dnsMismatch {
			return nil, false
		}
		return func() map[string]string {
			return base(map[string]string{"client_port": strconv.Itoa(int(tx.cport))})
		}, true
	case SpoofUnsolicited:
		if outcome != dnsUnsolicited {
			return nil, false
		}
		ent, fired := d.unsol.add(tx.client, t, 0)
		if !fired {
			return nil, false
		}
		return func() map[string]string {
			return base(map[string]string{
				"responses": strconv.Itoa(ent.size()),
				"seconds":   strconv.Itoa(r.detect.seconds),
				"window":    ent.newest().Sub(ent.oldest()).Round(time.Millisecond).String(),
			})
		}, true
	case SpoofIDRace:
		if outcome != dnsUnsolicited || !asked {
			return nil, false
		}
		k := raceKey{client: tx.client, server: tx.server, name: maphash.String(d.seed, m.qname)}
		ids := d.race.add(k, m.id, t, 0).size()
		if ids < r.detect.count {
			return nil, false
		}
		return func() map[string]string {
			return base(map[string]string{
				"distinct_ids": strconv.Itoa(ids),
				"seconds":      strconv.Itoa(r.detect.seconds),
			})
		}, true
	}
	return nil, false
}

func (d *dnsSpoof) clear() {
	if d.unsol != nil {
		d.unsol.clear()
	}
	if d.race != nil {
		d.race.clear()
	}
}

// dnsAmp is the detect:dns_amplification detector for one rule. Per
// victim (the client a response goes to) it sums over seconds the
// response bytes, the bytes of the queries they answered, and the bytes
// of responses that answer nothing. Reflection spoofs the victim's
// address in small queries (ANY, DNSSEC) to open resolvers, so the
// victim receives large answers to queries it never sent, or a stream
// far larger than what it asked. It fires when min_bytes of responses
// arrive and they are at least min_ratio times the matched query bytes,
// or when min_bytes of unmatched responses alone arrive.
type dnsAmp struct {
	rule *Rule
	rate *rateCounter[netip.Addr] // series: response bytes, matched query bytes, unmatched response bytes
}

const (
	ampRespBytes = iota
	ampQueryBytes
	ampUnmatchedBytes
)

func newDNSAmp(r *Rule, max int, stat *tableStat) *dnsAmp {
	return &dnsAmp{rule: r, rate: newRateCounter[netip.Addr](r.detect.span(), max, stat)}
}

func (d *dnsAmp) response(tx dnsTx, m *dnsMsg, outcome int, qsize uint64, t time.Time) (func() map[string]string, bool) {
	var vals [rateSeries]uint64
	vals[ampRespBytes] = m.size
	if outcome == dnsMatched {
		vals[ampQueryBytes] = qsize
	} else {
		vals[ampUnmatchedBytes] = m.size
	}
	ent := d.rate.add(tx.client, t, vals)
	ent.countTag(m.qtype)
	r := d.rule
	resp, query, unmatched := ent.sum(ampRespBytes), ent.sum(ampQueryBytes), ent.sum(ampUnmatchedBytes)
	var reason string
	switch {
	case unmatched >= r.minBytes:
		reason = "unmatched"
	case resp >= r.minBytes && float64(resp) >= r.ampRatio*float64(query):
		reason = "ratio"
	default:
		return nil, false
	}
	return func() map[string]string {
		m := map[string]string{
			"detector":        DetectDNSAmplification,
			"track":           TrackByDst.String(),
			"tracked_addr":    tx.client.String(),
			"reason":          reason,
			"response_bytes":  strconv.FormatUint(resp, 10),
			"query_bytes":     strconv.FormatUint(query, 10),
			"unmatched_bytes": strconv.FormatUint(unmatched, 10),
			"min_bytes":       strconv.FormatUint(r.minBytes, 10),
			"min_ratio":       strconv.FormatFloat(r.ampRatio, 'f', -1, 64),
			"top_qtype":       strconv.Itoa(int(ent.topTag())),
			"seconds":         strconv.Itoa(r.detect.seconds),
		}
		if query > 0 {
			m["ratio"] = strconv.FormatFloat(float64(resp)/float64(query), 'f', 1, 64)
		}
		return m
	}, true
}

func (d *dnsAmp) clear() { d.rate.clear() }

// registeredDomain returns the registrable domain of name (its effective
// TLD plus one label, by the Public Suffix List) and the labels left of
// it, or ok false for a name that is a public suffix itself.
//
// "The last two labels" would be wrong both ways: for www.bbc.co.uk it
// gives co.uk, lumping every British company into one domain, and for
// alice.github.io it gives github.io, one domain for every GitHub Pages
// site. A tunnel detector counting subdomains per domain would then see
// all of them as one busy domain.
func registeredDomain(name string) (domain, sub string, ok bool) {
	name = strings.TrimSuffix(name, ".")
	d, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return "", "", false
	}
	if len(name) > len(d) {
		sub = name[:len(name)-len(d)-1]
	}
	return d, sub, true
}

// dnsTunnel is the detect:dns_tunnel detector for one rule. It looks at
// queries, per (client, registered domain), skipping allowed domains.
//
//   - kind:subdomains keeps the distinct subdomain parts (the labels left
//     of the registered domain) seen within seconds, up to count, with
//     their entropy and length. It fires when count of them are distinct
//     and they average min_entropy bits per character or min_length
//     characters: data encoded into names (iodine, dnscat2, DNS
//     exfiltration) makes every query a new, long, random-looking name.
//   - kind:txt counts TXT and NULL queries: the record types tunnels use
//     to bring data back. It fires at count within seconds.
type dnsTunnel struct {
	rule *Rule
	subs *distinctCounter[tunnelKey, tunnelVal] // kind:subdomains
	txt  *windowCounter[tunnelKey]              // kind:txt
	seed maphash.Seed
	// samples holds the last query names per key, for the alert; only
	// keys already holding count-tunnelSamples subdomains record them,
	// so it stays small.
	samples *recentSet[tunnelKey]
	names   map[tunnelKey]*[tunnelSamples]string
}

type tunnelKey struct {
	client netip.Addr
	domain string
}

// tunnelVal is one distinct subdomain: its hash, and its entropy and
// length, which are the same for every sighting. The distinct value
// bits mark TXT, NULL, CNAME and MX queries.
type tunnelVal struct {
	h   uint64
	ent float32
	len uint16
}

const tunnelOddType = 1 // distinctVal bit: a TXT, NULL, CNAME or MX query

func newDNSTunnel(r *Rule, max int, stat *tableStat) *dnsTunnel {
	d := &dnsTunnel{rule: r, seed: maphash.MakeSeed()}
	if r.dnsKind == TunnelTXT {
		d.txt = newWindowCounter[tunnelKey](r.detect.count, r.detect.span(), max, stat)
	} else {
		d.subs = newDistinctCounter[tunnelKey, tunnelVal](r.detect.count, r.detect.span(), max, stat)
		d.samples = newRecentSet[tunnelKey](r.detect.span(), max, stat)
		d.names = make(map[tunnelKey]*[tunnelSamples]string)
	}
	return d
}

// query feeds one query from client.
func (d *dnsTunnel) query(client netip.Addr, m *dnsMsg, t time.Time) (tunnelKey, func() map[string]string, bool) {
	r := d.rule
	domain, sub, ok := registeredDomain(m.qname)
	if !ok || inDomains(domain, r.allow) {
		return tunnelKey{}, nil, false
	}
	k := tunnelKey{client: client, domain: domain}
	odd := m.qtype == qtypeTXT || m.qtype == qtypeNULL
	if r.dnsKind == TunnelTXT {
		if !odd {
			return k, nil, false
		}
		ent, fired := d.txt.add(k, t, m.qtype)
		if !fired {
			return k, nil, false
		}
		qname := m.qname
		return k, func() map[string]string {
			return map[string]string{
				"detector":          DetectDNSTunnel,
				"kind":              TunnelTXT,
				"client":            client.String(),
				"registered_domain": domain,
				"txt_null_queries":  strconv.Itoa(ent.size()),
				"seconds":           strconv.Itoa(r.detect.seconds),
				"sample_qnames":     qname,
			}
		}, true
	}
	if sub == "" {
		return k, nil, false
	}
	flat := strings.ReplaceAll(sub, ".", "")
	v := tunnelVal{h: maphash.String(d.seed, sub), ent: float32(entropy.Shannon([]byte(flat))), len: uint16(len(flat))}
	var bits uint8
	if odd || m.qtype == qtypeCNAME || m.qtype == qtypeMX {
		bits = tunnelOddType
	}
	e := d.subs.add(k, v, t, bits)
	n := e.size()
	d.sample(k, m.qname, n, t)
	if n < r.detect.count {
		return k, nil, false
	}
	var sumEnt, sumLen float64
	oddN := 0
	for _, x := range e.vals {
		sumEnt += float64(x.v.ent)
		sumLen += float64(x.v.len)
		if x.bits&tunnelOddType != 0 {
			oddN++
		}
	}
	avgEnt, avgLen := sumEnt/float64(len(e.vals)), sumLen/float64(len(e.vals))
	if avgEnt < r.minEntropy && avgLen < float64(r.minLength) {
		return k, nil, false
	}
	var samples []string
	if s := d.names[k]; s != nil {
		for _, q := range s {
			if q != "" {
				samples = append(samples, q)
			}
		}
	}
	return k, func() map[string]string {
		return map[string]string{
			"detector":          DetectDNSTunnel,
			"kind":              TunnelSubdomains,
			"client":            client.String(),
			"registered_domain": domain,
			"unique_subdomains": strconv.Itoa(n),
			"avg_entropy":       strconv.FormatFloat(avgEnt, 'f', 2, 64),
			"avg_length":        strconv.FormatFloat(avgLen, 'f', 1, 64),
			"txt_null_cname_mx": strconv.FormatFloat(float64(oddN)/float64(len(e.vals)), 'f', 2, 64),
			"sample_qnames":     strings.Join(samples, " "),
			"seconds":           strconv.Itoa(r.detect.seconds),
			"min_entropy":       strconv.FormatFloat(r.minEntropy, 'f', -1, 64),
			"min_length":        strconv.Itoa(r.minLength),
		}
	}, true
}

// sample records qname as one of the last names of k once k is close to
// firing.
func (d *dnsTunnel) sample(k tunnelKey, qname string, n int, t time.Time) {
	if n+tunnelSamples < d.rule.detect.count {
		return
	}
	// Drop sample slots whose keys the recent set has let go.
	if len(d.names) > 2*d.samples.len()+64 {
		for key := range d.names {
			if !d.samples.has(key, t) {
				delete(d.names, key)
			}
		}
	}
	d.samples.add(k, t)
	s := d.names[k]
	if s == nil {
		s = new([tunnelSamples]string)
		d.names[k] = s
	}
	copy(s[:], s[1:])
	s[tunnelSamples-1] = qname
}

func (d *dnsTunnel) clear() {
	if d.txt != nil {
		d.txt.clear()
	}
	if d.subs != nil {
		d.subs.clear()
		d.samples.clear()
		clear(d.names)
	}
}

// nxBurst is the detect:dns_nxdomain_burst detector for one rule. Per
// client it keeps the distinct names answered NXDOMAIN within seconds,
// marking those whose leftmost label has min_entropy bits per character.
// It fires when count names are distinct and at least half of them are
// marked: malware generating domains (DGA) tries many random names until
// one resolves. Typos and a broken search domain also produce NXDOMAIN
// bursts, but their names are words ("gooogle", "www", "mail").
type nxBurst struct {
	rule *Rule
	nx   *distinctCounter[netip.Addr, uint64] // name hash; bit 1: high entropy
	seed maphash.Seed
}

func newNXBurst(r *Rule, max int, stat *tableStat) *nxBurst {
	return &nxBurst{rule: r, nx: newDistinctCounter[netip.Addr, uint64](r.detect.count, r.detect.span(), max, stat), seed: maphash.MakeSeed()}
}

// leftLabel returns the first label of name.
func leftLabel(name string) string {
	l, _, _ := strings.Cut(name, ".")
	return l
}

func (d *nxBurst) response(client netip.Addr, m *dnsMsg, t time.Time) (func() map[string]string, bool) {
	if m.rcode != rcodeNX || m.qname == "" {
		return nil, false
	}
	r := d.rule
	var bits uint8
	if entropy.Shannon([]byte(leftLabel(m.qname))) >= r.minEntropy {
		bits = 1
	}
	e := d.nx.add(client, maphash.String(d.seed, m.qname), t, bits)
	n := e.size()
	if n < r.detect.count {
		return nil, false
	}
	high := 0
	for _, x := range e.vals {
		if x.bits != 0 {
			high++
		}
	}
	if float64(high) < nxHighShare*float64(len(e.vals)) {
		return nil, false
	}
	qname := m.qname
	return func() map[string]string {
		return map[string]string{
			"detector":           DetectNXDomainBurst,
			"track":              TrackByDst.String(),
			"tracked_addr":       client.String(),
			"nxdomain_names":     strconv.Itoa(n),
			"high_entropy_names": strconv.Itoa(high),
			"min_entropy":        strconv.FormatFloat(r.minEntropy, 'f', -1, 64),
			"seconds":            strconv.Itoa(r.detect.seconds),
			"sample_qname":       qname,
		}
	}, true
}

func (d *nxBurst) clear() { d.nx.clear() }
