package rules

import (
	"container/heap"
	"container/list"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// slowIdle is how long a slow flow is kept without a packet. The stream
// stage drops its flows after the same time and reports them in
// ClosedFlows; this is the fallback when it does not track the flow.
const slowIdle = 2 * time.Minute

// slowDetailSample is how many flow IDs and targets an alert lists.
const slowDetailSample = 5

// slowTable is the detect:slowloris state shared by all slowloris rules.
//
// It follows the HTTP flows the stream stage reassembles (packets with a
// FlowID), using the http_* AppFields it writes on client-to-server
// packets and the client's TCP window. A flow is tracked while it could
// be slow: its client is in the middle of a request head
// (headers_partial) or a request body (body_partial), or advertises a
// zero window. A flow that completes its request, goes idle between
// keep-alive requests, sends FIN or RST, or is closed by the stream
// stage leaves the table, and every rule's count, at once.
//
// Whether a flow qualifies for a rule depends on time as well as on its
// packets (a head becomes old enough, a client goes quiet), so each flow
// is queued at the next time its qualification can change, and flows due
// are re-checked on every packet and in Flush.
//
// Each rule counts the flows that qualify per tracked address (the
// client for track:by_src, the server for track:by_dst), and fires when a
// flow starts to qualify and its address then has count or more.
type slowTable struct {
	max   int
	m     map[uint64]*slowFlow
	lru   list.List // Value is *slowFlow; front = least recently seen
	due   slowHeap
	rules []slowRule // one per RuleSet.slow rule, in the same order
	stat  *tableStat // flows
	gstat *tableStat // tracked addresses, over rules
}

type slowRule struct {
	r      *Rule
	groups map[netip.Addr]map[uint64]*slowFlow // qualifying flows per tracked address
}

// Values of slowFlow.state.
const (
	slowNone uint8 = iota // no request head or body in progress (idle, complete, or unknown)
	slowHead              // headers_partial
	slowBody              // body_partial
)

// Bits of slowFlow.rules[i].
const (
	slowApplies   uint8 = 1 << iota // the rule's addresses match the flow
	slowQualified                   // the flow counts toward the rule
)

type slowFlow struct {
	id             uint64
	client, server netip.Addr
	cport, sport   uint16
	el             *list.Element
	hidx           int // index in slowTable.due, or -1
	due            time.Time

	last      time.Time // last packet, either direction
	lastData  time.Time // last client packet with payload
	state     uint8
	msgStart  time.Time // start of the request in progress
	expected  int64     // declared body length, or -1 if unknown
	seen      int64     // body bytes received
	zeroSince time.Time // since when the client's window is zero; zero time if it is not
	ignore    bool      // whitelisted client or a matching pass rule
	rules     []uint8
}

func newSlowTable(max int, stat, gstat *tableStat) *slowTable {
	return &slowTable{max: max, m: make(map[uint64]*slowFlow), stat: stat, gstat: gstat}
}

// view returns the flow as a packet from client to server.
func (f *slowFlow) view() view {
	return view{g: gTCP, src: f.client, dst: f.server, sport: f.cport, dport: f.sport, havePayload: true, haveLower: true}
}

// slowloris runs the slowloris rules for one packet: it drops the flows
// the stream stage closed, re-checks flows that are due, and applies the
// packet to its flow.
func (e *Engine) slowloris(rs *RuleSet, p *packet.ParsedPacket, v *view, out []Alert) []Alert {
	t := e.slow
	for _, id := range p.ClosedFlows {
		if f := t.m[id]; f != nil {
			t.remove(f)
		}
	}
	out = e.slowAge(out)
	if v.g != gTCP || p.FlowID == 0 {
		return out
	}
	f := t.m[p.FlowID]
	if v.flags&(tcpFIN|tcpRST) != 0 {
		if f != nil {
			t.remove(f)
		}
		return out
	}
	// Only client-to-server packets carry http_state, when the stream
	// stage is reassembling that direction.
	state, hasState := p.AppFields["http_state"]
	fromClient := hasState || f != nil && v.src == f.client && v.sport == f.cport
	if !fromClient {
		if f != nil {
			t.touch(f, e.now)
		}
		return out
	}
	zero := p.TCPWindow == 0
	if f == nil {
		if state != "headers_partial" && state != "body_partial" && !zero {
			return out
		}
		f = t.add(p.FlowID, v, e.now)
		e.slowFilter(rs, f)
	}
	t.touch(f, e.now)
	if len(v.getPayload()) > 0 {
		f.lastData = e.now
	}
	f.state = slowNone
	switch state {
	case "headers_partial", "body_partial":
		ns, err := strconv.ParseInt(p.AppFields["http_msg_start"], 10, 64)
		if err != nil {
			break
		}
		f.msgStart = time.Unix(0, ns).UTC()
		f.state = slowHead
		if state == "body_partial" {
			f.state = slowBody
			f.expected, f.seen = -1, 0
			if n, err := strconv.ParseInt(p.AppFields["http_body_expected"], 10, 64); err == nil {
				f.expected = n
			}
			if n, err := strconv.ParseInt(p.AppFields["http_body_seen"], 10, 64); err == nil {
				f.seen = n
			}
		}
	}
	switch {
	case !zero:
		f.zeroSince = time.Time{}
	case f.zeroSince.IsZero():
		f.zeroSince = e.now
	}
	if f.state == slowNone && f.zeroSince.IsZero() {
		t.remove(f)
		return out
	}
	return e.slowCheck(f, true, out)
}

// slowAge re-checks the flows due by now, and drops those idle too long.
func (e *Engine) slowAge(out []Alert) []Alert {
	t := e.slow
	for len(t.due) > 0 && !t.due[0].due.After(e.now) {
		f := t.due[0]
		if e.now.Sub(f.last) >= slowIdle {
			t.remove(f)
			continue
		}
		out = e.slowCheck(f, true, out)
	}
	return out
}

// slowFilter sets which rules apply to f: none for a whitelisted client
// or a flow a pass rule matches, as for any packet from the client.
func (e *Engine) slowFilter(rs *RuleSet, f *slowFlow) {
	fv := f.view()
	f.ignore = e.isWhitelisted(f.client) || e.passes(rs, &fv)
	f.rules = slices.Grow(f.rules[:0], len(rs.slow))[:len(rs.slow)]
	for i, r := range rs.slow {
		f.rules[i] = 0
		if !f.ignore && r.matchAddrs(&fv) {
			f.rules[i] = slowApplies
		}
	}
}

// slowCheck updates f's standing with every rule, emitting an alert
// (when emit is set) for each rule it starts to qualify for whose
// tracked address then has count flows, and requeues f.
func (e *Engine) slowCheck(f *slowFlow, emit bool, out []Alert) []Alert {
	t := e.slow
	now := e.now
	for i := range t.rules {
		sr := &t.rules[i]
		r := sr.r
		q := f.rules[i]&slowApplies != 0 && f.qualifies(r, now)
		was := f.rules[i]&slowQualified != 0
		if q == was {
			continue
		}
		key := f.client
		if r.detect.track == TrackByDst {
			key = f.server
		}
		if !q {
			f.rules[i] &^= slowQualified
			t.leave(sr, key, f.id)
			continue
		}
		f.rules[i] |= slowQualified
		g := sr.groups[key]
		if g == nil {
			g = make(map[uint64]*slowFlow)
			sr.groups[key] = g
			t.gstat.keys.Add(1)
		}
		g[f.id] = f
		if emit && len(g) >= r.detect.count {
			fv := f.view()
			details := slowDetails(r, key, g, now)
			out = e.emit(r, dedupKey{sid: r.SID, addr: key}, &fv, func() map[string]string { return details }, out)
		}
	}
	t.schedule(f, f.nextDue(t.rules, now))
	return out
}

// qualifies reports whether f counts toward r at now.
func (f *slowFlow) qualifies(r *Rule, now time.Time) bool {
	active := now.Sub(f.lastData) <= time.Duration(r.detect.seconds)*time.Second
	switch r.slowKind {
	case SlowHeaders:
		return f.state == slowHead && now.Sub(f.msgStart) > r.minAge && active
	case SlowBody:
		age := now.Sub(f.msgStart)
		return f.state == slowBody && f.expected >= 0 && f.expected-f.seen > int64(r.minRemaining) &&
			age > r.minAge && active && float64(f.seen) < float64(r.minRate)*age.Seconds()
	case SlowRead:
		return !f.zeroSince.IsZero() && now.Sub(f.zeroSince) > r.minAge
	}
	return false
}

// nextDue returns the earliest time after now at which f's
// qualification for some rule can change, or it goes idle.
func (f *slowFlow) nextDue(rules []slowRule, now time.Time) time.Time {
	due := f.last.Add(slowIdle)
	at := func(t time.Time) {
		if t.After(now) && t.Before(due) {
			due = t
		}
	}
	for i := range rules {
		if f.rules[i]&slowApplies == 0 {
			continue
		}
		r := rules[i].r
		quiet := f.lastData.Add(time.Duration(r.detect.seconds)*time.Second + 1)
		switch r.slowKind {
		case SlowHeaders:
			if f.state == slowHead {
				at(f.msgStart.Add(r.minAge + 1))
				at(quiet)
			}
		case SlowBody:
			if f.state == slowBody {
				at(f.msgStart.Add(r.minAge + 1))
				at(quiet)
				// The average rate drops below min_rate after
				// seen/min_rate seconds.
				at(f.msgStart.Add(time.Duration(float64(f.seen)/float64(r.minRate)*float64(time.Second)) + 1))
			}
		case SlowRead:
			if !f.zeroSince.IsZero() {
				at(f.zeroSince.Add(r.minAge + 1))
			}
		}
	}
	return due
}

// slowDetails describes the flows of one tracked address.
func slowDetails(r *Rule, key netip.Addr, g map[uint64]*slowFlow, now time.Time) map[string]string {
	var oldest time.Duration
	ids := make([]uint64, 0, len(g))
	targets := make(map[string]bool)
	clients := make(map[netip.Addr]bool)
	for id, f := range g {
		ids = append(ids, id)
		targets[netip.AddrPortFrom(f.server, f.sport).String()] = true
		clients[f.client] = true
		since := f.msgStart
		if r.slowKind == SlowRead {
			since = f.zeroSince
		}
		oldest = max(oldest, now.Sub(since))
	}
	slices.Sort(ids)
	sample := make([]string, 0, slowDetailSample)
	for _, id := range ids[:min(len(ids), slowDetailSample)] {
		sample = append(sample, strconv.FormatUint(id, 10))
	}
	tl := make([]string, 0, len(targets))
	for t := range targets {
		tl = append(tl, t)
	}
	slices.Sort(tl)
	d := map[string]string{
		"detector":         DetectSlowloris,
		"kind":             r.slowKind,
		"track":            r.detect.track.String(),
		"tracked_addr":     key.String(),
		"flows":            strconv.Itoa(len(g)),
		"count":            strconv.Itoa(r.detect.count),
		"oldest_age":       oldest.Round(time.Millisecond).String(),
		"min_age":          r.minAge.String(),
		"targets":          strings.Join(tl[:min(len(tl), slowDetailSample)], ","),
		"distinct_targets": strconv.Itoa(len(tl)),
		"clients":          strconv.Itoa(len(clients)),
		"sample_flow_ids":  strings.Join(sample, ","),
	}
	if r.slowKind != SlowRead {
		d["seconds"] = strconv.Itoa(r.detect.seconds)
	}
	if r.slowKind == SlowBody {
		d["min_rate"] = strconv.Itoa(r.minRate)
		d["min_remaining"] = strconv.Itoa(r.minRemaining)
	}
	return d
}

// activateSlow switches the table to the slowloris rules of rs. Flows are
// kept; their standing is recomputed without alerting, since nothing
// about them changed but the rules.
func (e *Engine) activateSlow(rs *RuleSet) {
	t := e.slow
	for i := range t.rules {
		t.gstat.keys.Add(-int64(len(t.rules[i].groups)))
	}
	if len(rs.slow) == 0 {
		t.clear()
		return
	}
	t.rules = t.rules[:0]
	for _, r := range rs.slow {
		t.rules = append(t.rules, slowRule{r: r, groups: make(map[netip.Addr]map[uint64]*slowFlow)})
	}
	for _, f := range t.m {
		e.slowFilter(rs, f)
		e.slowCheck(f, false, nil)
	}
}

func (t *slowTable) add(id uint64, v *view, now time.Time) *slowFlow {
	if len(t.m) >= t.max {
		t.remove(t.lru.Front().Value.(*slowFlow))
		t.stat.evictions.Add(1)
	}
	f := &slowFlow{id: id, client: v.src, server: v.dst, cport: v.sport, sport: v.dport, hidx: -1, last: now, lastData: now}
	f.el = t.lru.PushBack(f)
	t.m[id] = f
	t.stat.keys.Add(1)
	return f
}

func (t *slowTable) touch(f *slowFlow, now time.Time) {
	f.last = now
	t.lru.MoveToBack(f.el)
}

// remove drops f from the table and from every rule's count.
func (t *slowTable) remove(f *slowFlow) {
	for i := range t.rules {
		if f.rules[i]&slowQualified == 0 {
			continue
		}
		sr := &t.rules[i]
		key := f.client
		if sr.r.detect.track == TrackByDst {
			key = f.server
		}
		t.leave(sr, key, f.id)
	}
	if f.hidx >= 0 {
		heap.Remove(&t.due, f.hidx)
	}
	t.lru.Remove(f.el)
	delete(t.m, f.id)
	t.stat.keys.Add(-1)
}

func (t *slowTable) leave(sr *slowRule, key netip.Addr, id uint64) {
	g := sr.groups[key]
	delete(g, id)
	if len(g) == 0 {
		delete(sr.groups, key)
		t.gstat.keys.Add(-1)
	}
}

func (t *slowTable) schedule(f *slowFlow, due time.Time) {
	f.due = due
	if f.hidx >= 0 {
		heap.Fix(&t.due, f.hidx)
	} else {
		heap.Push(&t.due, f)
	}
}

func (t *slowTable) clear() {
	t.stat.keys.Add(-int64(len(t.m)))
	clear(t.m)
	t.lru.Init()
	t.due = t.due[:0]
	t.rules = t.rules[:0]
}

// slowHeap orders flows by due time.
type slowHeap []*slowFlow

func (h slowHeap) Len() int           { return len(h) }
func (h slowHeap) Less(i, j int) bool { return h[i].due.Before(h[j].due) }
func (h slowHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].hidx, h[j].hidx = i, j
}
func (h *slowHeap) Push(x any) {
	f := x.(*slowFlow)
	f.hidx = len(*h)
	*h = append(*h, f)
}
func (h *slowHeap) Pop() any {
	old := *h
	f := old[len(old)-1]
	old[len(old)-1] = nil
	f.hidx = -1
	*h = old[:len(old)-1]
	return f
}
