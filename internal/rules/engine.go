package rules

import (
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Alert kinds.
const (
	KindAlert   = "alert"
	KindSummary = "summary"
)

// Alert is one alert or dedup summary. Module 6 writes it as JSON Lines.
//
// For Kind "alert", Count is 1 and Time == FirstSeen == LastSeen. For
// Kind "summary", Count is the total number of matches in the dedup
// window (including the first), Time is when the window closed, and the
// address and port fields are those of the first match.
type Alert struct {
	Time      time.Time         `json:"time"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
	SID       int               `json:"sid"`
	Rev       int               `json:"rev"`
	Msg       string            `json:"msg"`
	Severity  string            `json:"severity"`
	Category  string            `json:"category,omitempty"`
	Proto     string            `json:"proto"`
	SrcIP     string            `json:"src_ip"`
	DstIP     string            `json:"dst_ip"`
	SrcPort   uint16            `json:"src_port"`
	DstPort   uint16            `json:"dst_port"`
	Count     int               `json:"count"`
	Kind      string            `json:"kind"`
	Details   map[string]string `json:"details,omitempty"`
}

// EngineConfig configures an Engine. Zero values select the defaults.
type EngineConfig struct {
	// Whitelist lists source addresses that never alert. A whitelisted
	// packet still updates handshake tracking (so its answers count), but
	// no rule is checked against it and handshakes it opens are not
	// counted by detectors.
	Whitelist []netip.Prefix
	// DedupWindow is the dedup window. Default 60s.
	DedupWindow time.Duration
	// MaxKeys caps the keys of every table (dedup, handshakes, and each
	// rule's window counters). Default 50000.
	MaxKeys int
	// HandshakeTimeout is how long a handshake may stay pending before it
	// counts as incomplete. Default 3s.
	HandshakeTimeout time.Duration
}

const (
	DefaultDedupWindow      = 60 * time.Second
	DefaultMaxKeys          = 50000
	DefaultHandshakeTimeout = 3 * time.Second
)

// Table names in EngineStats.Tables.
const (
	TableDedup           = "dedup"
	TableHandshake       = "handshake"
	TableDetectionFilter = "detection_filter"
	TableSYNFlood        = "syn_flood"
)

// EngineStats is a snapshot of engine counters.
type EngineStats struct {
	Packets     uint64 // packets passed to Process
	Alerts      uint64 // Kind "alert" alerts emitted
	Summaries   uint64 // Kind "summary" alerts emitted
	Suppressed  uint64 // matches folded into a dedup window instead of alerting
	Passed      uint64 // packets that matched a pass rule
	Whitelisted uint64 // packets from a whitelisted source
	Evictions   uint64 // keys evicted at the cap, over all tables
	Rules       int    // rules in the active rule set
	Reloads     uint64 // successful Reload calls
	ReloadFails uint64 // failed Reload calls
	Tables      map[string]TableStats
}

// TableStats describes one kind of table. For per-rule tables the numbers
// are summed over rules.
type TableStats struct {
	Keys      int64
	Evictions uint64
}

type tableStat struct {
	keys      atomic.Int64
	evictions atomic.Uint64
}

// Engine matches parsed packets against a RuleSet.
//
// Process and Flush must be called from a single goroutine (the packet
// pipeline). Reload and Stats may be called from any goroutine at any
// time: Reload swaps the rule set atomically and Process picks it up at
// its next call; Stats reads only atomic counters.
//
// Time: the engine clock is packet time, now = max(now, p.Timestamp). A
// packet older than the clock is treated as arriving at the clock time.
// time.Now is never used, so replaying a pcap is deterministic and
// capture clock steps backwards cannot shrink or reopen windows.
type Engine struct {
	cfg       EngineConfig
	next      atomic.Pointer[RuleSet] // set by Reload
	reloadMu  sync.Mutex
	active    *RuleSet // the set Process is using
	ruleState []*ruleState

	now   time.Time
	dedup *deduper
	hs    *handshakeTracker
	hsBuf []hsEvent

	packets, alerts, summaries, suppressed, passed, whitelisted atomic.Uint64
	reloads, reloadFails                                        atomic.Uint64
	nRules                                                      atomic.Int64
	tables                                                      [numTables]tableStat
}

const (
	tDedup = iota
	tHandshake
	tFilter
	tSYN
	numTables
)

var tableNames = [numTables]string{TableDedup, TableHandshake, TableDetectionFilter, TableSYNFlood}

// ruleState is the state of one stateful rule. It survives a reload when
// the rule's text is unchanged.
type ruleState struct {
	text   string
	filter *windowCounter[netip.Addr]
	syn    *synFlood
}

// NewEngine returns an engine using rs.
func NewEngine(rs *RuleSet, cfg EngineConfig) *Engine {
	if cfg.DedupWindow <= 0 {
		cfg.DedupWindow = DefaultDedupWindow
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = DefaultMaxKeys
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if rs == nil {
		rs = newRuleSet("", nil)
	}
	e := &Engine{cfg: cfg}
	e.dedup = newDeduper(cfg.DedupWindow, cfg.MaxKeys, &e.tables[tDedup])
	e.hs = newHandshakeTracker(cfg.HandshakeTimeout, cfg.MaxKeys, &e.tables[tHandshake])
	e.next.Store(rs)
	e.nRules.Store(int64(rs.Len()))
	e.activate(rs)
	return e
}

// Reload loads path and, if it parses cleanly, makes it the active rule
// set for the next Process call. On error the old rules stay active and
// the error (a *LoadError for syntax errors) is returned. State of rules
// whose text is unchanged (windows, detector counts) is kept; dedup
// windows are kept for every SID.
func (e *Engine) Reload(path string) error {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()
	rs, err := Load(path)
	if err != nil {
		e.reloadFails.Add(1)
		return err
	}
	e.next.Store(rs)
	e.nRules.Store(int64(rs.Len()))
	e.reloads.Add(1)
	return nil
}

// activate switches Process to rs, carrying over the state of unchanged
// stateful rules.
func (e *Engine) activate(rs *RuleSet) {
	old := make(map[string]*ruleState)
	for _, st := range e.ruleState {
		if st != nil {
			old[st.text] = st
		}
	}
	states := make([]*ruleState, len(rs.rules))
	for i, r := range rs.rules {
		if r.filter == nil && r.Detect == "" {
			continue
		}
		if st, ok := old[r.text]; ok {
			states[i] = st
			delete(old, r.text)
			if st.syn != nil {
				st.syn.rule = r
			}
			continue
		}
		st := &ruleState{text: r.text}
		if r.filter != nil {
			st.filter = newWindowCounter[netip.Addr](r.filter.count, r.filter.span(), e.cfg.MaxKeys, &e.tables[tFilter])
		}
		if r.Detect == DetectSYNFlood {
			st.syn = newSYNFlood(r, e.cfg.MaxKeys, &e.tables[tSYN])
		}
		states[i] = st
	}
	for _, st := range old {
		if st.filter != nil {
			st.filter.clear()
		}
		if st.syn != nil {
			st.syn.clear()
		}
	}
	if len(rs.synFlood) == 0 {
		e.hs.clear()
	}
	e.active, e.ruleState = rs, states
}

// Process runs the rules against one parsed packet and returns the alerts
// and summaries it produced (usually none). It must not be called
// concurrently with itself or Flush.
func (e *Engine) Process(p *packet.ParsedPacket) []Alert {
	if rs := e.next.Load(); rs != e.active {
		e.activate(rs)
	}
	rs := e.active
	e.packets.Add(1)
	if p.Timestamp.After(e.now) {
		e.now = p.Timestamp
	}
	now := e.now

	out := e.dedup.expire(now, nil)

	var v view
	v.init(p)

	if len(rs.synFlood) > 0 {
		e.hsBuf = e.hs.expire(now, e.hsBuf[:0])
		if v.g == gTCP {
			seg := tcpSegment{src: v.src, dst: v.dst, sport: v.sport, dport: v.dport, flags: v.flags, seq: p.TCPSeq, ack: p.TCPAck}
			e.hsBuf = e.hs.observe(&seg, now, e.hsBuf)
		}
		out = e.handshakeEvents(rs, e.hsBuf, out)
	}

	switch {
	case v.g == gNone:
	case e.isWhitelisted(v.src):
		e.whitelisted.Add(1)
	case e.passes(rs, &v):
		e.passed.Add(1)
	default:
		for _, r := range rs.groups[v.g].alert {
			if r.match(&v) {
				out = e.matched(r, &v, out)
			}
		}
	}
	e.count(out)
	return out
}

// Flush ends the input: every pending handshake times out (which may
// still fire a detector), then every open dedup window is closed and its
// summary emitted. The clock advances to the last handshake deadline.
func (e *Engine) Flush() []Alert {
	if rs := e.next.Load(); rs != e.active {
		e.activate(rs)
	}
	var out []Alert
	if len(e.active.synFlood) > 0 {
		e.hsBuf = e.hs.expireAll(e.hsBuf[:0])
		for _, ev := range e.hsBuf {
			if ev.t.After(e.now) {
				e.now = ev.t
			}
		}
		out = e.handshakeEvents(e.active, e.hsBuf, out)
	}
	out = e.dedup.flush(e.now, out)
	e.count(out)
	return out
}

func (e *Engine) count(out []Alert) {
	for i := range out {
		if out[i].Kind == KindSummary {
			e.summaries.Add(1)
		} else {
			e.alerts.Add(1)
		}
	}
}

func (e *Engine) isWhitelisted(a netip.Addr) bool {
	for _, p := range e.cfg.Whitelist {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (e *Engine) passes(rs *RuleSet, v *view) bool {
	for _, r := range rs.groups[v.g].pass {
		if r.match(v) {
			return true
		}
	}
	return false
}

// handshakeEvents feeds handshake outcomes to the SYN flood detectors.
// Each outcome is filtered as if it were the handshake's opening SYN
// (client -> server, flags S, no payload): a whitelisted client or a
// matching pass rule suppresses it, and a detector rule only counts
// handshakes that its addresses and ports match.
func (e *Engine) handshakeEvents(rs *RuleSet, evs []hsEvent, out []Alert) []Alert {
	for _, ev := range evs {
		if e.isWhitelisted(ev.key.client) {
			continue
		}
		syn := view{g: gTCP, src: ev.key.client, dst: ev.key.server, sport: ev.key.cport, dport: ev.key.sport, flags: tcpSYN, havePayload: true, haveLower: true}
		if e.passes(rs, &syn) {
			continue
		}
		for _, r := range rs.synFlood {
			if !r.matchAddrs(&syn) {
				continue
			}
			key, details, fired := e.ruleState[r.idx].syn.observe(ev)
			if !fired {
				continue
			}
			out = e.emit(r, key, &syn, details, out)
		}
	}
	return out
}

// matched handles a per-packet rule match: detection_filter, then dedup.
func (e *Engine) matched(r *Rule, v *view, out []Alert) []Alert {
	key := v.src
	var details func() map[string]string
	if f := r.filter; f != nil {
		if f.track == TrackByDst {
			key = v.dst
		}
		ent, fired := e.ruleState[r.idx].filter.add(key, e.now, v.dport)
		if !fired {
			return out
		}
		details = func() map[string]string {
			return map[string]string{
				"track":        f.track.String(),
				"tracked_addr": key.String(),
				"count":        strconv.Itoa(ent.size()),
				"seconds":      strconv.Itoa(f.seconds),
			}
		}
	}
	return e.emit(r, key, v, details, out)
}

// emit passes a firing rule through dedup.
func (e *Engine) emit(r *Rule, key netip.Addr, v *view, details func() map[string]string, out []Alert) []Alert {
	out, isNew := e.dedup.seen(dedupKey{sid: r.SID, addr: key}, e.now, func() Alert {
		a := Alert{
			Time: e.now, FirstSeen: e.now, LastSeen: e.now,
			SID: r.SID, Rev: r.Rev, Msg: r.Msg, Severity: r.Severity, Category: r.Category,
			Proto: groupNames[v.g], SrcIP: addrString(v.src), DstIP: addrString(v.dst),
			SrcPort: v.sport, DstPort: v.dport, Count: 1, Kind: KindAlert,
		}
		if details != nil {
			a.Details = details()
		}
		return a
	}, out)
	if !isNew {
		e.suppressed.Add(1)
	}
	return out
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// Stats returns a snapshot of the counters. It is safe to call from any
// goroutine.
func (e *Engine) Stats() EngineStats {
	s := EngineStats{
		Packets:     e.packets.Load(),
		Alerts:      e.alerts.Load(),
		Summaries:   e.summaries.Load(),
		Suppressed:  e.suppressed.Load(),
		Passed:      e.passed.Load(),
		Whitelisted: e.whitelisted.Load(),
		Rules:       int(e.nRules.Load()),
		Reloads:     e.reloads.Load(),
		ReloadFails: e.reloadFails.Load(),
		Tables:      make(map[string]TableStats, numTables),
	}
	for i := range e.tables {
		ts := TableStats{Keys: e.tables[i].keys.Load(), Evictions: e.tables[i].evictions.Load()}
		s.Tables[tableNames[i]] = ts
		s.Evictions += ts.Evictions
	}
	return s
}
