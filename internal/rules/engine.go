package rules

import (
	"net/netip"
	"slices"
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
	// KindIncident and KindIncidentUpdate are in correlate.go.
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
	// FragmentTimeout is how long a fragmented datagram is tracked after
	// its first fragment; one still incomplete then counts toward
	// frag_attack kind:flood. Default 30s.
	FragmentTimeout time.Duration
}

const (
	DefaultDedupWindow      = 60 * time.Second
	DefaultMaxKeys          = 50000
	DefaultHandshakeTimeout = 3 * time.Second
	DefaultFragmentTimeout  = 30 * time.Second
)

// Table names in EngineStats.Tables.
const (
	TableDedup            = "dedup"
	TableHandshake        = "handshake"
	TableDetectionFilter  = "detection_filter"
	TableSYNFlood         = "syn_flood"
	TablePortScan         = "port_scan"
	TableHostSweep        = "host_sweep"
	TablePingSweep        = "ping_sweep"
	TableTTLAnomaly       = "ttl_anomaly"
	TableFragments        = "fragments"
	TableFragFlood        = "frag_flood"
	TableTCPFlows         = "tcp_flows"
	TableARPBindings      = "arp_bindings"
	TableARPRequests      = "arp_requests"
	TableARPSpoof         = "arp_spoof"
	TableUDPFlood         = "udp_flood"
	TableUDPFlows         = "udp_flows"
	TableICMPFlood        = "icmp_flood"
	TableICMPPeers        = "icmp_peers"
	TableEchoRequests     = "echo_requests"
	TableICMPTunnel       = "icmp_tunnel"
	TableSlowFlows        = "slow_flows"
	TableSlowloris        = "slowloris"
	TableDNSQueries       = "dns_queries"
	TableDNSSpoof         = "dns_spoof"
	TableDNSAmp           = "dns_amplification"
	TableDNSTunnel        = "dns_tunnel"
	TableNXDomain         = "dns_nxdomain"
	TableBeacon           = "beacon"
	TableBeaconConns      = "beacon_conns"
	TableBaselineHosts    = "baseline_hosts"
	TableIncidentEntities = "incident_entities"
	TableIncidents        = "incidents"
)

// EngineStats is a snapshot of engine counters.
type EngineStats struct {
	Packets     uint64 // packets passed to Process
	Alerts      uint64 // Kind "alert" alerts emitted
	Summaries   uint64 // Kind "summary" alerts emitted
	Incidents   uint64 // Kind "incident" and "incident_update" alerts emitted
	Suppressed  uint64 // matches folded into a dedup window instead of alerting
	Passed      uint64 // packets that matched a pass rule
	Whitelisted uint64 // packets from a whitelisted source
	Evictions   uint64 // keys evicted at the cap, over all tables
	Rules       int    // rules in the active rule set
	Reloads     uint64 // successful Reload calls
	ReloadFails uint64 // failed Reload calls
	// FragmentsOverLimit counts datagrams that had more fragments than
	// the tracker stores per datagram; they are no longer checked.
	FragmentsOverLimit uint64
	Tables             map[string]TableStats
	// Feeds describes the threat-intel feeds of the latest loaded rule
	// set, in file order.
	Feeds []FeedStats
}

// FeedStats describes one loaded feed. Its age is computed by the caller
// against wall time: the engine clock is packet time.
type FeedStats struct {
	Name     string
	Type     string
	Path     string
	Entries  int
	Rejected int
	ModTime  time.Time
	MaxAge   time.Duration // 0: never stale
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

	now           time.Time
	dedup         *deduper
	hs            *handshakeTracker
	hsBuf         []hsEvent
	frags         *fragmentTracker
	fragBuf       []fragEvent
	fragOverLimit atomic.Uint64
	flows         *flowSet // completed TCP flows, for attribution and ttl_anomaly
	corr          *correlator
	arpTable      *arpTable
	arpReqs       *arpRequests
	echoReqs      *recentSet[echoKey] // outstanding echo requests, for icmp_flood kind:unsolicited_reply
	slow          *slowTable          // HTTP flows that may be slow, for slowloris
	dnsQueries    *dnsQueries         // outstanding DNS queries, for dns_spoof and dns_amplification
	dnsBuf        []dnsMsg
	notices       []Notice                 // for TakeNotices
	baselineShown atomic.Pointer[baseline] // the first baseline rule's detector, for BaselineStatus

	packets, alerts, summaries, incidents, suppressed, passed, whitelisted atomic.Uint64
	reloads, reloadFails                                                   atomic.Uint64
	nRules                                                                 atomic.Int64
	tables                                                                 [numTables]tableStat
}

const (
	tDedup = iota
	tHandshake
	tFilter
	tSYN
	tPortScan
	tHostSweep
	tPingSweep
	tTTL
	tFrags
	tFragFlood
	tTCPFlows
	tARPBindings
	tARPRequests
	tARPSpoof
	tUDPFlood
	tUDPFlows
	tICMPFlood
	tICMPPeers
	tEchoRequests
	tICMPTunnel
	tSlowFlows
	tSlowloris
	tDNSQueries
	tDNSSpoof
	tDNSAmp
	tDNSTunnel
	tNXDomain
	tBeacon
	tBeaconConns
	tBaselineHosts
	tIncEntities
	tIncidents
	numTables
)

var tableNames = [numTables]string{TableDedup, TableHandshake, TableDetectionFilter, TableSYNFlood, TablePortScan, TableHostSweep, TablePingSweep,
	TableTTLAnomaly, TableFragments, TableFragFlood, TableTCPFlows, TableARPBindings, TableARPRequests, TableARPSpoof,
	TableUDPFlood, TableUDPFlows, TableICMPFlood, TableICMPPeers, TableEchoRequests, TableICMPTunnel, TableSlowFlows, TableSlowloris,
	TableDNSQueries, TableDNSSpoof, TableDNSAmp, TableDNSTunnel, TableNXDomain,
	TableBeacon, TableBeaconConns, TableBaselineHosts, TableIncidentEntities, TableIncidents}

// scanTables maps a scan detector to its table.
var scanTables = map[string]int{DetectPortScan: tPortScan, DetectHostSweep: tHostSweep, DetectPingSweep: tPingSweep}

// ruleState is the state of one stateful rule. It survives a reload when
// the rule's text is unchanged.
type ruleState struct {
	text   string
	filter *windowCounter[netip.Addr]
	syn    *synFlood
	scan   *scanDetector
	ttl    *ttlAnomaly
	flood  *windowCounter[netip.Addr] // frag_attack kind:flood, keyed by source
	arp    *arpSpoof
	udp    *udpFlood
	icmp   *icmpFlood
	tunnel *icmpTunnel
	spoof  *dnsSpoof
	amp    *dnsAmp
	dnsTun *dnsTunnel
	nx     *nxBurst
	beacon *beacon
	base   *baseline
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
	if cfg.FragmentTimeout <= 0 {
		cfg.FragmentTimeout = DefaultFragmentTimeout
	}
	if rs == nil {
		rs = newRuleSet("", nil, nil)
	}
	e := &Engine{cfg: cfg}
	e.dedup = newDeduper(cfg.DedupWindow, cfg.MaxKeys, &e.tables[tDedup])
	e.hs = newHandshakeTracker(cfg.HandshakeTimeout, cfg.MaxKeys, &e.tables[tHandshake])
	e.frags = newFragmentTracker(cfg.FragmentTimeout, cfg.MaxKeys, &e.tables[tFrags])
	e.flows = newFlowSet(cfg.MaxKeys, &e.tables[tTCPFlows])
	e.corr = newCorrelator(cfg.MaxKeys, &e.tables[tIncEntities], &e.tables[tIncidents])
	e.arpTable = newARPTable(cfg.MaxKeys, &e.tables[tARPBindings])
	e.arpReqs = newARPRequests(cfg.MaxKeys, &e.tables[tARPRequests])
	e.echoReqs = newRecentSet[echoKey](echoRequestIdle, cfg.MaxKeys, &e.tables[tEchoRequests])
	e.slow = newSlowTable(cfg.MaxKeys, &e.tables[tSlowFlows], &e.tables[tSlowloris])
	e.dnsQueries = newDNSQueries(cfg.MaxKeys, &e.tables[tDNSQueries])
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

// Warnings returns the load warnings of the latest loaded rule set (feed
// lines that were rejected, empty feeds).
func (e *Engine) Warnings() []string {
	return e.next.Load().Warnings()
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
			if st.scan != nil {
				st.scan.rule = r
			}
			if st.ttl != nil {
				st.ttl.rule = r
			}
			if st.arp != nil {
				st.arp.rule = r
			}
			if st.udp != nil {
				st.udp.rule = r
			}
			if st.icmp != nil {
				st.icmp.rule = r
			}
			if st.tunnel != nil {
				st.tunnel.rule = r
			}
			if st.spoof != nil {
				st.spoof.rule = r
			}
			if st.amp != nil {
				st.amp.rule = r
			}
			if st.dnsTun != nil {
				st.dnsTun.rule = r
			}
			if st.nx != nil {
				st.nx.rule = r
			}
			if st.beacon != nil {
				st.beacon.rule = r
			}
			if st.base != nil {
				st.base.rule = r
			}
			continue
		}
		st := &ruleState{text: r.text}
		if r.filter != nil {
			st.filter = newWindowCounter[netip.Addr](r.filter.count, r.filter.span(), e.cfg.MaxKeys, &e.tables[tFilter])
		}
		switch r.Detect {
		case DetectSYNFlood:
			st.syn = newSYNFlood(r, e.cfg.MaxKeys, &e.tables[tSYN])
		case DetectPortScan, DetectHostSweep, DetectPingSweep:
			st.scan = newScanDetector(r, e.cfg.MaxKeys, &e.tables[scanTables[r.Detect]])
		case DetectTTLAnomaly:
			st.ttl = newTTLAnomaly(r, e.cfg.MaxKeys, &e.tables[tTTL])
		case DetectFragAttack:
			if r.fragKind == FragFlood {
				st.flood = newWindowCounter[netip.Addr](r.detect.count, r.detect.span(), e.cfg.MaxKeys, &e.tables[tFragFlood])
			}
		case DetectARPSpoof:
			st.arp = newARPSpoof(r, e.cfg.MaxKeys, &e.tables[tARPSpoof])
		case DetectUDPFlood:
			st.udp = newUDPFlood(r, e.cfg.MaxKeys, &e.tables[tUDPFlood], &e.tables[tUDPFlows])
		case DetectICMPFlood:
			st.icmp = newICMPFlood(r, e.cfg.MaxKeys, &e.tables[tICMPFlood], &e.tables[tICMPPeers])
		case DetectICMPTunnel:
			st.tunnel = newICMPTunnel(r, e.cfg.MaxKeys, &e.tables[tICMPTunnel])
		case DetectDNSSpoof:
			st.spoof = newDNSSpoof(r, e.cfg.MaxKeys, &e.tables[tDNSSpoof])
		case DetectDNSAmplification:
			st.amp = newDNSAmp(r, e.cfg.MaxKeys, &e.tables[tDNSAmp])
		case DetectDNSTunnel:
			st.dnsTun = newDNSTunnel(r, e.cfg.MaxKeys, &e.tables[tDNSTunnel])
		case DetectNXDomainBurst:
			st.nx = newNXBurst(r, e.cfg.MaxKeys, &e.tables[tNXDomain])
		case DetectBeacon:
			st.beacon = newBeacon(r, e.cfg.MaxKeys, &e.tables[tBeacon], &e.tables[tBeaconConns])
		case DetectBaseline:
			st.base = newBaseline(r, e.cfg.MaxKeys, &e.tables[tBaselineHosts])
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
		if st.scan != nil {
			st.scan.clear()
		}
		if st.ttl != nil {
			st.ttl.clear()
		}
		if st.flood != nil {
			st.flood.clear()
		}
		if st.arp != nil {
			st.arp.clear()
		}
		if st.udp != nil {
			st.udp.clear()
		}
		if st.icmp != nil {
			st.icmp.clear()
		}
		if st.tunnel != nil {
			st.tunnel.clear()
		}
		if st.spoof != nil {
			st.spoof.clear()
		}
		if st.amp != nil {
			st.amp.clear()
		}
		if st.dnsTun != nil {
			st.dnsTun.clear()
		}
		if st.nx != nil {
			st.nx.clear()
		}
		if st.beacon != nil {
			st.beacon.clear()
		}
		if st.base != nil {
			st.base.clear()
		}
	}
	var shown *baseline
	if len(rs.baseline) > 0 {
		shown = states[rs.baseline[0].idx].base
	}
	e.baselineShown.Store(shown)
	if !rs.handshakes {
		e.hs.clear()
	}
	if len(rs.frags) == 0 {
		e.frags.clear()
	}
	if !rs.handshakes {
		e.flows.clear()
	}
	e.corr.use(rs)
	if len(rs.arp) == 0 {
		e.arpTable.clear()
		e.arpReqs.clear()
	}
	if !rs.echoReqs {
		e.echoReqs.clear()
	}
	if !rs.dnsQueries {
		e.dnsQueries.clear()
	}
	e.activateSlow(rs)
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

	if rs.handshakes {
		e.hsBuf = e.hs.expire(now, e.hsBuf[:0])
		if v.g == gTCP {
			seg := tcpSegment{src: v.src, dst: v.dst, sport: v.sport, dport: v.dport, flags: v.flags, seq: p.TCPSeq, ack: p.TCPAck}
			e.hsBuf = e.hs.observe(&seg, now, e.hsBuf)
		}
		out = e.handshakeEvents(rs, e.hsBuf, out)
		if v.g == gTCP {
			v.established = e.flows.touch(hsKey{client: v.src, cport: v.sport, server: v.dst, sport: v.dport}, now) ||
				e.flows.touch(hsKey{client: v.dst, cport: v.dport, server: v.src, sport: v.sport}, now)
			if rs.callback && e.hs.started && !e.isWhitelisted(v.src) && !e.passes(rs, &v) {
				out = e.corr.connStart(rs, v.src, v.dst, v.sport, v.dport, now, out)
			}
		}
	}
	if rs.probes {
		if pr, ok := packetProbe(p, &v, now); ok {
			out = e.probe(rs, &pr, out)
		}
	}
	if len(rs.frags) > 0 {
		out = e.fragments(rs, p, &v, out)
	}
	if len(rs.arp) > 0 && v.g == gARP {
		out = e.arp(rs, p, &v, out)
	}
	if len(rs.udp) > 0 && v.g == gUDP {
		out = e.udpFloods(rs, p, &v, out)
	}
	if len(rs.icmp) > 0 && v.g == gICMP {
		out = e.icmp(rs, p, &v, out)
	}
	if len(rs.slow) > 0 {
		out = e.slowloris(rs, p, &v, out)
	}
	if len(rs.dns) > 0 && p.AppProtocol == packet.AppDNS && (v.g == gUDP || v.g == gTCP) {
		out = e.dns(rs, p, &v, out)
	}

	if len(rs.baseline) > 0 {
		out = e.baselineTick(rs, out)
	}

	switch {
	case v.g == gNone:
	case e.isWhitelisted(v.src):
		e.whitelisted.Add(1)
	case e.passes(rs, &v):
		e.passed.Add(1)
	default:
		if len(rs.ttl) > 0 {
			mode, hk := e.ttlMode(&v)
			for _, r := range rs.ttl {
				out = e.ttlAnomaly(r, p, &v, mode, hk, out)
			}
		}
		if len(rs.beacon) > 0 && (v.g == gTCP || v.g == gUDP) {
			out = e.beacons(rs, p, &v, out)
		}
		if len(rs.baseline) > 0 {
			e.baselineCount(rs, p, &v)
		}
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
// still fire a detector), slow HTTP connections due for a check are
// checked at the current clock, then every open dedup window is closed
// and its summary emitted. The clock advances to the last handshake
// deadline.
func (e *Engine) Flush() []Alert {
	if rs := e.next.Load(); rs != e.active {
		e.activate(rs)
	}
	var out []Alert
	if e.active.handshakes {
		e.hsBuf = e.hs.expireAll(e.hsBuf[:0])
		for _, ev := range e.hsBuf {
			if ev.t.After(e.now) {
				e.now = ev.t
			}
		}
		out = e.handshakeEvents(e.active, e.hsBuf, out)
	}
	if len(e.active.frags) > 0 {
		e.fragBuf = e.frags.expireAll(e.fragBuf[:0])
		for _, ev := range e.fragBuf {
			if ev.t.After(e.now) {
				e.now = ev.t
			}
		}
		out = e.fragExpired(e.active, e.fragBuf, out)
	}
	if len(e.active.slow) > 0 {
		out = e.slowAge(out)
	}
	out = e.dedup.flush(e.now, out)
	e.count(out)
	return out
}

func (e *Engine) count(out []Alert) {
	for i := range out {
		switch out[i].Kind {
		case KindSummary:
			e.summaries.Add(1)
		case KindIncident, KindIncidentUpdate:
			e.incidents.Add(1)
		default:
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

// handshakeEvents feeds handshake outcomes to the SYN flood detectors,
// and incomplete ones as probes to port_scan and host_sweep. Each outcome
// is filtered as if it were the handshake's opening SYN (client -> server,
// flags S, no payload): a whitelisted client or a matching pass rule
// suppresses it, and a detector rule only counts handshakes that its
// addresses and ports match.
func (e *Engine) handshakeEvents(rs *RuleSet, evs []hsEvent, out []Alert) []Alert {
	for i := range evs {
		ev := &evs[i]
		if ev.complete {
			e.flows.add(ev.key, ev.t)
		}
		if len(rs.ttl) > 0 {
			out = e.ttlHandshake(rs, ev, out)
		}
		if e.isWhitelisted(ev.key.client) {
			continue
		}
		syn := view{g: gTCP, src: ev.key.client, dst: ev.key.server, sport: ev.key.cport, dport: ev.key.sport, flags: tcpSYN, havePayload: true, haveLower: true}
		if ev.synFin {
			syn.flags |= tcpFIN
		}
		if e.passes(rs, &syn) {
			continue
		}
		pr, isProbe := handshakeProbe(*ev, &syn)
		for _, r := range rs.detectors {
			if !r.matchAddrs(&syn) {
				continue
			}
			st := e.ruleState[r.idx]
			switch {
			case st.syn != nil:
				key, details, fired := st.syn.observe(*ev)
				if fired {
					out = e.emit(r, dedupKey{sid: r.SID, addr: key}, &syn, details, out)
				}
			case st.scan != nil && isProbe && st.scan.accepts(&pr):
				dk, details, fired := st.scan.observe(&pr)
				if fired {
					out = e.emit(r, dk, &pr.v, details, out)
				}
			}
		}
	}
	return out
}

// probe feeds a per-packet probe to the scan detectors, filtered like a
// packet from the prober to the target.
func (e *Engine) probe(rs *RuleSet, pr *probe, out []Alert) []Alert {
	if e.isWhitelisted(pr.v.src) || e.passes(rs, &pr.v) {
		return out
	}
	for _, r := range rs.detectors {
		st := e.ruleState[r.idx]
		if st.scan == nil || !st.scan.accepts(pr) || !r.matchAddrs(&pr.v) {
			continue
		}
		if dk, details, fired := st.scan.observe(pr); fired {
			out = e.emit(r, dk, &pr.v, details, out)
		}
	}
	return out
}

// ttlMode classifies a packet for ttl_anomaly (see ttl.go): TCP packets
// of a handshake pending in the tracker are held under its key, and TCP
// packets of a completed flow are samples only.
func (e *Engine) ttlMode(v *view) (ttlMode, hsKey) {
	if v.g != gTCP {
		return ttlNow, hsKey{}
	}
	fromClient := hsKey{client: v.src, cport: v.sport, server: v.dst, sport: v.dport}
	fromServer := hsKey{client: v.dst, cport: v.dport, server: v.src, sport: v.sport}
	for _, k := range []hsKey{fromClient, fromServer} {
		if e.hs.pending(k) {
			return ttlHold, k
		}
	}
	for _, k := range []hsKey{fromClient, fromServer} {
		if e.flows.touch(k, e.now) {
			return ttlOnlySample, k
		}
	}
	return ttlNow, hsKey{}
}

// ttlAnomaly feeds a packet that is not whitelisted or passed to one
// ttl_anomaly rule.
func (e *Engine) ttlAnomaly(r *Rule, p *packet.ParsedPacket, v *view, mode ttlMode, hk hsKey, out []Alert) []Alert {
	if v.g == gARP || !slices.Contains(groupsFor(r.Proto), v.g) || !r.matchAddrs(v) {
		return out
	}
	d := e.ruleState[r.idx].ttl
	tag, anomalous := d.sample(v.src, p.IPTTL, e.now, mode)
	switch {
	case !anomalous:
	case mode == ttlHold:
		d.hold(hk, ttlHeld{src: v.src, dst: v.dst, sport: v.sport, dport: v.dport, tag: tag})
	default:
		if dk, details, fired := d.count(v.src, tag, e.now); fired {
			out = e.emit(r, dk, v, details, out)
		}
	}
	return out
}

// ttlHandshake applies a handshake outcome to ttl_anomaly: a completed
// flow is remembered, and anomalies held for the handshake are dropped
// if it completed or counted at the outcome time if not. Held anomalies
// already passed the whitelist, pass rules and the rule's addresses.
func (e *Engine) ttlHandshake(rs *RuleSet, ev *hsEvent, out []Alert) []Alert {
	for _, r := range rs.ttl {
		d := e.ruleState[r.idx].ttl
		for _, h := range d.resolve(ev) {
			if dk, details, fired := d.count(h.src, h.tag, ev.t); fired {
				hv := view{g: gTCP, src: h.src, dst: h.dst, sport: h.sport, dport: h.dport}
				out = e.emit(r, dk, &hv, details, out)
			}
		}
	}
	return out
}

// fragments runs the fragment tracker and the frag_attack rules for one
// packet. The tracker sees every usable fragment, whitelisted or not, so
// its state does not depend on the rules; alerts about the packet are
// filtered like the packet itself (whitelist, pass rules, the rule's
// addresses).
func (e *Engine) fragments(rs *RuleSet, p *packet.ParsedPacket, v *view, out []Alert) []Alert {
	e.fragBuf = e.frags.expire(e.now, e.fragBuf[:0])
	out = e.fragExpired(rs, e.fragBuf, out)
	if !fragmentUsable(p) {
		return out
	}
	e.fragBuf = e.frags.observe(p, v, e.now, e.fragBuf[:0])
	e.fragOverLimit.Store(e.frags.overLimit)
	if e.isWhitelisted(v.src) || e.passes(rs, v) {
		return out
	}
	for _, r := range rs.frags {
		if !r.matchAddrs(v) {
			continue
		}
		var details map[string]string
		switch r.fragKind {
		case FragTiny:
			if reason := tinyReason(p, r); reason != "" {
				details = fragDetails(FragTiny, p)
				details["reason"] = reason
				details["min_size"] = strconv.Itoa(r.minSize)
			}
		case FragOversize:
			if end := oversizeEnd(p); end != 0 {
				details = fragDetails(FragOversize, p)
				details["end"] = strconv.FormatUint(uint64(end), 10)
				details["limit"] = strconv.Itoa(maxIPPacket)
			}
		case FragOverlap:
			for _, ev := range e.fragBuf {
				if ev.overlap {
					details = fragDetails(FragOverlap, p)
					details["fragment"] = ev.frag.String()
					details["overlaps"] = ev.with.String()
					details["fragments_seen"] = strconv.Itoa(ev.nFrags)
					break
				}
			}
		}
		if details != nil {
			out = e.emit(r, dedupKey{sid: r.SID, addr: v.src}, v, func() map[string]string { return details }, out)
		}
	}
	return out
}

// fragExpired feeds datagrams that expired incomplete to the kind:flood
// rules, each filtered as a packet from its source to its destination.
func (e *Engine) fragExpired(rs *RuleSet, evs []fragEvent, out []Alert) []Alert {
	for _, ev := range evs {
		if ev.overlap || e.isWhitelisted(ev.key.src) {
			continue
		}
		dv := view{g: gIP, src: ev.key.src, dst: ev.key.dst, havePayload: true, haveLower: true}
		if e.passes(rs, &dv) {
			continue
		}
		for _, r := range rs.frags {
			if r.fragKind != FragFlood || !r.matchAddrs(&dv) {
				continue
			}
			ent, fired := e.ruleState[r.idx].flood.add(ev.key.src, ev.t, 0)
			if !fired {
				continue
			}
			details := func() map[string]string {
				return map[string]string{
					"detector":             DetectFragAttack,
					"kind":                 FragFlood,
					"track":                TrackBySrc.String(),
					"tracked_addr":         ev.key.src.String(),
					"incomplete_datagrams": strconv.Itoa(ent.size()),
					"seconds":              strconv.Itoa(r.detect.seconds),
					"window":               ent.newest().Sub(ent.oldest()).Round(time.Millisecond).String(),
					"timeout":              e.cfg.FragmentTimeout.String(),
				}
			}
			out = e.emit(r, dedupKey{sid: r.SID, addr: ev.key.src}, &dv, details, out)
		}
	}
	return out
}

// udpFloods runs the udp_flood rules for one UDP packet. Every packet is
// checked as a reply, whitelisted or passed or not; only packets that are
// neither, and that match a rule's addresses, count toward its volume.
func (e *Engine) udpFloods(rs *RuleSet, p *packet.ParsedPacket, v *view, out []Alert) []Alert {
	for _, r := range rs.udp {
		e.ruleState[r.idx].udp.reply(v, e.now)
	}
	if e.isWhitelisted(v.src) || e.passes(rs, v) {
		return out
	}
	for _, r := range rs.udp {
		if !r.matchAddrs(v) {
			continue
		}
		if key, details, fired := e.ruleState[r.idx].udp.forward(p, v, e.now); fired {
			out = e.emit(r, dedupKey{sid: r.SID, addr: key}, v, details, out)
		}
	}
	return out
}

// dns runs the DNS detectors for one DNS packet, UDP or a reassembled
// TCP segment, message by message. Queries enter the outstanding query
// table and responses are matched against it whether or not the packet
// is whitelisted or passed, so that the table knows every query; the
// rules only see packets that are neither.
func (e *Engine) dns(rs *RuleSet, p *packet.ParsedPacket, v *view, out []Alert) []Alert {
	e.dnsBuf = dnsMessages(p, e.dnsBuf[:0])
	if len(e.dnsBuf) == 0 {
		return out
	}
	skip := e.isWhitelisted(v.src) || e.passes(rs, v)
	for i := range e.dnsBuf {
		m := &e.dnsBuf[i]
		if !m.response {
			tx := dnsTx{client: v.src, server: v.dst, cport: v.sport, id: m.id}
			if rs.dnsQueries {
				e.dnsQueries.query(tx, m, e.now)
			}
			if skip {
				continue
			}
			for _, r := range rs.dns {
				st := e.ruleState[r.idx]
				if st.dnsTun == nil || !r.matchAddrs(v) {
					continue
				}
				if key, details, fired := st.dnsTun.query(v.src, m, e.now); fired {
					out = e.emit(r, dedupKey{sid: r.SID, addr: key.client, peer: v.dst}, v, details, out)
				}
			}
			continue
		}
		tx := dnsTx{client: v.dst, server: v.src, cport: v.dport, id: m.id}
		outcome, qsize, asked := dnsUnsolicited, uint64(0), false
		if rs.dnsQueries {
			outcome, qsize = e.dnsQueries.answer(tx, m, e.now)
			asked = outcome == dnsUnsolicited && m.qname != "" && e.dnsQueries.asked(tx, m.qname)
		}
		if skip {
			continue
		}
		for _, r := range rs.dns {
			if !r.matchAddrs(v) {
				continue
			}
			st := e.ruleState[r.idx]
			var details func() map[string]string
			fired := false
			switch {
			case st.spoof != nil:
				details, fired = st.spoof.response(tx, m, outcome, asked, e.now)
			case st.amp != nil:
				details, fired = st.amp.response(tx, m, outcome, qsize, e.now)
			case st.nx != nil:
				details, fired = st.nx.response(tx.client, m, e.now)
			}
			if fired {
				out = e.emit(r, dedupKey{sid: r.SID, addr: tx.client}, v, details, out)
			}
		}
	}
	return out
}

// icmp runs the icmp_flood and icmp_tunnel rules for one ICMP packet.
// Echo requests are recorded for kind:unsolicited_reply whether or not
// the packet is whitelisted or passed, so that the replies they solicit
// are known; the rules only count packets that are neither.
func (e *Engine) icmp(rs *RuleSet, p *packet.ParsedPacket, v *view, out []Alert) []Alert {
	v6 := p.IPVersion == 6
	request, reply := isEchoRequest(p.ICMPType, v6), isEchoReply(p.ICMPType, v6)
	unsolicited := false
	if rs.echoReqs && p.HasICMPEcho {
		switch {
		case request:
			e.echoReqs.add(echoKeyOf(p, v), e.now)
		case reply:
			unsolicited = !solicited(e.echoReqs, p, v, e.now)
		}
	}
	if e.isWhitelisted(v.src) || e.passes(rs, v) {
		return out
	}
	errMsg := isICMPError(p.ICMPType, v6)
	for _, r := range rs.icmp {
		if !r.matchAddrs(v) {
			continue
		}
		st := e.ruleState[r.idx]
		if st.tunnel != nil {
			if (request || reply) && p.HasICMPEcho {
				pair, details, fired := st.tunnel.observe(v.getPayload(), v.src, v.dst, request, e.now)
				if fired {
					out = e.emit(r, dedupKey{sid: r.SID, addr: pair.src, peer: pair.dst}, v, details, out)
				}
			}
			continue
		}
		switch r.icmpKind {
		case ICMPEcho:
			if !request {
				continue
			}
		case ICMPUnsolicitedReply:
			if !unsolicited {
				continue
			}
		case ICMPErrorFlood:
			if !errMsg {
				continue
			}
		}
		if key, details, fired := st.icmp.observe(p, v, e.now); fired {
			out = e.emit(r, dedupKey{sid: r.SID, addr: key}, v, details, out)
		}
	}
	return out
}

// matched handles a per-packet rule match: detection_filter, then dedup.
func (e *Engine) matched(r *Rule, v *view, out []Alert) []Alert {
	key := v.src
	dk := dedupKey{sid: r.SID}
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
			return r.feedDetails(v, map[string]string{
				"track":        f.track.String(),
				"tracked_addr": key.String(),
				"count":        strconv.Itoa(ent.size()),
				"seconds":      strconv.Itoa(f.seconds),
			})
		}
	} else if r.ipFeed != nil || r.domainFeed != nil || r.ja3Feed != nil {
		details = func() map[string]string { return r.feedDetails(v, nil) }
	}
	dk.addr = key
	if r.ipFeed != nil && r.filter == nil {
		// One alert per indicator and peer: a listed server contacted by
		// two hosts, or by one host on two ports, is one alert per host.
		dk.addr, dk.peer = v.src, v.dst
		if !r.ipFeed.ContainsIP(v.src) {
			dk.addr, dk.peer = v.dst, v.src
		}
	}
	return e.emit(r, dk, v, details, out)
}

// emit passes a firing rule through dedup.
func (e *Engine) emit(r *Rule, key dedupKey, v *view, details func() map[string]string, out []Alert) []Alert {
	out, isNew := e.dedup.seen(key, e.now, func() Alert {
		a := Alert{
			Time: e.now, FirstSeen: e.now, LastSeen: e.now,
			SID: r.SID, Rev: r.Rev, Msg: r.Msg, Severity: r.Severity, Category: r.Category,
			Proto: groupNames[v.g], SrcIP: addrString(v.src), DstIP: addrString(v.dst),
			SrcPort: v.sport, DstPort: v.dport, Count: 1, Kind: KindAlert,
		}
		if details != nil {
			a.Details = details()
		}
		if a.Details == nil {
			a.Details = make(map[string]string, 1)
		}
		a.Details[detailAttribution] = attribution(r, v)
		return a
	}, out)
	if !isNew {
		e.suppressed.Add(1)
		return out
	}
	if len(e.active.incident) > 0 {
		a := out[len(out)-1]
		out = e.corr.alert(e.active, r, v, &a, e.now, out)
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
		Packets:            e.packets.Load(),
		Alerts:             e.alerts.Load(),
		Summaries:          e.summaries.Load(),
		Incidents:          e.incidents.Load(),
		Suppressed:         e.suppressed.Load(),
		Passed:             e.passed.Load(),
		Whitelisted:        e.whitelisted.Load(),
		Rules:              int(e.nRules.Load()),
		Reloads:            e.reloads.Load(),
		ReloadFails:        e.reloadFails.Load(),
		FragmentsOverLimit: e.fragOverLimit.Load(),
		Tables:             make(map[string]TableStats, numTables),
	}
	for _, f := range e.next.Load().Feeds() {
		s.Feeds = append(s.Feeds, FeedStats{Name: f.Name, Type: f.Type.String(), Path: f.Path,
			Entries: f.Entries, Rejected: f.Rejected, ModTime: f.ModTime, MaxAge: f.MaxAge})
	}
	for i := range e.tables {
		ts := TableStats{Keys: e.tables[i].keys.Load(), Evictions: e.tables[i].evictions.Load()}
		s.Tables[tableNames[i]] = ts
		s.Evictions += ts.Evictions
	}
	return s
}
