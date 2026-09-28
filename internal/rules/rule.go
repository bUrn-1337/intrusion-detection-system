package rules

import (
	"bytes"
	"net/netip"
	"strings"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Action is what a rule does when it matches.
type Action uint8

const (
	// ActionAlert raises an alert.
	ActionAlert Action = iota
	// ActionPass suppresses every alert for the matching packet.
	ActionPass
)

func (a Action) String() string {
	if a == ActionPass {
		return "pass"
	}
	return "alert"
}

// Proto is the protocol a rule applies to.
type Proto uint8

const (
	ProtoIP Proto = iota
	ProtoTCP
	ProtoUDP
	ProtoICMP
	ProtoARP
)

var protoNames = [...]string{ProtoIP: "ip", ProtoTCP: "tcp", ProtoUDP: "udp", ProtoICMP: "icmp", ProtoARP: "arp"}

func (p Proto) String() string { return protoNames[p] }

// Track selects the address a stateful option counts by.
type Track uint8

const (
	TrackBySrc Track = iota
	TrackByDst
)

func (t Track) String() string {
	if t == TrackByDst {
		return "by_dst"
	}
	return "by_src"
}

// Severity levels, in increasing order.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Values of the detect option.
const (
	DetectSYNFlood   = "syn_flood"
	DetectPortScan   = "port_scan"
	DetectHostSweep  = "host_sweep"
	DetectPingSweep  = "ping_sweep"
	DetectTTLAnomaly = "ttl_anomaly"
	DetectFragAttack = "frag_attack"
	DetectARPSpoof   = "arp_spoof"
	DetectUDPFlood   = "udp_flood"
	DetectICMPFlood  = "icmp_flood"
	DetectICMPTunnel = "icmp_tunnel"
	DetectSlowloris  = "slowloris"
)

// Values of the slowloris kind option.
const (
	SlowHeaders = "slow_headers"
	SlowBody    = "slow_body"
	SlowRead    = "slow_read"
)

// Values of the frag_attack kind option.
const (
	FragOverlap  = "overlap"
	FragTiny     = "tiny"
	FragOversize = "oversize"
	FragFlood    = "flood"
)

// Rule is one parsed rule. The exported fields describe it; the matching
// criteria are unexported and only used by the engine.
type Rule struct {
	File     string
	Line     int
	Action   Action
	Proto    Proto
	SID      int
	Rev      int
	Msg      string
	Severity string
	Category string
	Detect   string // "" for a per-packet rule, or one of the Detect* names

	idx   int    // position in RuleSet.rules, used to find per-rule state
	text  string // the rule line with whitespace collapsed; identifies an unchanged rule across reloads
	bidir bool

	src, dst     addrSpec
	sport, dport portSpec

	hasFlags  bool
	flags     uint8 // tcpFlag* bits
	flagsPlus bool  // "S+": at least these

	sameIP, samePort bool
	ethDst           uint8 // ethBroadcast, ethMulticast, ethZero, or 0 for no check
	ethDstNeg        bool  // eth_dst:!value
	hasIType         bool
	itype            uint8
	hasICode         bool
	icode            uint8
	ttl              ttlCheck
	dsize            dsizeCheck
	arpOp            uint16 // packet.ARPRequest or packet.ARPReply, or 0 for no check
	// stream_anomaly: hasAnomaly is set by the option; anomaly is the
	// reason it names, or "" for any.
	hasAnomaly bool
	anomaly    string

	contents   []contentMatch
	appProto   string // packet.AppDNS etc., or ""
	appFields  []appField
	appReasons []string // AppFields keys, e.g. "malformed_reason"

	filter *windowSpec // detection_filter, or nil

	// Detector parameters (Detect != ""). The scan detectors use only
	// detect.seconds; they always track by source.
	detect   windowSpec
	minRatio float64 // syn_flood
	maxPorts int     // syn_flood max_distinct_ports
	distinct int     // port_scan distinct_ports, host_sweep and ping_sweep distinct_hosts

	// ttl_anomaly
	minSamples int
	maxHopDiff int
	external   bool     // scope:external: only sources outside homeNet
	homeNet    addrSpec // $HOME_NET, when external

	// frag_attack
	fragKind string
	minSize  int // tiny: smallest normal non-final fragment payload

	// arp_spoof
	arpKind string

	// udp_flood
	metric        string  // MetricPackets or MetricBytes
	maxReplyRatio float64 // max_reply_ratio

	// icmp_flood
	icmpKind string

	// slowloris; detect.seconds is the activity window of slow_headers
	// and slow_body.
	slowKind     string
	minAge       time.Duration
	minRate      int // slow_body: bytes per second
	minRemaining int // slow_body: bytes of declared body still to come
}

// Values of Rule.ethDst.
const (
	ethBroadcast uint8 = iota + 1
	ethMulticast
	ethZero // 00:00:00:00:00:00, which Linux puts on loopback frames
)

// ttlCheck is the ttl option: op is 0 (no check), '<', '>' or '='.
type ttlCheck struct {
	op byte
	n  uint8
}

func (c ttlCheck) match(ttl uint8) bool {
	switch c.op {
	case '<':
		return ttl < c.n
	case '>':
		return ttl > c.n
	}
	return ttl == c.n
}

// dsizeCheck is the dsize option: op is 0 (no check), '=', '<', '>' or
// 'r' for the inclusive range lo<>hi. '=', '<' and '>' compare with lo.
type dsizeCheck struct {
	op     byte
	lo, hi int
}

func (c dsizeCheck) match(n int) bool {
	switch c.op {
	case '<':
		return n < c.lo
	case '>':
		return n > c.lo
	case 'r':
		return c.lo <= n && n <= c.hi
	}
	return n == c.lo
}

// windowSpec is "count N within seconds S, tracked by address".
type windowSpec struct {
	track   Track
	count   int
	seconds int
}

func (w windowSpec) span() time.Duration { return time.Duration(w.seconds) * time.Second }

type contentMatch struct {
	pat    []byte // lowercased (ASCII only) when nocase
	nocase bool
}

type appField struct{ key, value string }

// TCP flag bits, in wire order.
const (
	tcpFIN uint8 = 1 << iota
	tcpSYN
	tcpRST
	tcpPSH
	tcpACK
	tcpURG
)

// RuleSet is a loaded rule file. It is immutable after Load and may be
// shared between goroutines.
type RuleSet struct {
	file  string
	rules []*Rule // file order

	// groups[g] holds the pass and alert rules a packet of group g is
	// checked against, in file order. "ip" rules are in every IP group.
	groups    [numGroups]ruleGroup
	detectors []*Rule // every detect: rule, in file order
	// handshakes is true when some detector consumes handshake outcomes
	// (syn_flood, port_scan, host_sweep, ttl_anomaly), so the tracker
	// must run.
	handshakes bool
	// probes is true when some scan detector consumes per-packet probes.
	probes bool
	ttl    []*Rule // detect:ttl_anomaly rules
	frags  []*Rule // detect:frag_attack rules; the fragment tracker runs when non-empty
	arp    []*Rule // detect:arp_spoof rules; the ARP tables run when non-empty
	udp    []*Rule // detect:udp_flood rules
	icmp   []*Rule // detect:icmp_flood and icmp_tunnel rules
	slow   []*Rule // detect:slowloris rules; the slow flow table runs when non-empty
	// echoReqs is true when some icmp_flood rule has kind
	// unsolicited_reply, so outstanding echo requests are tracked.
	echoReqs bool
	// arpStatic holds the arpbind directives: IPv4 address -> MAC.
	arpStatic map[netip.Addr]mac6
}

type ruleGroup struct{ pass, alert []*Rule }

// Rules returns the rules in file order. The caller must not modify them.
func (rs *RuleSet) Rules() []*Rule { return rs.rules }

// Len returns the number of rules.
func (rs *RuleSet) Len() int { return len(rs.rules) }

// File returns the path the rules were loaded from.
func (rs *RuleSet) File() string { return rs.file }

// group is the kind of packet as far as rule selection is concerned.
type group uint8

const (
	gNone group = iota // no IP header and not ARP: no rule applies
	gIP                // IP with some other (or undecodable) transport
	gTCP               // fully decoded TCP header
	gUDP               // fully decoded UDP header
	gICMP              // ICMP or ICMPv6
	gARP
	numGroups
)

var groupNames = [numGroups]string{gNone: "", gIP: "IP", gTCP: "TCP", gUDP: "UDP", gICMP: "ICMP", gARP: "ARP"}

// groupsFor lists the packet groups a rule of proto p is checked in.
func groupsFor(p Proto) []group {
	switch p {
	case ProtoTCP:
		return []group{gTCP}
	case ProtoUDP:
		return []group{gUDP}
	case ProtoICMP:
		return []group{gICMP}
	case ProtoARP:
		return []group{gARP}
	default:
		return []group{gIP, gTCP, gUDP, gICMP}
	}
}

func newRuleSet(file string, rules []*Rule, static map[netip.Addr]mac6) *RuleSet {
	rs := &RuleSet{file: file, rules: rules, arpStatic: static}
	for i, r := range rules {
		r.idx = i
		if r.Detect != "" {
			rs.detectors = append(rs.detectors, r)
			switch r.Detect {
			case DetectSYNFlood:
				rs.handshakes = true
			case DetectPortScan, DetectHostSweep:
				rs.handshakes, rs.probes = true, true
			case DetectPingSweep:
				rs.probes = true
			case DetectTTLAnomaly:
				// The handshake tracker tells completed flows apart.
				rs.handshakes = true
				rs.ttl = append(rs.ttl, r)
			case DetectFragAttack:
				rs.frags = append(rs.frags, r)
			case DetectARPSpoof:
				rs.arp = append(rs.arp, r)
			case DetectUDPFlood:
				rs.udp = append(rs.udp, r)
			case DetectICMPFlood, DetectICMPTunnel:
				rs.icmp = append(rs.icmp, r)
				if r.icmpKind == ICMPUnsolicitedReply {
					rs.echoReqs = true
				}
			case DetectSlowloris:
				rs.slow = append(rs.slow, r)
			}
			continue
		}
		for _, g := range groupsFor(r.Proto) {
			if r.Action == ActionPass {
				rs.groups[g].pass = append(rs.groups[g].pass, r)
			} else {
				rs.groups[g].alert = append(rs.groups[g].alert, r)
			}
		}
	}
	return rs
}

// view is the part of a packet rules look at, extracted once per packet.
// A synthetic view (p == nil) stands for the opening SYN of a handshake.
type view struct {
	p            *packet.ParsedPacket
	g            group
	src, dst     netip.Addr
	sport, dport uint16
	flags        uint8

	payload, lower []byte
	havePayload    bool
	haveLower      bool

	appLower     []byte // lowercased p.AppData
	haveAppLower bool
}

func (v *view) init(p *packet.ParsedPacket) {
	*v = view{p: p}
	switch {
	case p.IPVersion == 4 || p.IPVersion == 6:
		v.src, v.dst = toAddr(p.IPSrc), toAddr(p.IPDst)
		v.g = gIP
		switch {
		case p.L4Proto == packet.L4TCP && p.PayloadOffset >= 0:
			v.g = gTCP
			v.sport, v.dport = p.SrcPort, p.DstPort
			v.flags = flagBits(p.TCPFlags)
		case p.L4Proto == packet.L4UDP && p.PayloadOffset >= 0:
			v.g = gUDP
			v.sport, v.dport = p.SrcPort, p.DstPort
		case p.L4Proto == packet.L4ICMP:
			v.g = gICMP
		}
	case p.ARPOp != 0:
		v.g = gARP
		v.src, v.dst = toAddr(p.ARPSenderIP), toAddr(p.ARPTargetIP)
	}
}

func toAddr(ip []byte) netip.Addr {
	a, _ := netip.AddrFromSlice(ip)
	return a.Unmap()
}

func flagBits(f packet.TCPFlags) uint8 {
	var b uint8
	for _, x := range []struct {
		set bool
		bit uint8
	}{{f.FIN, tcpFIN}, {f.SYN, tcpSYN}, {f.RST, tcpRST}, {f.PSH, tcpPSH}, {f.ACK, tcpACK}, {f.URG, tcpURG}} {
		if x.set {
			b |= x.bit
		}
	}
	return b
}

func (v *view) getPayload() []byte {
	if !v.havePayload {
		v.havePayload = true
		if v.p != nil {
			v.payload = v.p.Payload()
		}
	}
	return v.payload
}

func (v *view) getLower() []byte {
	if !v.haveLower {
		v.haveLower = true
		v.lower = asciiLower(v.getPayload())
	}
	return v.lower
}

func (v *view) getAppLower() []byte {
	if !v.haveAppLower {
		v.haveAppLower = true
		v.appLower = asciiLower(v.p.AppData)
	}
	return v.appLower
}

// asciiLower returns a lowercased copy of b, folding only A-Z so that
// binary payloads keep their length and offsets.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// matchAddrs checks addresses and ports, in both orientations for <>.
func (r *Rule) matchAddrs(v *view) bool {
	if r.src.match(v.src) && r.sport.match(v.sport) && r.dst.match(v.dst) && r.dport.match(v.dport) {
		return true
	}
	return r.bidir && r.src.match(v.dst) && r.sport.match(v.dport) && r.dst.match(v.src) && r.dport.match(v.sport)
}

// match reports whether a per-packet rule matches v. The caller has
// already selected the rule by the packet's group. Cheap checks come
// first; content search is last.
func (r *Rule) match(v *view) bool {
	if !r.matchAddrs(v) {
		return false
	}
	if r.sameIP && v.src != v.dst {
		return false
	}
	if r.samePort && v.sport != v.dport {
		return false
	}
	if r.hasFlags {
		const mask = tcpFIN | tcpSYN | tcpRST | tcpPSH | tcpACK | tcpURG
		got := v.flags & mask
		if r.flagsPlus {
			if got&r.flags != r.flags {
				return false
			}
		} else if got != r.flags {
			return false
		}
	}
	if r.ethDst != 0 || r.hasIType || r.hasICode || r.ttl.op != 0 || r.arpOp != 0 || r.dsize.op != 0 {
		if !r.matchPacket(v) {
			return false
		}
	}
	if r.hasAnomaly && (v.p == nil || v.p.StreamAnomaly == "" || r.anomaly != "" && v.p.StreamAnomaly != r.anomaly) {
		return false
	}
	if r.appProto != "" || len(r.appFields) > 0 || len(r.appReasons) > 0 {
		if v.p == nil {
			return false
		}
		if r.appProto != "" && v.p.AppProtocol != r.appProto {
			return false
		}
		// With several messages (AppMore), one of them must satisfy
		// every app_field and app_reason.
		if len(r.appFields) > 0 || len(r.appReasons) > 0 {
			ok := r.matchApp(v.p.AppFields)
			for i := 0; !ok && i < len(v.p.AppMore); i++ {
				ok = r.matchApp(v.p.AppMore[i])
			}
			if !ok {
				return false
			}
		}
	}
	if len(r.contents) == 0 {
		return true
	}
	// Every content must be in the segment's payload, or every content in
	// the messages it completed (AppData), which may span segments.
	if r.matchContents(v.getPayload(), v.getLower) {
		return true
	}
	return v.p != nil && v.p.AppData != nil && r.matchContents(v.p.AppData, v.getAppLower)
}

func (r *Rule) matchApp(fields map[string]string) bool {
	for _, f := range r.appFields {
		got, ok := fields[f.key]
		if !ok || !strings.EqualFold(got, f.value) {
			return false
		}
	}
	for _, k := range r.appReasons {
		if fields[k] == "" {
			return false
		}
	}
	return true
}

// matchContents reports whether every content is in hay, or in lower()
// (hay lowercased) for nocase ones.
func (r *Rule) matchContents(hay []byte, lower func() []byte) bool {
	for _, c := range r.contents {
		h := hay
		if c.nocase {
			h = lower()
		}
		if !bytes.Contains(h, c.pat) {
			return false
		}
	}
	return true
}

// matchPacket checks eth_dst, itype, icode, ttl, arp_op and dsize, which
// need the real packet: a synthetic view never matches them.
func (r *Rule) matchPacket(v *view) bool {
	p := v.p
	if p == nil {
		return false
	}
	if r.ethDst != 0 && ethDstIs(p.EthDst, r.ethDst) == r.ethDstNeg {
		return false
	}
	if r.hasIType || r.hasICode {
		// PayloadOffset < 0: no ICMP header (a non-first fragment, or
		// truncated), so there is no type to compare.
		if v.g != gICMP || p.PayloadOffset < 0 {
			return false
		}
		if r.hasIType && p.ICMPType != r.itype || r.hasICode && p.ICMPCode != r.icode {
			return false
		}
	}
	if r.ttl.op != 0 && (p.IPVersion == 0 || !r.ttl.match(p.IPTTL)) {
		return false
	}
	if r.arpOp != 0 && (v.g != gARP || p.ARPOp != r.arpOp) {
		return false
	}
	// PayloadOffset < 0: the payload's start is unknown (no transport
	// header was decoded), so no size can be compared, not even 0.
	if r.dsize.op != 0 && (p.PayloadOffset < 0 || !r.dsize.match(len(v.getPayload()))) {
		return false
	}
	return true
}

// ethDstIs reports whether the destination MAC is of the given kind. A
// packet without an Ethernet header (no 6-byte MAC) is of no kind.
func ethDstIs(mac []byte, kind uint8) bool {
	if len(mac) != 6 {
		return false
	}
	switch kind {
	case ethBroadcast:
		return isBroadcast(mac)
	case ethMulticast:
		// The I/G bit (least significant bit of the first octet) marks a
		// group address; broadcast is the all-ones group, kept separate.
		return mac[0]&1 != 0 && !isBroadcast(mac)
	case ethZero:
		return isZeroMAC(mac)
	}
	return false
}

func isZeroMAC(mac []byte) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

func isBroadcast(mac []byte) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0xff {
			return false
		}
	}
	return true
}

// addrSpec is any, one address or prefix, or a list, optionally negated.
// A list matches an address that is in some positive item (or any
// address, if it has only negated items) and in no negated item.
type addrSpec struct {
	any       bool
	neg       bool
	pos, negs []netip.Prefix
}

func (s *addrSpec) match(a netip.Addr) bool {
	if s.any {
		return true
	}
	m := len(s.pos) == 0
	for _, p := range s.pos {
		if p.Contains(a) {
			m = true
			break
		}
	}
	if m {
		for _, p := range s.negs {
			if p.Contains(a) {
				m = false
				break
			}
		}
	}
	return m != s.neg
}

// portSpec has the same shape as addrSpec, with inclusive port ranges.
type portSpec struct {
	any       bool
	neg       bool
	pos, negs []portRange
}

type portRange struct{ lo, hi uint16 }

func (s *portSpec) match(port uint16) bool {
	if s.any {
		return true
	}
	m := len(s.pos) == 0
	for _, r := range s.pos {
		if r.lo <= port && port <= r.hi {
			m = true
			break
		}
	}
	if m {
		for _, r := range s.negs {
			if r.lo <= port && port <= r.hi {
				m = false
				break
			}
		}
	}
	return m != s.neg
}
