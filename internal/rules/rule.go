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

// DetectSYNFlood is the value of the detect option for the SYN flood
// detector.
const DetectSYNFlood = "syn_flood"

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
	Detect   string // "" for a per-packet rule, or DetectSYNFlood

	idx   int    // position in RuleSet.rules, used to find per-rule state
	text  string // the rule line with whitespace collapsed; identifies an unchanged rule across reloads
	bidir bool

	src, dst     addrSpec
	sport, dport portSpec

	hasFlags  bool
	flags     uint8 // tcpFlag* bits
	flagsPlus bool  // "S+": at least these

	contents   []contentMatch
	appProto   string // packet.AppDNS etc., or ""
	appFields  []appField
	appReasons []string // AppFields keys, e.g. "malformed_reason"

	filter *windowSpec // detection_filter, or nil

	// Detector parameters (Detect != "").
	detect   windowSpec
	minRatio float64
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
	groups   [numGroups]ruleGroup
	synFlood []*Rule
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

func newRuleSet(file string, rules []*Rule) *RuleSet {
	rs := &RuleSet{file: file, rules: rules}
	for i, r := range rules {
		r.idx = i
		if r.Detect != "" {
			rs.synFlood = append(rs.synFlood, r)
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
	if r.appProto != "" || len(r.appFields) > 0 || len(r.appReasons) > 0 {
		if v.p == nil {
			return false
		}
		if r.appProto != "" && v.p.AppProtocol != r.appProto {
			return false
		}
		for _, f := range r.appFields {
			got, ok := v.p.AppFields[f.key]
			if !ok || !strings.EqualFold(got, f.value) {
				return false
			}
		}
		for _, k := range r.appReasons {
			if v.p.AppFields[k] == "" {
				return false
			}
		}
	}
	for _, c := range r.contents {
		hay := v.getPayload()
		if c.nocase {
			hay = v.getLower()
		}
		if !bytes.Contains(hay, c.pat) {
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
