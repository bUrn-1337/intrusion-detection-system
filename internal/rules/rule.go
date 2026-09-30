package rules

import (
	"bytes"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/intel"
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
	// DNS detectors (dns.go).
	DetectDNSSpoof         = "dns_spoof"
	DetectDNSAmplification = "dns_amplification"
	DetectDNSTunnel        = "dns_tunnel"
	DetectNXDomainBurst    = "dns_nxdomain_burst"
	DetectBeacon           = "beacon"
	DetectBaseline         = "baseline"
	// DetectIncident rules correlate alerts into incidents (correlate.go).
	DetectIncident = "incident"
)

// Values of the incident kind option.
const (
	IncidentMultiStage      = "multi_stage"
	IncidentCompromisedHost = "compromised_host"
	IncidentCallback        = "callback"
)

// Values of the dns_spoof kind option.
const (
	SpoofUnsolicited   = "unsolicited_response"
	SpoofIDRace        = "id_race"
	SpoofQNameMismatch = "qname_mismatch"
)

// Values of the dns_tunnel kind option.
const (
	TunnelSubdomains = "subdomains"
	TunnelTXT        = "txt"
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

	contents    []contentMatch
	appProto    string // packet.AppDNS etc., or ""
	appFields   []appField
	appReasons  []string // AppFields keys, e.g. "malformed_reason"
	appContents []appContent
	appDomains  []appDomain
	fieldRegex  []fieldRegex     // regex on AppFields keys
	dataRegex   []*regexp.Regexp // regex:data

	// Threat-intel feeds (internal/intel).
	ipFeed     *intel.Feed // ip_feed: the source or destination is in it
	domainFeed *intel.Feed // domain_feed: one of domainKeys is in it
	domainKeys []string
	ja3Feed    *intel.Feed // ja3_feed: ja3_hash is in it
	ja3Label   uint8       // ja3Labeled, ja3Unlabeled, or 0 for either

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

	// dns_spoof and dns_tunnel
	dnsKind string
	// dns_amplification
	minBytes uint64
	ampRatio float64 // min_ratio
	// dns_tunnel and dns_nxdomain_burst
	minEntropy float64
	minLength  int      // dns_tunnel kind:subdomains
	allow      []string // dns_tunnel and beacon: domains never counted

	// slowloris; detect.seconds is the activity window of slow_headers
	// and slow_body.
	slowKind     string
	minAge       time.Duration
	minRate      int // slow_body: bytes per second
	minRemaining int // slow_body: bytes of declared body still to come

	// beacon; allow holds the allowed names.
	minEvents                int
	persistence              int // checks in a row that must pass
	minInterval, maxInterval time.Duration
	jitter, minFraction      float64
	allowPorts               portSpec
	allowAddrs               addrSpec
	hasAllowAddrs            bool

	// baseline
	interval       time.Duration
	learnIntervals int
	threshold      float64
	sustain        int
	maxStep        float64
	metrics        metricSet
	drop           metricSet // metrics that also fire when they fall
	minLevel       [numMetrics]float64
	// incident
	incKind     string
	minStages   int
	incWindow   time.Duration // multi_stage: between stages after the first; else from the exploit
	firstWindow time.Duration // multi_stage: from a first-stage alert to the next
	fromStages  stageSet
	toStages    stageSet
	// stage is the kill-chain stage of Category, -1 for none. Parse sets
	// it from the stage directives.
	stage int
}

// Values of Rule.ja3Label.
const (
	ja3Labeled uint8 = iota + 1
	ja3Unlabeled
)

// defaultDomainKeys are the AppFields domain_feed checks without a KEY:
// the DNS query name, the TLS server name and the HTTP Host.
var defaultDomainKeys = []string{"qname", "sni", "host"}

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

// appContent is app_content: pat is a substring of AppFields[key],
// lowercased (ASCII only) when nocase.
type appContent struct {
	key, pat string
	nocase   bool
}

// appDomain is app_domain:KEY,LIST: the field is one of names or a
// subdomain of one.
type appDomain struct {
	key   string
	names []string
}

// fieldRegex is regex on an AppFields key.
type fieldRegex struct {
	key string
	re  *regexp.Regexp
}

// maxRegexInput caps what one regex evaluation reads: only the first
// 16 KiB of a field or of the data is searched. RE2 runs in linear time,
// so this bounds the cost of each evaluation to a constant.
const maxRegexInput = 16 << 10

// DataKey is the regex key that means the application data: the
// messages a packet completed (AppData), or its payload if it completed
// none.
const DataKey = "data"

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
	probes   bool
	ttl      []*Rule // detect:ttl_anomaly rules
	frags    []*Rule // detect:frag_attack rules; the fragment tracker runs when non-empty
	arp      []*Rule // detect:arp_spoof rules; the ARP tables run when non-empty
	udp      []*Rule // detect:udp_flood rules
	icmp     []*Rule // detect:icmp_flood and icmp_tunnel rules
	slow     []*Rule // detect:slowloris rules; the slow flow table runs when non-empty
	dns      []*Rule // the DNS detectors (dns.go)
	beacon   []*Rule // detect:beacon rules
	baseline []*Rule // detect:baseline rules
	// dnsQueries is true when some dns_spoof or dns_amplification rule
	// needs the outstanding query table.
	dnsQueries bool
	// echoReqs is true when some icmp_flood rule has kind
	// unsolicited_reply, so outstanding echo requests are tracked.
	echoReqs bool
	// arpStatic holds the arpbind directives: IPv4 address -> MAC.
	arpStatic map[netip.Addr]mac6
	// stages holds the stage directives; incident holds the
	// detect:incident rules, and callback is true when one of them has
	// kind:callback, so connection starts are reported.
	stages   *stageTable
	incident []*Rule
	callback bool
	feeds    []*intel.Feed // feed directives, in file order
	warnings []string
}

type ruleGroup struct{ pass, alert []*Rule }

// Rules returns the rules in file order. The caller must not modify them.
func (rs *RuleSet) Rules() []*Rule { return rs.rules }

// Len returns the number of rules.
func (rs *RuleSet) Len() int { return len(rs.rules) }

// File returns the path the rules were loaded from.
func (rs *RuleSet) File() string { return rs.file }

// Feeds returns the feeds the rule file defines, in file order. The
// caller must not modify them.
func (rs *RuleSet) Feeds() []*intel.Feed { return rs.feeds }

// Warnings returns problems that did not stop the rules from loading,
// such as rejected feed entries.
func (rs *RuleSet) Warnings() []string { return rs.warnings }

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
	rs := &RuleSet{file: file, rules: rules, arpStatic: static, stages: newStageTable()}
	// The handshake tracker also tells alerts on completed flows apart
	// (attribution, see attribution.go), so it runs whenever there are
	// rules.
	rs.handshakes = len(rules) > 0
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
			case DetectBeacon:
				rs.beacon = append(rs.beacon, r)
			case DetectBaseline:
				rs.baseline = append(rs.baseline, r)
			case DetectIncident:
				rs.incident = append(rs.incident, r)
				if r.incKind == IncidentCallback {
					rs.callback = true
				}
			case DetectDNSSpoof, DetectDNSAmplification, DetectDNSTunnel, DetectNXDomainBurst:
				rs.dns = append(rs.dns, r)
				if r.Detect == DetectDNSSpoof || r.Detect == DetectDNSAmplification {
					rs.dnsQueries = true
				}
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

	// established is true for a TCP packet of a flow whose handshake
	// the tracker saw complete (for attribution).
	established bool
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
	if r.ipFeed != nil && !r.ipFeed.ContainsIP(v.src) && !r.ipFeed.ContainsIP(v.dst) {
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
	if r.appProto != "" || r.perMessage() {
		if v.p == nil {
			return false
		}
		if r.appProto != "" && v.p.AppProtocol != r.appProto {
			return false
		}
		// With several messages (AppMore), one of them must satisfy
		// every app_field, app_reason, app_content and field regex.
		if r.perMessage() {
			ok := r.matchApp(v.p.AppFields)
			for i := 0; !ok && i < len(v.p.AppMore); i++ {
				ok = r.matchApp(v.p.AppMore[i])
			}
			if !ok {
				return false
			}
		}
	}
	// Every content must be in the segment's payload, or every content in
	// the messages it completed (AppData), which may span segments. The
	// literals run before any data regex.
	if len(r.contents) > 0 && !r.matchContents(v.getPayload(), v.getLower) &&
		(v.p == nil || v.p.AppData == nil || !r.matchContents(v.p.AppData, v.getAppLower)) {
		return false
	}
	if len(r.dataRegex) > 0 {
		if v.p == nil {
			return false
		}
		data := v.p.AppData
		if data == nil {
			data = v.getPayload()
		}
		data = data[:min(len(data), maxRegexInput)]
		for _, re := range r.dataRegex {
			if !re.Match(data) {
				return false
			}
		}
	}
	return true
}

// perMessage reports whether r has options checked against the fields
// of one application message.
func (r *Rule) perMessage() bool {
	return len(r.appFields) > 0 || len(r.appReasons) > 0 || len(r.appContents) > 0 || len(r.appDomains) > 0 || len(r.fieldRegex) > 0 ||
		r.domainFeed != nil || r.ja3Feed != nil
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
	for _, c := range r.appContents {
		got, ok := fields[c.key]
		if !ok || !containsASCII(got, c.pat, c.nocase) {
			return false
		}
	}
	for _, d := range r.appDomains {
		got, ok := fields[d.key]
		if !ok || !inDomains(got, d.names) {
			return false
		}
	}
	for _, f := range r.fieldRegex {
		got, ok := fields[f.key]
		if !ok || !f.re.MatchString(got[:min(len(got), maxRegexInput)]) {
			return false
		}
	}
	if r.domainFeed != nil {
		if _, _, ok := r.domainHit(fields); !ok {
			return false
		}
	}
	if r.ja3Feed != nil {
		if _, ok := r.ja3Hit(fields); !ok {
			return false
		}
	}
	return true
}

// domainHit returns the first of r.domainKeys whose value is in r's
// domain feed, and the feed entry it matched. A DNS qname counts in
// queries only: the response repeats it, and would be a second alert
// for the same lookup that names the resolver as its source.
func (r *Rule) domainHit(fields map[string]string) (key, entry string, ok bool) {
	for _, k := range r.domainKeys {
		name, found := fields[k]
		if !found {
			continue
		}
		switch k {
		case "host":
			name = stripPort(name)
		case "qname":
			if fields["is_response"] == "true" {
				continue
			}
		}
		if entry, ok := r.domainFeed.MatchDomain(name); ok {
			return k, entry, true
		}
	}
	return "", "", false
}

// stripPort removes a ":port" suffix from an HTTP Host value.
func stripPort(host string) string {
	i := strings.LastIndexByte(host, ':')
	if i < 0 || strings.Contains(host[i:], "]") {
		return host
	}
	for j := i + 1; j < len(host); j++ {
		if host[j] < '0' || host[j] > '9' {
			return host
		}
	}
	return host[:i]
}

// ja3Hit returns the feed label of the message's ja3_hash, if the hash is
// in r's JA3 feed with the label kind r asks for.
func (r *Rule) ja3Hit(fields map[string]string) (string, bool) {
	label, ok := r.ja3Feed.LookupJA3(fields["ja3_hash"])
	switch {
	case !ok:
		return "", false
	case r.ja3Label == ja3Labeled && label == "", r.ja3Label == ja3Unlabeled && label != "":
		return "", false
	}
	return label, true
}

// feedDetails describes the feed entries a matching packet hit, for the
// alert: which side of the packet is in an ip feed, and which field and
// entry matched a domain or JA3 feed in the first message that matched.
func (r *Rule) feedDetails(v *view, d map[string]string) map[string]string {
	if r.ipFeed == nil && r.domainFeed == nil && r.ja3Feed == nil {
		return d
	}
	if d == nil {
		d = make(map[string]string)
	}
	if f := r.ipFeed; f != nil {
		src, dst := f.ContainsIP(v.src), f.ContainsIP(v.dst)
		d["ip_feed"] = f.Name
		switch {
		case src && dst:
			d["side"], d["indicator"] = "both", v.src.String()+","+v.dst.String()
		case src:
			d["side"], d["indicator"] = "src", v.src.String()
		default:
			d["side"], d["indicator"] = "dst", v.dst.String()
		}
	}
	if (r.domainFeed != nil || r.ja3Feed != nil) && v.p != nil {
		msgs := append([]map[string]string{v.p.AppFields}, v.p.AppMore...)
		for _, m := range msgs {
			if !r.matchApp(m) {
				continue
			}
			if r.domainFeed != nil {
				key, entry, _ := r.domainHit(m)
				d["domain_feed"], d["field"], d["name"], d["indicator"] = r.domainFeed.Name, key, m[key], entry
			}
			if r.ja3Feed != nil {
				label, _ := r.ja3Hit(m)
				d["ja3_feed"], d["ja3_hash"] = r.ja3Feed.Name, strings.ToLower(m["ja3_hash"])
				if label != "" {
					d["label"] = label
				}
			}
			break
		}
	}
	return d
}

// inDomains reports whether name, compared without case and a trailing
// dot, is one of names or a subdomain of one.
func inDomains(name string, names []string) bool {
	name = strings.TrimSuffix(name, ".")
	for _, d := range names {
		if len(name) == len(d) && strings.EqualFold(name, d) ||
			len(name) > len(d) && name[len(name)-len(d)-1] == '.' && strings.EqualFold(name[len(name)-len(d):], d) {
			return true
		}
	}
	return false
}

// containsASCII reports whether pat is in s; with fold, s is compared
// with A-Z folded to lower case (pat is already lower case).
func containsASCII(s, pat string, fold bool) bool {
	if !fold {
		return strings.Contains(s, pat)
	}
	if len(pat) == 0 {
		return true
	}
	for i := 0; i+len(pat) <= len(s); i++ {
		j := 0
		for ; j < len(pat); j++ {
			c := s[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != pat[j] {
				break
			}
		}
		if j == len(pat) {
			return true
		}
	}
	return false
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
