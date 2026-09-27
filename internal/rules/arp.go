package rules

import (
	"container/list"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// ARP spoofing detection (detect:arp_spoof).
//
// The engine keeps two tables for every rule set with an arp_spoof rule,
// fed by every ARP packet whether or not it is whitelisted or passed, so
// their contents do not depend on the rules:
//
//   - The binding table maps an IPv4 address to the MAC address that last
//     claimed it. It learns only from the sender IP and sender MAC of ARP
//     requests and replies, never from IP traffic (an IP packet's source
//     MAC is the last router's, not the sender's). Senders 0.0.0.0 (RFC
//     5227 probes), senders with an invalid MAC, and addresses with a
//     static binding (arpbind) are not learned.
//   - The request table holds the ARP requests seen in the last
//     arpRequestTimeout, keyed by (requester IP, requested IP), so a reply
//     can be matched to the request that asked for it. A request is not
//     consumed by its first reply: a duplicate reply is still solicited.
//
// Each rule has one kind; the per-rule counters count only packets that
// passed the whitelist, pass rules and the rule's addresses. Every kind
// except invalid_mac ignores packets whose sender IP is 0.0.0.0.
//
//   - static_violation: the sender IP has a static binding and the sender
//     MAC differs. Static bindings take precedence: such an address is
//     never learned, so mac_change and flip_flop never fire for it.
//   - mac_change: the sender IP was bound to another MAC.
//   - flip_flop: the sender IP went back to a MAC it had before, count
//     times within seconds (a "return" is a change whose new MAC is in the
//     address's change history).
//   - unsolicited_reply: count replies within seconds, per (sender IP,
//     sender MAC), that answer no outstanding request. A gratuitous ARP
//     (sender IP == target IP, request or reply) is unsolicited by nature
//     but also how a host announces itself at boot or after failover
//     (RFC 5227 sends two), so the first two per (IP, MAC) within seconds
//     are free and only later ones count.
//   - multi_ip: one sender MAC claims count distinct sender IPs within
//     seconds in replies (gratuitous ones included).
//   - mismatch: the Ethernet source MAC differs from the ARP sender MAC.
//   - invalid_mac: the ARP sender MAC is broadcast, multicast or zero.

// Values of the arp_spoof kind option.
const (
	ARPStaticViolation = "static_violation"
	ARPMACChange       = "mac_change"
	ARPFlipFlop        = "flip_flop"
	ARPUnsolicited     = "unsolicited_reply"
	ARPMultiIP         = "multi_ip"
	ARPMismatch        = "mismatch"
	ARPInvalidMAC      = "invalid_mac"
)

// arpKinds lists the arp_spoof kinds; arpCounted are the ones that take
// count and seconds.
var (
	arpKinds   = []string{ARPStaticViolation, ARPMACChange, ARPFlipFlop, ARPUnsolicited, ARPMultiIP, ARPMismatch, ARPInvalidMAC}
	arpCounted = []string{ARPFlipFlop, ARPUnsolicited, ARPMultiIP}
)

const (
	// arpHistory is how many MAC changes are kept per address.
	arpHistory = 8
	// arpIdle is how long a binding is kept without an ARP packet from
	// its address. It is longer than any ARP cache timeout, so a host
	// that is quiet for a while is not relearned as a new binding.
	arpIdle = 4 * time.Hour
	// arpRequestTimeout is how long a request waits for its reply.
	arpRequestTimeout = 5 * time.Second
	// arpGratuitousFree is how many gratuitous ARPs per (IP, MAC) within
	// seconds do not count as unsolicited replies.
	arpGratuitousFree = 2
)

type mac6 [6]byte

func (m mac6) String() string { return net.HardwareAddr(m[:]).String() }

func toMAC(b []byte) (mac6, bool) {
	var m mac6
	if len(b) != 6 {
		return m, false
	}
	copy(m[:], b)
	return m, true
}

// invalidMACReason returns why m cannot be a host's own address, or "".
func invalidMACReason(m mac6) string {
	switch {
	case isBroadcast(m[:]):
		return "broadcast"
	case m[0]&1 != 0:
		return "multicast"
	case isZeroMAC(m[:]):
		return "zero"
	}
	return ""
}

// arpChange is one change of an address's MAC.
type arpChange struct {
	t        time.Time
	from, to mac6
}

// arpBinding is what the table knows about one address.
type arpBinding struct {
	ip    netip.Addr
	mac   mac6
	first time.Time   // first ARP packet from the address
	since time.Time   // when mac was first claimed (the last change)
	last  time.Time   // latest ARP packet from the address
	hist  []arpChange // the last arpHistory changes, oldest first
}

// arpLearned is the result of arpTable.learn.
type arpLearned struct {
	changed  bool
	returned bool // the new MAC is in the change history
	old      mac6
	stable   time.Duration // how long old had been bound
	b        *arpBinding
}

// arpTable is the IP -> MAC binding table. Bindings are kept in least
// recently seen order: one unseen for arpIdle is dropped, and at the cap
// the least recently seen is evicted and counted. Times come from the
// engine clock; a time earlier than the binding's last is taken as last.
type arpTable struct {
	max  int
	m    map[netip.Addr]*list.Element // Value is *arpBinding
	lru  list.List                    // front = least recently seen
	stat *tableStat
}

func newARPTable(max int, stat *tableStat) *arpTable {
	return &arpTable{max: max, m: make(map[netip.Addr]*list.Element), stat: stat}
}

// learn records that ip claimed mac at t and reports whether that changed
// the binding.
func (a *arpTable) learn(ip netip.Addr, mac mac6, t time.Time) arpLearned {
	a.prune(t)
	if el, ok := a.m[ip]; ok {
		a.lru.MoveToBack(el)
		b := el.Value.(*arpBinding)
		if t.Before(b.last) {
			t = b.last
		}
		b.last = t
		if b.mac == mac {
			return arpLearned{b: b}
		}
		res := arpLearned{changed: true, old: b.mac, stable: t.Sub(b.since), b: b}
		for _, c := range b.hist {
			if c.from == mac || c.to == mac {
				res.returned = true
				break
			}
		}
		if len(b.hist) == arpHistory {
			b.hist = append(b.hist[:0], b.hist[1:]...)
		}
		b.hist = append(b.hist, arpChange{t: t, from: b.mac, to: mac})
		b.mac, b.since = mac, t
		return res
	}
	if len(a.m) >= a.max {
		a.remove(a.lru.Front())
		a.stat.evictions.Add(1)
	}
	b := &arpBinding{ip: ip, mac: mac, first: t, since: t, last: t}
	a.m[ip] = a.lru.PushBack(b)
	a.stat.keys.Add(1)
	return arpLearned{b: b}
}

// lookup returns the binding of ip, or nil.
func (a *arpTable) lookup(ip netip.Addr) *arpBinding {
	if el, ok := a.m[ip]; ok {
		return el.Value.(*arpBinding)
	}
	return nil
}

func (a *arpTable) prune(now time.Time) {
	for el := a.lru.Front(); el != nil; el = a.lru.Front() {
		if now.Sub(el.Value.(*arpBinding).last) <= arpIdle {
			return
		}
		a.remove(el)
	}
}

func (a *arpTable) remove(el *list.Element) {
	delete(a.m, a.lru.Remove(el).(*arpBinding).ip)
	a.stat.keys.Add(-1)
}

func (a *arpTable) clear() {
	a.stat.keys.Add(-int64(len(a.m)))
	clear(a.m)
	a.lru.Init()
}

// changesSince counts b's recorded changes at or after t.
func (b *arpBinding) changesSince(t time.Time) int {
	n := 0
	for _, c := range b.hist {
		if !c.t.Before(t) {
			n++
		}
	}
	return n
}

// arpReqKey identifies an outstanding request: who asked for which
// address. A probe's requester is 0.0.0.0, and so is the target of the
// reply that defends the address.
type arpReqKey struct{ requester, target netip.Addr }

type arpReq struct {
	key arpReqKey
	t   time.Time
}

// arpRequests holds requests younger than arpRequestTimeout, in arrival
// order, capped like the other tables.
type arpRequests struct {
	max  int
	m    map[arpReqKey]*list.Element // Value is *arpReq
	lru  list.List                   // front = oldest
	stat *tableStat
}

func newARPRequests(max int, stat *tableStat) *arpRequests {
	return &arpRequests{max: max, m: make(map[arpReqKey]*list.Element), stat: stat}
}

// add records a request at t; a repeated request restarts its timeout.
func (r *arpRequests) add(k arpReqKey, t time.Time) {
	r.prune(t)
	if el, ok := r.m[k]; ok {
		r.lru.MoveToBack(el)
		el.Value.(*arpReq).t = t
		return
	}
	if len(r.m) >= r.max {
		r.remove(r.lru.Front())
		r.stat.evictions.Add(1)
	}
	r.m[k] = r.lru.PushBack(&arpReq{key: k, t: t})
	r.stat.keys.Add(1)
}

// outstanding reports whether a request k is waiting at t.
func (r *arpRequests) outstanding(k arpReqKey, t time.Time) bool {
	r.prune(t)
	_, ok := r.m[k]
	return ok
}

func (r *arpRequests) prune(now time.Time) {
	for el := r.lru.Front(); el != nil; el = r.lru.Front() {
		if now.Sub(el.Value.(*arpReq).t) <= arpRequestTimeout {
			return
		}
		r.remove(el)
	}
}

func (r *arpRequests) remove(el *list.Element) {
	delete(r.m, r.lru.Remove(el).(*arpReq).key)
	r.stat.keys.Add(-1)
}

func (r *arpRequests) clear() {
	r.stat.keys.Add(-int64(len(r.m)))
	clear(r.m)
	r.lru.Init()
}

// arpClaim is a (sender IP, sender MAC) pair.
type arpClaim struct {
	ip  netip.Addr
	mac mac6
}

// arpSpoof is the per-rule state of an arp_spoof rule. Only the counted
// kinds have state: flips for flip_flop, replies and grat for
// unsolicited_reply, ips for multi_ip.
type arpSpoof struct {
	rule    *Rule
	flips   *windowCounter[netip.Addr]
	replies *windowCounter[arpClaim]
	grat    *windowCounter[arpClaim]
	ips     *distinctCounter[mac6, netip.Addr]
}

func newARPSpoof(r *Rule, max int, stat *tableStat) *arpSpoof {
	d := &arpSpoof{rule: r}
	span := r.detect.span()
	switch r.arpKind {
	case ARPFlipFlop:
		d.flips = newWindowCounter[netip.Addr](r.detect.count, span, max, stat)
	case ARPUnsolicited:
		d.replies = newWindowCounter[arpClaim](r.detect.count, span, max, stat)
		d.grat = newWindowCounter[arpClaim](arpGratuitousFree+1, span, max, stat)
	case ARPMultiIP:
		d.ips = newDistinctCounter[mac6, netip.Addr](r.detect.count, span, max, stat)
	}
	return d
}

func (d *arpSpoof) clear() {
	if d.flips != nil {
		d.flips.clear()
	}
	if d.replies != nil {
		d.replies.clear()
		d.grat.clear()
	}
	if d.ips != nil {
		d.ips.clear()
	}
}

// arpPacket is what the arp_spoof rules need from one ARP packet, after
// the tables were updated.
type arpPacket struct {
	op         uint16
	sha        mac6
	ethSrc     mac6
	hasEthSrc  bool
	zeroSender bool // sender IP 0.0.0.0
	gratuitous bool // sender IP == target IP
	solicited  bool // a reply matching an outstanding request
	invalid    string
	static     mac6 // the static binding of the sender IP, if isStatic
	isStatic   bool
	learned    arpLearned
}

func (a *arpPacket) opName() string {
	if a.op == packet.ARPRequest {
		return "request"
	}
	return "reply"
}

// arp updates the ARP tables with one ARP packet and runs the arp_spoof
// rules. Alerts are filtered like the packet itself (whitelist and pass
// rules on the sender IP, the rule's addresses).
func (e *Engine) arp(rs *RuleSet, p *packet.ParsedPacket, v *view, out []Alert) []Alert {
	sha, ok := toMAC(p.ARPSenderMAC)
	if !ok || !v.src.Is4() || !v.dst.Is4() || p.ARPOp != packet.ARPRequest && p.ARPOp != packet.ARPReply {
		return out
	}
	now := e.now
	a := arpPacket{op: p.ARPOp, sha: sha, zeroSender: v.src.IsUnspecified(), invalid: invalidMACReason(sha)}
	a.ethSrc, a.hasEthSrc = toMAC(p.EthSrc)
	a.gratuitous = !a.zeroSender && v.src == v.dst
	switch {
	case a.op == packet.ARPRequest && !a.gratuitous:
		e.arpReqs.add(arpReqKey{requester: v.src, target: v.dst}, now)
	case a.op == packet.ARPReply && !a.gratuitous && !a.zeroSender:
		a.solicited = e.arpReqs.outstanding(arpReqKey{requester: v.dst, target: v.src}, now)
	}
	a.static, a.isStatic = rs.arpStatic[v.src]
	if !a.zeroSender && a.invalid == "" && !a.isStatic {
		a.learned = e.arpTable.learn(v.src, sha, now)
	}

	if e.isWhitelisted(v.src) || e.passes(rs, v) {
		return out
	}
	for _, r := range rs.arp {
		if r.matchAddrs(v) {
			out = e.arpRule(r, &a, v, out)
		}
	}
	return out
}

// arpRule runs one arp_spoof rule on a packet.
func (e *Engine) arpRule(r *Rule, a *arpPacket, v *view, out []Alert) []Alert {
	if a.zeroSender && r.arpKind != ARPInvalidMAC {
		return out
	}
	d := e.ruleState[r.idx].arp
	dk := dedupKey{sid: r.SID, addr: v.src}
	base := func() map[string]string {
		return map[string]string{
			"detector": DetectARPSpoof,
			"kind":     r.arpKind,
			"ip":       v.src.String(),
			"op":       a.opName(),
		}
	}
	var details func() map[string]string
	switch r.arpKind {
	case ARPStaticViolation:
		if !a.isStatic || a.sha == a.static {
			return out
		}
		details = func() map[string]string {
			m := base()
			m["claimed_mac"], m["bound_mac"] = a.sha.String(), a.static.String()
			return m
		}
	case ARPMACChange:
		l := a.learned
		if !l.changed {
			return out
		}
		details = func() map[string]string {
			m := base()
			m["old_mac"], m["new_mac"] = l.old.String(), l.b.mac.String()
			m["old_stable"] = l.stable.Round(time.Millisecond).String()
			return m
		}
	case ARPFlipFlop:
		l := a.learned
		if !l.returned {
			return out
		}
		ent, fired := d.flips.add(v.src, e.now, 0)
		if !fired {
			return out
		}
		details = func() map[string]string {
			m := base()
			m["mac"], m["previous_mac"] = l.b.mac.String(), l.old.String()
			m["returns"] = strconv.Itoa(ent.size())
			m["changes"] = strconv.Itoa(l.b.changesSince(e.now.Add(-r.detect.span())))
			m["seconds"] = strconv.Itoa(r.detect.seconds)
			m["window"] = ent.newest().Sub(ent.oldest()).Round(time.Millisecond).String()
			return m
		}
	case ARPUnsolicited:
		c := arpClaim{ip: v.src, mac: a.sha}
		switch {
		case a.gratuitous:
			if _, repeated := d.grat.add(c, e.now, 0); !repeated {
				return out
			}
		case a.op != packet.ARPReply || a.solicited:
			return out
		}
		ent, fired := d.replies.add(c, e.now, 0)
		if !fired {
			return out
		}
		dk.mac, dk.hasMAC = a.sha, true
		details = func() map[string]string {
			m := base()
			m["mac"] = a.sha.String()
			m["replies"] = strconv.Itoa(ent.size())
			m["gratuitous"] = strconv.FormatBool(a.gratuitous)
			m["seconds"] = strconv.Itoa(r.detect.seconds)
			m["window"] = ent.newest().Sub(ent.oldest()).Round(time.Millisecond).String()
			return m
		}
	case ARPMultiIP:
		if a.op != packet.ARPReply {
			return out
		}
		ent := d.ips.add(a.sha, v.src, e.now, 0)
		if ent.size() < r.detect.count {
			return out
		}
		dk = dedupKey{sid: r.SID, mac: a.sha, hasMAC: true}
		details = func() map[string]string {
			ips := make([]netip.Addr, 0, len(ent.vals))
			for _, x := range ent.vals {
				ips = append(ips, x.v)
			}
			slices.SortFunc(ips, netip.Addr.Compare)
			strs := make([]string, len(ips))
			for i, ip := range ips {
				strs[i] = ip.String()
			}
			m := base()
			m["mac"] = a.sha.String()
			m["distinct_ips"] = strconv.Itoa(len(ips))
			m["ips"] = strings.Join(strs, ",")
			m["seconds"] = strconv.Itoa(r.detect.seconds)
			return m
		}
	case ARPMismatch:
		if !a.hasEthSrc || a.ethSrc == a.sha {
			return out
		}
		details = func() map[string]string {
			m := base()
			m["eth_src"], m["arp_sender_mac"] = a.ethSrc.String(), a.sha.String()
			return m
		}
	case ARPInvalidMAC:
		if a.invalid == "" {
			return out
		}
		details = func() map[string]string {
			m := base()
			m["mac"], m["reason"] = a.sha.String(), a.invalid
			return m
		}
	default:
		return out
	}
	return e.emit(r, dk, v, details, out)
}
