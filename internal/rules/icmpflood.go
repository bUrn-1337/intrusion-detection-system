package rules

import (
	"net/netip"
	"strconv"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
)

// Values of the icmp_flood kind option.
const (
	// ICMPEcho counts echo requests (ICMP type 8, ICMPv6 type 128) per
	// tracked address. Replies coming back do not make it less of a
	// flood: a flood that the victim answers costs it twice.
	ICMPEcho = "echo"
	// ICMPUnsolicitedReply counts echo replies (type 0, ICMPv6 129) that
	// answer no request the sensor saw, per receiver. Many of them are
	// the signature of a smurf or reflection attack: the attacker sends
	// echo requests with the victim's address as source to many hosts
	// (or a broadcast address), and all their replies land on the victim.
	ICMPUnsolicitedReply = "unsolicited_reply"
	// ICMPErrorFlood counts ICMP errors (destination unreachable, time
	// exceeded, parameter problem, and ICMPv6 packet too big) per
	// receiver. A port scan or UDP flood against closed ports also makes
	// the target send port unreachables back toward the scanner, so the
	// scanner can see an error flood of its own making; the threshold is
	// set well above what a scan produces from hosts that rate-limit
	// their ICMP errors (Linux sends at most 1000 a second in total and
	// far fewer to one destination, except on loopback).
	ICMPErrorFlood = "error_flood"
)

var icmpKinds = []string{ICMPEcho, ICMPUnsolicitedReply, ICMPErrorFlood}

// echoRequestIdle is how long an echo request waits for its reply. A
// reply later than this counts as unsolicited.
const echoRequestIdle = 10 * time.Second

// echoKey identifies an outstanding echo request. responder is the zero
// Addr for a request sent to a multicast or broadcast address, which any
// host may answer.
type echoKey struct {
	requester, responder netip.Addr
	id, seq              uint16
}

// isEchoRequest and isEchoReply take the ICMP type and whether the
// packet is ICMPv6.
func isEchoRequest(typ uint8, v6 bool) bool {
	if v6 {
		return typ == 128
	}
	return typ == 8
}

func isEchoReply(typ uint8, v6 bool) bool {
	if v6 {
		return typ == 129
	}
	return typ == 0
}

// isICMPError reports whether typ is an ICMP error message: destination
// unreachable, time exceeded or parameter problem (ICMP 3, 11, 12;
// ICMPv6 1, 3, 4), or ICMPv6 packet too big (2).
func isICMPError(typ uint8, v6 bool) bool {
	if v6 {
		return typ >= 1 && typ <= 4
	}
	return typ == 3 || typ == 11 || typ == 12
}

// echoKeyOf returns the key an echo request p (from v.src to v.dst)
// waits under.
func echoKeyOf(p *packet.ParsedPacket, v *view) echoKey {
	k := echoKey{requester: v.src, responder: v.dst, id: p.ICMPEchoID, seq: p.ICMPEchoSeq}
	if v.dst.IsMulticast() || v.dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || ethDstIs(p.EthDst, ethBroadcast) || ethDstIs(p.EthDst, ethMulticast) {
		k.responder = netip.Addr{}
	}
	return k
}

// solicited reports whether the echo reply p (from v.src to v.dst)
// answers a request in reqs: one from v.dst to v.src, or to a group
// address, with the same id and seq. The request is kept, since
// duplicates and every member of a group may answer it.
func solicited(reqs *recentSet[echoKey], p *packet.ParsedPacket, v *view, t time.Time) bool {
	k := echoKey{requester: v.dst, responder: v.src, id: p.ICMPEchoID, seq: p.ICMPEchoSeq}
	if reqs.has(k, t) {
		return true
	}
	k.responder = netip.Addr{}
	return reqs.has(k, t)
}

// icmpFlood is the detect:icmp_flood detector for one rule: a rateCounter
// of the packets of its kind per tracked address, and the distinct peers
// of each for the alert.
type icmpFlood struct {
	rule  *Rule
	rate  *rateCounter[netip.Addr]
	peers *distinctCounter[netip.Addr, netip.Addr]
}

func newICMPFlood(r *Rule, max int, stat, peerStat *tableStat) *icmpFlood {
	return &icmpFlood{
		rule:  r,
		rate:  newRateCounter[netip.Addr](r.detect.span(), max, stat),
		peers: newDistinctCounter[netip.Addr, netip.Addr](maxFloodSources, r.detect.span(), max, peerStat),
	}
}

// observe counts a packet of the rule's kind. The engine has already
// checked the kind, the whitelist, pass rules and the rule's addresses.
func (d *icmpFlood) observe(p *packet.ParsedPacket, v *view, t time.Time) (netip.Addr, func() map[string]string, bool) {
	r := d.rule
	key, peer := v.dst, v.src
	if r.icmpKind == ICMPEcho && r.detect.track == TrackBySrc {
		key, peer = v.src, v.dst
	}
	ent := d.rate.add(key, t, [rateSeries]uint64{1})
	if r.icmpKind == ICMPErrorFlood {
		ent.countTag(uint16(p.ICMPType)<<8 | uint16(p.ICMPCode))
	}
	peers := d.peers.add(key, peer, t, 0).size()
	n := ent.sum(0)
	if n < uint64(r.detect.count) {
		return key, nil, false
	}
	details := func() map[string]string {
		track := TrackByDst
		peerName := "distinct_sources"
		if r.icmpKind == ICMPEcho && r.detect.track == TrackBySrc {
			track, peerName = TrackBySrc, "distinct_destinations"
		}
		ps := strconv.Itoa(peers)
		if peers > maxFloodSources {
			ps = strconv.Itoa(maxFloodSources) + "+"
		}
		m := map[string]string{
			"detector":        DetectICMPFlood,
			"kind":            r.icmpKind,
			"track":           track.String(),
			"tracked_addr":    key.String(),
			"packets":         strconv.FormatUint(n, 10),
			"packets_per_sec": strconv.FormatFloat(float64(n)/float64(r.detect.seconds), 'f', 0, 64),
			"seconds":         strconv.Itoa(r.detect.seconds),
			peerName:          ps,
		}
		if r.icmpKind == ICMPErrorFlood {
			top := ent.topTag()
			m["top_error"] = upper.ICMPLabel(p.IPVersion, uint8(top>>8), uint8(top))
		}
		return m
	}
	return key, details, true
}

func (d *icmpFlood) clear() {
	d.rate.clear()
	d.peers.clear()
}
