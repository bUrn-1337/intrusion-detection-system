package rules

import (
	"net/netip"
	"strconv"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Values of the udp_flood metric option.
const (
	MetricPackets = "packets"
	MetricBytes   = "bytes"
)

// udpFlood is the detect:udp_flood detector for one rule. Per tracked
// address (the sender for by_src, the receiver for by_dst) it sums, over
// a rateCounter window, the forward UDP packets and bytes the rule's
// addresses match, and the replies that came back. It fires when the
// forward packets (metric:packets) or bytes (metric:bytes) reach count
// within seconds and replies / forward packets is at most maxReplyRatio.
//
// A reply is a UDP packet going the other way:
//
//   - by_src: the reverse of a flow the tracked sender used in the
//     window, with addresses and ports swapped. A sender that gets
//     answers on its flows is talking, not flooding.
//   - by_dst: any UDP packet the tracked receiver sent to one of the
//     addresses that sent it counted traffic in the window, on any
//     ports. A spoofed flood comes from many sources, so the question is
//     whether the victim answers the senders at all. Traffic a host
//     sends to itself (127.0.0.1 to 127.0.0.1 on lo) would be its own
//     reply by that test, so for it by_dst uses the by_src test instead.
//
// ICMP errors (port unreachable) are never replies: a flood at a closed
// port gets nothing but those back, and is still a flood.
//
// The reply check is what keeps busy but healthy UDP apart from a flood:
// a QUIC download or a video call sends thousands of packets a second
// one way, but the other side acknowledges or talks back on the same
// flow. Replies are looked for among every UDP packet, whitelisted or
// passed or not, since they only lower the ratio.
//
// Every table is bounded. Under a spoofed flood the pairs table fills
// with fake sources and evicts; a reply to an evicted source is missed,
// which can only raise the ratio of a key that is already being flooded.
type udpFlood struct {
	rule  *Rule
	rate  *rateCounter[netip.Addr]                 // series: forward packets, forward bytes, replies
	flows *recentSet[udpFlow]                      // by_src, and by_dst to itself: forward flows in the window
	pairs *recentSet[addrPair]                     // by_dst: (source, receiver) pairs in the window
	srcs  *distinctCounter[netip.Addr, netip.Addr] // by_dst: sources per receiver
}

const (
	udpFwdPackets = iota
	udpFwdBytes
	udpReplies
)

// maxFloodSources caps the distinct sources a by_dst udp_flood alert
// reports; more are reported as "100+".
const maxFloodSources = 100

type udpFlow struct {
	src, dst     netip.Addr
	sport, dport uint16
}

type addrPair struct{ src, dst netip.Addr }

// newUDPFlood returns the detector for r. The rate counter's keys are
// counted in stat, the flows, pairs and source sets in flowStat.
func newUDPFlood(r *Rule, max int, stat, flowStat *tableStat) *udpFlood {
	d := &udpFlood{
		rule:  r,
		rate:  newRateCounter[netip.Addr](r.detect.span(), max, stat),
		flows: newRecentSet[udpFlow](r.detect.span(), max, flowStat),
	}
	if r.detect.track == TrackByDst {
		d.pairs = newRecentSet[addrPair](r.detect.span(), max, flowStat)
		d.srcs = newDistinctCounter[netip.Addr, netip.Addr](maxFloodSources, r.detect.span(), max, flowStat)
	}
	return d
}

// reply counts v as a reply if it answers traffic this rule counted. It
// runs for every UDP packet before forward, so a packet is never its own
// reply.
func (d *udpFlood) reply(v *view, t time.Time) {
	var key netip.Addr
	if d.pairs != nil && v.src != v.dst {
		if !d.pairs.has(addrPair{src: v.dst, dst: v.src}, t) {
			return
		}
		key = v.src // the receiver that answered
	} else {
		if !d.flows.has(udpFlow{src: v.dst, dst: v.src, sport: v.dport, dport: v.sport}, t) {
			return
		}
		key = v.dst // the sender that got an answer (by_dst: the host itself)
	}
	d.rate.add(key, t, [rateSeries]uint64{udpReplies: 1})
}

// forward counts a packet the rule matched and, when the detector fires,
// returns the tracked address and a function that builds the details.
func (d *udpFlood) forward(p *packet.ParsedPacket, v *view, t time.Time) (netip.Addr, func() map[string]string, bool) {
	r := d.rule
	key := v.src
	if r.detect.track == TrackByDst {
		key = v.dst
		d.pairs.add(addrPair{src: v.src, dst: v.dst}, t)
		if v.src == v.dst {
			d.flows.add(udpFlow{src: v.src, dst: v.dst, sport: v.sport, dport: v.dport}, t)
		}
	} else {
		d.flows.add(udpFlow{src: v.src, dst: v.dst, sport: v.sport, dport: v.dport}, t)
	}
	size := uint64(p.UDPLen)
	if size == 0 { // an IPv6 jumbogram leaves the Length field 0
		size = uint64(8 + len(v.getPayload()))
	}
	ent := d.rate.add(key, t, [rateSeries]uint64{udpFwdPackets: 1, udpFwdBytes: size})
	ent.countTag(v.dport)
	srcs := 0
	if d.srcs != nil {
		srcs = d.srcs.add(key, v.src, t, 0).size()
	}
	pkts, bytes, replies := ent.sum(udpFwdPackets), ent.sum(udpFwdBytes), ent.sum(udpReplies)
	volume := pkts
	if r.metric == MetricBytes {
		volume = bytes
	}
	if volume < uint64(r.detect.count) {
		return key, nil, false
	}
	// replies/pkts <= maxReplyRatio, without dividing.
	if float64(replies) > r.maxReplyRatio*float64(pkts) {
		return key, nil, false
	}
	details := func() map[string]string {
		secs := float64(r.detect.seconds)
		m := map[string]string{
			"detector":        DetectUDPFlood,
			"track":           r.detect.track.String(),
			"tracked_addr":    key.String(),
			"metric":          r.metric,
			"packets":         strconv.FormatUint(pkts, 10),
			"bytes":           strconv.FormatUint(bytes, 10),
			"replies":         strconv.FormatUint(replies, 10),
			"reply_ratio":     strconv.FormatFloat(float64(replies)/float64(pkts), 'f', 4, 64),
			"max_reply_ratio": strconv.FormatFloat(r.maxReplyRatio, 'f', -1, 64),
			"packets_per_sec": strconv.FormatFloat(float64(pkts)/secs, 'f', 0, 64),
			"bytes_per_sec":   strconv.FormatFloat(float64(bytes)/secs, 'f', 0, 64),
			"top_dst_port":    strconv.Itoa(int(ent.topTag())),
			"seconds":         strconv.Itoa(r.detect.seconds),
		}
		if d.srcs != nil {
			s := strconv.Itoa(srcs)
			if srcs > maxFloodSources {
				s = strconv.Itoa(maxFloodSources) + "+"
			}
			m["distinct_sources"] = s
		}
		return m
	}
	return key, details, true
}

func (d *udpFlood) clear() {
	d.rate.clear()
	d.flows.clear()
	if d.pairs != nil {
		d.pairs.clear()
		d.srcs.clear()
	}
}
