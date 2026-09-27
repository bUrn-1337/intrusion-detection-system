package rules

import (
	"container/list"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Fragment attack detection: detect:frag_attack with kind overlap, tiny,
// oversize or flood.
//
// tiny and oversize look at one fragment at a time. overlap and flood
// need the fragmentTracker, which follows every fragmented datagram,
// keyed by (source, destination, protocol, IP ID) for IPv4 and by
// (source, destination, ID) for IPv6 (RFC 8200 section 4.5: the first
// fragment's final protocol can differ from the Fragment header's Next
// Header in later fragments, so the protocol is not part of an IPv6 key).
//
// A fragment covers bytes [FragOffset, FragOffset+FragPayloadLen) of its
// datagram. The tracker stores up to maxFragRanges ranges per datagram:
//
//   - A fragment with the same start and end as a stored one is an exact
//     duplicate (a retransmission or a duplicated packet) and is ignored.
//   - Any other fragment that shares a byte with a stored one is an
//     overlap. Overlaps are how teardrop crashes old stacks and how
//     attacks slip past an IDS that reassembles differently from the
//     target, and a correct sender never produces one.
//   - A datagram with more fragments than maxFragRanges stops being
//     checked; it is counted in EngineStats.FragmentsOverLimit and never
//     alerts (no legitimate datagram needs that many: 65535 bytes at the
//     IPv6 minimum MTU of 1280 is 52 fragments).
//
// A datagram is complete once its final fragment (MF clear) has arrived
// and its ranges cover every byte before that fragment's end. It stays in
// the table until timeout after its first fragment, so a late overlap is
// still caught. A datagram that times out incomplete is reported to the
// flood detectors. Datagrams dropped at the table cap are not.
//
// IPv4 fragments whose header checksum fails are ignored: the receiver
// drops them, so they cannot attack it, and a header that failed to parse
// has no usable lengths.

// maxFragRanges bounds the ranges stored per datagram.
const maxFragRanges = 64

// maxIPPacket is the largest IP packet a 16-bit length can describe.
const maxIPPacket = 65535

type fragKey struct {
	src, dst netip.Addr
	proto    uint8 // IPv4 only; 0 for IPv6
	id       uint32
}

type fragRange struct{ start, end uint32 } // [start, end)

type fragDatagram struct {
	key       fragKey
	first     time.Time
	ranges    []fragRange // sorted by start
	total     uint32      // end of the final fragment, when gotLast
	gotLast   bool
	complete  bool
	overLimit bool
}

// fragEvent is an overlap, or a datagram that expired incomplete.
type fragEvent struct {
	key      fragKey
	t        time.Time
	overlap  bool
	frag     fragRange // overlap: the new fragment
	with     fragRange // overlap: the stored fragment it overlaps
	nFrags   int       // fragments stored
	complete bool
}

type fragmentTracker struct {
	timeout   time.Duration
	max       int
	m         map[fragKey]*list.Element // Value is *fragDatagram
	order     list.List                 // creation order, oldest first
	stat      *tableStat
	overLimit uint64
}

func newFragmentTracker(timeout time.Duration, max int, stat *tableStat) *fragmentTracker {
	return &fragmentTracker{timeout: timeout, max: max, m: make(map[fragKey]*list.Element), stat: stat}
}

// fragKeyOf returns the datagram key of a fragment.
func fragKeyOf(p *packet.ParsedPacket, v *view) fragKey {
	k := fragKey{src: v.src, dst: v.dst, id: p.IPID}
	if p.IPVersion == 4 {
		k.proto = p.IPProto
	}
	return k
}

// fragmentUsable reports whether p is a fragment the detectors look at.
func fragmentUsable(p *packet.ParsedPacket) bool {
	return p.IPFragmented && (p.IPVersion == 6 || p.IPVersion == 4 && p.IPChecksumValid)
}

// expire removes datagrams whose timeout has passed by now and appends an
// event for each incomplete one.
func (ft *fragmentTracker) expire(now time.Time, out []fragEvent) []fragEvent {
	for el := ft.order.Front(); el != nil; el = ft.order.Front() {
		d := el.Value.(*fragDatagram)
		deadline := d.first.Add(ft.timeout)
		if now.Before(deadline) {
			break
		}
		out = ft.drop(el, deadline, out)
	}
	return out
}

// expireAll removes every datagram, as at end of input.
func (ft *fragmentTracker) expireAll(out []fragEvent) []fragEvent {
	for el := ft.order.Front(); el != nil; el = ft.order.Front() {
		out = ft.drop(el, el.Value.(*fragDatagram).first.Add(ft.timeout), out)
	}
	return out
}

func (ft *fragmentTracker) drop(el *list.Element, t time.Time, out []fragEvent) []fragEvent {
	d := ft.order.Remove(el).(*fragDatagram)
	delete(ft.m, d.key)
	ft.stat.keys.Add(-1)
	if !d.complete && !d.overLimit {
		out = append(out, fragEvent{key: d.key, t: t, nFrags: len(d.ranges)})
	}
	return out
}

// observe records one fragment (fragmentUsable is true) and appends an
// event if it overlaps a stored fragment.
func (ft *fragmentTracker) observe(p *packet.ParsedPacket, v *view, now time.Time, out []fragEvent) []fragEvent {
	key := fragKeyOf(p, v)
	el, ok := ft.m[key]
	if !ok {
		if len(ft.m) >= ft.max {
			front := ft.order.Front()
			delete(ft.m, ft.order.Remove(front).(*fragDatagram).key)
			ft.stat.keys.Add(-1)
			ft.stat.evictions.Add(1)
		}
		el = ft.order.PushBack(&fragDatagram{key: key, first: now})
		ft.m[key] = el
		ft.stat.keys.Add(1)
	}
	d := el.Value.(*fragDatagram)
	if d.overLimit {
		return out
	}
	r := fragRange{start: uint32(p.FragOffset), end: uint32(p.FragOffset) + p.FragPayloadLen}
	var hit *fragRange
	for i := range d.ranges {
		s := &d.ranges[i]
		if *s == r {
			return out // exact duplicate
		}
		if hit == nil && r.start < s.end && s.start < r.end {
			hit = s
		}
	}
	if len(d.ranges) == maxFragRanges {
		d.overLimit = true
		ft.overLimit++
		return out
	}
	if hit != nil {
		out = append(out, fragEvent{key: key, t: now, overlap: true, frag: r, with: *hit, nFrags: len(d.ranges) + 1, complete: d.complete})
	}
	i, _ := slices.BinarySearchFunc(d.ranges, r, func(a, b fragRange) int { return int(a.start) - int(b.start) })
	d.ranges = slices.Insert(d.ranges, i, r)
	if !p.MoreFragments {
		d.gotLast, d.total = true, r.end
	}
	if d.gotLast && !d.complete {
		var reach uint32
		for _, s := range d.ranges {
			if s.start > reach {
				break
			}
			reach = max(reach, s.end)
		}
		d.complete = reach >= d.total
	}
	return out
}

func (ft *fragmentTracker) clear() {
	ft.stat.keys.Add(-int64(len(ft.m)))
	clear(ft.m)
	ft.order.Init()
}

// tinyReason returns why fragment p is tiny under rule r, or "". A first
// fragment that splits the transport header is reported as such, being
// the more specific reason, even when it is also under min_size.
func tinyReason(p *packet.ParsedPacket, r *Rule) string {
	if reason := firstFragmentReason(p); reason != "" {
		return reason
	}
	if p.MoreFragments && p.FragPayloadLen < uint32(r.minSize) {
		return fmt.Sprintf("non-final fragment carries %d bytes, less than min_size %d", p.FragPayloadLen, r.minSize)
	}
	return ""
}

// firstFragmentReason returns why first fragment p does not hold the
// whole transport header, or "".
func firstFragmentReason(p *packet.ParsedPacket) string {
	if p.FragOffset != 0 {
		return ""
	}
	if p.L4Offset >= 0 {
		have := int64(p.L3Offset) + int64(p.IPTotalLen) - int64(p.L4Offset)
		var need int64
		name := ""
		switch p.IPProto {
		case 6:
			need, name = 20, "TCP"
		case 17:
			need, name = 8, "UDP"
		}
		if have < need {
			return fmt.Sprintf("first fragment carries %d bytes of the %s header, need %d", max(have, 0), name, need)
		}
		return ""
	}
	// IPv6: Module 2 found no upper-layer header, so the header chain does
	// not fit in the first fragment (RFC 7112). ESP and No Next Header end
	// the chain without one; a capture cut short by the snap length proves
	// nothing.
	if p.IPVersion == 6 && p.IPProto != 50 && p.IPProto != 59 && p.CaptureLen >= p.WireLen {
		return "IPv6 first fragment does not contain the whole header chain and upper-layer header (RFC 7112)"
	}
	return ""
}

// oversizeEnd returns the fragment's end offset when it lies past the
// largest IP packet, or 0.
func oversizeEnd(p *packet.ParsedPacket) uint32 {
	if end := uint32(p.FragOffset) + p.FragPayloadLen; end > maxIPPacket {
		return end
	}
	return 0
}

// fragDetails describes one fragment for alert details.
func fragDetails(kind string, p *packet.ParsedPacket) map[string]string {
	return map[string]string{
		"detector":    DetectFragAttack,
		"kind":        kind,
		"ip_id":       strconv.FormatUint(uint64(p.IPID), 10),
		"frag_offset": strconv.Itoa(int(p.FragOffset)),
		"payload_len": strconv.FormatUint(uint64(p.FragPayloadLen), 10),
		"more_frags":  strconv.FormatBool(p.MoreFragments),
	}
}

func (r fragRange) String() string { return fmt.Sprintf("%d-%d", r.start, r.end) }
