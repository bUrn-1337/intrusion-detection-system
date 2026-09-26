package rules

import (
	"container/list"
	"net/netip"
	"time"
)

// handshakeTracker follows TCP three-way handshakes and reports how each
// one ended: completed, or incomplete (reset, timed out, abandoned or
// evicted). It is detector-neutral: the SYN flood detector counts its
// outcomes, and the port-scan detector will reuse it.
//
// A pending handshake is keyed by (client ip, client port, server ip,
// server port), where the client is the sender of the SYN.
//
//   - SYN without ACK creates the entry. A retransmitted SYN (same key, same
//     sequence number) is ignored. A SYN with a different sequence number
//     on the same key abandons the old attempt (incomplete) and starts a
//     new one.
//   - SYN-ACK from the server with ack == client seq + 1 marks the entry
//     answered. Any other ack number is ignored.
//   - The client's ACK (no SYN, no RST) with ack == server seq + 1, after
//     the entry was answered, completes it and removes it.
//   - RST from either side removes the entry as incomplete. The spec only
//     names the server's RST; a client RST is what a half-open (SYN) scan
//     sends after the SYN-ACK, so it is counted the same way.
//   - An entry not completed within timeout of its first SYN is incomplete;
//     the outcome is timed at the deadline.
//
// The table holds at most max entries. Entries are kept in creation order,
// so expiry pops from the front; at the cap the oldest pending entry
// (which is also the least recently seen in practice, since handshakes are
// short) is evicted and reported as incomplete.
//
// Checksum status is deliberately ignored: offloading and receive merging
// produce Invalid checksums on legitimate traffic.
type handshakeTracker struct {
	timeout time.Duration
	max     int
	m       map[hsKey]*list.Element // Value is *hsEntry
	order   list.List               // creation order, oldest first
	stat    *tableStat
}

type hsKey struct {
	client, server netip.Addr
	cport, sport   uint16
}

type hsEntry struct {
	key       hsKey
	synAt     time.Time
	seq       uint32 // client ISN
	answered  bool
	serverSeq uint32 // server ISN, valid when answered
}

// hsEvent is the outcome of one handshake.
type hsEvent struct {
	key      hsKey
	t        time.Time
	complete bool
	reason   string // for incomplete: "rst", "timeout", "reused", "evicted"
}

// tcpSegment is what the tracker needs from a TCP packet.
type tcpSegment struct {
	src, dst     netip.Addr
	sport, dport uint16
	flags        uint8
	seq, ack     uint32
}

func newHandshakeTracker(timeout time.Duration, max int, stat *tableStat) *handshakeTracker {
	return &handshakeTracker{timeout: timeout, max: max, m: make(map[hsKey]*list.Element), stat: stat}
}

// expire reports every pending handshake whose deadline is at or before
// now as incomplete, oldest first.
func (h *handshakeTracker) expire(now time.Time, out []hsEvent) []hsEvent {
	for el := h.order.Front(); el != nil; el = h.order.Front() {
		e := el.Value.(*hsEntry)
		deadline := e.synAt.Add(h.timeout)
		if now.Before(deadline) {
			break
		}
		h.remove(el)
		out = append(out, hsEvent{key: e.key, t: deadline, reason: "timeout"})
	}
	return out
}

// expireAll times out every pending handshake, as at the end of input.
func (h *handshakeTracker) expireAll(out []hsEvent) []hsEvent {
	for el := h.order.Front(); el != nil; el = h.order.Front() {
		e := el.Value.(*hsEntry)
		h.remove(el)
		out = append(out, hsEvent{key: e.key, t: e.synAt.Add(h.timeout), reason: "timeout"})
	}
	return out
}

// observe updates the table with one TCP segment seen at now and appends
// any outcomes. Call expire(now) first so outcomes stay in time order.
func (h *handshakeTracker) observe(s *tcpSegment, now time.Time, out []hsEvent) []hsEvent {
	fromClient := hsKey{client: s.src, cport: s.sport, server: s.dst, sport: s.dport}
	fromServer := hsKey{client: s.dst, cport: s.dport, server: s.src, sport: s.sport}
	syn, ack, rst := s.flags&tcpSYN != 0, s.flags&tcpACK != 0, s.flags&tcpRST != 0

	switch {
	case rst:
		for _, k := range []hsKey{fromServer, fromClient} {
			if el, ok := h.m[k]; ok {
				h.remove(el)
				return append(out, hsEvent{key: k, t: now, reason: "rst"})
			}
		}
	case syn && !ack:
		if el, ok := h.m[fromClient]; ok {
			e := el.Value.(*hsEntry)
			if e.seq == s.seq {
				return out // retransmission
			}
			h.remove(el)
			out = append(out, hsEvent{key: fromClient, t: now, reason: "reused"})
		}
		if len(h.m) >= h.max {
			old := h.order.Front()
			h.remove(old)
			h.stat.evictions.Add(1)
			out = append(out, hsEvent{key: old.Value.(*hsEntry).key, t: now, reason: "evicted"})
		}
		h.m[fromClient] = h.order.PushBack(&hsEntry{key: fromClient, synAt: now, seq: s.seq})
		h.stat.keys.Add(1)
	case syn && ack:
		if el, ok := h.m[fromServer]; ok {
			e := el.Value.(*hsEntry)
			if s.ack == e.seq+1 {
				e.answered, e.serverSeq = true, s.seq
			}
		}
	case ack:
		if el, ok := h.m[fromClient]; ok {
			e := el.Value.(*hsEntry)
			if e.answered && s.ack == e.serverSeq+1 {
				h.remove(el)
				out = append(out, hsEvent{key: fromClient, t: now, complete: true})
			}
		}
	}
	return out
}

func (h *handshakeTracker) remove(el *list.Element) {
	delete(h.m, h.order.Remove(el).(*hsEntry).key)
	h.stat.keys.Add(-1)
}

func (h *handshakeTracker) clear() {
	h.stat.keys.Add(-int64(len(h.m)))
	clear(h.m)
	h.order.Init()
}

func (h *handshakeTracker) len() int { return len(h.m) }
