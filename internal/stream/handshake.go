package stream

import (
	"hash/maphash"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// The handshake table has hsSets sets of hsWays entries: 65536 entries,
// about 4 MB, allocated once and without pointers, so a SYN flood of
// spoofed sources costs neither allocations nor GC work. A new
// connection takes a free or stale way of its set, or the one with the
// oldest SYN.
const (
	hsWays = 4
	hsSets = 1 << 14
)

// pending is a connection whose SYN or SYN-ACK was seen but which has
// not carried data yet, so it has no flow. When its first data segment
// opens the flow, the flow takes the client and initial sequence numbers
// from here and starts in sync, as if it had been opened by the SYN.
type pending struct {
	key       flowKey
	used      bool
	clientIsA bool
	saw       [2]bool   // SYN from the client (toServer), SYN-ACK (toClient)
	isn       [2]uint32 // by direction
	t         int64     // engine time of the first SYN or SYN-ACK, UnixNano
}

type handshakes struct {
	sets [][hsWays]pending
	seed maphash.Seed
	ttl  int64 // entries older than this are ignored
}

func newHandshakes(ttl time.Duration) handshakes {
	return handshakes{sets: make([][hsWays]pending, hsSets), seed: maphash.MakeSeed(), ttl: int64(ttl)}
}

func (t *handshakes) set(k flowKey) *[hsWays]pending {
	return &t.sets[maphash.Comparable(t.seed, k)%hsSets]
}

// get returns the live entry for k, or nil.
func (t *handshakes) get(k flowKey, now int64) *pending {
	s := t.set(k)
	for i := range s {
		if e := &s[i]; e.used && e.key == k {
			if now-e.t > t.ttl {
				e.used = false
				return nil
			}
			return e
		}
	}
	return nil
}

// slot returns a cleared entry for a key that has none: a free or stale
// way of its set, or else the one with the oldest SYN.
func (t *handshakes) slot(k flowKey, now int64) *pending {
	s := t.set(k)
	victim := &s[0]
	for i := range s {
		e := &s[i]
		if !e.used || now-e.t > t.ttl {
			victim = e
			break
		}
		if e.t < victim.t {
			victim = e
		}
	}
	*victim = pending{}
	return victim
}

func (t *handshakes) drop(k flowKey, now int64) {
	if e := t.get(k, now); e != nil {
		e.used = false
	}
}

// handshake records a SYN or SYN-ACK without payload on a connection
// that has no flow. fromA says which endpoint sent it.
func (r *Reassembler) handshake(key flowKey, fromA bool, p *packet.ParsedPacket) {
	now := r.now.UnixNano()
	e := r.hs.get(key, now)
	if p.TCPFlags.ACK { // SYN-ACK: the sender is the server
		if e == nil || e.clientIsA == fromA {
			if r.ports[p.SrcPort] == None {
				return
			}
			if e == nil {
				e = r.hs.slot(key, now)
			}
			*e = pending{key: key, used: true, clientIsA: !fromA, t: now}
		}
		e.saw[toClient], e.isn[toClient] = true, p.TCPSeq
		return
	}
	if r.ports[p.DstPort] == None {
		return
	}
	if e != nil && e.clientIsA == fromA && e.saw[toServer] && e.isn[toServer] == p.TCPSeq {
		return // a retransmitted SYN
	}
	// A SYN with a new ISN is a new connection on the same 4-tuple.
	if e == nil {
		e = r.hs.slot(key, now)
	}
	*e = pending{key: key, used: true, clientIsA: fromA, t: now}
	e.saw[toServer], e.isn[toServer] = true, p.TCPSeq
}
