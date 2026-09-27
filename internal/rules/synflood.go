package rules

import (
	"math"
	"net/netip"
	"strconv"
	"time"
)

// synFlood is the detect:syn_flood detector for one rule. It counts the
// handshake tracker's outcomes per tracked address (the client for
// by_src, the server for by_dst).
//
// It fires when the last count incomplete handshakes of a key fall within
// seconds, and incomplete / (incomplete + completed) over that same span
// is at least minRatio. Completions are kept in a second window counter
// that stores only as many as can matter: with count incompletes, the
// ratio holds iff completed <= count*(1-r)/r, so keeping one more than that
// is enough to decide. Both counters are bounded like every other table.
//
// by_dst is the one that catches spoofed floods: every SYN has a
// different fake source, so no single source ever reaches count.
type synFlood struct {
	rule *Rule
	inc  *windowCounter[netip.Addr]
	comp *windowCounter[netip.Addr] // nil when minRatio is 0
}

func newSYNFlood(r *Rule, max int, stat *tableStat) *synFlood {
	d := &synFlood{rule: r, inc: newWindowCounter[netip.Addr](r.detect.count, r.detect.span(), max, stat)}
	if r.minRatio > 0 {
		keep := float64(r.detect.count)*(1-r.minRatio)/r.minRatio + 2
		d.comp = newWindowCounter[netip.Addr](int(math.Min(keep, maxCount)), r.detect.span(), max, stat)
	}
	return d
}

// observe counts one outcome and, when the detector fires, returns the
// tracked address and a function that builds the alert details.
func (d *synFlood) observe(ev hsEvent) (netip.Addr, func() map[string]string, bool) {
	key := ev.key.client
	if d.rule.detect.track == TrackByDst {
		key = ev.key.server
	}
	if ev.complete {
		if d.comp != nil {
			d.comp.add(key, ev.t, 0)
		}
		return key, nil, false
	}
	ent, full := d.inc.add(key, ev.t, ev.key.sport)
	if !full {
		return key, nil, false
	}
	n := ent.size()
	oldest := ent.oldest()
	completed := 0
	if d.comp != nil {
		completed = d.comp.countSince(key, oldest)
	}
	ratio := float64(n) / float64(n+completed)
	if ratio < d.rule.minRatio {
		return key, nil, false
	}
	span := ent.newest().Sub(oldest)
	// Called synchronously by the engine, before ent can change.
	details := func() map[string]string {
		return map[string]string{
			"detector":     DetectSYNFlood,
			"track":        d.rule.detect.track.String(),
			"tracked_addr": key.String(),
			"incomplete":   strconv.Itoa(n),
			"completed":    strconv.Itoa(completed),
			"ratio":        strconv.FormatFloat(ratio, 'f', 2, 64),
			"top_dst_port": strconv.Itoa(int(ent.topTag())),
			"window":       span.Round(time.Millisecond).String(),
		}
	}
	return key, details, true
}

func (d *synFlood) clear() {
	d.inc.clear()
	if d.comp != nil {
		d.comp.clear()
	}
}
