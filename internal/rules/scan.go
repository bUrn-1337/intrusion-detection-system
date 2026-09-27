package rules

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Scan detection: detect:port_scan, detect:host_sweep and detect:ping_sweep.
//
// All three count probes, per source, in a distinctCounter. A probe is a
// packet that asks "is anything there?" and that normal clients do not
// send, or send only as part of a connection that then works:
//
//   - A TCP handshake that does not complete: the target reset it (closed
//     port), nobody answered within the handshake timeout (filtered port),
//     or the prober reset it after the SYN-ACK (half-open scan of an open
//     port; recorded as open). This covers SYN scans and connect scans.
//     The outcome comes from the handshake tracker, so it is counted when
//     the handshake ends, not when the SYN is sent. A completed handshake
//     is never a probe: browsing to many hosts must not look like a
//     sweep. Handshakes dropped at the tracker's cap ("evicted") have an
//     unknown outcome and are not counted either. A SYN that also has FIN
//     set is counted as kind synfin.
//   - A TCP packet with FIN only (fin), no flags (null) or FIN+PSH+URG
//     (xmas). Real stacks never send these outside a connection's FIN
//     exchange, which always carries ACK.
//   - An ICMP port unreachable (ICMPv4 type 3 code 3, ICMPv6 type 1 code
//     4) sent back to the host that sent the quoted UDP datagram (quoted
//     source == outer destination). It stands for the quoted datagram: a
//     udp probe from the quoted source to the quoted destination and port.
//     A UDP probe that gets no answer (open or filtered) is not seen.
//   - For ping_sweep only: an ICMP Echo Request (type 8, ICMPv6 128).
//
// Plain UDP datagrams are never probes: a client talking to many DNS or
// NTP servers is normal.
//
// Each probe is checked like a packet from the prober to the target: a
// whitelisted prober or a matching pass rule suppresses it, and a detector
// rule counts only probes that its protocol (tcp and udp select that kind
// of probe; ip takes both), addresses and ports match.

// Probe kinds, stored as bits of distinctVal.bits.
const (
	probeSYN uint8 = 1 << iota
	probeSYNFIN
	probeFIN
	probeNULL
	probeXmas
	probeUDP
	probeEcho
	probeOpen // the target answered with a SYN-ACK
)

var probeKinds = []struct {
	bit  uint8
	name string
}{
	{probeSYN, "syn"}, {probeFIN, "fin"}, {probeNULL, "null"}, {probeXmas, "xmas"},
	{probeSYNFIN, "synfin"}, {probeUDP, "udp"}, {probeEcho, "echo"},
}

// probe is one probe, seen as the packet from the prober to the target.
// v.g is gTCP, gUDP or gICMP.
type probe struct {
	v    view
	kind uint8
	t    time.Time
}

// packetProbe classifies one packet. TCP SYN probes are not classified
// here; they come from handshake outcomes (handshakeProbe).
func packetProbe(p *packet.ParsedPacket, v *view, now time.Time) (probe, bool) {
	switch v.g {
	case gTCP:
		var kind uint8
		switch v.flags & (tcpFIN | tcpSYN | tcpRST | tcpPSH | tcpACK | tcpURG) {
		case 0:
			kind = probeNULL
		case tcpFIN:
			kind = probeFIN
		case tcpFIN | tcpPSH | tcpURG:
			kind = probeXmas
		default:
			return probe{}, false
		}
		return probe{v: *v, kind: kind, t: now}, true
	case gICMP:
		v4 := p.IPVersion == 4
		switch {
		case v4 && p.ICMPType == 8, !v4 && p.ICMPType == 128:
			return probe{v: *v, kind: probeEcho, t: now}, true
		case v4 && p.ICMPType == 3 && p.ICMPCode == 3, !v4 && p.ICMPType == 1 && p.ICMPCode == 4:
			if p.ICMPInnerSrc == nil || p.ICMPInnerProto != 17 || !p.ICMPInnerHasPorts {
				return probe{}, false
			}
			src := toAddr(p.ICMPInnerSrc)
			if src != v.dst {
				return probe{}, false // not sent back to the prober
			}
			pv := view{g: gUDP, src: src, dst: toAddr(p.ICMPInnerDst), sport: p.ICMPInnerSrcPort, dport: p.ICMPInnerDstPort, havePayload: true, haveLower: true}
			return probe{v: pv, kind: probeUDP, t: now}, true
		}
	}
	return probe{}, false
}

// handshakeProbe turns an incomplete handshake into a probe. syn is the
// handshake's opening SYN view.
func handshakeProbe(ev hsEvent, syn *view) (probe, bool) {
	if ev.complete || ev.reason == "evicted" {
		return probe{}, false
	}
	kind := probeSYN
	if ev.synFin {
		kind = probeSYNFIN
	}
	if ev.answered {
		kind |= probeOpen
	}
	return probe{v: *syn, kind: kind, t: ev.t}, true
}

// scanKey is what a scan detector counts per: the source, plus the port
// and transport for host_sweep.
type scanKey struct {
	src  netip.Addr
	port uint16
	udp  bool
}

// scanTarget is one distinct value: the port and transport for
// port_scan, the host for host_sweep and ping_sweep.
type scanTarget struct {
	host netip.Addr
	port uint16
	udp  bool
}

// scanDetector is the detect:port_scan, host_sweep or ping_sweep detector
// for one rule. It fires when a key has at least rule.distinct distinct
// targets, each last seen within seconds.
//
//   - port_scan: key source, target (port, tcp|udp), over all target
//     hosts. A sweep of one port across many hosts is host_sweep's, not a
//     port scan.
//   - host_sweep: key (source, port, tcp|udp), target host.
//   - ping_sweep: key source, target host; Echo Requests only.
type scanDetector struct {
	rule *Rule
	seen *distinctCounter[scanKey, scanTarget]
	// hosts holds, for port_scan only, up to maxListed+1 recent target
	// hosts per source for the alert's target_hosts. It has the same keys
	// as seen, so its table statistics are not reported.
	hosts     *distinctCounter[scanKey, netip.Addr]
	hostsStat tableStat
}

func newScanDetector(r *Rule, max int, stat *tableStat) *scanDetector {
	d := &scanDetector{rule: r, seen: newDistinctCounter[scanKey, scanTarget](r.distinct, r.detect.span(), max, stat)}
	if r.Detect == DetectPortScan {
		d.hosts = newDistinctCounter[scanKey, netip.Addr](maxListed, r.detect.span(), max, &d.hostsStat)
	}
	return d
}

// accepts reports whether pr is the kind of probe the rule counts.
func (d *scanDetector) accepts(pr *probe) bool {
	if (d.rule.Detect == DetectPingSweep) != (pr.kind&probeEcho != 0) {
		return false
	}
	switch d.rule.Proto {
	case ProtoTCP:
		return pr.v.g == gTCP
	case ProtoUDP:
		return pr.v.g == gUDP
	case ProtoICMP:
		return pr.v.g == gICMP
	}
	return true
}

// observe counts pr and, when the detector fires, returns the dedup key
// and a function that builds the alert details. The caller has checked
// accepts and the rule's addresses.
func (d *scanDetector) observe(pr *probe) (dedupKey, func() map[string]string, bool) {
	udp := pr.v.g == gUDP
	key := scanKey{src: pr.v.src}
	target := scanTarget{host: pr.v.dst}
	var hosts *distinctEntry[scanKey, netip.Addr]
	switch d.rule.Detect {
	case DetectPortScan:
		target = scanTarget{port: pr.v.dport, udp: udp}
		hosts = d.hosts.add(key, pr.v.dst, pr.t, 0)
	case DetectHostSweep:
		key.port, key.udp = pr.v.dport, udp
	}
	ent := d.seen.add(key, target, pr.t, pr.kind)
	if ent.size() < d.rule.distinct {
		return dedupKey{}, nil, false
	}
	dk := dedupKey{sid: d.rule.SID, addr: key.src}
	if d.rule.Detect == DetectHostSweep {
		// One alert per swept port, not one per source.
		dk.port, dk.hasPort = key.port, true
	}
	// Called synchronously by the engine, before ent or hosts can change.
	details := func() map[string]string {
		m := map[string]string{
			"detector":     d.rule.Detect,
			"track":        TrackBySrc.String(),
			"tracked_addr": key.src.String(),
			"seconds":      strconv.Itoa(d.rule.detect.seconds),
			"window":       ent.newest.Sub(ent.oldest()).Round(time.Millisecond).String(),
		}
		n := strconv.Itoa(ent.size())
		switch d.rule.Detect {
		case DetectPortScan:
			m["distinct_ports"] = n
			m["scan_types"] = scanTypes(ent.vals)
			var hs []netip.Addr
			for _, x := range hosts.vals {
				hs = append(hs, x.v)
			}
			m["target_hosts"] = joinAddrs(hs, maxListed)
			var ports, open []int
			for _, x := range ent.vals {
				ports = append(ports, int(x.v.port))
				if x.bits&probeOpen != 0 {
					open = append(open, int(x.v.port))
				}
			}
			m["ports"] = joinInts(ports, maxListed)
			m["open_ports"] = joinInts(open, maxListed)
		case DetectHostSweep:
			m["dst_port"] = strconv.Itoa(int(key.port))
			m["proto"] = "tcp"
			if key.udp {
				m["proto"] = "udp"
			}
			m["distinct_hosts"] = n
			m["scan_types"] = scanTypes(ent.vals)
			m["hosts"] = joinHosts(ent.vals, maxListed)
		case DetectPingSweep:
			m["distinct_hosts"] = n
			m["hosts"] = joinHosts(ent.vals, maxListed)
		}
		return m
	}
	return dk, details, true
}

func (d *scanDetector) clear() {
	d.seen.clear()
	if d.hosts != nil {
		d.hosts.clear()
	}
}

// maxListed caps the ports and hosts listed in alert details.
const maxListed = 20

// scanTypes returns "syn:18,udp:3": how many of the stored targets were
// probed with each kind, in a fixed order.
func scanTypes(vals []distinctVal[scanTarget]) string {
	var parts []string
	for _, k := range probeKinds {
		n := 0
		for _, x := range vals {
			if x.bits&k.bit != 0 {
				n++
			}
		}
		if n > 0 {
			parts = append(parts, k.name+":"+strconv.Itoa(n))
		}
	}
	return strings.Join(parts, ",")
}

// joinHosts returns up to limit distinct target hosts, sorted.
func joinHosts(vals []distinctVal[scanTarget], limit int) string {
	var hosts []netip.Addr
	for _, x := range vals {
		hosts = append(hosts, x.v.host)
	}
	return joinAddrs(hosts, limit)
}

// joinAddrs returns up to limit distinct addresses, sorted.
func joinAddrs(hosts []netip.Addr, limit int) string {
	slices.SortFunc(hosts, netip.Addr.Compare)
	hosts = slices.Compact(hosts)
	var b strings.Builder
	for i, h := range hosts[:min(len(hosts), limit)] {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(h.String())
	}
	return b.String()
}

// joinInts returns up to limit distinct values, sorted.
func joinInts(v []int, limit int) string {
	slices.Sort(v)
	v = slices.Compact(v)
	parts := make([]string, 0, min(len(v), limit))
	for _, n := range v[:min(len(v), limit)] {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, ",")
}
