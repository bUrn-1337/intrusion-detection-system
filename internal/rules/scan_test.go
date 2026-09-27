package rules

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Scan detector tests. Packets go through the real parsers and a real
// engine (Process, then Flush), in time order.

const (
	scanner = "203.0.113.50"
	target  = "192.0.2.10"
)

// tpkt is one packet at one time.
type tpkt struct {
	ts time.Time
	p  pkt
}

// runPackets feeds pkts to a new engine using rules and returns every
// alert, including those from Flush.
func runPackets(t *testing.T, rules string, cfg EngineConfig, pkts []tpkt) ([]Alert, *Engine) {
	t.Helper()
	e := NewEngine(mustParse(t, rules), cfg)
	var out []Alert
	for _, tp := range pkts {
		out = append(out, e.Process(tp.p.parsed(t, tp.ts))...)
	}
	return append(out, e.Flush()...), e
}

// probeKind builds the packets of one probe from src to dst:port at ts.
//
//	refused  SYN answered by RST/ACK (closed port)
//	silent   SYN, no answer (filtered; times out)
//	halfopen SYN, SYN-ACK, RST from the prober (open port, SYN scan)
//	complete SYN, SYN-ACK, ACK (a real connection)
//	synfin   SYN+FIN answered by RST/ACK
//	fin, null, xmas   one packet with those flags
//	udp      UDP datagram answered by ICMP port unreachable
//	echo     ICMP Echo Request (port ignored)
func probeKind(tb testing.TB, kind, src, dst string, port uint16, ts time.Time) []tpkt {
	tb.Helper()
	sport := 40000 + port
	c2s := pkt{proto: "tcp", src: src, dst: dst, sport: sport, dport: port, seq: 1000}
	s2c := pkt{proto: "tcp", src: dst, dst: src, sport: port, dport: sport}
	with := func(p pkt, flags string, seq, ack uint32) pkt {
		p.flags, p.seq, p.ack = flags, seq, ack
		return p
	}
	ms := time.Millisecond
	switch kind {
	case "refused":
		return []tpkt{{ts, with(c2s, "S", 1000, 0)}, {ts.Add(ms), with(s2c, "RA", 0, 1001)}}
	case "silent":
		return []tpkt{{ts, with(c2s, "S", 1000, 0)}}
	case "halfopen":
		return []tpkt{{ts, with(c2s, "S", 1000, 0)}, {ts.Add(ms), with(s2c, "SA", 5000, 1001)}, {ts.Add(2 * ms), with(c2s, "R", 1001, 0)}}
	case "complete":
		return []tpkt{{ts, with(c2s, "S", 1000, 0)}, {ts.Add(ms), with(s2c, "SA", 5000, 1001)}, {ts.Add(2 * ms), with(c2s, "A", 1001, 5001)}}
	case "synfin":
		return []tpkt{{ts, with(c2s, "SF", 1000, 0)}, {ts.Add(ms), with(s2c, "RA", 0, 1001)}}
	case "fin":
		return []tpkt{{ts, with(c2s, "F", 1000, 0)}}
	case "null":
		return []tpkt{{ts, with(c2s, "", 1000, 0)}}
	case "xmas":
		return []tpkt{{ts, with(c2s, "FPU", 1000, 0)}}
	case "udp":
		u := pkt{proto: "udp", src: src, dst: dst, sport: sport, dport: port, payload: "x"}
		return []tpkt{{ts, u}, {ts.Add(ms), pkt{proto: "icmp", src: dst, dst: src, unreach: &u}}}
	case "echo":
		return []tpkt{{ts, pkt{proto: "icmp", src: src, dst: dst}}}
	}
	tb.Fatalf("bad probe kind %q", kind)
	return nil
}

// portProbes probes ports 1..n on dst, one every step from ts.
func portProbes(tb testing.TB, kind, src, dst string, n int, ts time.Time, step time.Duration) []tpkt {
	var out []tpkt
	for i := range n {
		out = append(out, probeKind(tb, kind, src, dst, uint16(1+i), ts.Add(time.Duration(i)*step))...)
	}
	return out
}

// hostProbes probes port on hosts 192.0.2.1..n, one every step from ts.
func hostProbes(tb testing.TB, kind, src string, port uint16, n int, ts time.Time, step time.Duration) []tpkt {
	var out []tpkt
	for i := range n {
		out = append(out, probeKind(tb, kind, src, fmt.Sprintf("192.0.2.%d", 1+i), port, ts.Add(time.Duration(i)*step))...)
	}
	return out
}

func sortByTime(ps []tpkt) []tpkt {
	for i := 1; i < len(ps); i++ { // insertion sort: stable, inputs are nearly sorted
		for j := i; j > 0 && ps[j].ts.Before(ps[j-1].ts); j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
	return ps
}

const portScanRule = `alert ip any any -> any any (msg:"port scan"; detect:port_scan; distinct_ports:10; seconds:10; sid:41; severity:medium; category:recon;)`

func alertsOf(as []Alert, sid int) []Alert {
	var out []Alert
	for _, a := range as {
		if a.SID == sid && a.Kind == KindAlert {
			out = append(out, a)
		}
	}
	return out
}

func TestPortScanProbeKinds(t *testing.T) {
	for _, kind := range []string{"refused", "silent", "halfopen", "synfin", "fin", "null", "xmas", "udp"} {
		name := map[string]string{"refused": "syn", "silent": "syn", "halfopen": "syn"}[kind]
		if name == "" {
			name = kind
		}
		t.Run(kind, func(t *testing.T) {
			got, _ := runPackets(t, portScanRule, EngineConfig{}, portProbes(t, kind, scanner, target, 9, t0, 100*time.Millisecond))
			if len(got) != 0 {
				t.Fatalf("9 probes (n-1) alerted:%s", alertLines(got))
			}
			got, _ = runPackets(t, portScanRule, EngineConfig{}, portProbes(t, kind, scanner, target, 10, t0, 100*time.Millisecond))
			as := alertsOf(got, 41)
			if len(got) != 1 || len(as) != 1 {
				t.Fatalf("10 probes: want one alert, got:%s", alertLines(got))
			}
			d := as[0].Details
			want := map[string]string{
				"detector": "port_scan", "track": "by_src", "tracked_addr": scanner,
				"distinct_ports": "10", "scan_types": name + ":10", "target_hosts": target,
				"ports": "1,2,3,4,5,6,7,8,9,10", "seconds": "10",
			}
			for k, v := range want {
				if d[k] != v {
					t.Errorf("details[%s] = %q, want %q (all: %v)", k, d[k], v, d)
				}
			}
			wantOpen := ""
			if kind == "halfopen" {
				wantOpen = "1,2,3,4,5,6,7,8,9,10"
			}
			if d["open_ports"] != wantOpen {
				t.Errorf("open_ports = %q, want %q", d["open_ports"], wantOpen)
			}
			if as[0].SrcIP != scanner || as[0].DstIP != target {
				t.Errorf("alert %s -> %s", as[0].SrcIP, as[0].DstIP)
			}
		})
	}
}

// TestPortScanNotProbes lists traffic to many ports that is not probing.
func TestPortScanNotProbes(t *testing.T) {
	ms := time.Millisecond
	tests := []struct {
		name string
		pkts []tpkt
	}{
		{"completed handshakes", portProbes(t, "complete", scanner, target, 30, t0, 10*ms)},
		{"plain udp without icmp", func() []tpkt {
			var out []tpkt
			for i := range 30 {
				out = append(out, tpkt{at(time.Duration(i) * ms), pkt{proto: "udp", src: scanner, dst: target, sport: 5000, dport: uint16(1 + i)}})
			}
			return out
		}()},
		// Packets from connections that started before the IDS did.
		{"mid-connection FIN/ACK, ACK, PSH/ACK, RST", func() []tpkt {
			var out []tpkt
			for i := range 30 {
				for _, f := range []string{"FA", "A", "PA", "R", "RA"} {
					out = append(out, tpkt{at(time.Duration(i) * ms), pkt{proto: "tcp", src: scanner, dst: target, sport: 5000, dport: uint16(1 + i), flags: f, seq: 7, ack: 9}})
				}
			}
			return out
		}()},
		// A port unreachable that goes to someone other than the host that
		// sent the quoted datagram (quoted source 10.9.9.9) is not a probe
		// by either.
		{"icmp not sent back to the prober", func() []tpkt {
			var out []tpkt
			for i := range 30 {
				u := pkt{proto: "udp", src: "10.9.9.9", dst: target, sport: 5000, dport: uint16(1 + i)}
				out = append(out, tpkt{at(time.Duration(i) * ms), pkt{proto: "icmp", src: target, dst: scanner, unreach: &u}})
			}
			return out
		}()},
		// A port unreachable quoting a TCP segment is not a UDP probe.
		{"icmp port unreachable quoting tcp", func() []tpkt {
			var out []tpkt
			for i := range 30 {
				q := pkt{proto: "tcp", src: scanner, dst: target, sport: 5000, dport: uint16(1 + i), flags: "S"}
				out = append(out, tpkt{at(time.Duration(i) * ms), pkt{proto: "icmp", src: target, dst: scanner, unreach: &q}})
			}
			return out
		}()},
		{"9 refused + 1 completed", append(portProbes(t, "refused", scanner, target, 9, t0, 10*ms), probeKind(t, "complete", scanner, target, 500, at(time.Second))...)},
		{"echo requests", portProbes(t, "echo", scanner, target, 30, t0, 10*ms)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := runPackets(t, portScanRule, EngineConfig{}, tt.pkts); len(got) != 0 {
				t.Errorf("alerted:%s", alertLines(got))
			}
		})
	}
}

func TestPortScanMixedKinds(t *testing.T) {
	var ps []tpkt
	kinds := []string{"refused", "fin", "udp", "xmas", "null"}
	for i := range 10 {
		ps = append(ps, probeKind(t, kinds[i%len(kinds)], scanner, target, uint16(100+i), at(time.Duration(i)*50*time.Millisecond))...)
	}
	got, _ := runPackets(t, portScanRule, EngineConfig{}, sortByTime(ps))
	as := alertsOf(got, 41)
	if len(as) != 1 {
		t.Fatalf("want one alert:%s", alertLines(got))
	}
	if got, want := as[0].Details["scan_types"], "syn:2,fin:2,null:2,xmas:2,udp:2"; got != want {
		t.Errorf("scan_types = %q, want %q", got, want)
	}
}

// TestPortScanCountsPorts checks that the distinct value is the port,
// over all target hosts: many probes of one port, or one port on many
// hosts, are not a port scan; 5 ports on each of 2 hosts are 5 ports; 10
// ports spread over 2 hosts are.
func TestPortScanCountsPorts(t *testing.T) {
	ms := time.Millisecond
	repeated := func() []tpkt {
		var out []tpkt
		for i := range 30 {
			out = append(out, probeKind(t, "fin", scanner, target, 80, at(time.Duration(i)*ms))...)
		}
		return out
	}()
	if got, _ := runPackets(t, portScanRule, EngineConfig{}, repeated); len(got) != 0 {
		t.Errorf("30 probes of one port alerted:%s", alertLines(got))
	}
	if got, _ := runPackets(t, portScanRule, EngineConfig{}, hostProbes(t, "fin", scanner, 22, 30, t0, ms)); len(got) != 0 {
		t.Errorf("one port on 30 hosts alerted:%s", alertLines(got))
	}
	same := append(portProbes(t, "fin", scanner, "192.0.2.1", 5, t0, ms), portProbes(t, "fin", scanner, "192.0.2.2", 5, at(10*ms), ms)...)
	if got, _ := runPackets(t, portScanRule, EngineConfig{}, same); len(got) != 0 {
		t.Errorf("ports 1-5 on 2 hosts alerted:%s", alertLines(got))
	}
	var spread []tpkt
	for i := range 10 {
		spread = append(spread, probeKind(t, "fin", scanner, fmt.Sprintf("192.0.2.%d", 1+i%2), uint16(1+i), at(time.Duration(i)*ms))...)
	}
	got, _ := runPackets(t, portScanRule, EngineConfig{}, spread)
	as := alertsOf(got, 41)
	if len(as) != 1 || as[0].Details["target_hosts"] != "192.0.2.1,192.0.2.2" || as[0].Details["ports"] != "1,2,3,4,5,6,7,8,9,10" {
		t.Errorf("10 ports over 2 hosts:%s", alertLines(got))
	}
	// tcp and udp probes of the same port number are different ports.
	mixed := append(portProbes(t, "fin", scanner, target, 5, t0, ms), portProbes(t, "udp", scanner, target, 5, at(10*ms), ms)...)
	if got, _ := runPackets(t, portScanRule, EngineConfig{}, mixed); len(alertsOf(got, 41)) != 1 {
		t.Errorf("5 tcp + 5 udp:%s", alertLines(got))
	}
}

func TestPortScanWindow(t *testing.T) {
	sec := time.Second
	tests := []struct {
		name  string
		times []time.Duration
		fire  bool
	}{
		{"10 probes exactly 10s apart", []time.Duration{0, 1 * sec, 2 * sec, 3 * sec, 4 * sec, 5 * sec, 6 * sec, 7 * sec, 8 * sec, 10 * sec}, true},
		{"10 probes 10s + 1ms apart", []time.Duration{0, 1 * sec, 2 * sec, 3 * sec, 4 * sec, 5 * sec, 6 * sec, 7 * sec, 8 * sec, 10*sec + time.Millisecond}, false},
		{"slow scan, one per 2s", []time.Duration{0, 2 * sec, 4 * sec, 6 * sec, 8 * sec, 10 * sec, 12 * sec, 14 * sec, 16 * sec, 18 * sec, 20 * sec, 22 * sec}, false},
		// Timestamps that go backwards are recorded at the newest time, so
		// the late-stamped probe still counts as recent.
		{"backwards timestamps", []time.Duration{100 * sec, 101 * sec, 102 * sec, 103 * sec, 104 * sec, 105 * sec, 106 * sec, 107 * sec, 108 * sec, 0}, true},
		// Backwards stamps never make an old probe look fresh: the probe at
		// 0 expires when the clock reaches 30s, and the 8 stamped 1..8s
		// after that count at 30s, leaving 9 targets.
		{"backwards cannot revive", []time.Duration{0, 30 * sec, 1 * sec, 2 * sec, 3 * sec, 4 * sec, 5 * sec, 6 * sec, 7 * sec, 8 * sec}, false},
		{"backwards, one more", []time.Duration{0, 30 * sec, 1 * sec, 2 * sec, 3 * sec, 4 * sec, 5 * sec, 6 * sec, 7 * sec, 8 * sec, 9 * sec}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ps []tpkt
			for i, d := range tt.times {
				ps = append(ps, probeKind(t, "fin", scanner, target, uint16(1+i), at(d))...)
			}
			got, _ := runPackets(t, portScanRule, EngineConfig{}, ps)
			if fired := len(alertsOf(got, 41)) > 0; fired != tt.fire {
				t.Errorf("fired = %v, want %v:%s", fired, tt.fire, alertLines(got))
			}
		})
	}
}

func TestPortScanEviction(t *testing.T) {
	ms := time.Millisecond
	var ps []tpkt
	// Three scanners interleaved; the table holds two, so each new one
	// evicts the least recently seen and nobody reaches 10.
	for i := range 10 {
		for j, src := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
			ps = append(ps, probeKind(t, "fin", src, target, uint16(1+i), at(time.Duration(i*3+j)*ms))...)
		}
	}
	got, e := runPackets(t, portScanRule, EngineConfig{MaxKeys: 2}, ps)
	if len(got) != 0 {
		t.Errorf("alerted despite eviction:%s", alertLines(got))
	}
	st := e.Stats().Tables[TablePortScan]
	if st.Evictions == 0 || st.Keys > 2 {
		t.Errorf("port_scan table: %+v", st)
	}
	// With room for all three, each fires.
	got, e = runPackets(t, portScanRule, EngineConfig{MaxKeys: 3}, ps)
	if n := len(alertsOf(got, 41)); n != 3 {
		t.Errorf("MaxKeys 3: %d alerts:%s", n, alertLines(got))
	}
	if st := e.Stats().Tables[TablePortScan]; st.Evictions != 0 || st.Keys != 3 {
		t.Errorf("port_scan table: %+v", st)
	}
}

func TestPortScanRuleScope(t *testing.T) {
	ms := time.Millisecond
	tcpProbes := portProbes(t, "refused", scanner, target, 10, t0, ms)
	udpProbes := portProbes(t, "udp", scanner, target, 10, t0, ms)
	tests := []struct {
		name  string
		rules string
		cfg   EngineConfig
		pkts  []tpkt
		fire  bool
	}{
		{"tcp rule, tcp probes", strings.Replace(portScanRule, "alert ip", "alert tcp", 1), EngineConfig{}, tcpProbes, true},
		{"tcp rule, udp probes", strings.Replace(portScanRule, "alert ip", "alert tcp", 1), EngineConfig{}, udpProbes, false},
		{"udp rule, udp probes", strings.Replace(portScanRule, "alert ip", "alert udp", 1), EngineConfig{}, udpProbes, true},
		{"udp rule, tcp probes", strings.Replace(portScanRule, "alert ip", "alert udp", 1), EngineConfig{}, tcpProbes, false},
		{"destination outside the rule", strings.Replace(portScanRule, "-> any any", "-> 10.0.0.0/8 any", 1), EngineConfig{}, tcpProbes, false},
		{"whitelisted scanner", portScanRule, EngineConfig{Whitelist: mustPrefixes(scanner + "/32")}, append(tcpProbes, udpProbes...), false},
		{"whitelisted scanner, fin", portScanRule, EngineConfig{Whitelist: mustPrefixes(scanner + "/32")}, portProbes(t, "fin", scanner, target, 10, t0, ms), false},
		// The ICMP comes from the target; whitelisting it must not hide the
		// scanner's UDP probes.
		{"whitelisted target, udp", portScanRule, EngineConfig{Whitelist: mustPrefixes(target + "/32")}, udpProbes, true},
		{"pass rule for the scanner", portScanRule + "\npass ip " + scanner + " any -> any any (msg:\"ok\"; sid:99;)", EngineConfig{}, append(tcpProbes, udpProbes...), false},
		{"pass rule for udp only", portScanRule + "\npass udp " + scanner + " any -> any any (msg:\"ok\"; sid:99;)", EngineConfig{}, udpProbes, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := runPackets(t, tt.rules, tt.cfg, tt.pkts)
			if fired := len(alertsOf(got, 41)) > 0; fired != tt.fire {
				t.Errorf("fired = %v, want %v:%s", fired, tt.fire, alertLines(got))
			}
		})
	}
}

func TestPortScanIPv6UDP(t *testing.T) {
	got, _ := runPackets(t, portScanRule, EngineConfig{}, portProbes(t, "udp", "2001:db8::50", "2001:db8::10", 10, t0, time.Millisecond))
	as := alertsOf(got, 41)
	if len(as) != 1 || as[0].Details["scan_types"] != "udp:10" || as[0].SrcIP != "2001:db8::50" {
		t.Errorf("IPv6 UDP scan:%s", alertLines(got))
	}
}

const hostSweepRule = `alert ip any any -> any any (msg:"host sweep"; detect:host_sweep; distinct_hosts:8; seconds:30; sid:42; severity:medium; category:recon;)`

func TestHostSweep(t *testing.T) {
	ms := time.Millisecond
	t.Run("n-1 hosts", func(t *testing.T) {
		if got, _ := runPackets(t, hostSweepRule, EngineConfig{}, hostProbes(t, "refused", scanner, 22, 7, t0, ms)); len(got) != 0 {
			t.Errorf("alerted:%s", alertLines(got))
		}
	})
	t.Run("n hosts", func(t *testing.T) {
		got, _ := runPackets(t, hostSweepRule, EngineConfig{}, hostProbes(t, "refused", scanner, 22, 8, t0, ms))
		as := alertsOf(got, 42)
		if len(got) != 1 || len(as) != 1 {
			t.Fatalf("want one alert:%s", alertLines(got))
		}
		want := map[string]string{"detector": "host_sweep", "tracked_addr": scanner, "dst_port": "22", "proto": "tcp", "distinct_hosts": "8", "scan_types": "syn:8",
			"hosts": "192.0.2.1,192.0.2.2,192.0.2.3,192.0.2.4,192.0.2.5,192.0.2.6,192.0.2.7,192.0.2.8"}
		for k, v := range want {
			if as[0].Details[k] != v {
				t.Errorf("details[%s] = %q, want %q", k, as[0].Details[k], v)
			}
		}
	})
	t.Run("udp sweep", func(t *testing.T) {
		got, _ := runPackets(t, hostSweepRule, EngineConfig{}, hostProbes(t, "udp", scanner, 161, 8, t0, ms))
		if as := alertsOf(got, 42); len(as) != 1 || as[0].Details["proto"] != "udp" || as[0].Details["dst_port"] != "161" {
			t.Errorf("udp sweep:%s", alertLines(got))
		}
	})
	t.Run("hosts on different ports do not add up", func(t *testing.T) {
		var ps []tpkt
		for i := range 8 {
			ps = append(ps, probeKind(t, "refused", scanner, fmt.Sprintf("192.0.2.%d", 1+i), uint16(20+i%2), at(time.Duration(i)*ms))...)
		}
		if got, _ := runPackets(t, hostSweepRule, EngineConfig{}, ps); len(got) != 0 {
			t.Errorf("alerted:%s", alertLines(got))
		}
	})
	t.Run("tcp and udp on one port do not add up", func(t *testing.T) {
		ps := append(hostProbes(t, "refused", scanner, 53, 4, t0, ms), hostProbes(t, "udp", scanner, 53, 8, at(time.Second), ms)[8:]...)
		ps = append(ps, hostProbes(t, "refused", scanner, 53, 4, at(2*time.Second), ms)...)
		if got, _ := runPackets(t, hostSweepRule, EngineConfig{}, ps); len(got) != 0 {
			t.Errorf("alerted:%s", alertLines(got))
		}
	})
	t.Run("completed connections to many hosts", func(t *testing.T) {
		if got, _ := runPackets(t, hostSweepRule, EngineConfig{}, hostProbes(t, "complete", scanner, 443, 40, t0, 10*ms)); len(got) != 0 {
			t.Errorf("alerted:%s", alertLines(got))
		}
	})
	t.Run("window", func(t *testing.T) {
		if got, _ := runPackets(t, hostSweepRule, EngineConfig{}, hostProbes(t, "refused", scanner, 22, 8, t0, 30*time.Second/7)); len(alertsOf(got, 42)) != 1 {
			t.Errorf("8 hosts over exactly 30s:%s", alertLines(got))
		}
		if got, _ := runPackets(t, hostSweepRule, EngineConfig{}, hostProbes(t, "refused", scanner, 22, 8, t0, 30*time.Second/7+time.Millisecond)); len(got) != 0 {
			t.Errorf("8 hosts over 30s+7ms:%s", alertLines(got))
		}
	})
	t.Run("one alert per swept port", func(t *testing.T) {
		ps := append(hostProbes(t, "refused", scanner, 22, 8, t0, ms), hostProbes(t, "refused", scanner, 23, 8, at(time.Second), ms)...)
		got, _ := runPackets(t, hostSweepRule, EngineConfig{}, ps)
		as := alertsOf(got, 42)
		if len(as) != 2 || as[0].Details["dst_port"] != "22" || as[1].Details["dst_port"] != "23" {
			t.Errorf("want alerts for 22 and 23:%s", alertLines(got))
		}
	})
	t.Run("eviction", func(t *testing.T) {
		var ps []tpkt
		for i := range 8 {
			for j, src := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
				ps = append(ps, probeKind(t, "fin", src, fmt.Sprintf("192.0.2.%d", 1+i), 22, at(time.Duration(i*3+j)*ms))...)
			}
		}
		got, e := runPackets(t, hostSweepRule, EngineConfig{MaxKeys: 2}, ps)
		if st := e.Stats().Tables[TableHostSweep]; len(got) != 0 || st.Evictions == 0 {
			t.Errorf("table %+v:%s", st, alertLines(got))
		}
	})
}

const pingSweepRule = `alert icmp any any -> any any (msg:"ping sweep"; detect:ping_sweep; distinct_hosts:8; seconds:30; sid:43; severity:low; category:recon;)`

func TestPingSweep(t *testing.T) {
	ms := time.Millisecond
	t.Run("n-1 hosts", func(t *testing.T) {
		if got, _ := runPackets(t, pingSweepRule, EngineConfig{}, hostProbes(t, "echo", scanner, 0, 7, t0, ms)); len(got) != 0 {
			t.Errorf("alerted:%s", alertLines(got))
		}
	})
	t.Run("n hosts", func(t *testing.T) {
		got, _ := runPackets(t, pingSweepRule, EngineConfig{}, hostProbes(t, "echo", scanner, 0, 8, t0, ms))
		as := alertsOf(got, 43)
		if len(got) != 1 || len(as) != 1 || as[0].Details["distinct_hosts"] != "8" || as[0].Details["detector"] != "ping_sweep" || as[0].Proto != "ICMP" {
			t.Fatalf("want one alert:%s", alertLines(got))
		}
	})
	t.Run("ipv6", func(t *testing.T) {
		var ps []tpkt
		for i := range 8 {
			ps = append(ps, probeKind(t, "echo", "2001:db8::50", fmt.Sprintf("2001:db8::%x", 0x100+i), 0, at(time.Duration(i)*ms))...)
		}
		if got, _ := runPackets(t, pingSweepRule, EngineConfig{}, ps); len(alertsOf(got, 43)) != 1 {
			t.Errorf("IPv6 sweep:%s", alertLines(got))
		}
	})
	t.Run("many pings to one host", func(t *testing.T) {
		var ps []tpkt
		for i := range 50 {
			ps = append(ps, probeKind(t, "echo", scanner, target, 0, at(time.Duration(i)*ms))...)
		}
		if got, _ := runPackets(t, pingSweepRule, EngineConfig{}, ps); len(got) != 0 {
			t.Errorf("alerted:%s", alertLines(got))
		}
	})
	t.Run("tcp probes are not pings", func(t *testing.T) {
		rules := strings.Replace(pingSweepRule, "alert icmp", "alert ip", 1)
		if got, _ := runPackets(t, rules, EngineConfig{}, hostProbes(t, "refused", scanner, 80, 20, t0, ms)); len(got) != 0 {
			t.Errorf("alerted:%s", alertLines(got))
		}
	})
	t.Run("port unreachables are not pings", func(t *testing.T) {
		if got, _ := runPackets(t, pingSweepRule, EngineConfig{}, hostProbes(t, "udp", scanner, 161, 20, t0, ms)); len(got) != 0 {
			t.Errorf("alerted:%s", alertLines(got))
		}
	})
	t.Run("window", func(t *testing.T) {
		if got, _ := runPackets(t, pingSweepRule, EngineConfig{}, hostProbes(t, "echo", scanner, 0, 8, t0, 30*time.Second/7+ms)); len(got) != 0 {
			t.Errorf("alerted over 30s+7ms:%s", alertLines(got))
		}
	})
	t.Run("whitelisted", func(t *testing.T) {
		if got, _ := runPackets(t, pingSweepRule, EngineConfig{Whitelist: mustPrefixes(scanner + "/32")}, hostProbes(t, "echo", scanner, 0, 8, t0, ms)); len(got) != 0 {
			t.Errorf("alerted:%s", alertLines(got))
		}
	})
	t.Run("eviction", func(t *testing.T) {
		var ps []tpkt
		for i := range 8 {
			for j, src := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
				ps = append(ps, probeKind(t, "echo", src, fmt.Sprintf("192.0.2.%d", 1+i), 0, at(time.Duration(i*3+j)*ms))...)
			}
		}
		got, e := runPackets(t, pingSweepRule, EngineConfig{MaxKeys: 2}, ps)
		if st := e.Stats().Tables[TablePingSweep]; len(got) != 0 || st.Evictions == 0 {
			t.Errorf("table %+v:%s", st, alertLines(got))
		}
	})
}

// TestSYNFloodMaxDistinctPorts checks the flood's port condition at the
// boundary: incompletes over 5 ports fire, over 6 do not.
func TestSYNFloodMaxDistinctPorts(t *testing.T) {
	const rule = `alert tcp any any -> any any (msg:"flood"; detect:syn_flood; track:by_src; count:50; seconds:5; sid:2;)`
	run := func(ports int) []Alert {
		var ps []tpkt
		for i := range 60 {
			ps = append(ps, probeKind(t, "refused", attacker, victim, uint16(80+i%ports), at(time.Duration(i)*10*time.Millisecond))...)
		}
		// probeKind derives the client port from the server port; give each
		// attempt its own so the tracker sees 60 handshakes.
		for i := range ps {
			if ps[i].p.src == attacker {
				ps[i].p.sport = uint16(20000 + i)
			} else {
				ps[i].p.dport = uint16(20000 + i - 1)
			}
		}
		got, _ := runPackets(t, rule, EngineConfig{}, ps)
		return got
	}
	got := run(5)
	if as := alertsOf(got, 2); len(as) != 1 || as[0].Details["distinct_ports"] != "5" {
		t.Errorf("5 ports: want one alert with distinct_ports 5:%s", alertLines(got))
	}
	if got := run(6); len(got) != 0 {
		t.Errorf("6 ports alerted:%s", alertLines(got))
	}
	if got := run(1); len(alertsOf(got, 2)) != 1 || alertsOf(got, 2)[0].Details["distinct_ports"] != "1" {
		t.Errorf("1 port:%s", alertLines(got))
	}
}

func mustPrefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}
