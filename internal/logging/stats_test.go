package logging

import (
	"fmt"
	"math"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

func tcpPkt(src string, size uint32) *packet.ParsedPacket {
	return &packet.ParsedPacket{
		WireLen: size, EthType: packet.EthTypeIPv4, IPSrc: net.ParseIP(src).To4(), IPDst: net.IPv4(10, 9, 9, 9).To4(),
		L4Proto: packet.L4TCP,
	}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9*math.Max(1, math.Abs(b)) }

func TestAggregatorRates(t *testing.T) {
	a := NewAggregator(AggregatorConfig{}, t0)
	for i := 0; i < 100; i++ {
		a.Packet(tcpPkt("10.0.0.1", 100))
	}
	a.Tick(t0.Add(time.Second))
	s := a.Snapshot()
	if !near(s.PPS, 100) || !near(s.BPS, 10000) || !near(s.AvgPPS, 100) || !near(s.AvgBPS, 10000) {
		t.Errorf("after 1s: pps %v bps %v avg %v %v", s.PPS, s.BPS, s.AvgPPS, s.AvgBPS)
	}

	// A late tick: the rate is over the real elapsed time.
	for i := 0; i < 300; i++ {
		a.Packet(tcpPkt("10.0.0.1", 50))
	}
	a.Tick(t0.Add(3 * time.Second))
	s = a.Snapshot()
	if !near(s.PPS, 150) || !near(s.BPS, 7500) {
		t.Errorf("after 3s: pps %v bps %v", s.PPS, s.BPS)
	}
	if !near(s.AvgPPS, 400.0/3) || !near(s.AvgBPS, 25000.0/3) {
		t.Errorf("after 3s: avg %v %v", s.AvgPPS, s.AvgBPS)
	}
	if s.Packets != 400 || s.Bytes != 25000 {
		t.Errorf("totals %d %d", s.Packets, s.Bytes)
	}

	// The average only covers the last 60 samples: 60 idle seconds push
	// the traffic out.
	for i := 1; i <= 59; i++ {
		a.Tick(t0.Add(time.Duration(3+i) * time.Second))
	}
	if s = a.Snapshot(); !near(s.AvgPPS, 300.0/61) || s.PPS != 0 {
		// The first sample fell out: the 2s sample (300 pkts) + 59 idle 1s samples = 61s.
		t.Errorf("after 59 idle: avg %v pps %v", s.AvgPPS, s.PPS)
	}
	a.Tick(t0.Add(63 * time.Second))
	if s = a.Snapshot(); s.AvgPPS != 0 || s.AvgBPS != 0 {
		t.Errorf("after 60 idle: avg %v %v", s.AvgPPS, s.AvgBPS)
	}
	if s.Packets != 400 {
		t.Errorf("totals changed: %d", s.Packets)
	}
}

func TestAggregatorBreakdown(t *testing.T) {
	a := NewAggregator(AggregatorConfig{}, t0)
	add := func(n int, p packet.ParsedPacket) {
		for i := 0; i < n; i++ {
			q := p
			a.Packet(&q)
		}
	}
	ip := net.IPv4(10, 0, 0, 1).To4()
	add(5, packet.ParsedPacket{IPSrc: ip, L4Proto: packet.L4TCP, AppProtocol: packet.AppHTTP})
	add(3, packet.ParsedPacket{IPSrc: ip, L4Proto: packet.L4TCP, AppProtocol: packet.AppTLS})
	add(4, packet.ParsedPacket{IPSrc: ip, L4Proto: packet.L4UDP, AppProtocol: packet.AppDNS})
	add(2, packet.ParsedPacket{IPSrc: ip, L4Proto: packet.L4ICMP})
	add(2, packet.ParsedPacket{EthType: packet.EthTypeARP})
	add(1, packet.ParsedPacket{EthType: 0x88cc})
	add(1, packet.ParsedPacket{IPSrc: ip}) // a later fragment
	a.Tick(t0.Add(time.Second))
	s := a.Snapshot()
	wantL4 := []Count{{"TCP", 8}, {"UDP", 4}, {"ARP", 2}, {"ICMP", 2}, {"NO-L4", 1}, {"NON-IP", 1}}
	if !reflect.DeepEqual(s.ByL4, wantL4) {
		t.Errorf("by L4 %v, want %v", s.ByL4, wantL4)
	}
	wantApp := []Count{{"NONE", 6}, {"HTTP", 5}, {"DNS", 4}, {"TLS", 3}}
	if !reflect.DeepEqual(s.ByApp, wantApp) {
		t.Errorf("by app %v, want %v", s.ByApp, wantApp)
	}
	tot := s.Totals()
	if tot.Packets != 18 || tot.ByL4["TCP"] != 8 || tot.ByApp["NONE"] != 6 {
		t.Errorf("totals %+v", tot)
	}
	if got := a.Totals(); !reflect.DeepEqual(got, tot) {
		t.Errorf("Aggregator.Totals %+v, snapshot %+v", got, tot)
	}
}

func TestAggregatorTopN(t *testing.T) {
	a := NewAggregator(AggregatorConfig{}, t0)
	// Source i sends i packets of 1000-50*i bytes: most packets and most
	// bytes rank differently.
	for i := 1; i <= 15; i++ {
		for j := 0; j < i; j++ {
			a.Packet(tcpPkt(fmt.Sprintf("10.0.0.%d", i), uint32(1000-50*i)))
		}
	}
	// Alerts: 10.0.0.3 has 1 alert plus a summary of 5 (4 more), 10.0.0.7
	// has 2 alerts, 10.0.0.9 a summary of count 1 (nothing new).
	al := func(src, kind string, count int) rules.Alert {
		return rules.Alert{SrcIP: src, Kind: kind, Count: count, SID: 1}
	}
	a.Alert(al("10.0.0.3", rules.KindAlert, 1))
	a.Alert(al("10.0.0.3", rules.KindSummary, 5))
	a.Alert(al("10.0.0.7", rules.KindAlert, 1))
	a.Alert(al("10.0.0.7", rules.KindAlert, 1))
	a.Alert(al("10.0.0.9", rules.KindSummary, 1))
	a.Alert(al("::ffff:10.0.0.7", rules.KindAlert, 1)) // same source, v4-mapped
	a.Tick(t0.Add(time.Second))
	s := a.Snapshot()

	var wantPkts []string
	for i := 15; i >= 6; i-- {
		wantPkts = append(wantPkts, fmt.Sprintf("10.0.0.%d", i))
	}
	if got := ips(s.TopPackets); !reflect.DeepEqual(got, wantPkts) {
		t.Errorf("top by packets %v, want %v", got, wantPkts)
	}
	if s.TopPackets[0].Packets != 15 || s.TopPackets[0].Bytes != 15*250 {
		t.Errorf("top talker %+v", s.TopPackets[0])
	}
	// bytes(i) = i*(1000-50i): 10:5000, 11:4950 9:4950 12:4800 8:4800
	// 13:4550 7:4550 14:4200 6:4200 15:3750 5:3750.
	wantBytes := []string{"10.0.0.10", "10.0.0.11", "10.0.0.9", "10.0.0.12", "10.0.0.8", "10.0.0.13", "10.0.0.7", "10.0.0.14", "10.0.0.6", "10.0.0.15"}
	if got := ips(s.TopBytes); !reflect.DeepEqual(got, wantBytes) {
		t.Errorf("top by bytes %v, want %v", got, wantBytes)
	}
	if got := s.TopAlerts; len(got) != 2 || got[0].IP != "10.0.0.3" || got[0].Alerts != 5 || got[1].IP != "10.0.0.7" || got[1].Alerts != 3 {
		t.Errorf("top by alerts %+v", got)
	}
	if s.TrackedIPs != 15 || s.Untracked != 0 || s.Alerts != 6 {
		t.Errorf("tracked %d untracked %d alerts %d", s.TrackedIPs, s.Untracked, s.Alerts)
	}
}

func ips(ts []Talker) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.IP)
	}
	return out
}

func TestAggregatorIPCapAndWindows(t *testing.T) {
	a := NewAggregator(AggregatorConfig{MaxIPs: 5}, t0)
	for i := 1; i <= 10; i++ {
		for j := 0; j < 2; j++ {
			a.Packet(tcpPkt(fmt.Sprintf("10.0.0.%d", i), 100))
		}
	}
	a.Tick(t0.Add(time.Second))
	s := a.Snapshot()
	if s.TrackedIPs != 5 || s.Untracked != 10 || len(s.TopPackets) != 5 {
		t.Errorf("cap 5: tracked %d untracked %d top %d", s.TrackedIPs, s.Untracked, len(s.TopPackets))
	}
	// Known sources keep counting at the cap.
	a.Packet(tcpPkt("10.0.0.1", 100))
	a.Tick(t0.Add(2 * time.Second))
	if s = a.Snapshot(); s.TopPackets[0].IP != "10.0.0.1" || s.TopPackets[0].Packets != 3 {
		t.Errorf("top %+v", s.TopPackets[0])
	}

	// After one window the old counts are still shown (previous window);
	// the new window has its own cap.
	a.Tick(t0.Add(TalkerWindow))
	for i := 6; i <= 10; i++ {
		a.Packet(tcpPkt(fmt.Sprintf("10.0.0.%d", i), 100))
	}
	a.Tick(t0.Add(TalkerWindow + time.Second))
	if s = a.Snapshot(); s.TrackedIPs != 10 || s.Untracked != 10 {
		t.Errorf("two windows: tracked %d untracked %d", s.TrackedIPs, s.Untracked)
	}
	// Another window: the first is gone.
	a.Tick(t0.Add(2 * TalkerWindow))
	if s = a.Snapshot(); s.TrackedIPs != 5 || s.Untracked != 0 || s.TopPackets[0].Packets != 1 {
		t.Errorf("window rolled: tracked %d untracked %d top %+v", s.TrackedIPs, s.Untracked, s.TopPackets)
	}
	// A long idle gap empties both windows.
	a.Tick(t0.Add(5 * TalkerWindow))
	if s = a.Snapshot(); s.TrackedIPs != 0 || len(s.TopPackets) != 0 {
		t.Errorf("after gap: tracked %d top %v", s.TrackedIPs, s.TopPackets)
	}
}

func TestAggregatorRecentAlerts(t *testing.T) {
	a := NewAggregator(AggregatorConfig{RecentAlerts: 3}, t0)
	a.Alert(rules.Alert{SID: 1})
	a.Alert(rules.Alert{SID: 2})
	a.Tick(t0.Add(time.Second))
	if got := sids(a.Snapshot().RecentAlerts); !reflect.DeepEqual(got, []int{1, 2}) {
		t.Errorf("recent %v", got)
	}
	for i := 3; i <= 7; i++ {
		a.Alert(rules.Alert{SID: i})
	}
	a.Tick(t0.Add(2 * time.Second))
	if got := sids(a.Snapshot().RecentAlerts); !reflect.DeepEqual(got, []int{5, 6, 7}) {
		t.Errorf("recent %v, want [5 6 7]", got)
	}
	if def := NewAggregator(AggregatorConfig{}, t0); len(def.ring) != 200 {
		t.Errorf("default ring %d", len(def.ring))
	}
}

func sids(as []rules.Alert) []int {
	var out []int
	for _, a := range as {
		out = append(out, a.SID)
	}
	return out
}

// TestAggregatorConcurrentSnapshots reads snapshots while the pipeline
// goroutine feeds and ticks, under -race.
func TestAggregatorConcurrentSnapshots(t *testing.T) {
	a := NewAggregator(AggregatorConfig{MaxIPs: 100}, t0)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				s := a.Snapshot()
				for _, c := range s.ByL4 {
					_ = c.Packets
				}
				for _, al := range s.RecentAlerts {
					_ = al.SID
				}
				_ = s.Totals()
			}
		}()
	}
	now := t0
	for i := 0; i < 50000; i++ {
		a.Packet(tcpPkt(fmt.Sprintf("10.0.%d.%d", i%7, i%200), 60))
		if i%100 == 0 {
			a.Alert(rules.Alert{SID: i, SrcIP: "10.0.0.1", Kind: rules.KindAlert})
		}
		if i%1000 == 0 {
			now = now.Add(time.Second)
			a.Tick(now)
		}
	}
	close(done)
	wg.Wait()
	a.Tick(now.Add(time.Second))
	if s := a.Snapshot(); s.Packets != 50000 || s.Alerts != 500 {
		t.Errorf("packets %d alerts %d", s.Packets, s.Alerts)
	}
}

func BenchmarkAggregatorPacket(b *testing.B) {
	a := NewAggregator(AggregatorConfig{}, t0)
	ps := make([]*packet.ParsedPacket, 1024)
	for i := range ps {
		ps[i] = tcpPkt(fmt.Sprintf("10.0.%d.%d", i/256, i%256), 100)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Packet(ps[i%len(ps)])
	}
}
