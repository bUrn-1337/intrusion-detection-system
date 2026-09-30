package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

const stageRules = `stage recon recon
stage exploit web,credential
stage c2 malware
stage exfil exfiltration
stage impact dos
`

// corrRules has one signature rule per stage plus an unstaged one, and
// the three incident kinds.
const corrRules = stageRules + `alert tcp any any -> any any (msg:"scan"; sid:10; severity:low; category:recon;)
alert tcp any any -> any any (msg:"web"; sid:20; severity:high; category:web;)
alert tcp any any -> any any (msg:"c2"; sid:30; category:malware;)
alert tcp any any -> any any (msg:"exfil"; sid:40; category:exfiltration;)
alert tcp any any -> any any (msg:"dos"; sid:50; category:dos;)
alert tcp any any -> any any (msg:"odd"; sid:60; severity:low; category:anomaly;)
alert ip any any -> any any (msg:"ms"; detect:incident; kind:multi_stage; sid:100; category:incident;)
alert ip any any -> any any (msg:"ch"; detect:incident; kind:compromised_host; sid:101; category:incident;)
alert ip any any -> any any (msg:"cb"; detect:incident; kind:callback; sid:102; category:incident;)
`

// corrHarness feeds synthetic alerts straight to a correlator.
type corrHarness struct {
	t     *testing.T
	rs    *RuleSet
	c     *correlator
	stats [2]tableStat
	out   []Alert // every incident so far
}

func newCorrHarness(t *testing.T, text string, maxKeys int) *corrHarness {
	t.Helper()
	h := &corrHarness{t: t, rs: mustParse(t, text)}
	h.c = newCorrelator(maxKeys, &h.stats[0], &h.stats[1])
	h.c.use(h.rs)
	return h
}

func (h *corrHarness) rule(sid int) *Rule {
	for _, r := range h.rs.rules {
		if r.SID == sid {
			return r
		}
	}
	h.t.Fatalf("no rule %d", sid)
	return nil
}

// alert feeds an alert of rule sid from src to dst at t0+d and returns
// the incidents it produced.
func (h *corrHarness) alert(sid int, src, dst string, reliable bool, d time.Duration) []Alert {
	h.t.Helper()
	r := h.rule(sid)
	v := view{g: gTCP, src: netip.MustParseAddr(src)}
	if dst != "" {
		v.dst = netip.MustParseAddr(dst)
	}
	a := Alert{Severity: r.Severity, Details: map[string]string{detailAttribution: attrSpoofable}}
	if reliable {
		a.Details[detailAttribution] = attrReliable
	}
	out := h.c.alert(h.rs, r, &v, &a, at(d), nil)
	h.out = append(h.out, out...)
	return out
}

// syn reports a connection start from src to dst port 4444.
func (h *corrHarness) syn(src, dst string, d time.Duration) []Alert {
	out := h.c.connStart(h.rs, netip.MustParseAddr(src), netip.MustParseAddr(dst), 40000, 4444, at(d), nil)
	h.out = append(h.out, out...)
	return out
}

func incidentsOf(as []Alert, sid int) []Alert {
	var out []Alert
	for _, a := range as {
		if a.SID == sid {
			out = append(out, a)
		}
	}
	return out
}

const (
	atkIP  = "192.0.2.1"
	vicIP  = "198.51.100.10"
	vic2IP = "198.51.100.11"
	outIP  = "203.0.113.5"
)

func TestStageDirective(t *testing.T) {
	rs := mustParse(t, stageRules+`alert tcp any any -> any any (msg:"m"; sid:1; category:web;)
alert tcp any any -> any any (msg:"m"; sid:2; category:policy;)
`)
	if !slices.Equal(rs.stages.names, []string{"recon", "exploit", "c2", "exfil", "impact"}) {
		t.Errorf("stages %v", rs.stages.names)
	}
	if rs.rules[0].stage != 1 || rs.rules[1].stage != -1 {
		t.Errorf("rule stages %d, %d", rs.rules[0].stage, rs.rules[1].stage)
	}
	// A category only a rule uses is fine.
	mustParse(t, "stage own my-cat\nalert tcp any any -> any any (msg:\"m\"; sid:1; category:my-cat;)\n")

	var many strings.Builder
	for i := range maxStages + 1 {
		fmt.Fprintf(&many, "stage s%d recon%d\n", i, i)
	}
	for _, tc := range []struct {
		name, text string
		line       int
		frag       string
	}{
		{"no category", "stage recon\n", 1, `want "stage NAME CATEGORY`},
		{"bad name", "stage re$con recon\n", 1, "stage name"},
		{"bad category", "stage recon re$con\n", 1, `category "re$con"`},
		{"name twice", "stage recon recon\nstage recon web\n", 2, "stage recon defined twice (first on line 1)"},
		{"category twice", "stage recon recon\nstage exploit web,recon\n", 2, "category recon is already mapped to stage recon (line 1)"},
		{"category twice in one", "stage exploit web,web\n", 1, "category web listed twice"},
		{"unknown category", "stage recon recon\nstage exploit web,webb\n", 2, `unknown category "webb"`},
		{"too many", many.String(), maxStages + 1, "more than 16 stages"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.text), "s.rules")
			var le *LoadError
			if !errors.As(err, &le) {
				t.Fatalf("err %v", err)
			}
			found := false
			for _, se := range le.Errors {
				if se.Line == tc.line && strings.Contains(se.Reason, tc.frag) {
					found = true
				}
			}
			if !found {
				t.Errorf("errors %v, want line %d with %q", err, tc.line, tc.frag)
			}
		})
	}
}

func TestIncidentOptions(t *testing.T) {
	rs := mustParse(t, corrRules)
	ms, ch, cb := rs.incident[0], rs.incident[1], rs.incident[2]
	exploit := stageSet(1 << 1)
	if ms.minStages != 2 || ms.incWindow != time.Hour || ms.firstWindow != 24*time.Hour || ms.fromStages != exploit {
		t.Errorf("multi_stage defaults %d %v %v %b", ms.minStages, ms.incWindow, ms.firstWindow, ms.fromStages)
	}
	if ch.incWindow != 24*time.Hour || ch.fromStages != exploit || ch.toStages != 1<<2|1<<3 {
		t.Errorf("compromised_host defaults %v %b %b", ch.incWindow, ch.fromStages, ch.toStages)
	}
	if cb.incWindow != 120*time.Second || cb.fromStages != exploit || !rs.callback {
		t.Errorf("callback defaults %v %b", cb.incWindow, cb.fromStages)
	}
	r := mustParse(t, stageRules+`alert ip any any -> any any (msg:"m"; detect:incident; kind:multi_stage; min_stages:3; window:600; first_window:7200; from:exploit,c2; sid:1;)`).rules[0]
	if r.minStages != 3 || r.incWindow != 10*time.Minute || r.firstWindow != 2*time.Hour || r.fromStages != 1<<1|1<<2 {
		t.Errorf("multi_stage options %d %v %v %b", r.minStages, r.incWindow, r.firstWindow, r.fromStages)
	}
	// Without an exploit stage, multi_stage simply does not follow the
	// victim; the other kinds need from.
	r = mustParse(t, "stage a recon\nstage b web\n"+`alert ip any any -> any any (msg:"m"; detect:incident; kind:multi_stage; sid:1;)`).rules[0]
	if r.fromStages != 0 {
		t.Errorf("from %b without an exploit stage", r.fromStages)
	}

	const hdr = `alert ip any any -> any any `
	for _, tc := range []struct{ rule, frag string }{
		{`(msg:"m"; detect:incident; kind:multi_stage; sid:1;)`, ""},
		{`(msg:"m"; detect:incident; sid:1;)`, "detect:incident needs kind"},
		{`(msg:"m"; detect:incident; kind:chain; sid:1;)`, `kind "chain": want multi_stage, compromised_host or callback`},
		{`(msg:"m"; detect:incident; kind:callback; severity:high; sid:1;)`, "severity is not valid with detect:incident"},
		{`(msg:"m"; detect:incident; kind:callback; min_stages:2; sid:1;)`, "min_stages and first_window are only valid with kind:multi_stage"},
		{`(msg:"m"; detect:incident; kind:compromised_host; first_window:60; sid:1;)`, "min_stages and first_window are only valid with kind:multi_stage"},
		{`(msg:"m"; detect:incident; kind:multi_stage; to:c2; sid:1;)`, "to is only valid with kind:compromised_host"},
		{`(msg:"m"; detect:incident; kind:callback; from:weaponize; sid:1;)`, `from: unknown stage "weaponize"`},
		{`(msg:"m"; detect:incident; kind:callback; from:exploit,exploit; sid:1;)`, "stage exploit listed twice"},
		{`(msg:"m"; detect:incident; kind:multi_stage; min_stages:1; sid:1;)`, "min_stages: 1: at least 2"},
		{`(msg:"m"; detect:incident; kind:multi_stage; min_stages:6; sid:1;)`, "min_stages 6: the file defines only 5 stages"},
		{`(msg:"m"; detect:incident; kind:callback; window:0; sid:1;)`, "window:"},
		{`(msg:"m"; detect:incident; kind:callback; window:86401; sid:1;)`, "window:"},
		{`(msg:"m"; detect:incident; kind:compromised_host; from:c2; sid:1;)`, "from and to share a stage"},
		{`(msg:"m"; detect:incident; kind:callback; count:3; sid:1;)`, "option count is not valid with detect:incident"},
		{`(msg:"m"; kind:callback; window:60; sid:1;)`, "option kind is only valid with detect:"},
		{`(msg:"m"; detect:incident; kind:callback; content:"x"; sid:1;)`, "option content cannot be combined with detect"},
	} {
		_, err := Parse(strings.NewReader(stageRules+hdr+tc.rule), "i.rules")
		switch {
		case tc.frag == "" && err != nil:
			t.Errorf("%s: %v", tc.rule, err)
		case tc.frag != "" && (err == nil || !strings.Contains(err.Error(), tc.frag)):
			t.Errorf("%s: error %v, want %q", tc.rule, err, tc.frag)
		}
	}
	for _, tc := range []struct{ text, frag string }{
		{hdr + `(msg:"m"; detect:incident; kind:callback; sid:1;)`, "detect:incident needs stage directives"},
		{`alert tcp any any -> any any (msg:"m"; detect:incident; kind:callback; sid:1;)`, "detect:incident requires protocol ip"},
		{`alert ip any any <> any any (msg:"m"; detect:incident; kind:callback; sid:1;)`, "detect:incident needs a one-way rule"},
		{"stage a recon\n" + hdr + `(msg:"m"; detect:incident; kind:callback; sid:1;)`, "from: the default stage exploit is not defined"},
		{"stage a recon\nstage exploit web\n" + hdr + `(msg:"m"; detect:incident; kind:compromised_host; sid:1;)`, "to: the default stage c2 is not defined"},
	} {
		_, err := Parse(strings.NewReader(tc.text), "i.rules")
		if err == nil || !strings.Contains(err.Error(), tc.frag) {
			t.Errorf("%q: error %v, want %q", tc.text, err, tc.frag)
		}
	}
}

// TestAttributionClasses checks reliable() for every detector and every
// kind of signature rule.
func TestAttributionClasses(t *testing.T) {
	type want struct{ tcp, tcpEstab, udp, other bool }
	// For detectors: tcp = the alert's view is TCP, udp = UDP, other =
	// ICMP/IP/ARP as the detector sees it.
	detectors := map[string]want{
		DetectSYNFlood:         {},
		DetectPortScan:         {},
		DetectHostSweep:        {},
		DetectPingSweep:        {},
		DetectTTLAnomaly:       {},
		DetectFragAttack:       {},
		DetectARPSpoof:         {true, true, true, true},
		DetectUDPFlood:         {},
		DetectICMPFlood:        {},
		DetectICMPTunnel:       {},
		DetectSlowloris:        {true, true, true, true},
		DetectDNSSpoof:         {},
		DetectDNSAmplification: {},
		DetectDNSTunnel:        {tcp: true, tcpEstab: true},
		DetectNXDomainBurst:    {tcp: true, tcpEstab: true},
		DetectBeacon:           {true, true, true, true},
		DetectBaseline:         {},
		DetectIncident:         {},
	}
	for d := range detectorOptions {
		w, ok := detectors[d]
		if !ok {
			t.Errorf("detector %s has no attribution class in this table", d)
			continue
		}
		r := &Rule{Detect: d}
		for _, c := range []struct {
			v    view
			want bool
		}{{view{g: gTCP}, w.tcp}, {view{g: gTCP, established: true}, w.tcpEstab}, {view{g: gUDP}, w.udp}, {view{g: gICMP}, w.other}} {
			if got := reliable(r, &c.v); got != c.want {
				t.Errorf("detect:%s group %s established %v: reliable %v, want %v", d, groupNames[c.v.g], c.v.established, got, c.want)
			}
		}
	}

	// Signature rules, by what they look at.
	sigs := []struct {
		name string
		rule string
		want want
	}{
		{"header only", `alert tcp any any -> any any (msg:"m"; sid:1;)`, want{tcpEstab: true}},
		{"content", `alert tcp any any -> any any (msg:"m"; content:"x"; sid:1;)`, want{tcpEstab: true}},
		{"flags", `alert tcp any any -> any any (msg:"m"; flags:S; sid:1;)`, want{tcpEstab: true}},
		{"ip_feed", `alert ip any any -> any any (msg:"m"; ip_feed:f; sid:1;)`, want{tcpEstab: true}},
		{"app_proto", `alert tcp any any -> any any (msg:"m"; app_proto:http; sid:1;)`, want{tcp: true, tcpEstab: true}},
		{"app_field", `alert tcp any any -> any any (msg:"m"; app_field:method=GET; sid:1;)`, want{tcp: true, tcpEstab: true}},
		{"app_content", `alert tcp any any -> any any (msg:"m"; app_content:uri,"x"; sid:1;)`, want{tcp: true, tcpEstab: true}},
		{"domain_feed", `alert ip any any -> any any (msg:"m"; domain_feed:d; sid:1;)`, want{tcp: true, tcpEstab: true}},
		{"stream_anomaly", `alert tcp any any -> any any (msg:"m"; stream_anomaly; sid:1;)`, want{tcp: true, tcpEstab: true}},
		{"udp app_proto", `alert udp any any -> any any (msg:"m"; app_proto:dns; sid:1;)`, want{}},
		{"icmp", `alert icmp any any -> any any (msg:"m"; sid:1;)`, want{}},
		{"arp", `alert arp any any -> any any (msg:"m"; sid:1;)`, want{}},
	}
	dir := feedDir(t, map[string]string{"ips.txt": "203.0.113.1\n", "d.txt": "evil.example\n"})
	for _, s := range sigs {
		rs, err := loadIn(t, dir, "feed ip f ips.txt\nfeed domain d d.txt\n"+s.rule)
		if err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		r := rs.rules[0]
		for _, c := range []struct {
			v    view
			want bool
		}{{view{g: gTCP}, s.want.tcp}, {view{g: gTCP, established: true}, s.want.tcpEstab}, {view{g: gUDP}, s.want.udp},
			{view{g: gICMP}, s.want.other}, {view{g: gIP}, s.want.other}, {view{g: gARP}, s.want.other}} {
			if !slices.Contains(groupsFor(r.Proto), c.v.g) {
				continue
			}
			if got := reliable(r, &c.v); got != c.want {
				t.Errorf("%s group %s established %v: reliable %v, want %v", s.name, groupNames[c.v.g], c.v.established, got, c.want)
			}
		}
	}

	// Every signature rule in rules.conf, by category: TCP alerts are
	// reliable on an established flow; without one only app-layer and
	// stream rules are.
	conf, err := Load("../../rules.conf")
	if err != nil {
		t.Fatal(err)
	}
	cats := make(map[string]int)
	for _, r := range conf.rules {
		if r.Detect != "" {
			continue
		}
		cats[r.Category]++
		appLayer := r.appProto != "" || r.perMessage() || r.hasAnomaly
		for _, g := range groupsFor(r.Proto) {
			if g == gTCP {
				if !reliable(r, &view{g: g, established: true}) || reliable(r, &view{g: g}) != appLayer {
					t.Errorf("sid %d (%s): TCP attribution wrong", r.SID, r.Category)
				}
			} else if reliable(r, &view{g: g, established: true}) {
				t.Errorf("sid %d (%s): %s alert reliable", r.SID, r.Category, groupNames[g])
			}
		}
	}
	for _, c := range []string{"recon", "web", "web-attack", "evasion", "credential", "threat-intel", "dos", "policy", "dns"} {
		if cats[c] == 0 {
			t.Errorf("rules.conf has no signature rule of category %s any more; update this test", c)
		}
	}
}

// TestAttributionEngine checks Details["attribution"] on real packets.
func TestAttributionEngine(t *testing.T) {
	rs := mustParse(t, `alert tcp any any -> any 80 (msg:"m"; content:"EVIL"; sid:1;)
alert udp any any -> any any (msg:"u"; content:"EVIL"; sid:2;)
alert tcp any any -> any 8080 (msg:"a"; app_proto:http; sid:3;)
`)
	e := NewEngine(rs, EngineConfig{})
	attr := func(p pkt, d time.Duration) string {
		out := e.Process(p.parsed(t, at(d)))
		if len(out) != 1 {
			t.Fatalf("%+v: %s", p, alertLines(out))
		}
		return out[0].Details[detailAttribution]
	}
	// Payload without a handshake: spoofable.
	if got := attr(pkt{proto: "tcp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1000, dport: 80, flags: "PA", seq: 1, ack: 1, payload: "EVIL"}, 0); got != attrSpoofable {
		t.Errorf("no handshake: %s", got)
	}
	// After a completed handshake: reliable, in both directions.
	c, s := "10.0.0.3", "10.0.0.2"
	for i, p := range []pkt{
		{proto: "tcp", src: c, dst: s, sport: 2000, dport: 80, flags: "S", seq: 100},
		{proto: "tcp", src: s, dst: c, sport: 80, dport: 2000, flags: "SA", seq: 500, ack: 101},
		{proto: "tcp", src: c, dst: s, sport: 2000, dport: 80, flags: "A", seq: 101, ack: 501},
	} {
		if out := e.Process(p.parsed(t, at(time.Second+time.Duration(i)*time.Millisecond))); len(out) != 0 {
			t.Fatalf("handshake alerted: %s", alertLines(out))
		}
	}
	if got := attr(pkt{proto: "tcp", src: c, dst: s, sport: 2000, dport: 80, flags: "PA", seq: 101, ack: 501, payload: "EVIL"}, 2*time.Second); got != attrReliable {
		t.Errorf("established: %s", got)
	}
	if got := attr(pkt{proto: "udp", src: c, dst: s, sport: 2000, dport: 80, payload: "EVIL"}, 3*time.Second); got != attrSpoofable {
		t.Errorf("udp: %s", got)
	}
	// Application layer without a handshake seen: reliable.
	if got := attr(pkt{proto: "tcp", src: "10.0.0.9", dst: s, sport: 3000, dport: 8080, flags: "PA", seq: 1, ack: 1,
		payload: "GET / HTTP/1.1\r\nHost: x\r\n\r\n"}, 4*time.Second); got != attrReliable {
		t.Errorf("app layer: %s", got)
	}
}

func TestMultiStage(t *testing.T) {
	t.Run("two stages", func(t *testing.T) {
		h := newCorrHarness(t, corrRules, 100)
		if out := h.alert(10, atkIP, vicIP, true, 0); len(out) != 0 {
			t.Fatalf("recon alone: %s", alertLines(out))
		}
		out := incidentsOf(h.alert(20, atkIP, vicIP, true, 23*time.Hour), 100)
		if len(out) != 1 || out[0].Kind != KindIncident || out[0].Severity != SeverityHigh || out[0].Details["chain"] != "recon -> exploit" ||
			out[0].SrcIP != atkIP || out[0].DstIP != vicIP || out[0].Details["attacker"] != atkIP {
			t.Fatalf("got %s", alertLines(out))
		}
		// recon (low, 1) + exploit (high, 3), both against the victim:
		// 2 stages x 4.
		if out[0].Details["score"] != "8" || out[0].Details["contributing_total"] != "2" {
			t.Errorf("score %s contributing %s", out[0].Details["score"], out[0].Details["contributing"])
		}
		// A third stage: critical, as an update with the same id.
		up := incidentsOf(h.alert(30, atkIP, vicIP, true, 23*time.Hour+time.Hour), 100)
		if len(up) != 1 || up[0].Kind != KindIncidentUpdate || up[0].Severity != SeverityCritical || up[0].Details["incident_id"] != out[0].Details["incident_id"] ||
			up[0].Details["stages"] != "recon,exploit,c2" || !up[0].FirstSeen.Equal(at(23*time.Hour)) {
			t.Errorf("update %s", alertLines(up))
		}
	})
	// Windows at their exact limits: recon -> next 24h, others 1h.
	for _, tc := range []struct {
		name   string
		gap    time.Duration
		first  int
		second int
		fires  bool
	}{
		{"recon window exact", 24 * time.Hour, 10, 20, true},
		{"recon window passed", 24*time.Hour + time.Second, 10, 20, false},
		{"exploit window exact", time.Hour, 20, 30, true},
		{"exploit window passed", time.Hour + time.Second, 20, 30, false},
		{"c2 to exfil passed", time.Hour + time.Second, 30, 40, false},
		{"reverse order", time.Second, 20, 10, false},
		{"reverse order, c2 then recon", 3 * time.Hour, 30, 10, false},
		{"same stage twice", time.Second, 20, 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCorrHarness(t, corrRules, 100)
			h.alert(tc.first, atkIP, vicIP, true, 0)
			out := incidentsOf(h.alert(tc.second, atkIP, vicIP, true, tc.gap), 100)
			if (len(out) == 1) != tc.fires {
				t.Errorf("fires %v, want %v: %s", len(out) == 1, tc.fires, alertLines(out))
			}
		})
	}
	t.Run("chain through a repeated stage", func(t *testing.T) {
		// exploit, exploit 50m later, c2 50m after that: each step is
		// within 1h, so the chain holds.
		h := newCorrHarness(t, corrRules, 100)
		h.alert(20, atkIP, vicIP, true, 0)
		h.alert(20, atkIP, vicIP, true, 50*time.Minute)
		if out := incidentsOf(h.alert(30, atkIP, vicIP, true, 100*time.Minute), 100); len(out) != 1 {
			t.Errorf("got %s", alertLines(out))
		}
	})
	t.Run("spoofable only", func(t *testing.T) {
		h := newCorrHarness(t, corrRules, 100)
		h.alert(10, atkIP, vicIP, false, 0)
		h.alert(20, atkIP, vicIP, false, time.Minute)
		h.alert(50, atkIP, vicIP, false, 2*time.Minute)
		if len(h.out) != 0 {
			t.Errorf("spoofable alerts named an atkIP: %s", alertLines(h.out))
		}
	})
	t.Run("spoofable recon corroborated", func(t *testing.T) {
		// A SYN scan (spoofable) then a web attack on a completed
		// connection from the same source: the scan joins the chain.
		h := newCorrHarness(t, corrRules, 100)
		h.alert(10, atkIP, vicIP, false, 0)
		if out := incidentsOf(h.alert(20, atkIP, vicIP, true, time.Hour), 100); len(out) != 1 {
			t.Errorf("got %s", alertLines(out))
		}
	})
	t.Run("corroboration is per victim", func(t *testing.T) {
		// A reliable alert against another host does not make spoofable
		// alerts against the victim count.
		h := newCorrHarness(t, corrRules, 100)
		h.alert(20, atkIP, vic2IP, true, 0)
		h.alert(20, atkIP, vicIP, false, time.Minute)
		h.alert(30, atkIP, vicIP, false, 2*time.Minute)
		if out := incidentsOf(h.out, 100); len(out) != 0 {
			t.Errorf("got %s", alertLines(out))
		}
	})
	t.Run("victim set", func(t *testing.T) {
		// A sweep of other hosts counts as recon for an exploit of the
		// victim.
		h := newCorrHarness(t, corrRules, 100)
		h.alert(10, atkIP, vic2IP, false, 0)
		if out := incidentsOf(h.alert(20, atkIP, vicIP, true, time.Hour), 100); len(out) != 1 {
			t.Errorf("got %s", alertLines(out))
		}
		// But a later stage against another host does not.
		h = newCorrHarness(t, corrRules, 100)
		h.alert(20, atkIP, vic2IP, true, 0)
		if out := incidentsOf(h.alert(30, atkIP, vicIP, true, time.Minute), 100); len(out) != 0 {
			t.Errorf("got %s", alertLines(out))
		}
	})
	t.Run("follow the victim", func(t *testing.T) {
		h := newCorrHarness(t, corrRules, 100)
		h.alert(10, atkIP, vicIP, true, 0)
		h.alert(20, atkIP, vicIP, true, time.Hour)
		out := incidentsOf(h.alert(30, vicIP, outIP, true, time.Hour+30*time.Minute), 100)
		if len(out) != 1 || out[0].Kind != KindIncidentUpdate || out[0].Details["chain"] != "recon -> exploit -> c2" || out[0].Severity != SeverityCritical {
			t.Errorf("got %s", alertLines(out))
		}
		// The victim's c2 and exfil before the exploit (it was infected
		// already) do not count, though they follow the recon in time.
		h = newCorrHarness(t, corrRules, 100)
		h.alert(10, atkIP, vicIP, true, 0)
		h.alert(30, vicIP, outIP, true, time.Minute)
		h.alert(40, vicIP, outIP, true, 2*time.Minute)
		out = incidentsOf(h.alert(20, atkIP, vicIP, true, 3*time.Minute), 100)
		if len(out) != 1 || out[0].Details["chain"] != "recon -> exploit" || out[0].Severity != SeverityHigh {
			t.Errorf("got %s", alertLines(out))
		}
		// Nor does a spoofable one.
		if out := incidentsOf(h.alert(40, vicIP, vic2IP, false, 3*time.Minute), 100); len(out) != 0 {
			t.Errorf("got %s", alertLines(out))
		}
	})
	t.Run("unstaged alerts add to the score only", func(t *testing.T) {
		h := newCorrHarness(t, corrRules, 100)
		h.alert(60, outIP, vicIP, false, 0) // low, spoofable, no stage
		h.alert(10, atkIP, vicIP, true, time.Minute)
		out := incidentsOf(h.alert(20, atkIP, vicIP, true, 2*time.Minute), 100)
		if len(out) != 1 || out[0].Details["score"] != "10" {
			t.Errorf("got %s", alertLines(out))
		}
	})
	t.Run("header filters atkIP and victim", func(t *testing.T) {
		h := newCorrHarness(t, stageRules+`alert tcp any any -> any any (msg:"s"; sid:10; category:recon;)
alert tcp any any -> any any (msg:"w"; sid:20; category:web;)
alert ip 192.0.2.0/24 any -> 198.51.100.11 any (msg:"ms"; detect:incident; kind:multi_stage; sid:100;)
`, 100)
		h.alert(10, atkIP, vicIP, true, 0)
		h.alert(20, atkIP, vicIP, true, time.Minute)
		h.alert(10, atkIP, vic2IP, true, 0)
		h.alert(20, atkIP, vic2IP, true, time.Minute)
		if out := incidentsOf(h.out, 100); len(out) != 1 || out[0].DstIP != vic2IP {
			t.Errorf("got %s", alertLines(out))
		}
	})
	t.Run("min_stages", func(t *testing.T) {
		h := newCorrHarness(t, stageRules+`alert tcp any any -> any any (msg:"s"; sid:10; category:recon;)
alert tcp any any -> any any (msg:"w"; sid:20; category:web;)
alert tcp any any -> any any (msg:"c"; sid:30; category:malware;)
alert ip any any -> any any (msg:"ms"; detect:incident; kind:multi_stage; min_stages:3; sid:100;)
`, 100)
		h.alert(10, atkIP, vicIP, true, 0)
		h.alert(20, atkIP, vicIP, true, time.Minute)
		if len(h.out) != 0 {
			t.Fatalf("2 stages: %s", alertLines(h.out))
		}
		if out := h.alert(30, atkIP, vicIP, true, 2*time.Minute); len(out) != 1 || out[0].Kind != KindIncident || out[0].Severity != SeverityCritical {
			t.Errorf("3 stages: %s", alertLines(out))
		}
	})
}

func TestLongestChain(t *testing.T) {
	ev := func(stage int, d time.Duration) chainEvent {
		return chainEvent{contribution: contribution{t: at(d), stage: stage}}
	}
	// The best chain skips the stray c2 alert that comes too early.
	evs := []chainEvent{ev(0, 0), ev(2, time.Minute), ev(1, 2*time.Hour), ev(2, 2*time.Hour+time.Minute), ev(3, 2*time.Hour+2*time.Minute)}
	chain := longestChain(evs, 24*time.Hour, time.Hour)
	var stages []int
	for _, c := range chain {
		stages = append(stages, c.stage)
	}
	if !slices.Equal(stages, []int{0, 1, 2, 3}) {
		t.Errorf("chain stages %v", stages)
	}
	// Stages only need to be non-decreasing: a repeated exploit bridges
	// a c2 alert that is more than an hour after the first exploit.
	evs = []chainEvent{ev(1, 0), ev(1, 50*time.Minute), ev(2, 100*time.Minute)}
	if got := len(longestChain(evs, 24*time.Hour, time.Hour)); got != 3 {
		t.Errorf("repeated stage: chain of %d events, want 3", got)
	}
	if longestChain(nil, time.Hour, time.Hour) != nil {
		t.Error("empty chain")
	}
}

func TestCompromisedHost(t *testing.T) {
	for _, tc := range []struct {
		name          string
		exploitReli   bool
		sid           int
		c2Reliable    bool
		gap           time.Duration
		fires         bool
		exploitedAttr string
	}{
		{"c2 after exploit", true, 30, true, time.Hour, true, attrReliable},
		{"exfil after exploit", true, 40, true, time.Hour, true, attrReliable},
		{"spoofable exploit still counts", false, 30, true, time.Hour, true, attrSpoofable},
		{"window exact", true, 30, true, 24 * time.Hour, true, attrReliable},
		{"window passed", true, 30, true, 24*time.Hour + time.Second, false, ""},
		{"spoofable c2", true, 30, false, time.Hour, false, ""},
		{"not a to stage", true, 50, true, time.Hour, false, ""},
		{"c2 before exploit", true, 30, true, -time.Hour, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCorrHarness(t, corrRules, 100)
			base := 2 * time.Hour
			h.alert(20, atkIP, vicIP, tc.exploitReli, base)
			h.alert(tc.sid, vicIP, outIP, tc.c2Reliable, base+tc.gap)
			out := incidentsOf(h.out, 101)
			if (len(out) == 1) != tc.fires {
				t.Fatalf("fires %v, want %v: %s", len(out) == 1, tc.fires, alertLines(h.out))
			}
			if !tc.fires {
				return
			}
			a := out[0]
			if a.Severity != SeverityCritical || a.SrcIP != vicIP || a.Details["host"] != vicIP || a.Details["exploited_by"] != atkIP ||
				a.Details["exploited_by_attribution"] != tc.exploitedAttr || a.Details["attacker"] != "" {
				t.Errorf("got %s", alertLines(out))
			}
		})
	}
	t.Run("stages grow", func(t *testing.T) {
		h := newCorrHarness(t, corrRules, 100)
		h.alert(20, atkIP, vicIP, true, 0)
		first := incidentsOf(h.alert(30, vicIP, outIP, true, time.Minute), 101)
		again := incidentsOf(h.alert(30, vicIP, outIP, true, 2*time.Minute), 101)
		up := incidentsOf(h.alert(40, vicIP, outIP, true, 3*time.Minute), 101)
		if len(first) != 1 || len(again) != 0 || len(up) != 1 || up[0].Kind != KindIncidentUpdate || up[0].Details["stages"] != "exploit,c2,exfil" ||
			up[0].Details["incident_id"] != first[0].Details["incident_id"] {
			t.Errorf("first %s\nagain %s\nup %s", alertLines(first), alertLines(again), alertLines(up))
		}
	})
}

func TestCallback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reliable   bool
		sid        int
		from, to   string
		gap        time.Duration
		fires      bool
		connectsTo string
	}{
		{"callback", true, 20, vicIP, atkIP, 60 * time.Second, true, ""},
		{"window exact", true, 20, vicIP, atkIP, 120 * time.Second, true, ""},
		{"too late", true, 20, vicIP, atkIP, 121 * time.Second, false, ""},
		{"attacker to victim", true, 20, atkIP, vicIP, time.Second, false, ""},
		{"to another host", true, 20, vicIP, outIP, time.Second, false, ""},
		{"spoofable exploit", false, 20, vicIP, atkIP, time.Second, false, ""},
		{"not an exploit", true, 10, vicIP, atkIP, time.Second, false, ""},
		{"before the exploit", true, 20, vicIP, atkIP, -time.Second, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCorrHarness(t, corrRules, 100)
			base := time.Hour
			if tc.gap < 0 {
				h.alert(30, vicIP, outIP, true, 0) // the victim has a history
				h.syn(tc.from, tc.to, base+tc.gap)
				h.alert(tc.sid, atkIP, vicIP, tc.reliable, base)
			} else {
				h.alert(tc.sid, atkIP, vicIP, tc.reliable, base)
				h.syn(tc.from, tc.to, base+tc.gap)
			}
			out := incidentsOf(h.out, 102)
			if (len(out) == 1) != tc.fires {
				t.Fatalf("fires %v, want %v: %s", len(out) == 1, tc.fires, alertLines(h.out))
			}
			if tc.fires {
				a := out[0]
				if a.Severity != SeverityCritical || a.SrcIP != vicIP || a.DstIP != atkIP || a.DstPort != 4444 ||
					a.Details["attacker"] != atkIP || a.Details["victim"] != vicIP || a.Details["chain"] != "exploit -> callback" {
					t.Errorf("got %s", alertLines(out))
				}
			}
		})
	}
	t.Run("once", func(t *testing.T) {
		h := newCorrHarness(t, corrRules, 100)
		h.alert(20, atkIP, vicIP, true, 0)
		h.syn(vicIP, atkIP, time.Second)
		h.syn(vicIP, atkIP, 2*time.Second)
		if out := incidentsOf(h.out, 102); len(out) != 1 {
			t.Errorf("got %s", alertLines(out))
		}
	})
}

// TestCallbackEngine drives callback through packets: a retransmitted
// SYN is not a new connection, and the direction matters.
func TestCallbackEngine(t *testing.T) {
	rs := mustParse(t, stageRules+`alert tcp any any -> any 80 (msg:"exploit"; content:"EVIL"; sid:20; category:web;)
alert ip any any -> any any (msg:"cb"; detect:incident; kind:callback; sid:102; category:incident;)
`)
	e := NewEngine(rs, EngineConfig{})
	x, y := "10.0.0.1", "10.0.0.2"
	var all []Alert
	send := func(p pkt, d time.Duration) []Alert {
		out := e.Process(p.parsed(t, at(d)))
		all = append(all, out...)
		return out
	}
	send(pkt{proto: "tcp", src: x, dst: y, sport: 5000, dport: 80, flags: "S", seq: 100}, 0)
	send(pkt{proto: "tcp", src: y, dst: x, sport: 80, dport: 5000, flags: "SA", seq: 700, ack: 101}, time.Millisecond)
	send(pkt{proto: "tcp", src: x, dst: y, sport: 5000, dport: 80, flags: "A", seq: 101, ack: 701}, 2*time.Millisecond)
	if out := send(pkt{proto: "tcp", src: x, dst: y, sport: 5000, dport: 80, flags: "PA", seq: 101, ack: 701, payload: "EVIL"}, 3*time.Millisecond); len(out) != 1 {
		t.Fatalf("exploit: %s", alertLines(out))
	}
	// The attacker opening another connection is not a callback.
	if out := send(pkt{proto: "tcp", src: x, dst: y, sport: 5001, dport: 4444, flags: "S", seq: 1}, time.Second); len(out) != 0 {
		t.Errorf("x -> y: %s", alertLines(out))
	}
	out := send(pkt{proto: "tcp", src: y, dst: x, sport: 6000, dport: 4444, flags: "S", seq: 9}, 30*time.Second)
	if len(out) != 1 || out[0].Kind != KindIncident || out[0].SrcIP != y || out[0].DstPort != 4444 {
		t.Fatalf("callback: %s", alertLines(out))
	}
	// A retransmission of the SYN is not a new connection (and the
	// incident exists anyway), nor is a SYN-ACK.
	if out := send(pkt{proto: "tcp", src: y, dst: x, sport: 6000, dport: 4444, flags: "S", seq: 9}, 31*time.Second); len(out) != 0 {
		t.Errorf("retransmission: %s", alertLines(out))
	}
	if s := e.Stats(); s.Incidents != 1 || s.Alerts != 1 || s.Tables[TableIncidents].Keys != 1 || s.Tables[TableIncidentEntities].Keys != 2 {
		t.Errorf("stats incidents %d alerts %d tables %+v %+v", s.Incidents, s.Alerts, s.Tables[TableIncidents], s.Tables[TableIncidentEntities])
	}

	// Only new SYNs count: a retransmitted SYN within the window after a
	// fresh exploit does not.
	e2 := NewEngine(rs, EngineConfig{})
	e2.Process(pkt{proto: "tcp", src: y, dst: x, sport: 7000, dport: 4444, flags: "S", seq: 5}.parsed(t, at(0)))
	e2.corr.record(addrEntity(netip.MustParseAddr(y)), contribution{t: at(time.Millisecond), sid: 20, stage: 1, role: roleVictim, reliable: true,
		peer: addrEntity(netip.MustParseAddr(x))})
	if out := e2.Process(pkt{proto: "tcp", src: y, dst: x, sport: 7000, dport: 4444, flags: "S", seq: 5}.parsed(t, at(time.Second))); len(out) != 0 {
		t.Errorf("retransmitted SYN counted: %s", alertLines(out))
	}
	if out := e2.Process(pkt{proto: "tcp", src: y, dst: x, sport: 7001, dport: 4444, flags: "S", seq: 6}.parsed(t, at(2*time.Second))); len(out) != 1 {
		t.Errorf("new SYN: %s", alertLines(out))
	}
}

func TestCorrelatorCaps(t *testing.T) {
	t.Run("history", func(t *testing.T) {
		h := newCorrHarness(t, corrRules, 100)
		h.alert(10, atkIP, vicIP, true, 0)
		for i := range 200 {
			h.alert(20, atkIP, vicIP, true, time.Duration(i+1)*time.Second)
		}
		en := h.c.entity(addrEntity(netip.MustParseAddr(atkIP)))
		if len(en.hist) != corrHistCap {
			t.Fatalf("history %d", len(en.hist))
		}
		// The recon alert is kept: repeats are evicted first.
		if en.hist[0].sid != 10 || en.hist[len(en.hist)-1].t != at(200*time.Second) {
			t.Errorf("history %d..%v", en.hist[0].sid, en.hist[len(en.hist)-1].t.Sub(t0))
		}
		// Without repeats, the oldest goes.
		h = newCorrHarness(t, corrRules, 1000)
		for i := range corrHistCap + 1 {
			h.alert(20, atkIP, fmt.Sprintf("198.51.100.%d", i+1), true, time.Duration(i)*time.Second)
		}
		en = h.c.entity(addrEntity(netip.MustParseAddr(atkIP)))
		if len(en.hist) != corrHistCap || en.hist[0].peer.String() != "198.51.100.2" {
			t.Errorf("history %d from %s", len(en.hist), en.hist[0].peer)
		}
	})
	t.Run("entities", func(t *testing.T) {
		h := newCorrHarness(t, corrRules, 4)
		h.alert(10, "192.0.2.1", "192.0.2.2", true, 0)
		h.alert(10, "192.0.2.3", "192.0.2.4", true, time.Second)
		h.alert(10, "192.0.2.1", "192.0.2.5", true, 2*time.Second) // 192.0.2.2 is least recently active
		if h.c.entity(addrEntity(netip.MustParseAddr("192.0.2.2"))) != nil || h.c.entity(addrEntity(netip.MustParseAddr("192.0.2.1"))) == nil ||
			len(h.c.ents) != 4 || h.stats[0].evictions.Load() != 1 || h.stats[0].keys.Load() != 4 {
			t.Errorf("entities %d, evictions %d", len(h.c.ents), h.stats[0].evictions.Load())
		}
		if newCorrelator(50000, &h.stats[0], &h.stats[1]).max != corrMaxEntities {
			t.Error("entity cap above 10000")
		}
	})
	t.Run("expiry", func(t *testing.T) {
		h := newCorrHarness(t, corrRules, 100)
		h.alert(10, atkIP, vicIP, true, 0)
		h.alert(60, outIP, outIP, true, corrIdle) // exactly 24h: kept
		if len(h.c.ents) != 3 {
			t.Errorf("entities %d at 24h", len(h.c.ents))
		}
		h.alert(60, outIP, outIP, true, corrIdle+time.Second)
		if len(h.c.ents) != 1 || h.stats[0].keys.Load() != 1 {
			t.Errorf("entities %d after 24h", len(h.c.ents))
		}
		// Old contributions go even while the entity stays active.
		h = newCorrHarness(t, corrRules, 100)
		h.alert(10, atkIP, vicIP, true, 0)
		h.alert(60, atkIP, vic2IP, true, 20*time.Hour)
		h.alert(60, atkIP, vic2IP, true, 25*time.Hour)
		if en := h.c.entity(addrEntity(netip.MustParseAddr(atkIP))); len(en.hist) != 2 || en.hist[0].sid != 60 {
			t.Errorf("history %+v", en.hist)
		}
	})
	t.Run("incidents expire", func(t *testing.T) {
		h := newCorrHarness(t, corrRules, 100)
		h.alert(10, atkIP, vicIP, true, 0)
		h.alert(20, atkIP, vicIP, true, time.Minute)
		h.alert(20, atkIP, vicIP, true, 2*time.Minute) // no change
		h.alert(10, atkIP, vicIP, true, 25*time.Hour)
		h.alert(20, atkIP, vicIP, true, 25*time.Hour+time.Minute)
		out := incidentsOf(h.out, 100)
		if len(out) != 2 || out[0].Kind != KindIncident || out[1].Kind != KindIncident || out[0].Details["incident_id"] != out[1].Details["incident_id"] {
			t.Errorf("got %s", alertLines(out))
		}
	})
}

// TestIncidentUpdates: one incident, then one update per stage gained,
// however many alerts contribute.
func TestIncidentUpdates(t *testing.T) {
	h := newCorrHarness(t, corrRules, 100)
	d := time.Duration(0)
	step := func(sid, n int) {
		for range n {
			h.alert(sid, atkIP, vicIP, true, d)
			d += 10 * time.Second
		}
	}
	step(10, 50)
	step(20, 50)
	step(30, 50)
	step(40, 50)
	out := incidentsOf(h.out, 100)
	var kinds, chains []string
	for _, a := range out {
		kinds = append(kinds, a.Kind)
		chains = append(chains, a.Details["chain"])
	}
	if !slices.Equal(kinds, []string{KindIncident, KindIncidentUpdate, KindIncidentUpdate}) ||
		!slices.Equal(chains, []string{"recon -> exploit", "recon -> exploit -> c2", "recon -> exploit -> c2 -> exfil"}) {
		t.Errorf("got %s", alertLines(out))
	}
	last := out[len(out)-1]
	if n := strings.Count(last.Details["contributing"], ",") + 1; n != maxContributing {
		t.Errorf("contributing lists %d", n)
	}
	// Severity rising alone also updates: min_stages 2 means a
	// 2-stage incident is high, and going critical needs a 3rd stage,
	// so check severityRank directly instead.
	if severityRank(SeverityCritical) <= severityRank(SeverityHigh) || severityRank(SeverityHigh) <= severityRank(SeverityMedium) {
		t.Error("severity order")
	}
}

func TestIncidentID(t *testing.T) {
	k := incKey{sid: 100, a: addrEntity(netip.MustParseAddr(atkIP)), b: addrEntity(netip.MustParseAddr(vicIP))}
	id := incidentID(IncidentMultiStage, k)
	if id != incidentID(IncidentMultiStage, k) || !strings.HasPrefix(id, "inc-") || len(id) != 20 {
		t.Errorf("id %s", id)
	}
	k2 := k
	k2.a, k2.b = k.b, k.a
	if incidentID(IncidentMultiStage, k2) == id || incidentID(IncidentCallback, k) == id {
		t.Error("ids collide")
	}
	// Two engines see the same attack: the same id.
	ids := make([]string, 2)
	for i := range ids {
		h := newCorrHarness(t, corrRules, 100)
		h.alert(10, atkIP, vicIP, true, time.Duration(i)*time.Hour)
		h.alert(20, atkIP, vicIP, true, time.Duration(i)*time.Hour+time.Minute)
		ids[i] = incidentsOf(h.out, 100)[0].Details["incident_id"]
	}
	if ids[0] != ids[1] || ids[0] != id {
		t.Errorf("ids %v, want %s", ids, id)
	}
}

// TestCorrelatorReload: histories survive a reload with the same stages
// and are dropped when the stages change or incident rules go away.
func TestCorrelatorReload(t *testing.T) {
	h := newCorrHarness(t, corrRules, 100)
	h.alert(10, atkIP, vicIP, true, 0)
	h.c.use(mustParse(t, corrRules+`alert tcp any any -> any any (msg:"new"; sid:70;)`))
	if len(h.c.ents) != 2 {
		t.Errorf("same stages: %d entities", len(h.c.ents))
	}
	h.c.use(mustParse(t, strings.Replace(corrRules, "stage impact dos", "stage damage dos", 1)))
	if len(h.c.ents) != 0 || h.stats[0].keys.Load() != 0 {
		t.Errorf("new stages: %d entities", len(h.c.ents))
	}
	h.alert(10, atkIP, vicIP, true, time.Second)
	h.c.use(mustParse(t, stageRules))
	if len(h.c.ents) != 0 {
		t.Errorf("no incident rules: %d entities", len(h.c.ents))
	}
}

// TestARPEntity: arp_spoof alerts are recorded under the sender MAC.
func TestARPEntity(t *testing.T) {
	r := &Rule{Detect: DetectARPSpoof}
	p := pkt{proto: "arp", src: "192.0.2.1", dst: "192.0.2.2"}.parsed(t, t0)
	var v view
	v.init(p)
	a, tg := actorTarget(r, &v)
	if !a.isMAC || a.String() != "02:00:00:00:00:01" || tg.String() != "192.0.2.1" {
		t.Errorf("actor %s target %s", a, tg)
	}
	a, tg = actorTarget(&Rule{Detect: DetectNXDomainBurst}, &view{src: netip.MustParseAddr(outIP), dst: netip.MustParseAddr(vicIP)})
	if a.String() != vicIP || tg.valid() {
		t.Errorf("nxdomain actor %s target %s", a, tg)
	}
}
