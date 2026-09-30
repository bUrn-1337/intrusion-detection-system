package rules

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/intel"
	"github.com/bUrn-1337/intrusion-detection-system/internal/testutil/pcapgen"
)

// feedDir writes files (name -> content) into a temp dir and returns it.
func feedDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// loadIn writes rules into dir/rules.conf and loads it.
func loadIn(t *testing.T, dir, rules string) (*RuleSet, error) {
	t.Helper()
	path := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(path, []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

var testFeeds = map[string]string{
	"ips.txt":     "# test feed\n203.0.113.66\n198.51.100.0/24\n10.0.0.1\n2001:db8:bad::/48\n",
	"domains.txt": "evil.example\nbad.example.net # c2\nlocalhost\n",
	"ja3.txt":     "e7d705a3286e19ea42f587b344ee6865,Tofsee\n6734f37431670b3ab4292b8f60f29984\n",
}

const feedRules = `feed ip bad_ips ips.txt
feed domain bad_domains domains.txt max_age:30d
feed ja3 bad_ja3 ja3.txt max_age:0
alert ip any any -> any any (msg:"ip feed"; ip_feed:bad_ips; sid:1;)
alert udp any any -> any 53 (msg:"dns feed"; app_proto:dns; domain_feed:bad_domains,qname; sid:2;)
alert tcp any any -> any any (msg:"any name feed"; domain_feed:bad_domains; sid:3;)
alert tcp any any -> any any (msg:"ja3 labeled"; ja3_feed:bad_ja3,labeled; sid:4; severity:critical;)
alert tcp any any -> any any (msg:"ja3 unlabeled"; ja3_feed:bad_ja3,unlabeled; sid:5; severity:high;)
alert tcp any any -> any any (msg:"ja3 any"; ja3_feed:bad_ja3; sid:6;)
`

func TestFeedDirectives(t *testing.T) {
	dir := feedDir(t, testFeeds)
	rs, err := loadIn(t, dir, feedRules)
	if err != nil {
		t.Fatal(err)
	}
	feeds := rs.Feeds()
	if len(feeds) != 3 || feeds[0].Name != "bad_ips" || feeds[1].Name != "bad_domains" || feeds[2].Name != "bad_ja3" {
		t.Fatalf("feeds %v", feeds)
	}
	if feeds[0].Entries != 3 || feeds[0].Rejected != 1 || feeds[1].Entries != 2 || feeds[1].Rejected != 1 || feeds[2].Entries != 2 {
		t.Errorf("counts: %+v %+v %+v", feeds[0], feeds[1], feeds[2])
	}
	if feeds[0].MaxAge != intel.DefaultMaxAge || feeds[1].MaxAge != 30*24*time.Hour || feeds[2].MaxAge != 0 {
		t.Errorf("max ages %v %v %v", feeds[0].MaxAge, feeds[1].MaxAge, feeds[2].MaxAge)
	}
	if feeds[0].Path != filepath.Join(dir, "ips.txt") {
		t.Errorf("path %s: relative paths are relative to the rules file", feeds[0].Path)
	}
	want := []string{
		"feed bad_ips: " + filepath.Join(dir, "ips.txt") + ":4: 10.0.0.1 is private (RFC 1918, 10.0.0.0/8)",
		"feed bad_domains: " + filepath.Join(dir, "domains.txt") + ":3: \"localhost\" is not a domain name: a single label would match a whole top-level domain",
	}
	if got := rs.Warnings(); !slicesEqual(got, want) {
		t.Errorf("warnings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	st := NewEngine(rs, EngineConfig{}).Stats()
	if len(st.Feeds) != 3 || st.Feeds[0] != (FeedStats{Name: "bad_ips", Type: "ip", Path: feeds[0].Path, Entries: 3, Rejected: 1,
		ModTime: feeds[0].ModTime, MaxAge: intel.DefaultMaxAge}) {
		t.Errorf("Stats.Feeds %+v", st.Feeds)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFeedErrors(t *testing.T) {
	dir := feedDir(t, testFeeds)
	for _, tc := range []struct{ rules, want string }{
		{"feed ip x", "want feed TYPE NAME PATH"},
		{"feed ip x a b c", "want feed TYPE NAME PATH"},
		{"feed url x ips.txt", `feed type "url": want ip, domain or ja3`},
		{"feed ip x$ ips.txt", `feed name "x$"`},
		{"feed ip x ips.txt\nfeed domain x domains.txt", "feed x defined twice (first defined on line 1)"},
		{"feed ip x missing.txt", "feed x: stat " + filepath.Join(dir, "missing.txt") + ": no such file"},
		{"feed ip x ips.txt max_age:soon", `"max_age:soon": want max_age:DURATION`},
		{"feed ip x ips.txt age:7d", `"age:7d": want max_age:DURATION`},
		{"feed ip x ips.txt max_age:-1h", "want max_age:DURATION"},
		{"feed ip x ips.txt max_age:99999d", "want max_age:DURATION"},
		{`alert ip any any -> any any (msg:"m"; ip_feed:nope; sid:1;)`, `ip_feed: no feed named "nope" (define it with: feed ip nope PATH)`},
		{"feed domain d domains.txt\n" + `alert ip any any -> any any (msg:"m"; ip_feed:d; sid:1;)`, "ip_feed: feed d holds domain entries, not ip"},
		{"feed ip i ips.txt\n" + `alert ip any any -> any any (msg:"m"; domain_feed:i; sid:1;)`, "domain_feed: feed i holds ip entries, not domain"},
		{"feed ip i ips.txt\n" + `alert ip any any -> any any (msg:"m"; ja3_feed:i; sid:1;)`, "ja3_feed: feed i holds ip entries, not ja3"},
		{"feed ip i ips.txt\n" + `alert ip any any -> any any (msg:"m"; ip_feed:i,src; sid:1;)`, `ip_feed "i,src": want ip_feed:NAME`},
		{"feed domain d domains.txt\n" + `alert ip any any -> any any (msg:"m"; domain_feed:d,a=b; sid:1;)`, `domain_feed key "a=b"`},
		{"feed ja3 j ja3.txt\n" + `alert ip any any -> any any (msg:"m"; ja3_feed:j,maybe; sid:1;)`, "want ja3_feed:NAME, ja3_feed:NAME,labeled or ja3_feed:NAME,unlabeled"},
		{"feed ip i ips.txt\n" + `alert ip any any -> any any (msg:"m"; ip_feed:i; ip_feed:i; sid:1;)`, "option ip_feed given more than once"},
		{"feed ip i ips.txt\n" + `alert ip any any -> any any (msg:"m"; ip_feed:i; detect:port_scan; distinct_ports:5; seconds:5; sid:1;)`, "option ip_feed cannot be combined with detect"},
		{"feed ip i ips.txt\n" + `alert arp any any -> any any (msg:"m"; ip_feed:i; sid:1;)`, "ip_feed requires an IP protocol"},
		{"feed domain d domains.txt\n" + `alert icmp any any -> any any (msg:"m"; domain_feed:d; sid:1;)`, "domain_feed, ja3_feed and regex on a field require protocol ip, tcp or udp"},
		{"feed ip i ips.txt\n" + `alert ip any any -> any any (msg:"m"; ip_feed; sid:1;)`, "option ip_feed needs a value"},
	} {
		_, err := loadIn(t, dir, tc.rules)
		var le *LoadError
		if !errors.As(err, &le) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q:\n got %v\nwant %q", tc.rules, err, tc.want)
		}
	}
	// A feed directory is an error, as is an empty feed a warning.
	if _, err := loadIn(t, dir, "feed ip x "+dir); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("directory: %v", err)
	}
	empty := feedDir(t, map[string]string{"e.txt": "# nothing yet\n"})
	rs, err := loadIn(t, empty, "feed ip e e.txt")
	if err != nil || len(rs.Warnings()) != 1 || !strings.Contains(rs.Warnings()[0], "has no valid entries") {
		t.Errorf("empty feed: %v %v", err, rs)
	}
	// An absolute path is used as is.
	rs, err = loadIn(t, t.TempDir(), "feed ip x "+filepath.Join(dir, "ips.txt"))
	if err != nil || rs.Feeds()[0].Entries != 3 {
		t.Errorf("absolute path: %v", err)
	}
}

func TestParseAge(t *testing.T) {
	for s, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "0": 0, "0d": 0, "12h": 12 * time.Hour, "90m": 90 * time.Minute, "3650d": maxFeedAge} {
		if got, err := parseAge(s); err != nil || got != want {
			t.Errorf("parseAge(%q) = %v, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "d", "7", "-1d", "3651d", "1.5d", "-5m", "87601h", "7w"} {
		if _, err := parseAge(s); err == nil {
			t.Errorf("parseAge(%q) accepted", s)
		}
	}
}

func feedEngine(t *testing.T) *Engine {
	t.Helper()
	rs, err := loadIn(t, feedDir(t, testFeeds), feedRules)
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine(rs, EngineConfig{})
}

func TestIPFeedMatch(t *testing.T) {
	e := feedEngine(t)
	cases := []struct {
		p       pkt
		details map[string]string // nil: no alert
	}{
		{pkt{proto: "tcp", src: "192.0.2.10", dst: "203.0.113.66", sport: 40000, dport: 443, flags: "S"},
			map[string]string{"ip_feed": "bad_ips", "side": "dst", "indicator": "203.0.113.66", "attribution": "spoofable"}},
		// Same indicator and peer, other port: deduplicated.
		{pkt{proto: "tcp", src: "192.0.2.10", dst: "203.0.113.66", sport: 40001, dport: 80, flags: "S"}, nil},
		// The indicator talks to another host: a new alert.
		{pkt{proto: "udp", src: "198.51.100.9", dst: "192.0.2.11", sport: 53, dport: 5353},
			map[string]string{"ip_feed": "bad_ips", "side": "src", "indicator": "198.51.100.9", "attribution": "spoofable"}},
		// Reply direction of the first flow: same indicator and peer.
		{pkt{proto: "tcp", src: "203.0.113.66", dst: "192.0.2.10", sport: 443, dport: 40000, flags: "SA"}, nil},
		{pkt{proto: "icmp", src: "198.51.100.1", dst: "198.51.100.2"},
			map[string]string{"ip_feed": "bad_ips", "side": "both", "indicator": "198.51.100.1,198.51.100.2", "attribution": "spoofable"}},
		{pkt{proto: "tcp", src: "2001:db8::1", dst: "2001:db8:bad:1::5", sport: 1, dport: 2, flags: "S"},
			map[string]string{"ip_feed": "bad_ips", "side": "dst", "indicator": "2001:db8:bad:1::5", "attribution": "spoofable"}},
		// Rejected and unlisted addresses.
		{pkt{proto: "tcp", src: "192.0.2.10", dst: "10.0.0.1", sport: 40000, dport: 443, flags: "S"}, nil},
		{pkt{proto: "tcp", src: "192.0.2.10", dst: "203.0.113.67", sport: 40000, dport: 443, flags: "S"}, nil},
	}
	for i, tc := range cases {
		out := e.Process(tc.p.parsed(t, at(time.Duration(i)*time.Second)))
		var got map[string]string
		for _, a := range out {
			if a.SID == 1 && a.Kind == KindAlert {
				got = a.Details
			}
		}
		if !maps.Equal(got, tc.details) {
			t.Errorf("case %d %s->%s: details %v, want %v%s", i, tc.p.src, tc.p.dst, got, tc.details, alertLines(out))
		}
	}
}

func TestDomainFeedMatch(t *testing.T) {
	e := feedEngine(t)
	http := func(src, host string) pkt {
		return pkt{proto: "tcp", src: src, dst: "192.0.2.80", sport: 40000, dport: 80, flags: "PA", seq: 1, ack: 1,
			payload: "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"}
	}
	tls := func(src, sni string) pkt {
		return pkt{proto: "tcp", src: src, dst: "192.0.2.43", sport: 40000, dport: 443, flags: "PA", seq: 1, ack: 1,
			payload: string(pcapgen.TLSClientHello(sni))}
	}
	cases := []struct {
		p    pkt
		sids map[int]map[string]string
	}{
		{dnsQ("192.0.2.1", 5000, "192.0.2.53", 1, "evil.example", 1), map[int]map[string]string{
			2: {"domain_feed": "bad_domains", "field": "qname", "name": "evil.example", "indicator": "evil.example", "attribution": "spoofable"}}},
		{dnsQ("192.0.2.2", 5000, "192.0.2.53", 2, "WWW.Bad.Example.Net", 1), map[int]map[string]string{
			2: {"domain_feed": "bad_domains", "field": "qname", "name": "www.bad.example.net", "indicator": "bad.example.net", "attribution": "spoofable"}}},
		// The response to the first query: the same lookup, no alert.
		{dnsR("192.0.2.53", "192.0.2.1", 5000, 1, "evil.example", 1, 0, 0), nil},
		{dnsQ("192.0.2.3", 5000, "192.0.2.53", 3, "notevil.example", 1), nil},
		{dnsQ("192.0.2.3", 5000, "192.0.2.53", 4, "localhost", 1), nil},
		{tls("192.0.2.4", "cdn.evil.example"), map[int]map[string]string{
			3: {"domain_feed": "bad_domains", "field": "sni", "name": "cdn.evil.example", "indicator": "evil.example", "attribution": "reliable"}}},
		{http("192.0.2.5", "evil.example:8080"), map[int]map[string]string{
			3: {"domain_feed": "bad_domains", "field": "host", "name": "evil.example:8080", "indicator": "evil.example", "attribution": "reliable"}}},
		{http("192.0.2.6", "evil.example.com"), nil},
		{tls("192.0.2.7", "example.net"), nil},
	}
	for i, tc := range cases {
		out := e.Process(tc.p.parsed(t, at(time.Duration(i)*time.Second)))
		got := make(map[int]map[string]string)
		for _, a := range out {
			if a.Kind == KindAlert && a.SID >= 2 && a.SID <= 3 {
				got[a.SID] = a.Details
			}
		}
		if len(got) != len(tc.sids) {
			t.Errorf("case %d: alerts %s, want sids %v", i, alertLines(out), tc.sids)
			continue
		}
		for sid, d := range tc.sids {
			if !maps.Equal(got[sid], d) {
				t.Errorf("case %d sid %d: details %v, want %v", i, sid, got[sid], d)
			}
		}
	}
}

func TestJA3FeedMatch(t *testing.T) {
	// ClientHellos whose JA3 hashes are put in the feed.
	labeled := pcapgen.ClientHello{SNI: "a.example", Ciphers: []uint16{0x1301}, Groups: []uint16{29}, Points: []byte{0}}
	unlabeled := pcapgen.ClientHello{SNI: "b.example", Ciphers: []uint16{0x1302}}
	other := pcapgen.ClientHello{SNI: "c.example", Ciphers: []uint16{0x1303}}
	hash := func(c pcapgen.ClientHello) string {
		p := pkt{proto: "tcp", src: "192.0.2.1", dst: "192.0.2.2", sport: 1, dport: 443, flags: "PA", seq: 1, ack: 1, payload: string(c.Record())}
		h := p.parsed(t, t0).AppFields["ja3_hash"]
		if len(h) != 32 {
			t.Fatalf("no ja3_hash for %+v", c)
		}
		return h
	}
	dir := feedDir(t, map[string]string{"ja3.txt": strings.ToUpper(hash(labeled)) + ", Evil Family\n" + hash(unlabeled) + "\n"})
	rs, err := loadIn(t, dir, `feed ja3 j ja3.txt
alert tcp any any -> any any (msg:"labeled"; ja3_feed:j,labeled; sid:4; severity:critical;)
alert tcp any any -> any any (msg:"unlabeled"; ja3_feed:j,unlabeled; sid:5; severity:high;)
alert tcp any any -> any any (msg:"any"; ja3_feed:j; sid:6;)
`)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(rs, EngineConfig{})
	for i, tc := range []struct {
		c    pcapgen.ClientHello
		sids map[int]map[string]string
	}{
		{labeled, map[int]map[string]string{
			4: {"ja3_feed": "j", "ja3_hash": hash(labeled), "label": "Evil Family", "attribution": "reliable"},
			6: {"ja3_feed": "j", "ja3_hash": hash(labeled), "label": "Evil Family", "attribution": "reliable"}}},
		{unlabeled, map[int]map[string]string{
			5: {"ja3_feed": "j", "ja3_hash": hash(unlabeled), "attribution": "reliable"},
			6: {"ja3_feed": "j", "ja3_hash": hash(unlabeled), "attribution": "reliable"}}},
		{other, nil},
	} {
		p := pkt{proto: "tcp", src: "192.0.2." + string(rune('1'+i)), dst: "198.51.100.1", sport: 40000, dport: 443, flags: "PA", seq: 1, ack: 1, payload: string(tc.c.Record())}
		out := e.Process(p.parsed(t, at(time.Duration(i)*time.Second)))
		got := make(map[int]map[string]string)
		for _, a := range out {
			got[a.SID] = a.Details
			if a.SID == 4 && a.Severity != SeverityCritical || a.SID == 5 && a.Severity != SeverityHigh {
				t.Errorf("sid %d severity %s", a.SID, a.Severity)
			}
		}
		if len(got) != len(tc.sids) {
			t.Errorf("case %d: %s, want %v", i, alertLines(out), tc.sids)
			continue
		}
		for sid, d := range tc.sids {
			if !maps.Equal(got[sid], d) {
				t.Errorf("case %d sid %d: %v, want %v", i, sid, got[sid], d)
			}
		}
	}
}

// Reloading the rules reloads their feeds; a failed reload keeps the old
// feeds.
func TestFeedReload(t *testing.T) {
	dir := feedDir(t, map[string]string{"ips.txt": "203.0.113.1\n"})
	rules := "feed ip f ips.txt\n" + `alert ip any any -> any any (msg:"m"; ip_feed:f; sid:1;)` + "\n"
	rs, err := loadIn(t, dir, rules)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(rs, EngineConfig{})
	send := func(i int, dst string) int {
		p := pkt{proto: "udp", src: "192.0.2.1", dst: dst, sport: 1000, dport: 2000}
		return len(e.Process(p.parsed(t, at(time.Duration(i)*time.Second))))
	}
	if send(0, "203.0.113.1") != 1 || send(1, "203.0.113.2") != 0 {
		t.Fatal("before reload")
	}
	if err := os.WriteFile(filepath.Join(dir, "ips.txt"), []byte("203.0.113.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The file changed, but nothing reloaded yet: the old feed is in use.
	if send(2, "203.0.113.2") != 0 {
		t.Error("feed changed without a reload")
	}
	if err := e.Reload(filepath.Join(dir, "rules.conf")); err != nil {
		t.Fatal(err)
	}
	if send(3, "203.0.113.2") != 1 || send(4, "203.0.113.9") != 0 {
		t.Error("after reload")
	}
	if st := e.Stats(); len(st.Feeds) != 1 || st.Feeds[0].Entries != 1 {
		t.Errorf("stats %+v", st.Feeds)
	}
	// A missing feed fails the reload; the loaded feed stays.
	if err := os.Remove(filepath.Join(dir, "ips.txt")); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(filepath.Join(dir, "rules.conf")); err == nil {
		t.Fatal("reload with a missing feed succeeded")
	}
	if send(5, "203.0.113.2") != 0 { // deduplicated, but still matched
		t.Error("dedup")
	}
	if st := e.Stats(); st.ReloadFails != 1 || len(st.Feeds) != 1 {
		t.Errorf("stats after failed reload %+v", st)
	}
	if send(6, "198.51.100.1") != 0 {
		t.Error("unexpected match")
	}
}

func TestStripPort(t *testing.T) {
	for in, want := range map[string]string{
		"evil.example": "evil.example", "evil.example:8080": "evil.example", "evil.example:": "evil.example",
		"[2001:db8::1]:80": "[2001:db8::1]", "[2001:db8::1]": "[2001:db8::1]", "a:b": "a:b", "": "",
	} {
		if got := stripPort(in); got != want {
			t.Errorf("stripPort(%q) = %q, want %q", in, got, want)
		}
	}
}
