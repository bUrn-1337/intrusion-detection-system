package intel

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func parse(t *testing.T, typ Type, text string) *Feed {
	t.Helper()
	f, err := Parse(strings.NewReader(text), "test", typ, "feed.txt")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func reasons(f *Feed) string {
	var b strings.Builder
	for _, p := range f.Problems {
		b.WriteString(p.String() + "\n")
	}
	return b.String()
}

func TestParseType(t *testing.T) {
	for _, typ := range []Type{IP, Domain, JA3} {
		got, ok := ParseType(typ.String())
		if !ok || got != typ {
			t.Errorf("ParseType(%q) = %v, %v", typ.String(), got, ok)
		}
	}
	for _, s := range []string{"", "IP", "url", "Type(0)"} {
		if _, ok := ParseType(s); ok {
			t.Errorf("ParseType(%q) accepted", s)
		}
	}
}

func TestIPRejections(t *testing.T) {
	for _, tc := range []struct{ entry, reason string }{
		{"10.1.2.3", "10.1.2.3 is private (RFC 1918, 10.0.0.0/8)"},
		{"172.16.0.1", "private (RFC 1918, 172.16.0.0/12)"},
		{"172.31.255.255", "172.16.0.0/12"},
		{"192.168.1.1", "192.168.0.0/16"},
		{"127.0.0.1", "loopback"},
		{"::1", "loopback (::1)"},
		{"169.254.10.10", "link-local (169.254.0.0/16)"},
		{"fe80::1", "link-local (fe80::/10)"},
		{"100.64.0.1", "carrier-grade NAT"},
		{"100.127.255.255", "carrier-grade NAT"},
		{"224.0.0.251", "multicast (224.0.0.0/4)"},
		{"239.255.255.250", "multicast"},
		{"ff02::fb", "multicast (ff00::/8)"},
		{"0.0.0.0", "this network"},
		{"::", "unspecified"},
		{"255.255.255.255", "limited broadcast"},
		{"fd12:3456::1", "unique local"},
		// A prefix that covers a reserved range.
		{"8.0.0.0/6", "includes a range that is private (RFC 1918, 10.0.0.0/8)"},
		{"0.0.0.0/0", "includes a range"},
		{"100.0.0.0/8", "includes a range that is carrier-grade NAT"},
		{"::/0", "includes a range"},
		// Invalid.
		{"1.2.3", "not an IP address"},
		{"1.2.3.4/33", "not an IP address"},
		{"256.1.1.1", "not an IP address"},
		{"example.com", "not an IP address"},
		{"fe80::1%eth0", "not an IP address"},
		{"1.2.3.4 5.6.7.8", "not an IP address"},
		{"::ffff:8.8.8.8", "IPv4-mapped"},
	} {
		f := parse(t, IP, tc.entry+"\n")
		if f.Rejected != 1 || f.Entries != 0 || len(f.Problems) != 1 {
			t.Errorf("%q: rejected %d, entries %d", tc.entry, f.Rejected, f.Entries)
			continue
		}
		p := f.Problems[0]
		if p.File != "feed.txt" || p.Line != 1 || !strings.Contains(p.Reason, tc.reason) {
			t.Errorf("%q: problem %v, want reason containing %q", tc.entry, p, tc.reason)
		}
	}
	// Neighbours of the reserved ranges, and documentation ranges, are
	// fine.
	for _, ok := range []string{"9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0",
		"192.167.255.255", "192.169.0.0", "100.63.255.255", "100.128.0.0", "126.255.255.255",
		"128.0.0.0", "169.253.255.255", "223.255.255.255", "240.0.0.1", "1.0.0.0",
		"192.0.2.1", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "2001:db8::/32",
		"fbff:ffff::1", "fe00::1", "fec0::1", "8.8.8.8"} {
		f := parse(t, IP, ok)
		if f.Rejected != 0 || f.Entries != 1 {
			t.Errorf("%q rejected: %s", ok, reasons(f))
		}
	}
}

func TestIPContains(t *testing.T) {
	f := parse(t, IP, `# comment
203.0.113.7
198.51.100.0/24   # a whole net
198.51.100.5      # inside the /24: merged
192.0.2.0/25
192.0.2.128/25    # adjacent: merged into one range
2001:db8:1::/48
2001:db8:1:5::1
10.0.0.1          # rejected
203.0.113.7       # duplicate
1.2.3.4/16        # host bits dropped: 1.2.0.0/16
`)
	if f.Entries != 8 || f.Rejected != 1 {
		t.Fatalf("entries %d, rejected %d: %s", f.Entries, f.Rejected, reasons(f))
	}
	if len(f.ips.v4) != 4 || len(f.ips.v6) != 1 {
		t.Errorf("ranges not merged: %v %v", f.ips.v4, f.ips.v6)
	}
	for addr, want := range map[string]bool{
		"203.0.113.7": true, "203.0.113.6": false, "203.0.113.8": false,
		"198.51.100.0": true, "198.51.100.255": true, "198.51.99.255": false, "198.51.101.0": false,
		"192.0.2.0": true, "192.0.2.127": true, "192.0.2.128": true, "192.0.2.255": true, "192.0.3.0": false,
		"1.2.0.0": true, "1.2.255.255": true, "1.3.0.0": false, "1.1.255.255": false,
		"::ffff:203.0.113.7": true,
		"2001:db8:1::":       true, "2001:db8:1:ffff:ffff:ffff:ffff:ffff": true, "2001:db8:2::": false,
		"2001:db8::ffff": false, "0.0.0.0": false, "255.255.255.255": false, "::": false,
		"10.0.0.1": false,
	} {
		if got := f.ContainsIP(netip.MustParseAddr(addr)); got != want {
			t.Errorf("ContainsIP(%s) = %v, want %v", addr, got, want)
		}
	}
	if f.ContainsIP(netip.Addr{}) {
		t.Error("the zero Addr matched")
	}
	var nilFeed *Feed
	if nilFeed.ContainsIP(netip.MustParseAddr("203.0.113.7")) {
		t.Error("nil feed matched")
	}
}

// The range set agrees with a linear scan over the prefixes.
func TestIPContainsMatchesLinear(t *testing.T) {
	var lines []string
	var prefixes []netip.Prefix
	for i := range 3000 {
		// Public-looking addresses spread over 1.0.0.0-9.255.255.255 and
		// 20.0.0.0 onward, with some nested and overlapping prefixes.
		a := netip.AddrFrom4([4]byte{byte(1 + i%9), byte(i * 7), byte(i * 13), byte(i * 31)})
		bits := []int{32, 24, 20, 16, 31, 12}[i%6]
		p := netip.PrefixFrom(a, bits).Masked()
		lines = append(lines, p.String())
		prefixes = append(prefixes, p)
	}
	f := parse(t, IP, strings.Join(lines, "\n"))
	if f.Rejected != 0 {
		t.Fatal(reasons(f))
	}
	for i := range 200000 {
		a := netip.AddrFrom4([4]byte{byte(1 + i%10), byte(i * 3), byte(i * 11), byte(i)})
		want := false
		for _, p := range prefixes {
			if p.Contains(a) {
				want = true
				break
			}
		}
		if got := f.ContainsIP(a); got != want {
			t.Fatalf("ContainsIP(%s) = %v, want %v", a, got, want)
		}
	}
}

func TestDomainRejections(t *testing.T) {
	for _, tc := range []struct{ entry, reason string }{
		{"com", "single label"},
		{"localhost", "single label"},
		{"exa mple.com", "not allowed"},
		{"example..com", "empty label"},
		{".example.com", "empty label"},
		{"exa$mple.com", "not allowed"},
		{"bücher.example", "not allowed"},
		{"123.456", "no letter"},
		{"192.0.2.1", "IP address"},
		{"2001:db8::1", "IP address"},
		{strings.Repeat("a", 64) + ".example", "longer than 63"},
		{strings.Repeat("abcdefghi.", 26) + "example", "longer than 253"},
		{"http://example.com/x", "not allowed"},
	} {
		f := parse(t, Domain, tc.entry)
		if f.Rejected != 1 || f.Entries != 0 || !strings.Contains(f.Problems[0].Reason, tc.reason) {
			t.Errorf("%q: rejected %d, problems %s; want reason containing %q", tc.entry, f.Rejected, reasons(f), tc.reason)
		}
	}
}

func TestDomainMatch(t *testing.T) {
	f := parse(t, Domain, `
evil.example        # and every name below it
Bad-Host.Example.Net.
*.wild.example
xn--bcher-kva.example
under_score.example.org
`)
	if f.Entries != 5 || f.Rejected != 0 {
		t.Fatalf("entries %d: %s", f.Entries, reasons(f))
	}
	for name, want := range map[string]string{
		"evil.example":            "evil.example",
		"EVIL.Example.":           "evil.example",
		"www.evil.example":        "evil.example",
		"a.b.c.evil.example":      "evil.example",
		"notevil.example":         "",
		"evil.example.com":        "",
		"example":                 "",
		"bad-host.example.net":    "bad-host.example.net",
		"x.BAD-HOST.example.net":  "bad-host.example.net",
		"example.net":             "",
		"host.example.net":        "",
		"wild.example":            "wild.example",
		"a.wild.example":          "wild.example",
		"xn--bcher-kva.example":   "xn--bcher-kva.example",
		"under_score.example.org": "under_score.example.org",
		"":                        "",
		".":                       "",
		"..evil.example":          "evil.example",
		strings.Repeat("a.", 130) + "evil.example": "",
	} {
		got, ok := f.MatchDomain(name)
		if got != want || ok != (want != "") {
			t.Errorf("MatchDomain(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	var nilFeed *Feed
	if _, ok := nilFeed.MatchDomain("evil.example"); ok {
		t.Error("nil feed matched")
	}
	// The shortest listed ancestor wins.
	f = parse(t, Domain, "a.evil.example\nevil.example\n")
	if got, _ := f.MatchDomain("x.a.evil.example"); got != "evil.example" {
		t.Errorf("nested: %q", got)
	}
}

func TestDomainMatchNoAlloc(t *testing.T) {
	f := parse(t, Domain, "evil.example\n")
	n := testing.AllocsPerRun(100, func() {
		f.MatchDomain("www.somewhere-else.example.com")
		f.MatchDomain("WWW.NOT-EVIL.EXAMPLE")
	})
	if n != 0 {
		t.Errorf("MatchDomain allocated %.0f times on a miss", n)
	}
}

func TestJA3Entries(t *testing.T) {
	f := parse(t, JA3, `
# hash[,label]
e7d705a3286e19ea42f587b344ee6865,Tofsee
E7D705A3286E19EA42F587B344EE6865,duplicate keeps the first label
6734f37431670b3ab4292b8f60f29984 , Trickbot
b386946a5a44d1ddcc843bc75336dfce
a0e9f5d64349fb13191bc781f81f42e1,label "with" bad;chars\and a very long tail that goes on past sixty-four bytes
not-a-hash
e7d705a3286e19ea42f587b344ee686,short
e7d705a3286e19ea42f587b344ee6865z
`)
	if f.Entries != 4 || f.Rejected != 3 {
		t.Fatalf("entries %d, rejected %d: %s", f.Entries, f.Rejected, reasons(f))
	}
	for hash, want := range map[string]string{
		"e7d705a3286e19ea42f587b344ee6865": "Tofsee",
		"E7D705A3286E19EA42F587B344EE6865": "Tofsee",
		"6734f37431670b3ab4292b8f60f29984": "Trickbot",
		"b386946a5a44d1ddcc843bc75336dfce": "",
		"a0e9f5d64349fb13191bc781f81f42e1": "label _with_ bad_chars_and a very long tail that goes on past si",
	} {
		got, ok := f.LookupJA3(hash)
		if !ok || got != want {
			t.Errorf("LookupJA3(%s) = %q, %v; want %q", hash, got, ok, want)
		}
	}
	for _, miss := range []string{"", "00000000000000000000000000000000", "e7d705a3286e19ea42f587b344ee686"} {
		if _, ok := f.LookupJA3(miss); ok {
			t.Errorf("LookupJA3(%q) matched", miss)
		}
	}
	for i, want := range []int{8, 9, 10} {
		if f.Problems[i].Line != want {
			t.Errorf("problem %d on line %d, want %d", i, f.Problems[i].Line, want)
		}
	}
}

func TestLineHandling(t *testing.T) {
	long := strings.Repeat("a", MaxLineLen) + ".example"
	f := parse(t, Domain, "\uFEFFfirst.example\r\n"+long+"\nafter.example # trailing comment\n  \n\t# indented comment\nlast.example")
	if f.Entries != 3 || f.Rejected != 1 || f.Problems[0].Line != 2 || !strings.Contains(f.Problems[0].Reason, "longer than") {
		t.Fatalf("entries %d, rejected %d: %s", f.Entries, f.Rejected, reasons(f))
	}
	for _, name := range []string{"first.example", "after.example", "last.example"} {
		if _, ok := f.MatchDomain(name); !ok {
			t.Errorf("%s missing", name)
		}
	}
	// Only MaxProblems problems are kept.
	f = parse(t, IP, strings.Repeat("10.0.0.1\n", MaxProblems+5)+"192.0.2.1\n")
	if f.Rejected != MaxProblems+5 || len(f.Problems) != MaxProblems || f.Entries != 1 {
		t.Errorf("rejected %d, problems %d, entries %d", f.Rejected, len(f.Problems), f.Entries)
	}
	// An empty file is an empty feed.
	if f := parse(t, JA3, ""); f.Entries != 0 || f.Rejected != 0 {
		t.Errorf("empty: %+v", f)
	}
	if _, err := Parse(strings.NewReader(""), "x", 0, "p"); err == nil {
		t.Error("type 0 accepted")
	}
}

func TestMaxEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a feed of MaxEntries lines")
	}
	var b strings.Builder
	for i := range MaxEntries + 3 {
		fmt.Fprintf(&b, "h%d.example\n", i)
	}
	f := parse(t, Domain, b.String())
	if f.Entries != MaxEntries || f.Rejected != 3 || !strings.Contains(f.Problems[0].Reason, "the 3 lines after this one are ignored") {
		t.Errorf("entries %d, rejected %d: %s", f.Entries, f.Rejected, reasons(f))
	}
}

func TestLoadAndStaleness(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	f, err := Load("x", IP, path)
	if err != nil {
		t.Fatal(err)
	}
	if !f.ModTime.Equal(old) || f.MaxAge != DefaultMaxAge || f.Name != "x" || f.Path != path {
		t.Errorf("feed %+v", f)
	}
	if got := f.Age(old.Add(time.Hour)); got != time.Hour {
		t.Errorf("Age = %v", got)
	}
	if f.Stale(old.Add(DefaultMaxAge)) || !f.Stale(old.Add(DefaultMaxAge+time.Second)) {
		t.Error("stale boundary")
	}
	f.MaxAge = 0
	if f.Stale(old.Add(1000 * DefaultMaxAge)) {
		t.Error("MaxAge 0 is never stale")
	}

	// Reloading the file picks up new entries and the new mtime.
	if err := os.WriteFile(path, []byte("192.0.2.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := Load("x", IP, path)
	if err != nil {
		t.Fatal(err)
	}
	if g.ContainsIP(netip.MustParseAddr("192.0.2.1")) || !g.ContainsIP(netip.MustParseAddr("192.0.2.2")) || !g.ModTime.After(old) {
		t.Errorf("reloaded feed %+v", g)
	}
	// The first feed is unchanged.
	if !f.ContainsIP(netip.MustParseAddr("192.0.2.1")) {
		t.Error("old feed changed")
	}

	if _, err := Load("x", IP, filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("missing file loaded")
	}
	if _, err := Load("x", IP, dir); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("directory: %v", err)
	}
	// Devices and FIFOs are refused before they are opened: reading them
	// would block or never end.
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fifo, "/dev/zero", "/dev/null"} {
		if _, err := Load("x", IP, p); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Errorf("%s: %v", p, err)
		}
	}
	// A symlink to a regular file is fine.
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if g, err := Load("x", IP, link); err != nil || g.Entries != 1 {
		t.Errorf("symlink: %v", err)
	}
}

func FuzzFeed(f *testing.F) {
	f.Add(uint8(IP), "203.0.113.7\n198.51.100.0/24 # c\n10.0.0.1\n::1\n2001:db8::/32\n")
	f.Add(uint8(Domain), "evil.example\n*.x.example.\ncom\n192.0.2.1\n")
	f.Add(uint8(JA3), "e7d705a3286e19ea42f587b344ee6865,Tofsee\nzz\n")
	f.Fuzz(func(t *testing.T, typ uint8, text string) {
		typ = typ%3 + 1
		feed, err := Parse(strings.NewReader(text), "fuzz", Type(typ), "f")
		if err != nil {
			t.Fatal(err)
		}
		if feed.Entries < 0 || feed.Rejected < len(feed.Problems) || len(feed.Problems) > MaxProblems {
			t.Fatalf("counts: %+v", feed)
		}
		for _, line := range strings.Split(text, "\n") {
			line, _, _ = strings.Cut(line, "#")
			line = strings.TrimSpace(line)
			switch Type(typ) {
			case IP:
				// Every accepted address matches, and none is reserved.
				if p, reason := parseIPEntry(line); reason == "" {
					if !feed.ContainsIP(p.Addr()) {
						t.Fatalf("%s accepted but not contained", p)
					}
				}
			case Domain:
				if key, reason := domainKey(line); reason == "" {
					if _, ok := feed.MatchDomain("sub." + strings.TrimPrefix(line, "*.")); !ok {
						t.Fatalf("subdomain of %q (key %q) not matched", line, key)
					}
				}
			}
		}
		for _, r := range reserved {
			if feed.ContainsIP(r.p.Addr()) {
				t.Fatalf("reserved %s matched", r.p)
			}
		}
	})
}

// ---- benchmarks: 100k entries ----

func bigIPFeed(b *testing.B) *Feed {
	var sb strings.Builder
	for i := range 100_000 {
		// 20.0.0.0 onward: public, distinct /32s and some /24s.
		if i%10 == 0 {
			fmt.Fprintf(&sb, "%d.%d.%d.0/24\n", 20+i>>16, byte(i>>8), byte(i))
		} else {
			fmt.Fprintf(&sb, "%d.%d.%d.%d\n", 20+i>>16, byte(i>>8), byte(i), byte(i*7))
		}
	}
	f, err := Parse(strings.NewReader(sb.String()), "b", IP, "b")
	if err != nil || f.Entries != 100_000 {
		b.Fatalf("%v %d %s", err, f.Entries, reasons(f))
	}
	return f
}

func bigDomainFeed(b *testing.B) *Feed {
	var sb strings.Builder
	for i := range 100_000 {
		fmt.Fprintf(&sb, "host%d.bad%d.example\n", i, i%977)
	}
	f, err := Parse(strings.NewReader(sb.String()), "b", Domain, "b")
	if err != nil || f.Entries != 100_000 {
		b.Fatalf("%v %d", err, f.Entries)
	}
	return f
}

func BenchmarkLoadIP100k(b *testing.B) {
	for b.Loop() {
		bigIPFeed(b)
	}
}

func BenchmarkLoadDomain100k(b *testing.B) {
	for b.Loop() {
		bigDomainFeed(b)
	}
}

func BenchmarkContainsIP100k(b *testing.B) {
	f := bigIPFeed(b)
	addrs := make([]netip.Addr, 1024)
	for i := range addrs {
		addrs[i] = netip.AddrFrom4([4]byte{byte(20 + i%3), byte(i * 7), byte(i * 13), byte(i)})
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		f.ContainsIP(addrs[i&1023])
		i++
	}
}

func BenchmarkMatchDomain100k(b *testing.B) {
	f := bigDomainFeed(b)
	names := make([]string, 1024)
	for i := range names {
		if i%2 == 0 {
			names[i] = fmt.Sprintf("www.cdn%d.provider.example.com", i) // miss
		} else {
			names[i] = fmt.Sprintf("a.host%d.bad%d.example", i, i%977) // hit
		}
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		f.MatchDomain(names[i&1023])
		i++
	}
}
