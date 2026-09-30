package rules

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Fragment attack detector tests. Fragments are raw frames from fragFrame,
// run through the real parsers.

const fragRules = `alert ip any any -> any any (msg:"overlap"; sid:21; detect:frag_attack; kind:overlap;)
alert ip any any -> any any (msg:"tiny"; sid:22; detect:frag_attack; kind:tiny;)
alert ip any any -> any any (msg:"oversize"; sid:23; detect:frag_attack; kind:oversize;)
alert ip any any -> any any (msg:"flood"; sid:24; detect:frag_attack; kind:flood; count:3; seconds:30;)
`

const (
	fragSrc  = "203.0.113.9"
	fragDst  = "192.0.2.10"
	fragSrc6 = "2001:db8::9"
	fragDst6 = "2001:db8::10"
)

// tfrag is one fragment at one time.
type tfrag struct {
	ts      time.Duration
	src     string // default fragSrc
	id      uint32
	proto   uint8 // default 17
	offset  int
	mf      bool
	n       int // payload bytes
	payload []byte
}

func (f tfrag) frame(tb testing.TB, v6 bool) []byte {
	src, dst := fragSrc, fragDst
	if v6 {
		src, dst = fragSrc6, fragDst6
	}
	if f.src != "" {
		src = f.src
	}
	proto := f.proto
	if proto == 0 {
		proto = 17
	}
	data := f.payload
	if data == nil {
		data = make([]byte, f.n)
	}
	return fragFrame(tb, src, dst, f.id, proto, f.offset, f.mf, data)
}

// runFrags feeds frags to a new engine and returns the alerts (not
// summaries) by sid, and the engine.
func runFrags(t *testing.T, rules string, cfg EngineConfig, v6 bool, frags []tfrag) (map[int][]Alert, *Engine) {
	t.Helper()
	e := NewEngine(mustParse(t, rules), cfg)
	var out []Alert
	for _, f := range frags {
		out = append(out, e.Process(parseFrame(f.frame(t, v6), at(f.ts)))...)
	}
	out = append(out, e.Flush()...)
	got := make(map[int][]Alert)
	for _, a := range out {
		if a.Kind == KindAlert {
			got[a.SID] = append(got[a.SID], a)
		}
	}
	return got, e
}

func fragSIDs(got map[int][]Alert) string {
	var parts []string
	for _, sid := range slices.Sorted(mapsKeys(got)) {
		parts = append(parts, strconv.Itoa(sid)+"x"+strconv.Itoa(len(got[sid])))
	}
	return strings.Join(parts, " ")
}

func mapsKeys(m map[int][]Alert) func(func(int) bool) {
	return func(yield func(int) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// udpFirst returns a first-fragment payload: an 8-byte UDP header and
// zeros, n bytes in all.
func udpFirst(n int) []byte {
	b := make([]byte, n)
	b[0], b[1], b[2], b[3] = 0x13, 0x88, 0, 53
	return b
}

func TestFragAttack(t *testing.T) {
	ms := time.Millisecond
	s := time.Second
	// A correct two-fragment datagram: 1480 bytes then 520.
	good := []tfrag{{id: 1, offset: 0, mf: true, payload: udpFirst(1480)}, {ts: ms, id: 1, offset: 1480, n: 520}}
	tests := []struct {
		name  string
		frags []tfrag
		want  string // sid x alerts, e.g. "21x1"
	}{
		{"good datagram", good, ""},
		{"out of order", []tfrag{good[1], good[0]}, ""},

		// overlap
		{"overlap", []tfrag{{id: 1, mf: true, payload: udpFirst(1480)}, {ts: ms, id: 1, offset: 1472, n: 528}}, "21x1"},
		{"overlap contained", []tfrag{{id: 1, mf: true, payload: udpFirst(1480)}, {ts: ms, id: 1, offset: 8, mf: true, n: 256}}, "21x1"},
		{"overlap after complete", append(slices.Clone(good), tfrag{ts: 2 * ms, id: 1, offset: 1000, n: 520}), "21x1"},
		{"exact duplicate", []tfrag{good[0], good[0], good[1], good[1]}, ""},
		{"adjacent", []tfrag{{id: 1, mf: true, payload: udpFirst(1480)}, {id: 1, offset: 1480, mf: true, n: 1480}, {id: 1, offset: 2960, n: 8}}, ""},
		{"other id", []tfrag{{id: 1, mf: true, payload: udpFirst(1480)}, {id: 2, offset: 1472, n: 528}}, ""},
		{"other proto", []tfrag{{id: 1, mf: true, payload: udpFirst(1480)}, {id: 1, proto: 6, offset: 1472, n: 528}}, ""},
		{"other source", []tfrag{{id: 1, mf: true, payload: udpFirst(1480)}, {id: 1, src: "203.0.113.8", offset: 1472, n: 528}}, ""},
		// Timeout 30s: a fragment 30s after the first starts a new datagram.
		{"overlap before timeout", []tfrag{{id: 1, mf: true, payload: udpFirst(1480)}, {ts: 30*s - ms, id: 1, offset: 1472, n: 528}}, "21x1"},
		{"overlap after timeout", []tfrag{{id: 1, mf: true, payload: udpFirst(1480)}, {ts: 30 * s, id: 1, offset: 1472, n: 528}}, ""},

		// tiny (min_size 256)
		{"tiny non-final", []tfrag{{id: 1, mf: true, payload: udpFirst(248)}, {id: 1, offset: 248, n: 8}}, "22x1"},
		{"min_size edge", []tfrag{{id: 1, mf: true, payload: udpFirst(256)}, {id: 1, offset: 256, n: 8}}, ""},
		{"small final ok", []tfrag{{id: 1, mf: true, payload: udpFirst(1480)}, {id: 1, offset: 1480, n: 1}}, ""},

		// oversize: the last byte may be at 65534 (end 65535).
		{"ping of death", []tfrag{{id: 1, proto: 1, offset: 65528, n: 8}}, "23x1"},
		{"oversize edge", []tfrag{{id: 1, proto: 1, offset: 65528, n: 7}}, ""},
		{"oversize long", []tfrag{{id: 1, proto: 1, offset: 65000, n: 1000}}, "23x1"},
	}
	for _, v6 := range []bool{false, true} {
		for _, tt := range tests {
			name := tt.name
			if v6 {
				name += " v6"
			}
			t.Run(name, func(t *testing.T) {
				want := tt.want
				if v6 && tt.name == "other proto" {
					want = "21x1" // the IPv6 key has no protocol
				}
				got, _ := runFrags(t, fragRules, EngineConfig{}, v6, tt.frags)
				if s := fragSIDs(got); s != want {
					t.Errorf("fired %q, want %q", s, want)
				}
			})
		}
	}
}

func TestFragOverlapDetails(t *testing.T) {
	got, _ := runFrags(t, fragRules, EngineConfig{}, false, []tfrag{
		{id: 77, mf: true, payload: udpFirst(1480)},
		{ts: time.Millisecond, id: 77, offset: 1472, n: 528},
	})
	a := got[21]
	if len(a) != 1 {
		t.Fatalf("alerts %v", fragSIDs(got))
	}
	want := map[string]string{"detector": "frag_attack", "kind": "overlap", "ip_id": "77", "frag_offset": "1472", "payload_len": "528",
		"more_frags": "false", "fragment": "1472-2000", "overlaps": "0-1480", "fragments_seen": "2"}
	for k, v := range want {
		if a[0].Details[k] != v {
			t.Errorf("details[%s] = %q, want %q", k, a[0].Details[k], v)
		}
	}
	if a[0].SrcIP != fragSrc || a[0].DstIP != fragDst {
		t.Errorf("%s -> %s", a[0].SrcIP, a[0].DstIP)
	}
}

// TestFragTinyTransport checks the first-fragment transport header check,
// with min_size low enough not to fire on its own.
func TestFragTinyTransport(t *testing.T) {
	rules := `alert ip any any -> any any (msg:"tiny"; sid:22; detect:frag_attack; kind:tiny; min_size:1;)`
	tests := []struct {
		name  string
		v6    bool
		proto uint8
		first []byte
		want  string
	}{
		{"tcp 16", false, 6, make([]byte, 16), "22x1"},
		{"tcp 20", false, 6, make([]byte, 20), ""},
		{"udp 7", false, 17, make([]byte, 7), "22x1"},
		{"udp 8", false, 17, make([]byte, 8), ""},
		{"icmp 4", false, 1, make([]byte, 4), ""},
		{"tcp 16 v6", true, 6, make([]byte, 16), "22x1"},
		{"tcp 24 v6", true, 6, make([]byte, 24), ""},
		{"udp 8 v6", true, 17, make([]byte, 8), ""},
		// RFC 7112: the header chain must be complete in the first
		// fragment. A Destination Options header claiming 24 bytes, of
		// which 8 arrive, leaves no upper-layer header.
		{"v6 chain cut", true, 60, []byte{17, 2, 0, 0, 0, 0, 0, 0}, "22x1"},
		{"v6 chain complete", true, 60, slices.Concat([]byte{17, 0, 1, 4, 0, 0, 0, 0}, make([]byte, 8)), ""},
		// No Next Header ends the chain without an upper-layer header.
		{"v6 no next header", true, 59, make([]byte, 8), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := runFrags(t, rules, EngineConfig{}, tt.v6, []tfrag{
				{id: 5, proto: tt.proto, mf: true, payload: tt.first},
				{ts: time.Millisecond, id: 5, proto: tt.proto, offset: 64, n: 8},
			})
			if s := fragSIDs(got); s != tt.want {
				t.Errorf("fired %q, want %q", s, tt.want)
			}
			if tt.want != "" && !strings.Contains(got[22][0].Details["reason"], "header") {
				t.Errorf("reason %q", got[22][0].Details["reason"])
			}
		})
	}
}

// TestFragFlood checks the incomplete-datagram window: count 3 within 30s
// of expiry times, each datagram expiring 30s after its first fragment.
func TestFragFlood(t *testing.T) {
	s := time.Second
	half := func(id uint32, ts time.Duration) tfrag {
		return tfrag{ts: ts, id: id, mf: true, payload: udpFirst(1480)}
	}
	tests := []struct {
		name  string
		frags []tfrag
		want  string
	}{
		{"three", []tfrag{half(1, 0), half(2, s), half(3, 2*s)}, "24x1"},
		{"two", []tfrag{half(1, 0), half(2, s)}, ""},
		{"window edge", []tfrag{half(1, 0), half(2, 15*s), half(3, 30*s)}, "24x1"},
		{"past window", []tfrag{half(1, 0), half(2, 15*s), half(3, 30*s+time.Millisecond)}, ""},
		// Expiry during Process, not only at Flush.
		{"expired by traffic", []tfrag{half(1, 0), half(2, s), half(3, 2*s), {ts: 100 * s, id: 9, proto: 6, offset: 0, payload: make([]byte, 20)}}, "24x1"},
		{"complete ones do not count", []tfrag{half(1, 0), half(2, s), half(3, 2*s), {ts: 3 * s, id: 3, offset: 1480, n: 8}}, ""},
		{"per source", []tfrag{half(1, 0), half(2, s), {ts: 2 * s, src: "203.0.113.8", id: 3, mf: true, payload: udpFirst(1480)}}, ""},
		// A missing first fragment is incomplete too.
		{"tail only", []tfrag{{id: 1, offset: 1480, n: 8}, {id: 2, offset: 1480, n: 8}, {id: 3, offset: 1480, n: 8}}, "24x1"},
		// Time going backwards: the late fragments count at the clock.
		{"backwards", []tfrag{half(1, 60*s), half(2, 0), half(3, 0)}, "24x1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := runFrags(t, fragRules, EngineConfig{}, false, tt.frags)
			if s := fragSIDs(got); s != tt.want {
				t.Errorf("fired %q, want %q", s, tt.want)
			}
		})
	}
	got, _ := runFrags(t, fragRules, EngineConfig{}, false, []tfrag{half(1, 0), half(2, s), half(3, 2*s)})
	d := got[24][0].Details
	if d["incomplete_datagrams"] != "3" || d["window"] != "2s" || d["timeout"] != "30s" || d["tracked_addr"] != fragSrc {
		t.Errorf("details %v", d)
	}
	// The fragment timeout is configurable.
	got, _ = runFrags(t, fragRules, EngineConfig{FragmentTimeout: 5 * time.Second}, false,
		[]tfrag{half(1, 0), {ts: 6 * s, id: 1, offset: 1472, n: 528}})
	if s := fragSIDs(got); s != "" {
		t.Errorf("5s timeout: fired %q", s)
	}
}

// TestFragOverLimit checks that a datagram with more than maxFragRanges
// fragments is counted and then ignored: no overlap, no flood.
func TestFragOverLimit(t *testing.T) {
	var frags []tfrag
	for i := range maxFragRanges + 1 {
		frags = append(frags, tfrag{id: 1, offset: 8 * i, mf: true, n: 8})
	}
	frags = append(frags, tfrag{id: 1, offset: 8, mf: true, n: 16}) // overlaps
	for i := range 2 {
		frags = append(frags, tfrag{id: uint32(10 + i), offset: 8, n: 8})
	}
	rules := `alert ip any any -> any any (msg:"overlap"; sid:21; detect:frag_attack; kind:overlap;)
alert ip any any -> any any (msg:"flood"; sid:24; detect:frag_attack; kind:flood; count:3; seconds:30;)`
	got, e := runFrags(t, rules, EngineConfig{}, false, frags)
	if s := fragSIDs(got); s != "" {
		t.Errorf("fired %q", s)
	}
	if n := e.Stats().FragmentsOverLimit; n != 1 {
		t.Errorf("FragmentsOverLimit = %d, want 1", n)
	}
	// Exactly maxFragRanges+1 fragments: the last one trips the limit.
	_, e = runFrags(t, rules, EngineConfig{}, false, frags[:maxFragRanges+1])
	if n := e.Stats().FragmentsOverLimit; n != 1 {
		t.Errorf("%d fragments: FragmentsOverLimit = %d, want 1", maxFragRanges+1, n)
	}
	_, e = runFrags(t, rules, EngineConfig{}, false, frags[:maxFragRanges])
	if n := e.Stats().FragmentsOverLimit; n != 0 {
		t.Errorf("%d fragments: FragmentsOverLimit = %d, want 0", maxFragRanges, n)
	}
	// With 63 stored, the overlap is the 64th fragment: within the limit.
	got, e = runFrags(t, rules, EngineConfig{}, false, slices.Concat(frags[:maxFragRanges-1], frags[maxFragRanges+1:maxFragRanges+2]))
	if s := fragSIDs(got); s != "21x1" {
		t.Errorf("at the limit: fired %q, want 21x1", s)
	}
	if n := e.Stats().FragmentsOverLimit; n != 0 {
		t.Errorf("at the limit: FragmentsOverLimit = %d", n)
	}
}

// TestFragEviction checks the table cap: the oldest datagram is dropped,
// counted as an eviction, and not reported as incomplete.
func TestFragEviction(t *testing.T) {
	var frags []tfrag
	for i := range 5 {
		frags = append(frags, tfrag{ts: time.Duration(i) * time.Millisecond, id: uint32(i), mf: true, payload: udpFirst(1480)})
	}
	// The first datagram's second half arrives after its eviction: it is
	// a new datagram, so the overlap is missed.
	frags = append(frags, tfrag{ts: 10 * time.Millisecond, id: 0, offset: 1472, n: 528})
	got, e := runFrags(t, fragRules, EngineConfig{MaxKeys: 2}, false, frags)
	// Two datagrams survive to expiry (ids 4 and the new 0): no flood.
	if s := fragSIDs(got); s != "" {
		t.Errorf("fired %q", s)
	}
	if st := e.Stats().Tables[TableFragments]; st.Evictions != 4 || st.Keys != 0 {
		t.Errorf("fragment table %+v, want 4 evictions, 0 keys after Flush", st)
	}
}

// TestFragWhitelistPass checks that whitelisted sources and passed
// fragments do not alert, and the tracker still sees them.
func TestFragWhitelistPass(t *testing.T) {
	frags := []tfrag{{id: 1, mf: true, payload: udpFirst(1480)}, {ts: time.Millisecond, id: 1, offset: 1472, n: 528}, {id: 2, proto: 1, offset: 65528, n: 8}}
	got, _ := runFrags(t, fragRules, EngineConfig{Whitelist: []netip.Prefix{netip.MustParsePrefix(fragSrc + "/32")}}, false, frags)
	if s := fragSIDs(got); s != "" {
		t.Errorf("whitelisted: fired %q", s)
	}
	got, _ = runFrags(t, fragRules+`pass ip `+fragSrc+` any -> any any (msg:"p"; sid:30;)`, EngineConfig{}, false, frags)
	if s := fragSIDs(got); s != "" {
		t.Errorf("passed: fired %q", s)
	}
	got, _ = runFrags(t, strings.ReplaceAll(fragRules, "alert ip any", "alert ip !"+fragSrc), EngineConfig{}, false, frags)
	if s := fragSIDs(got); s != "" {
		t.Errorf("rule addresses: fired %q", s)
	}
}

// TestFragBadChecksum checks that IPv4 fragments with a bad header
// checksum are ignored.
func TestFragBadChecksum(t *testing.T) {
	e := NewEngine(mustParse(t, fragRules), EngineConfig{})
	b := tfrag{id: 1, proto: 1, offset: 65528, n: 8}.frame(t, false)
	b[14+10] ^= 0xff
	out := slices.Concat(e.Process(parseFrame(b, t0)), e.Flush())
	if len(out) != 0 {
		t.Errorf("bad checksum alerted:%s", alertLines(out))
	}
}

// TestFragDedup checks that repeated attacks from one source are one
// alert per rule within the dedup window.
func TestFragDedup(t *testing.T) {
	var frags []tfrag
	for i := range 10 {
		frags = append(frags, tfrag{ts: time.Duration(i) * time.Second, id: uint32(i), proto: 1, offset: 65528, n: 8})
	}
	got, _ := runFrags(t, fragRules, EngineConfig{}, false, frags)
	if s := fragSIDs(got); s != "23x1 24x1" {
		t.Errorf("fired %q, want 23x1 24x1", s)
	}
}

// TestFragTrackerClear checks that removing every frag rule clears the
// tracker.
func TestFragTrackerClear(t *testing.T) {
	e := NewEngine(mustParse(t, fragRules), EngineConfig{})
	e.Process(parseFrame(tfrag{id: 1, mf: true, payload: udpFirst(1480)}.frame(t, false), t0))
	if k := e.Stats().Tables[TableFragments].Keys; k != 1 {
		t.Fatalf("keys %d", k)
	}
	e.next.Store(mustParse(t, `alert tcp any any -> any 1 (msg:"x"; sid:1;)`))
	e.Process(pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2}.parsed(t, at(time.Second)))
	if k := e.Stats().Tables[TableFragments].Keys; k != 0 {
		t.Errorf("keys %d after the frag rules were removed", k)
	}
}
