package rules

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// loadErrors parses text and returns its errors as "line: reason".
func loadErrors(t *testing.T, text string) []string {
	t.Helper()
	_, err := Parse(strings.NewReader(text), "v.rules")
	if err == nil {
		return nil
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("err = %v", err)
	}
	var out []string
	for _, se := range le.Errors {
		out = append(out, strings.TrimPrefix(se.Error(), "v.rules:"))
	}
	return out
}

func TestVariables(t *testing.T) {
	const vars = `var HOME_NET [10.0.0.0/8, 192.168.0.0/16]
var EXTERNAL_NET !$HOME_NET
var WEB 192.0.2.10
var SERVERS [$WEB,192.0.2.20]
var HTTP_PORTS [80,8080]
var ALL any
`
	tests := []struct {
		name      string
		rule      string
		match     []string // addresses the source field matches
		noMatch   []string
		dport     []uint16 // ports the destination port field matches
		noDport   []uint16
		wantField string // expanded source field, as in the rule text
	}{
		{"list var", `alert tcp $HOME_NET any -> any any`, []string{"10.1.2.3", "192.168.1.1"}, []string{"172.16.0.1"}, nil, nil, "[10.0.0.0/8,192.168.0.0/16]"},
		{"negated var", `alert tcp $EXTERNAL_NET any -> any any`, []string{"172.16.0.1", "8.8.8.8"}, []string{"10.1.2.3"}, nil, nil, "![10.0.0.0/8,192.168.0.0/16]"},
		{"double negation", `alert tcp !$EXTERNAL_NET any -> any any`, []string{"10.1.2.3"}, []string{"8.8.8.8"}, nil, nil, "[10.0.0.0/8,192.168.0.0/16]"},
		{"negate list var", `alert tcp !$HOME_NET any -> any any`, []string{"8.8.8.8"}, []string{"10.0.0.1"}, nil, nil, "![10.0.0.0/8,192.168.0.0/16]"},
		{"var of var spliced", `alert tcp $SERVERS any -> any any`, []string{"192.0.2.10", "192.0.2.20"}, []string{"192.0.2.11"}, nil, nil, "[192.0.2.10,192.0.2.20]"},
		{"spliced in list", `alert tcp [$HOME_NET,8.8.8.8] any -> any any`, []string{"10.0.0.1", "8.8.8.8"}, []string{"8.8.4.4"}, nil, nil, "[10.0.0.0/8,192.168.0.0/16,8.8.8.8]"},
		{"negated in list", `alert tcp [10.0.0.0/8,!$WEB] any -> any any`, []string{"10.0.0.1"}, []string{"192.0.2.10"}, nil, nil, "[10.0.0.0/8,!192.0.2.10]"},
		{"negated list in list", `alert tcp [0.0.0.0/0,!$HOME_NET] any -> any any`, []string{"8.8.8.8"}, []string{"10.0.0.1", "192.168.3.3"}, nil, nil, "[0.0.0.0/0,!10.0.0.0/8,!192.168.0.0/16]"},
		{"any var", `alert tcp $ALL any -> any any`, []string{"1.2.3.4"}, nil, nil, nil, "any"},
		{"port var", `alert tcp any any -> any $HTTP_PORTS`, nil, nil, []uint16{80, 8080}, []uint16{81}, "any"},
		{"port var negated", `alert tcp any any -> any !$HTTP_PORTS`, nil, nil, []uint16{81}, []uint16{80}, "any"},
		{"port var in list", `alert tcp any any -> any [$HTTP_PORTS,443]`, nil, nil, []uint16{80, 443}, []uint16{22}, "any"},
		{"any var as port", `alert tcp any any -> any $ALL`, nil, nil, []uint16{1}, nil, "any"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := mustParse(t, vars+tt.rule+` (msg:"m"; sid:1;)`)
			r := rs.Rules()[0]
			if r.Line != 7 {
				t.Errorf("rule line %d, want 7", r.Line)
			}
			if f := strings.Fields(r.text)[2]; f != tt.wantField {
				t.Errorf("text source field %q, want %q (text %q)", f, tt.wantField, r.text)
			}
			for _, a := range tt.match {
				if !r.src.match(netip.MustParseAddr(a)) {
					t.Errorf("source %s does not match", a)
				}
			}
			for _, a := range tt.noMatch {
				if r.src.match(netip.MustParseAddr(a)) {
					t.Errorf("source %s matches", a)
				}
			}
			for _, p := range tt.dport {
				if !r.dport.match(p) {
					t.Errorf("port %d does not match", p)
				}
			}
			for _, p := range tt.noDport {
				if r.dport.match(p) {
					t.Errorf("port %d matches", p)
				}
			}
		})
	}
}

// TestVariablesOrder checks that a variable can be used before, and
// defined in terms of variables defined after, its own line.
func TestVariablesOrder(t *testing.T) {
	rs := mustParse(t, `alert tcp $A any -> any any (msg:"m"; sid:1;)
var A [$B,10.0.0.1]
var B 10.0.0.2
`)
	r := rs.Rules()[0]
	if !r.src.match(netip.MustParseAddr("10.0.0.2")) || !r.src.match(netip.MustParseAddr("10.0.0.1")) || r.src.match(netip.MustParseAddr("10.0.0.3")) {
		t.Errorf("src = %+v", r.src)
	}
}

// TestVariablesReload checks that changing a variable changes the text of
// the rules that use it (so their state is not carried over), and that
// unrelated rules keep theirs.
func TestVariablesReload(t *testing.T) {
	a := mustParse(t, "var X 10.0.0.1\nalert tcp $X any -> any any (msg:\"m\"; sid:1;)\nalert tcp any any -> any any (msg:\"n\"; sid:2;)")
	b := mustParse(t, "var X 10.0.0.2\nalert tcp $X any -> any any (msg:\"m\"; sid:1;)\nalert tcp any any -> any any (msg:\"n\"; sid:2;)")
	if a.rules[0].text == b.rules[0].text {
		t.Errorf("same text %q after the variable changed", a.rules[0].text)
	}
	if a.rules[1].text != b.rules[1].text {
		t.Errorf("unrelated rule text changed: %q vs %q", a.rules[1].text, b.rules[1].text)
	}
}

func TestVariableErrors(t *testing.T) {
	const rule = ` (msg:"m"; sid:1;)`
	tests := []struct {
		name string
		text string
		want []string // "line: fragment", in order
	}{
		{"undefined in rule", "alert tcp $NOPE any -> any any" + rule, []string{"1: source address: undefined variable $NOPE"}},
		{"undefined in port", "alert tcp any any -> any $P" + rule, []string{"1: destination port: undefined variable $P"}},
		{"undefined in var", "var A [$B,10.0.0.1]", []string{"1: variable A: undefined variable $B"}},
		{"redefined", "var A 10.0.0.1\nvar A 10.0.0.2", []string{"2: variable A redefined (first defined on line 1)"}},
		{"self reference", "var A $A", []string{"1: variable A: reference cycle A -> A"}},
		{"self reference negated", "var A !$A", []string{"1: variable A: reference cycle A -> A"}},
		{"self reference in list", "var A [10.0.0.1,$A]", []string{"1: variable A: reference cycle A -> A"}},
		{"cycle", "var A $B\nvar B $C\nvar C $A", []string{
			"1: variable A: reference cycle A -> B -> C -> A",
			"2: variable B: reference cycle A -> B -> C -> A",
			"3: variable C: reference cycle A -> B -> C -> A",
		}},
		{"bad name", "var 1A 10.0.0.1", []string{`1: variable name "1A"`}},
		{"bad name char", "var A-B 10.0.0.1", []string{`1: variable name "A-B"`}},
		{"no value", "var A", []string{"1: variable A: want one value"}},
		{"two values", "var A 10.0.0.1 10.0.0.2", []string{"1: variable A: want one value (var NAME value), got 2 fields"}},
		{"bad value", "var A a..b", []string{`1: variable A: "a..b" is neither an address value`}},
		{"name var as address", "var N example.com\nalert tcp $N any -> any any" + rule, []string{"2: source address: $N holds names, not addresses"}},
		{"mixed types", "var P [80,443]\nvar A [$P,10.0.0.1]", []string{`2: variable A: "[80,443,10.0.0.1]" is neither`}},
		{"port var as address", "var P 80\nalert tcp $P any -> any any" + rule, []string{"2: source address: $P holds ports, not addresses"}},
		{"address var as port", "var A 10.0.0.1\nalert tcp any $A -> any any" + rule, []string{"2: source port: $A holds addresses, not ports"}},
		{"negated var in list", "var A !10.0.0.1\nalert tcp [$A,10.0.0.2] any -> any any" + rule, []string{"2: source address: $A cannot be used inside a list"}},
		{"any var in list", "var A any\nalert tcp [$A,10.0.0.2] any -> any any" + rule, []string{"2: source address: $A cannot be used inside a list"}},
		{"partial reference", "var A 10\nalert tcp 10.0.0.$A any -> any any" + rule, []string{"2: source address: bad variable reference"}},
		{"bad reference name", "alert tcp $1 any -> any any" + rule, []string{`1: source address: bad variable reference "$1"`}},
		{"use of invalid var", "var A a..b\nalert tcp $A any -> any any" + rule, []string{
			"1: variable A:",
			"2: source address: $A is invalid (line 1)",
		}},
		{"var of invalid var", "var A a..b\nvar B $A", []string{"1: variable A:", "2: variable B: $A is invalid (line 1)"}},
		{"double negated any", "var A any\nalert tcp !$A any -> any any" + rule, []string{"2: source address: !any matches nothing"}},
		{"external needs home", `alert ip any any -> any any (msg:"m"; sid:1; detect:ttl_anomaly; count:5; seconds:60;)`, []string{"1: scope:external needs a HOME_NET variable"}},
		{"home net of ports", "var HOME_NET 80\n" + `alert ip any any -> any any (msg:"m"; sid:1; detect:ttl_anomaly; count:5; seconds:60;)`, []string{"2: scope:external: $HOME_NET holds ports"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := loadErrors(t, tt.text)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d errors, want %d:\n%s", len(got), len(tt.want), strings.Join(got, "\n"))
			}
			for i, w := range tt.want {
				line, frag, _ := strings.Cut(w, ": ")
				if !strings.HasPrefix(got[i], line+": ") || !strings.Contains(got[i], frag) {
					t.Errorf("error %d = %q, want line %s with %q", i, got[i], line, frag)
				}
			}
		})
	}
}

func TestNewOptionsParse(t *testing.T) {
	r := one(t, `alert tcp any any -> any any (msg:"m"; sid:1; same_ip; same_port; eth_dst:multicast; ttl:<3;)`)
	if !r.sameIP || !r.samePort || r.ethDst != ethMulticast || r.ttl != (ttlCheck{'<', 3}) {
		t.Errorf("%+v", r)
	}
	r = one(t, `alert icmp any any -> any any (msg:"m"; sid:1; itype:8; icode:0; eth_dst:broadcast; ttl:>250;)`)
	if !r.hasIType || r.itype != 8 || !r.hasICode || r.icode != 0 || r.ethDst != ethBroadcast || r.ttl != (ttlCheck{'>', 250}) {
		t.Errorf("%+v", r)
	}
	for v, want := range map[string]dsizeCheck{
		"0": {'=', 0, 0}, "<3": {'<', 3, 0}, ">1472": {'>', 1472, 0}, "65535": {'=', 65535, 0},
		"10<>20": {'r', 10, 20}, "7<>7": {'r', 7, 7}, "0<>65535": {'r', 0, 65535},
	} {
		if r := one(t, `alert ip any any -> any any (msg:"m"; sid:1; dsize:`+v+`;)`); r.dsize != want {
			t.Errorf("dsize:%s = %+v, want %+v", v, r.dsize, want)
		}
	}
	r = one(t, `alert ip any any -> any any (msg:"m"; sid:1; itype:255; ttl:0;)`)
	if r.itype != 255 || r.hasICode || r.ttl != (ttlCheck{'=', 0}) {
		t.Errorf("%+v", r)
	}
	r = one(t, "var HOME_NET 10.0.0.0/8\n"+`alert ip any any -> any any (msg:"m"; sid:1; detect:ttl_anomaly; count:5; seconds:60;)`)
	if r.minSamples != 10 || r.maxHopDiff != 3 || !r.external || !r.homeNet.match(netip.MustParseAddr("10.1.1.1")) || r.homeNet.match(netip.MustParseAddr("11.1.1.1")) {
		t.Errorf("ttl_anomaly defaults: %+v", r)
	}
	r = one(t, `alert tcp any any -> any any (msg:"m"; sid:1; detect:ttl_anomaly; count:5; seconds:60; scope:all; min_samples:3; max_hop_diff:0;)`)
	if r.minSamples != 3 || r.maxHopDiff != 0 || r.external {
		t.Errorf("ttl_anomaly options: %+v", r)
	}
	r = one(t, `alert ip any any -> any any (msg:"m"; sid:1; detect:frag_attack; kind:tiny;)`)
	if r.fragKind != FragTiny || r.minSize != 256 {
		t.Errorf("frag tiny defaults: %+v", r)
	}
	r = one(t, `alert ip any any -> any any (msg:"m"; sid:1; detect:frag_attack; kind:tiny; min_size:100;)`)
	if r.minSize != 100 {
		t.Errorf("min_size: %+v", r)
	}
	r = one(t, `alert ip any any -> any any (msg:"m"; sid:1; detect:frag_attack; kind:flood; count:50; seconds:30;)`)
	if r.fragKind != FragFlood || r.detect.count != 50 || r.detect.seconds != 30 {
		t.Errorf("frag flood: %+v", r)
	}
}

func TestNewOptionErrors(t *testing.T) {
	const tcp = `alert tcp any any -> any any (msg:"m"; sid:1; `
	const ip = `alert ip any any -> any any (msg:"m"; sid:1; `
	tests := []struct{ line, want string }{
		{tcp + `same_ip:1;)`, "same_ip takes no value"},
		{tcp + `same_port:yes;)`, "same_port takes no value"},
		{tcp + `same_ip; same_ip;)`, "option same_ip given more than once"},
		{`alert icmp any any -> any any (msg:"m"; sid:1; same_port;)`, "same_port requires protocol tcp or udp"},
		{`alert ip any any -> any any (msg:"m"; sid:1; same_port;)`, "same_port requires protocol tcp or udp"},
		{`alert arp any any -> any any (msg:"m"; sid:1; same_ip;)`, "same_ip, ttl and dsize require an IP protocol"},
		{`alert arp any any -> any any (msg:"m"; sid:1; ttl:5;)`, "same_ip, ttl and dsize require an IP protocol"},
		{tcp + `eth_dst:unicast;)`, `eth_dst "unicast": want broadcast, multicast or zero, optionally negated with '!'`},
		{tcp + `eth_dst:!;)`, `eth_dst "!": want broadcast`},
		{tcp + `eth_dst:!!zero;)`, `eth_dst "!!zero": want broadcast`},
		{tcp + `eth_dst:! zero;)`, `eth_dst "! zero": want broadcast`},
		{tcp + `eth_dst;)`, "option eth_dst needs a value"},
		{tcp + `itype:8;)`, "itype and icode require protocol icmp or ip"},
		{`alert udp any any -> any any (msg:"m"; sid:1; icode:3;)`, "itype and icode require protocol icmp or ip"},
		{ip + `itype:256;)`, `itype "256": want an integer from 0 to 255`},
		{ip + `icode:-1;)`, `icode "-1"`},
		{ip + `itype:8; itype:0;)`, "option itype given more than once"},
		{tcp + `ttl:<0;)`, "<0 matches no TTL"},
		{tcp + `ttl:>255;)`, ">255 matches no TTL"},
		{tcp + `ttl:256;)`, `ttl: "256": want N, <N or >N`},
		{tcp + `ttl:<=3;)`, `ttl: "=3"`},
		{tcp + `ttl:;)`, `ttl: ""`},
		{tcp + `ttl:<;)`, `ttl: ""`},
		{tcp + `dsize:<0;)`, "<0 matches no payload size"},
		{tcp + `dsize:>65535;)`, ">65535 matches no payload size"},
		{tcp + `dsize:65536;)`, `dsize: "65536": want N, <N, >N or N<>M`},
		{tcp + `dsize:-1;)`, `dsize: "-1"`},
		{tcp + `dsize:;)`, `dsize: ""`},
		{tcp + `dsize:>;)`, `dsize: ">"`},
		{tcp + `dsize:<=3;)`, `dsize: "<=3"`},
		{tcp + `dsize:10<>5;)`, `range is empty (10 > 5)`},
		{tcp + `dsize:<>5;)`, `dsize: "<>5"`},
		{tcp + `dsize:5<>;)`, `dsize: "5<>"`},
		{tcp + `dsize:1<>2<>3;)`, `dsize: "1<>2<>3"`},
		{tcp + `dsize:>1<>3;)`, `dsize: ">1<>3"`},
		{tcp + `dsize:1; dsize:2;)`, "option dsize given more than once"},
		{`alert arp any any -> any any (msg:"m"; sid:1; dsize:5;)`, "same_ip, ttl and dsize require an IP protocol"},
		{tcp + `detect:syn_flood; track:by_dst; count:5; seconds:1; dsize:5;)`, "option dsize cannot be combined with detect"},
		{tcp + `detect:syn_flood; track:by_dst; count:5; seconds:1; same_ip;)`, "option same_ip cannot be combined with detect"},
		{tcp + `detect:syn_flood; track:by_dst; count:5; seconds:1; ttl:5;)`, "option ttl cannot be combined with detect"},
		{ip + `kind:tiny;)`, "option kind is only valid with detect:frag_attack"},
		{ip + `scope:all;)`, "option scope is only valid with detect:ttl_anomaly"},
		{ip + `min_samples:5;)`, "option min_samples is only valid with detect:ttl_anomaly"},
		{ip + `detect:ttl_anomaly; seconds:60; scope:all;)`, "detect:ttl_anomaly needs count"},
		{ip + `detect:ttl_anomaly; count:5; seconds:60; scope:inside;)`, `scope "inside": want external or all`},
		{ip + `detect:ttl_anomaly; count:5; seconds:60; scope:all; min_samples:0;)`, `min_samples: "0"`},
		{ip + `detect:ttl_anomaly; count:5; seconds:60; scope:all; max_hop_diff:256;)`, `max_hop_diff "256"`},
		{ip + `detect:ttl_anomaly; count:5; seconds:60; scope:all; kind:tiny;)`, "option kind is not valid with detect:ttl_anomaly"},
		{`alert arp any any -> any any (msg:"m"; sid:1; detect:ttl_anomaly; count:5; seconds:60; scope:all;)`, "detect:ttl_anomaly requires protocol ip, tcp, udp or icmp"},
		{ip + `detect:frag_attack;)`, "detect:frag_attack needs kind"},
		{ip + `detect:frag_attack; kind:big;)`, `kind "big": want overlap, tiny, oversize or flood`},
		{ip + `detect:frag_attack; kind:flood; count:5;)`, "kind:flood needs count and seconds"},
		{ip + `detect:frag_attack; kind:overlap; count:5; seconds:3;)`, "count and seconds are only valid with kind:flood"},
		{ip + `detect:frag_attack; kind:overlap; min_size:100;)`, "min_size is only valid with kind:tiny"},
		{ip + `detect:frag_attack; kind:tiny; min_size:0;)`, `min_size: "0"`},
		{ip + `detect:frag_attack; kind:tiny; min_size:65536;)`, `min_size: "65536"`},
		{ip + `detect:frag_attack; kind:tiny; scope:all;)`, "option scope is not valid with detect:frag_attack"},
		{`alert udp any any -> any any (msg:"m"; sid:1; detect:frag_attack; kind:tiny;)`, "detect:frag_attack requires protocol ip"},
		{`pass ip any any -> any any (msg:"m"; sid:1; detect:frag_attack; kind:tiny;)`, "detect cannot be used with a pass rule"},
	}
	for _, tt := range tests {
		got := loadErrors(t, tt.line)
		if !slices.ContainsFunc(got, func(s string) bool { return strings.Contains(s, tt.want) }) {
			t.Errorf("%s\n  errors %q do not mention %q", tt.line, got, tt.want)
		}
	}
}

func TestNewOptionsMatch(t *testing.T) {
	bcast := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	mcast4 := [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}
	mcast6 := [6]byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
	notGroup := [6]byte{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff} // I/G bit clear
	ff := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}       // group bit set, not broadcast
	icmp := func(ty, code uint8) *[2]uint8 { return &[2]uint8{ty, code} }
	land := pkt{proto: "tcp", src: "10.0.0.5", dst: "10.0.0.5", sport: 139, dport: 139, flags: "S"}
	tests := []struct {
		name string
		rule string // header and options, sid is appended
		p    pkt
		want bool
	}{
		{"same_ip land", `alert tcp any any -> any any (msg:"m"; same_ip;`, land, true},
		{"same_ip differs", `alert tcp any any -> any any (msg:"m"; same_ip;`, pkt{proto: "tcp", src: "10.0.0.5", dst: "10.0.0.6", sport: 139, dport: 139, flags: "S"}, false},
		{"same_ip v6", `alert udp any any -> any any (msg:"m"; same_ip;`, pkt{proto: "udp", src: "2001:db8::1", dst: "2001:db8::1", sport: 1, dport: 2}, true},
		{"same_ip icmp", `alert ip any any -> any any (msg:"m"; same_ip;`, pkt{proto: "icmp", src: "10.0.0.5", dst: "10.0.0.5"}, true},
		{"same_port", `alert tcp any any -> any any (msg:"m"; same_port;`, land, true},
		{"same_port differs", `alert tcp any any -> any any (msg:"m"; same_port;`, pkt{proto: "tcp", src: "10.0.0.5", dst: "10.0.0.5", sport: 139, dport: 138, flags: "S"}, false},
		{"land full", `alert tcp any any -> any any (msg:"m"; same_ip; same_port; flags:S+;`, land, true},
		{"land needs syn", `alert tcp any any -> any any (msg:"m"; same_ip; same_port; flags:S+;`, pkt{proto: "tcp", src: "10.0.0.5", dst: "10.0.0.5", sport: 139, dport: 139, flags: "A"}, false},

		{"broadcast", `alert ip any any -> any any (msg:"m"; eth_dst:broadcast;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.255", sport: 1, dport: 2, ethDst: bcast}, true},
		{"broadcast not multicast", `alert ip any any -> any any (msg:"m"; eth_dst:multicast;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.255", sport: 1, dport: 2, ethDst: bcast}, false},
		{"multicast v4", `alert ip any any -> any any (msg:"m"; eth_dst:multicast;`, pkt{proto: "udp", src: "10.0.0.1", dst: "224.0.0.1", sport: 1, dport: 2, ethDst: mcast4}, true},
		{"multicast v6", `alert ip any any -> any any (msg:"m"; eth_dst:multicast;`, pkt{proto: "icmp", src: "fe80::1", dst: "ff02::1", ethDst: mcast6}, true},
		{"multicast not broadcast", `alert ip any any -> any any (msg:"m"; eth_dst:broadcast;`, pkt{proto: "udp", src: "10.0.0.1", dst: "224.0.0.1", sport: 1, dport: 2, ethDst: mcast4}, false},
		{"group bit almost broadcast", `alert ip any any -> any any (msg:"m"; eth_dst:multicast;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, ethDst: ff}, true},
		{"group bit clear", `alert ip any any -> any any (msg:"m"; eth_dst:multicast;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, ethDst: notGroup}, false},
		{"unicast", `alert ip any any -> any any (msg:"m"; eth_dst:broadcast;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2}, false},
		{"arp broadcast", `alert arp any any -> any any (msg:"m"; eth_dst:broadcast;`, pkt{proto: "arp", src: "10.0.0.1", dst: "10.0.0.2", ethDst: bcast}, true},
		{"zero", `alert ip any any -> any any (msg:"m"; eth_dst:zero;`, pkt{proto: "udp", src: "127.0.0.1", dst: "127.0.0.1", sport: 1, dport: 2, zeroMACs: true}, true},
		{"zero not unicast", `alert ip any any -> any any (msg:"m"; eth_dst:zero;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2}, false},
		{"not zero on loopback", `alert ip any any -> any any (msg:"m"; eth_dst:!zero;`, pkt{proto: "udp", src: "127.0.0.1", dst: "127.0.0.1", sport: 1, dport: 2, zeroMACs: true}, false},
		{"not zero on unicast", `alert ip any any -> any any (msg:"m"; eth_dst:!zero;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2}, true},
		{"zero not almost zero", `alert ip any any -> any any (msg:"m"; eth_dst:zero;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, ethDst: [6]byte{0, 0, 0, 0, 0, 1}}, false},
		{"not broadcast on broadcast", `alert ip any any -> any any (msg:"m"; eth_dst:!broadcast;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.255", sport: 1, dport: 2, ethDst: bcast}, false},
		{"not broadcast on unicast", `alert ip any any -> any any (msg:"m"; eth_dst:!broadcast;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2}, true},
		{"not multicast on multicast", `alert ip any any -> any any (msg:"m"; eth_dst:!multicast;`, pkt{proto: "udp", src: "10.0.0.1", dst: "224.0.0.1", sport: 1, dport: 2, ethDst: mcast4}, false},
		{"not multicast on broadcast", `alert ip any any -> any any (msg:"m"; eth_dst:!multicast;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.255", sport: 1, dport: 2, ethDst: bcast}, true},

		{"itype echo", `alert icmp any any -> any any (msg:"m"; itype:8;`, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.2"}, true},
		{"itype echo v6", `alert icmp any any -> any any (msg:"m"; itype:128;`, pkt{proto: "icmp", src: "2001:db8::1", dst: "2001:db8::2"}, true},
		{"itype other", `alert icmp any any -> any any (msg:"m"; itype:0;`, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.2"}, false},
		{"itype icode", `alert icmp any any -> any any (msg:"m"; itype:11; icode:0;`, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.2", icmp: icmp(11, 0)}, true},
		{"icode differs", `alert icmp any any -> any any (msg:"m"; itype:11; icode:1;`, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.2", icmp: icmp(11, 0)}, false},
		{"icode only", `alert icmp any any -> any any (msg:"m"; icode:3;`, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.2", icmp: icmp(3, 3)}, true},
		{"ip rule icmp", `alert ip any any -> any any (msg:"m"; itype:8;`, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.2"}, true},
		{"ip rule itype:0 not tcp", `alert ip any any -> any any (msg:"m"; itype:0;`, pkt{proto: "tcp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, flags: "S"}, false},

		{"ttl <", `alert ip any any -> any any (msg:"m"; ttl:<3;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, ttl: 2}, true},
		{"ttl < edge", `alert ip any any -> any any (msg:"m"; ttl:<3;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, ttl: 3}, false},
		{"ttl >", `alert ip any any -> any any (msg:"m"; ttl:>200;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, ttl: 201}, true},
		{"ttl > edge", `alert ip any any -> any any (msg:"m"; ttl:>200;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, ttl: 200}, false},
		{"ttl =", `alert ip any any -> any any (msg:"m"; ttl:1;`, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.2", ttl: 1}, true},
		{"ttl = differs", `alert ip any any -> any any (msg:"m"; ttl:1;`, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.2", ttl: 2}, false},
		{"hop limit", `alert ip any any -> any any (msg:"m"; ttl:<2;`, pkt{proto: "icmp", src: "2001:db8::1", dst: "2001:db8::2", ttl: 1}, true},

		{"dsize =", `alert udp any any -> any any (msg:"m"; dsize:5;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: "hello"}, true},
		{"dsize = differs", `alert udp any any -> any any (msg:"m"; dsize:4;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: "hello"}, false},
		{"dsize 0", `alert tcp any any -> any any (msg:"m"; dsize:0;`, pkt{proto: "tcp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, flags: "S"}, true},
		{"dsize <", `alert ip any any -> any any (msg:"m"; dsize:<6;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: "hello"}, true},
		{"dsize < edge", `alert ip any any -> any any (msg:"m"; dsize:<5;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: "hello"}, false},
		{"dsize >", `alert ip any any -> any any (msg:"m"; dsize:>4;`, pkt{proto: "tcp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, flags: "PA", payload: "hello"}, true},
		{"dsize > edge", `alert ip any any -> any any (msg:"m"; dsize:>5;`, pkt{proto: "tcp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, flags: "PA", payload: "hello"}, false},
		{"dsize range low edge", `alert ip any any -> any any (msg:"m"; dsize:5<>9;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: "hello"}, true},
		{"dsize range high edge", `alert ip any any -> any any (msg:"m"; dsize:1<>5;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: "hello"}, true},
		{"dsize below range", `alert ip any any -> any any (msg:"m"; dsize:6<>9;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: "hello"}, false},
		{"dsize above range", `alert ip any any -> any any (msg:"m"; dsize:1<>4;`, pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: "hello"}, false},
		{"dsize echo data only", `alert icmp any any -> any any (msg:"m"; itype:8; dsize:4;`, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.2", payload: "ping", echoID: 7, echoSeq: 1}, true},
		{"dsize echo excludes id and seq", `alert icmp any any -> any any (msg:"m"; dsize:8;`, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.2", payload: "ping"}, false},
		{"dsize echo v6", `alert icmp any any -> any any (msg:"m"; dsize:4;`, pkt{proto: "icmp", src: "2001:db8::1", dst: "2001:db8::2", payload: "ping"}, true},
		{"dsize error message", `alert icmp any any -> any any (msg:"m"; dsize:4;`, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.2", icmp: icmp(11, 0), payload: "abcd"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firing(t, tt.rule+" sid:1;)", tt.p)
			if (len(got) > 0) != tt.want {
				t.Errorf("fired %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPacketOptionsNeedPacket checks that eth_dst, itype, icode and ttl
// never match a synthetic view (a handshake's opening SYN), while
// same_ip and same_port, which only look at addresses, do.
func TestPacketOptionsNeedPacket(t *testing.T) {
	syn := view{g: gTCP, src: netip.MustParseAddr("10.0.0.1"), dst: netip.MustParseAddr("10.0.0.1"), sport: 5, dport: 5, flags: tcpSYN, havePayload: true, haveLower: true}
	for opt, want := range map[string]bool{
		"eth_dst:broadcast;": false, "ttl:<255;": false, "ttl:>0;": false, "dsize:0;": false, "dsize:<65535;": false, "same_ip;": true, "same_port;": true,
	} {
		r := one(t, `pass tcp any any -> any any (msg:"m"; sid:1; `+opt+`)`)
		if got := r.match(&syn); got != want {
			t.Errorf("%s on a synthetic view = %v, want %v", opt, got, want)
		}
	}
	r := one(t, `pass ip any any -> any any (msg:"m"; sid:1; itype:0;)`)
	icmpSyn := syn
	icmpSyn.g = gICMP
	if r.match(&icmpSyn) {
		t.Error("itype matched a synthetic view")
	}
}

// TestITypeNeedsHeader checks that itype does not match an ICMP packet
// without a decoded header: a non-first fragment has ICMPType 0, which
// must not look like an Echo Reply.
func TestITypeNeedsHeader(t *testing.T) {
	e := NewEngine(mustParse(t, `alert icmp any any -> any any (msg:"m"; sid:1; itype:0;)`), EngineConfig{})
	b := fragFrame(t, "10.0.0.1", "10.0.0.2", 7, 1, 1480, false, make([]byte, 100))
	if got := e.Process(parseFrame(b, t0)); len(got) != 0 {
		t.Errorf("itype:0 matched a non-first fragment:%s", alertLines(got))
	}
}

// TestEthDstWithoutEthernet checks a packet with no Ethernet header (a
// Linux cooked or raw IP capture): it is of no eth_dst kind, so every
// value fails and every negated value matches.
func TestEthDstWithoutEthernet(t *testing.T) {
	p := pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2}.parsed(t, t0)
	p.EthDst = nil
	for _, kind := range []string{"broadcast", "multicast", "zero"} {
		for _, neg := range []bool{false, true} {
			v := kind
			if neg {
				v = "!" + kind
			}
			r := one(t, `alert ip any any -> any any (msg:"m"; sid:1; eth_dst:`+v+`;)`)
			var vw view
			vw.init(p)
			if got := r.match(&vw); got != neg {
				t.Errorf("eth_dst:%s on a frame without Ethernet: match %v, want %v", v, got, neg)
			}
		}
	}
}
