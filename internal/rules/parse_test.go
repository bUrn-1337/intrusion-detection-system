package rules

import (
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

func one(t *testing.T, line string) *Rule {
	t.Helper()
	rs := mustParse(t, line)
	if rs.Len() != 1 {
		t.Fatalf("got %d rules", rs.Len())
	}
	return rs.Rules()[0]
}

func TestParseOptions(t *testing.T) {
	const hdr = "alert tcp any any -> any any "
	tests := []struct {
		name  string
		line  string
		check func(t *testing.T, r *Rule)
	}{
		{"minimal, defaults", hdr + `(msg:"m"; sid:1;)`, func(t *testing.T, r *Rule) {
			if r.Action != ActionAlert || r.Proto != ProtoTCP || r.Msg != "m" || r.SID != 1 || r.Rev != 1 || r.Severity != "medium" || r.Category != "" || r.Detect != "" || r.bidir {
				t.Errorf("%+v", r)
			}
		}},
		{"last semicolon optional", hdr + `(msg:"m"; sid:1)`, func(t *testing.T, r *Rule) {
			if r.SID != 1 {
				t.Error(r.SID)
			}
		}},
		{"pass", `pass udp any any -> any any (msg:"m"; sid:1;)`, func(t *testing.T, r *Rule) {
			if r.Action != ActionPass || r.Proto != ProtoUDP {
				t.Errorf("%v %v", r.Action, r.Proto)
			}
		}},
		{"protos", `alert icmp any any <> any any (msg:"m"; sid:1;)`, func(t *testing.T, r *Rule) {
			if r.Proto != ProtoICMP || !r.bidir {
				t.Errorf("%v %v", r.Proto, r.bidir)
			}
		}},
		{"msg escapes", hdr + `(msg:"a \"q\" b\; c\\d (e)"; sid:1;)`, func(t *testing.T, r *Rule) {
			if r.Msg != `a "q" b; c\d (e)` {
				t.Errorf("%q", r.Msg)
			}
		}},
		{"rev severity category", hdr + `(msg:"m"; sid:7; rev:3; severity:critical; category:web-attack_2;)`, func(t *testing.T, r *Rule) {
			if r.Rev != 3 || r.Severity != "critical" || r.Category != "web-attack_2" {
				t.Errorf("%+v", r)
			}
		}},
		{"flags exact", hdr + `(msg:"m"; sid:1; flags:SA;)`, func(t *testing.T, r *Rule) {
			if !r.hasFlags || r.flagsPlus || r.flags != tcpSYN|tcpACK {
				t.Errorf("%v %v %b", r.hasFlags, r.flagsPlus, r.flags)
			}
		}},
		{"flags plus, all letters", hdr + `(msg:"m"; sid:1; flags:SAFRPU+;)`, func(t *testing.T, r *Rule) {
			if !r.flagsPlus || r.flags != 0x3f {
				t.Errorf("%v %b", r.flagsPlus, r.flags)
			}
		}},
		{"flags zero", hdr + `(msg:"m"; sid:1; flags:0;)`, func(t *testing.T, r *Rule) {
			if !r.hasFlags || r.flags != 0 || r.flagsPlus {
				t.Errorf("%v %b", r.hasFlags, r.flags)
			}
		}},
		{"content hex, escapes, nocase", hdr + `(msg:"m"; sid:1; content:"GET|20 2F|a\|\;\"|0d0a|"; content:"Host"; nocase;)`, func(t *testing.T, r *Rule) {
			want := []contentMatch{{pat: []byte("GET /a|;\"\r\n")}, {pat: []byte("host"), nocase: true}}
			if !reflect.DeepEqual(r.contents, want) {
				t.Errorf("%+v", r.contents)
			}
		}},
		{"content with semicolon inside quotes", hdr + `(msg:"m"; sid:1; content:"a;b";)`, func(t *testing.T, r *Rule) {
			if string(r.contents[0].pat) != "a;b" {
				t.Errorf("%q", r.contents[0].pat)
			}
		}},
		{"app options", hdr + `(msg:"m"; sid:1; app_proto:http; app_field:method=GET; app_field:host="a b"; app_reason:suspicious; app_reason:malformed;)`, func(t *testing.T, r *Rule) {
			if r.appProto != packet.AppHTTP ||
				!reflect.DeepEqual(r.appFields, []appField{{"method", "GET"}, {"host", "a b"}}) ||
				!reflect.DeepEqual(r.appReasons, []string{"suspicious_reason", "malformed_reason"}) {
				t.Errorf("%v %v %v", r.appProto, r.appFields, r.appReasons)
			}
		}},
		{"app_proto values", `alert udp any any -> any any (msg:"m"; sid:1; app_proto:dns;)`, func(t *testing.T, r *Rule) {
			if r.appProto != packet.AppDNS {
				t.Error(r.appProto)
			}
		}},
		{"detection_filter", hdr + `(msg:"m"; sid:1; detection_filter:track by_dst, count 5, seconds 30;)`, func(t *testing.T, r *Rule) {
			if r.filter == nil || *r.filter != (windowSpec{TrackByDst, 5, 30}) {
				t.Errorf("%+v", r.filter)
			}
		}},
		{"detection_filter any order", hdr + `(msg:"m"; sid:1; detection_filter: seconds 2 ,track by_src,count 9 ;)`, func(t *testing.T, r *Rule) {
			if *r.filter != (windowSpec{TrackBySrc, 9, 2}) {
				t.Errorf("%+v", r.filter)
			}
		}},
		{"detect syn_flood", hdr + `(msg:"m"; sid:1; detect:syn_flood; track:by_dst; count:100; seconds:5; min_incomplete_ratio:0.5;)`, func(t *testing.T, r *Rule) {
			if r.Detect != DetectSYNFlood || r.detect != (windowSpec{TrackByDst, 100, 5}) || r.minRatio != 0.5 {
				t.Errorf("%+v", r)
			}
		}},
		{"detect syn_flood max_distinct_ports", hdr + `(msg:"m"; sid:1; detect:syn_flood; track:by_dst; count:100; seconds:5; max_distinct_ports:30;)`, func(t *testing.T, r *Rule) {
			if r.maxPorts != 30 || r.minRatio != 0.8 {
				t.Errorf("maxPorts %d minRatio %v", r.maxPorts, r.minRatio)
			}
		}},
		{"detect port_scan", `alert ip any any -> any any (msg:"m"; sid:1; detect:port_scan; distinct_ports:20; seconds:10;)`, func(t *testing.T, r *Rule) {
			if r.Detect != DetectPortScan || r.distinct != 20 || r.detect.seconds != 10 || r.Proto != ProtoIP || r.maxPorts != 0 {
				t.Errorf("got %+v", r)
			}
		}},
		{"detect host_sweep on udp", `alert udp any any -> any 161 (msg:"m"; sid:1; detect:host_sweep; distinct_hosts:15; seconds:30;)`, func(t *testing.T, r *Rule) {
			if r.Detect != DetectHostSweep || r.distinct != 15 || r.detect.seconds != 30 {
				t.Errorf("got %+v", r)
			}
		}},
		{"detect ping_sweep", `alert icmp any any -> any any (msg:"m"; sid:1; detect:ping_sweep; distinct_hosts:15; seconds:30;)`, func(t *testing.T, r *Rule) {
			if r.Detect != DetectPingSweep || r.distinct != 15 || r.detect.seconds != 30 {
				t.Errorf("got %+v", r)
			}
		}},
		{"detect default ratio", hdr + `(msg:"m"; sid:1; detect:syn_flood; track:by_src; count:1; seconds:1;)`, func(t *testing.T, r *Rule) {
			if r.minRatio != 0.8 || r.maxPorts != 5 {
				t.Error(r.minRatio, r.maxPorts)
			}
		}},
		{"whitespace and tabs", "  alert\ttcp  any any\t-> any any   ( msg : \"m\" ;  sid : 5 ; )  ", func(t *testing.T, r *Rule) {
			if r.SID != 5 || r.Msg != "m" {
				t.Errorf("%+v", r)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.check(t, one(t, tt.line)) })
	}
}

func TestAddrSpec(t *testing.T) {
	tests := []struct {
		spec string
		in   []string
		out  []string
	}{
		{"any", []string{"1.2.3.4", "::1"}, nil},
		{"10.0.0.1", []string{"10.0.0.1"}, []string{"10.0.0.2", "::ffff:10.0.0.2"}},
		{"10.0.0.0/8", []string{"10.0.0.1", "10.255.255.255"}, []string{"11.0.0.0", "::a00:1"}},
		{"10.1.2.3/8", []string{"10.9.9.9"}, []string{"11.0.0.0"}}, // host bits are masked
		{"2001:db8::1", []string{"2001:db8::1"}, []string{"2001:db8::2", "10.0.0.1"}},
		{"2001:db8::/32", []string{"2001:db8:ffff::1"}, []string{"2001:db9::1"}},
		{"::ffff:10.0.0.1", []string{"10.0.0.1"}, nil}, // mapped form is unmapped
		{"!10.0.0.0/8", []string{"11.0.0.1", "::1"}, []string{"10.1.1.1"}},
		{"[10.0.0.1,192.168.0.0/16]", []string{"10.0.0.1", "192.168.5.5"}, []string{"10.0.0.2"}},
		{"[10.0.0.0/8,!10.0.0.1]", []string{"10.0.0.2"}, []string{"10.0.0.1", "11.0.0.1"}},
		{"[!10.0.0.1,!10.0.0.2]", []string{"10.0.0.3", "::1"}, []string{"10.0.0.1", "10.0.0.2"}},
		{"![10.0.0.1,10.0.0.2]", []string{"10.0.0.3"}, []string{"10.0.0.1", "10.0.0.2"}},
		{"[10.0.0.1, 2001:db8::/64]", []string{"2001:db8::5"}, nil}, // header splitting drops spaces inside lists
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			spec := strings.ReplaceAll(tt.spec, " ", "")
			s, err := parseAddrSpec(spec)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range tt.in {
				if !s.match(netip.MustParseAddr(a).Unmap()) {
					t.Errorf("%s should match %s", tt.spec, a)
				}
			}
			for _, a := range tt.out {
				if s.match(netip.MustParseAddr(a).Unmap()) {
					t.Errorf("%s should not match %s", tt.spec, a)
				}
			}
		})
	}
}

func TestPortSpec(t *testing.T) {
	tests := []struct {
		spec    string
		in, out []uint16
	}{
		{"any", []uint16{0, 65535}, nil},
		{"80", []uint16{80}, []uint16{81, 0}},
		{"0", []uint16{0}, []uint16{1}},
		{"1000:2000", []uint16{1000, 1500, 2000}, []uint16{999, 2001}},
		{"1024:", []uint16{1024, 65535}, []uint16{1023}},
		{":1023", []uint16{0, 1023}, []uint16{1024}},
		{"!22", []uint16{21, 23}, []uint16{22}},
		{"!1:1023", []uint16{0, 1024}, []uint16{1, 1023}},
		{"[80,443,8000:8080]", []uint16{80, 443, 8000, 8080}, []uint16{81, 8081}},
		{"[1:1023,!22]", []uint16{21, 23}, []uint16{22, 1024}},
		{"![80,443]", []uint16{8080}, []uint16{80, 443}},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			s, err := parsePortSpec(tt.spec)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range tt.in {
				if !s.match(p) {
					t.Errorf("%s should match %d", tt.spec, p)
				}
			}
			for _, p := range tt.out {
				if s.match(p) {
					t.Errorf("%s should not match %d", tt.spec, p)
				}
			}
		})
	}
}

// TestParseErrors checks that each error is reported with the right line
// and a useful reason.
func TestParseErrors(t *testing.T) {
	const hdr = "alert tcp any any -> any any "
	tests := []struct {
		name, line, want string
	}{
		{"unknown option", hdr + `(msg:"m"; sid:1; conten:"x";)`, `unknown option "conten"`},
		{"unknown flag option", hdr + `(msg:"m"; sid:1; nocasee;)`, `unknown option "nocasee"`},
		{"missing msg", hdr + `(sid:1;)`, "missing required option msg"},
		{"missing sid", hdr + `(msg:"m";)`, "missing required option sid"},
		{"empty msg", hdr + `(msg:""; sid:1;)`, "msg must not be empty"},
		{"unquoted msg", hdr + `(msg:m; sid:1;)`, "want a double-quoted string"},
		{"bad escape", hdr + `(msg:"a\n"; sid:1;)`, `unknown escape \n`},
		{"sid zero", hdr + `(msg:"m"; sid:0;)`, `sid: "0": want an integer from 1`},
		{"sid text", hdr + `(msg:"m"; sid:abc;)`, `sid: "abc"`},
		{"rev bad", hdr + `(msg:"m"; sid:1; rev:-1;)`, `rev: "-1"`},
		{"option twice", hdr + `(msg:"m"; sid:1; rev:1; rev:2;)`, "option rev given more than once"},
		{"option without value", hdr + `(msg:"m"; sid:1; severity;)`, "option severity needs a value"},
		{"severity", hdr + `(msg:"m"; sid:1; severity:urgent;)`, `severity "urgent"`},
		{"category", hdr + `(msg:"m"; sid:1; category:a b;)`, `category "a b"`},
		{"flags letter", hdr + `(msg:"m"; sid:1; flags:SX;)`, `unknown flag 'X'`},
		{"flags lowercase", hdr + `(msg:"m"; sid:1; flags:s;)`, `unknown flag 's'`},
		{"flags repeated", hdr + `(msg:"m"; sid:1; flags:SS;)`, `flag 'S' repeated`},
		{"flags plus only", hdr + `(msg:"m"; sid:1; flags:+;)`, "no flags given"},
		{"flags on udp", `alert udp any any -> any any (msg:"m"; sid:1; flags:S;)`, "flags requires protocol tcp"},
		{"content unquoted", hdr + `(msg:"m"; sid:1; content:abc;)`, "want a double-quoted string"},
		{"content empty", hdr + `(msg:"m"; sid:1; content:"";)`, "empty content"},
		{"content odd hex", hdr + `(msg:"m"; sid:1; content:"|0d 0|";)`, "odd number of digits"},
		{"content bad hex", hdr + `(msg:"m"; sid:1; content:"|zz|";)`, `bad hex byte "zz"`},
		{"content open hex", hdr + `(msg:"m"; sid:1; content:"|0d";)`, "unterminated |hex|"},
		{"nocase without content", hdr + `(msg:"m"; sid:1; nocase;)`, "nocase must follow a content"},
		{"nocase twice", hdr + `(msg:"m"; sid:1; content:"a"; nocase; nocase;)`, "nocase given twice"},
		{"nocase with value", hdr + `(msg:"m"; sid:1; content:"a"; nocase:1;)`, "nocase takes no value"},
		{"app_proto", hdr + `(msg:"m"; sid:1; app_proto:smtp;)`, `app_proto "smtp"`},
		{"app_field no equals", hdr + `(msg:"m"; sid:1; app_field:method;)`, `want KEY=VALUE`},
		{"app_field bad key", hdr + `(msg:"m"; sid:1; app_field:a.b=c;)`, `app_field key "a.b"`},
		{"app_reason", hdr + `(msg:"m"; sid:1; app_reason:evil;)`, `app_reason "evil"`},
		{"app on icmp", `alert icmp any any -> any any (msg:"m"; sid:1; app_proto:dns;)`, "require protocol ip, tcp or udp"},
		{"detection_filter missing", hdr + `(msg:"m"; sid:1; detection_filter:track by_src, count 5;)`, "missing seconds"},
		{"detection_filter track", hdr + `(msg:"m"; sid:1; detection_filter:track by_foo, count 5, seconds 1;)`, `track "by_foo"`},
		{"detection_filter count", hdr + `(msg:"m"; sid:1; detection_filter:track by_src, count 0, seconds 1;)`, "count"},
		{"detection_filter term", hdr + `(msg:"m"; sid:1; detection_filter:track by_src, count 5, secs 1;)`, `unknown term "secs"`},
		{"detection_filter too big", hdr + `(msg:"m"; sid:1; detection_filter:track by_src, count 100001, seconds 1;)`, "1 to 100000"},
		{"detect unknown", hdr + `(msg:"m"; sid:1; detect:port_sweep;)`, `detect "port_sweep": want syn_flood, port_scan, host_sweep, ping_sweep, ttl_anomaly, frag_attack, arp_spoof, udp_flood, icmp_flood, icmp_tunnel, slowloris, dns_spoof, dns_amplification, dns_tunnel or dns_nxdomain_burst`},
		{"port_scan missing params", hdr + `(msg:"m"; sid:1; detect:port_scan;)`, "detect:port_scan needs distinct_ports, seconds"},
		{"port_scan with track", hdr + `(msg:"m"; sid:1; detect:port_scan; distinct_ports:20; seconds:10; track:by_dst;)`, "option track is not valid with detect:port_scan"},
		{"port_scan with count", hdr + `(msg:"m"; sid:1; detect:port_scan; distinct_ports:20; seconds:10; count:5;)`, "option count is not valid with detect:port_scan"},
		{"port_scan with distinct_hosts", hdr + `(msg:"m"; sid:1; detect:port_scan; distinct_hosts:20; seconds:10;)`, "not valid with detect:port_scan"},
		{"port_scan with ratio", hdr + `(msg:"m"; sid:1; detect:port_scan; distinct_ports:20; seconds:10; min_incomplete_ratio:0.5;)`, "option min_incomplete_ratio is not valid with detect:port_scan"},
		{"port_scan too many", hdr + `(msg:"m"; sid:1; detect:port_scan; distinct_ports:1001; seconds:10;)`, "1 to 1000"},
		{"port_scan zero", hdr + `(msg:"m"; sid:1; detect:port_scan; distinct_ports:0; seconds:10;)`, "distinct_ports"},
		{"port_scan on icmp", `alert icmp any any -> any any (msg:"m"; sid:1; detect:port_scan; distinct_ports:20; seconds:10;)`, "requires protocol ip, tcp or udp"},
		{"host_sweep with distinct_ports", hdr + `(msg:"m"; sid:1; detect:host_sweep; distinct_ports:15; seconds:30;)`, "option distinct_ports is not valid with detect:host_sweep"},
		{"host_sweep missing seconds", hdr + `(msg:"m"; sid:1; detect:host_sweep; distinct_hosts:15;)`, "detect:host_sweep needs seconds"},
		{"host_sweep on arp", `alert arp any any -> any any (msg:"m"; sid:1; detect:host_sweep; distinct_hosts:15; seconds:30;)`, "requires protocol ip, tcp or udp"},
		{"ping_sweep on tcp", hdr + `(msg:"m"; sid:1; detect:ping_sweep; distinct_hosts:15; seconds:30;)`, "requires protocol ip or icmp"},
		{"both distinct options", `alert ip any any -> any any (msg:"m"; sid:1; detect:host_sweep; distinct_hosts:15; distinct_ports:3; seconds:30;)`, "cannot both be given"},
		{"distinct twice", `alert ip any any -> any any (msg:"m"; sid:1; detect:host_sweep; distinct_hosts:15; distinct_hosts:3; seconds:30;)`, "distinct_hosts given more than once"},
		{"max_distinct_ports with port_scan", hdr + `(msg:"m"; sid:1; detect:port_scan; distinct_ports:20; seconds:10; max_distinct_ports:5;)`, "option max_distinct_ports is not valid with detect:port_scan"},
		{"max_distinct_ports range", hdr + `(msg:"m"; sid:1; detect:syn_flood; track:by_src; count:5; seconds:1; max_distinct_ports:0;)`, "max_distinct_ports"},
		{"max_distinct_ports without detect", hdr + `(msg:"m"; sid:1; max_distinct_ports:5;)`, "option max_distinct_ports is only valid with detect:syn_flood"},
		{"distinct_hosts without detect", hdr + `(msg:"m"; sid:1; distinct_hosts:5;)`, "option distinct_hosts is only valid with detect:host_sweep, detect:ping_sweep"},
		{"seconds without detect", hdr + `(msg:"m"; sid:1; seconds:5;)`, "option seconds is only valid with detect:syn_flood, detect:port_scan"},
		{"pass with port_scan", `pass ip any any -> any any (msg:"m"; sid:1; detect:port_scan; distinct_ports:20; seconds:10;)`, "detect cannot be used with a pass rule"},
		{"detect missing params", hdr + `(msg:"m"; sid:1; detect:syn_flood; count:5;)`, "needs track, seconds"},
		{"detect ratio range", hdr + `(msg:"m"; sid:1; detect:syn_flood; track:by_src; count:5; seconds:1; min_incomplete_ratio:1.5;)`, "min_incomplete_ratio"},
		{"detect on udp", `alert udp any any -> any any (msg:"m"; sid:1; detect:syn_flood; track:by_src; count:5; seconds:1;)`, "requires protocol tcp"},
		{"detect with content", hdr + `(msg:"m"; sid:1; detect:syn_flood; track:by_src; count:5; seconds:1; content:"x";)`, "content cannot be combined with detect"},
		{"detector option without detect", hdr + `(msg:"m"; sid:1; count:5;)`, "only valid with detect"},
		{"pass with filter", `pass tcp any any -> any any (msg:"m"; sid:1; detection_filter:track by_src, count 5, seconds 1;)`, "cannot be used with a pass rule"},
		{"action", `drop tcp any any -> any any (msg:"m"; sid:1;)`, `unknown action "drop"`},
		{"proto", `alert sctp any any -> any any (msg:"m"; sid:1;)`, `unknown protocol "sctp"`},
		{"direction", `alert tcp any any <- any any (msg:"m"; sid:1;)`, `unknown direction "<-"`},
		{"bad address", `alert tcp 10.0.0.256 any -> any any (msg:"m"; sid:1;)`, `source address: invalid address "10.0.0.256"`},
		{"bad cidr", `alert tcp any any -> 10.0.0.0/33 any (msg:"m"; sid:1;)`, `destination address: invalid CIDR "10.0.0.0/33"`},
		{"not any", `alert tcp !any any -> any any (msg:"m"; sid:1;)`, "!any matches nothing"},
		{"empty list", `alert tcp [] any -> any any (msg:"m"; sid:1;)`, "empty list"},
		{"nested list", `alert tcp [10.0.0.1,[10.0.0.2]] any -> any any (msg:"m"; sid:1;)`, "list items must be"},
		{"list with any", `alert tcp [any,10.0.0.1] any -> any any (msg:"m"; sid:1;)`, "list items must be"},
		{"zone", `alert tcp fe80::1%eth0 any -> any any (msg:"m"; sid:1;)`, "invalid address"},
		{"bad port", `alert tcp any 65536 -> any any (msg:"m"; sid:1;)`, `source port: invalid port "65536"`},
		{"bad range", `alert tcp any any -> any 2000:1000 (msg:"m"; sid:1;)`, "start is after end"},
		{"bare colon", `alert tcp any any -> any : (msg:"m"; sid:1;)`, "invalid port range"},
		{"port on ip", `alert ip any 80 -> any any (msg:"m"; sid:1;)`, "ports must be any for protocol ip"},
		{"port on arp", `alert arp any any -> any 1 (msg:"m"; sid:1;)`, "ports must be any for protocol arp"},
		{"too few fields", `alert tcp any any -> any (msg:"m"; sid:1;)`, "header has 6 fields"},
		{"no options", `alert tcp any any -> any any`, "missing options"},
		{"no close paren", `alert tcp any any -> any any (msg:"m"; sid:1;`, "must end with ')'"},
		{"unbalanced bracket", `alert tcp [10.0.0.1 any -> any any (msg:"m"; sid:1;)`, "unbalanced '['"},
		{"unterminated quote", hdr + `(msg:"m; sid:1;)`, "unterminated quoted string"},
		{"empty option", hdr + `(msg:"m";; sid:1;)`, "empty option"},
		{"stream_anomaly reason", hdr + `(msg:"m"; sid:1; stream_anomaly:gap;)`, `stream_anomaly "gap": want overlap_conflict, oversize_headers or too_many_ooo_segments, or no value for any`},
		{"stream_anomaly empty", hdr + `(msg:"m"; sid:1; stream_anomaly:;)`, `stream_anomaly ""`},
		{"stream_anomaly twice", hdr + `(msg:"m"; sid:1; stream_anomaly; stream_anomaly:oversize_headers;)`, "option stream_anomaly given more than once"},
		{"stream_anomaly on udp", `alert udp any any -> any any (msg:"m"; sid:1; stream_anomaly;)`, "stream_anomaly requires protocol tcp or ip"},
		{"stream_anomaly with detect", hdr + `(msg:"m"; sid:1; detect:slowloris; kind:slow_read; track:by_src; count:5; stream_anomaly;)`, "option stream_anomaly cannot be combined with detect"},
		{"slowloris missing", hdr + `(msg:"m"; sid:1; detect:slowloris; kind:slow_read;)`, "detect:slowloris needs track, count"},
		{"slowloris kind", hdr + `(msg:"m"; sid:1; detect:slowloris; kind:slow_write; track:by_src; count:5;)`, `kind "slow_write": want slow_headers, slow_body, slow_read`},
		{"slowloris on udp", `alert udp any any -> any any (msg:"m"; sid:1; detect:slowloris; kind:slow_read; track:by_src; count:5;)`, "detect:slowloris requires protocol tcp"},
		{"slowloris min_rate", hdr + `(msg:"m"; sid:1; detect:slowloris; kind:slow_headers; track:by_src; count:5; min_rate:10;)`, "min_rate and min_remaining are only valid with kind:slow_body"},
		{"slowloris min_remaining", hdr + `(msg:"m"; sid:1; detect:slowloris; kind:slow_read; track:by_src; count:5; min_remaining:10;)`, "min_rate and min_remaining are only valid with kind:slow_body"},
		{"slowloris read seconds", hdr + `(msg:"m"; sid:1; detect:slowloris; kind:slow_read; track:by_src; count:5; seconds:5;)`, "seconds is not valid with kind:slow_read"},
		{"slowloris min_age", hdr + `(msg:"m"; sid:1; detect:slowloris; kind:slow_read; track:by_src; count:5; min_age:0;)`, "min_age"},
		{"slowloris min_rate big", hdr + `(msg:"m"; sid:1; detect:slowloris; kind:slow_body; track:by_src; count:5; min_rate:2000000000;)`, "min_rate"},
		{"min_age elsewhere", hdr + `(msg:"m"; sid:1; min_age:5;)`, "option min_age is only valid with detect:slowloris"},
		{"min_age other detector", hdr + `(msg:"m"; sid:1; detect:syn_flood; track:by_dst; count:5; seconds:1; min_age:5;)`, "option min_age is not valid with detect:syn_flood"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := "# comment\n\n" + tt.line + "\n"
			_, err := Parse(strings.NewReader(text), "f.rules")
			var le *LoadError
			if !errors.As(err, &le) {
				t.Fatalf("err = %v, want a *LoadError", err)
			}
			found := false
			for _, se := range le.Errors {
				if se.Line != 3 || se.File != "f.rules" {
					t.Errorf("error at %s:%d, want f.rules:3: %v", se.File, se.Line, se)
				}
				if strings.Contains(se.Reason, tt.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("errors %v do not mention %q", le.Errors, tt.want)
			}
			if !strings.Contains(err.Error(), "f.rules:3: ") {
				t.Errorf("Error() = %q", err)
			}
		})
	}
}

// TestParseReportsAllErrors checks that one load reports every bad line,
// several problems on one line, and duplicate sids, all with line numbers.
func TestParseReportsAllErrors(t *testing.T) {
	text := strings.Join([]string{
		`# header comment`,
		`alert tcp any any -> any any (msg:"ok"; sid:1;)`,
		`alert tcp any any -> any any (msg:"typo"; sid:2; sverity:high;)`,
		``,
		`alert tcp any any -> any 99999 (msg:"two problems"; sid:3; flags:X;)`,
		`alert tcp any any -> any any (msg:"dup"; sid:1;)`,
		`alert udp any any -> any any (msg:"no sid";)`,
		`alert tcp any any -> any any (msg:"dup of a bad line"; sid:2;)`,
	}, "\n")
	rs, err := Parse(strings.NewReader(text), "multi.rules")
	if rs != nil {
		t.Error("RuleSet returned with errors")
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("err = %v", err)
	}
	type lr struct {
		line int
		frag string
	}
	want := []lr{
		{3, `unknown option "sverity"`},
		{5, `destination port: invalid port "99999"`},
		{5, `unknown flag 'X'`},
		{6, "duplicate sid 1 (first defined on line 2)"},
		{7, "missing required option sid"},
		{8, "duplicate sid 2 (first defined on line 3)"},
	}
	if len(le.Errors) != len(want) {
		t.Fatalf("got %d errors, want %d:\n%v", len(le.Errors), len(want), err)
	}
	for i, w := range want {
		got := le.Errors[i]
		if got.Line != w.line || !strings.Contains(got.Reason, w.frag) {
			t.Errorf("error %d = %v, want line %d with %q", i, got, w.line, w.frag)
		}
	}
	var se *SyntaxError
	if !errors.As(err, &se) || se.Line != 3 {
		t.Errorf("errors.As SyntaxError = %v", se)
	}
}

func TestLoad(t *testing.T) {
	if _, err := Load("does-not-exist.rules"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	rs, err := Load("../../rules.conf")
	if err != nil {
		t.Fatalf("rules.conf: %v", err)
	}
	if rs.Len() != 74 || len(rs.detectors) != 36 {
		t.Errorf("rules.conf: %d rules, %d detectors", rs.Len(), len(rs.detectors))
	}
	for _, r := range rs.Rules() {
		if r.Msg == "" || r.Category == "" || r.Severity == "" || r.File != "../../rules.conf" || r.Line == 0 {
			t.Errorf("rule %d incomplete: %+v", r.SID, r)
		}
	}
	empty, err := Parse(strings.NewReader("# nothing\n\n"), "e")
	if err != nil || empty.Len() != 0 {
		t.Errorf("empty file: %v %v", empty, err)
	}
}

func TestGrouping(t *testing.T) {
	rs := mustParse(t, strings.Join([]string{
		`alert ip any any -> any any (msg:"ip"; sid:1;)`,
		`alert tcp any any -> any any (msg:"tcp"; sid:2;)`,
		`pass udp any any -> any any (msg:"udp pass"; sid:3;)`,
		`alert arp any any -> any any (msg:"arp"; sid:4;)`,
		`alert icmp any any -> any any (msg:"icmp"; sid:5;)`,
		`alert tcp any any -> any any (msg:"syn"; sid:6; detect:syn_flood; track:by_dst; count:5; seconds:1;)`,
	}, "\n"))
	sids := func(rules []*Rule) []int {
		var out []int
		for _, r := range rules {
			out = append(out, r.SID)
		}
		return out
	}
	for _, c := range []struct {
		g           group
		pass, alert []int
	}{
		{gIP, nil, []int{1}},
		{gTCP, nil, []int{1, 2}},
		{gUDP, []int{3}, []int{1}},
		{gICMP, nil, []int{1, 5}},
		{gARP, nil, []int{4}},
		{gNone, nil, nil},
	} {
		if got := sids(rs.groups[c.g].pass); !reflect.DeepEqual(got, c.pass) {
			t.Errorf("group %d pass = %v, want %v", c.g, got, c.pass)
		}
		if got := sids(rs.groups[c.g].alert); !reflect.DeepEqual(got, c.alert) {
			t.Errorf("group %d alert = %v, want %v", c.g, got, c.alert)
		}
	}
	if got := sids(rs.detectors); !reflect.DeepEqual(got, []int{6}) || !rs.handshakes || rs.probes {
		t.Errorf("detectors = %v, handshakes %v, probes %v", got, rs.handshakes, rs.probes)
	}
}

func FuzzLoad(f *testing.F) {
	if b, err := os.ReadFile("../../rules.conf"); err == nil {
		f.Add(string(b))
	}
	f.Add(`alert tcp [10.0.0.0/8,!10.0.0.1] 1024: <> ![::1,2001:db8::/32] [80,!81,90:95] (msg:"a\"b"; sid:1; content:"x|0d 0a|"; nocase; flags:SA+;)`)
	f.Add(`alert tcp any any -> any any (msg:"m"; sid:1; detection_filter:track by_src, count 5, seconds 30;)`)
	f.Add(`alert tcp any any -> any any (msg:"m"; sid:2; detect:syn_flood; track:by_dst; count:5; seconds:1; min_incomplete_ratio:0.3)`)
	f.Add(`alert ip any any -> any any (msg:"m"; sid:3; detect:port_scan; distinct_ports:20; seconds:10;)`)
	f.Add(`alert icmp any any -> any any (msg:"m"; sid:4; detect:ping_sweep; distinct_hosts:15; seconds:30;)`)
	f.Add("alert tcp any any -> any any (msg:\"m\"; sid:1;)\nalert tcp any any -> any any (msg:\"m\"; sid:1;)")
	f.Add(`alert tcp [ any -> any any (msg:"; sid:1`)
	f.Add("var HOME_NET [10.0.0.0/8,fc00::/7]\nvar EXTERNAL_NET !$HOME_NET\nvar P [80,443]\n" +
		`alert tcp $EXTERNAL_NET any -> [$HOME_NET,!10.0.0.1] !$P (msg:"m"; sid:1; same_ip; same_port; flags:S+; ttl:<3;)`)
	f.Add("var A $B\nvar B [$A,1.2.3.4]\nalert ip $A any -> any any (msg:\"m\"; sid:1;)")
	f.Add(`alert icmp any any -> 255.255.255.255 any (msg:"m"; sid:1; itype:8; icode:0; eth_dst:broadcast; ttl:>200;)`)
	f.Add("var HOME_NET 10.0.0.0/8\n" + `alert ip any any -> any any (msg:"m"; sid:1; detect:ttl_anomaly; count:5; seconds:60; min_samples:10; max_hop_diff:3; scope:external;)`)
	f.Add(`alert ip any any -> any any (msg:"m"; sid:1; detect:frag_attack; kind:tiny; min_size:256;)`)
	f.Add(`alert ip any any -> any any (msg:"m"; sid:1; detect:frag_attack; kind:flood; count:50; seconds:30;)`)
	f.Add("arpbind 192.168.1.1 aa:bb:cc:dd:ee:01\narpbind 192.168.1.2 AA-BB-CC-DD-EE-02\n" +
		`alert arp any any -> any any (msg:"m"; sid:1; detect:arp_spoof; kind:static_violation;)`)
	f.Add(`alert arp any any -> any any (msg:"m"; sid:1; detect:arp_spoof; kind:flip_flop; count:3; seconds:60;)`)
	f.Add(`alert arp any any -> any any (msg:"m"; sid:1; detect:arp_spoof; kind:multi_ip; count:10; seconds:60;)`)
	f.Add(`pass arp 10.20.0.0/16 any -> any any (msg:"m"; sid:1; arp_op:reply; eth_dst:!broadcast;)`)
	f.Add("arpbind 10.0.0.1 02:00:00:00:00:01\narpbind 10.0.0.1 ff:ff:ff:ff:ff:ff\narpbind ::1 x")
	f.Add(`alert icmp any any -> any any (msg:"m"; sid:1; itype:8; dsize:>1472;)` + "\n" +
		`alert udp any any -> any any (msg:"m"; sid:2; dsize:0<>65535;)` + "\n" +
		`alert tcp any any -> any any (msg:"m"; sid:3; dsize:<1; flags:S;)`)
	f.Add(`alert ip any any -> any any (msg:"m"; sid:1; dsize:9<>3;)`)
	f.Add(`alert ip any any -> any any (msg:"m"; sid:1; dsize:5<>;)`)
	f.Add(`alert udp any any -> any any (msg:"m"; sid:1; detect:udp_flood; track:by_dst; metric:bytes; count:100000000; seconds:5; max_reply_ratio:0.02;)`)
	f.Add(`alert icmp any any -> any any (msg:"m"; sid:1; detect:icmp_flood; kind:echo; track:by_src; count:1000; seconds:5;)` + "\n" +
		`alert icmp any any -> any any (msg:"m"; sid:2; detect:icmp_flood; kind:unsolicited_reply; count:100; seconds:5;)`)
	f.Add(`alert icmp any any -> any any (msg:"m"; sid:1; detect:icmp_tunnel; count:10; seconds:60;)`)
	f.Add(`alert tcp any any -> any 80 (msg:"m"; sid:1; app_content:uri,"UNION",nocase; regex:query,"(?i)union\s+select\b"; regex:headers_raw,"\(\)\s*\{";)`)
	f.Add(`alert udp any any -> any any (msg:"m"; sid:2; regex:data,"\x00{4}\"\;";)` + "\n" +
		`alert tcp any any -> any any (msg:"m"; sid:3; app_content:user_agent,"|73 71|lmap";)`)
	f.Add(`alert tcp any any -> any any (msg:"m"; sid:1; regex:uri,"a(";)` + "\n" +
		`alert tcp any any -> any any (msg:"m"; sid:2; app_content:uri,"x",bad;)`)
	f.Add(`alert udp any any -> any 53 (msg:"m"; sid:1; detect:dns_spoof; kind:id_race; count:10; seconds:2;)` + "\n" +
		`alert udp any any -> any any (msg:"m"; sid:2; detect:dns_spoof; kind:qname_mismatch;)` + "\n" +
		`alert udp any any -> any any (msg:"m"; sid:3; detect:dns_amplification; min_bytes:1000000; seconds:5; min_ratio:10;)`)
	f.Add("var ALLOW [in-addr.arpa,ip6.arpa]\n" +
		`alert udp any any -> any any (msg:"m"; sid:1; detect:dns_tunnel; kind:subdomains; count:50; seconds:60; min_entropy:3.5; min_length:50; allow:$ALLOW;)` + "\n" +
		`alert udp any any -> any any (msg:"m"; sid:2; detect:dns_tunnel; kind:txt; count:100; seconds:60;)` + "\n" +
		`alert udp any any -> any any (msg:"m"; sid:3; detect:dns_nxdomain_burst; count:30; seconds:60; min_entropy:3.0;)`)
	f.Add("var A [dns.google,cloudflare-dns.com]\nvar B [$A,c.com]\n" +
		`alert tcp any any -> any 443 (msg:"m"; sid:1; app_proto:tls; app_domain:sni,$B;)` + "\n" +
		`alert tcp any any -> any 443 (msg:"m"; sid:2; app_domain:sni,!$A;)` + "\n" +
		`alert tcp $A any -> any any (msg:"m"; sid:3; detect:dns_spoof;)`)
	f.Fuzz(func(t *testing.T, text string) {
		rs, err := Parse(strings.NewReader(text), "fuzz")
		if err != nil {
			if rs != nil {
				t.Error("RuleSet with error")
			}
			var le *LoadError
			if errors.As(err, &le) {
				for _, se := range le.Errors {
					if se.Line < 1 || se.Reason == "" {
						t.Errorf("bad error %+v", se)
					}
				}
			}
			return
		}
		seen := make(map[int]bool)
		for _, r := range rs.Rules() {
			if r.SID < 1 || r.Msg == "" || seen[r.SID] {
				t.Errorf("bad rule %+v", r)
			}
			seen[r.SID] = true
		}
		// Loaded rules must be usable without panicking.
		e := NewEngine(rs, EngineConfig{})
		p := pkt{proto: "tcp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1234, dport: 80, flags: "PA", payload: "GET / HTTP/1.1\r\n\r\n"}
		e.Process(fuzzPacket(t, p))
		e.Process(fuzzPacket(t, pkt{proto: "icmp", src: "10.0.0.1", dst: "10.0.0.1", ttl: 2, ethDst: [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}))
		e.Process(parseFrame(fragFrame(t, "10.0.0.1", "10.0.0.2", 1, 17, 65528, true, make([]byte, 8)), t0))
		e.Flush()
	})
}

var fuzzPackets = map[pkt][]byte{}

func fuzzPacket(t *testing.T, p pkt) *packet.ParsedPacket {
	b, ok := fuzzPackets[p]
	if !ok {
		b = p.bytes(t)
		fuzzPackets[p] = b
	}
	return parseFrame(append([]byte(nil), b...), t0)
}

func TestParseSlowloris(t *testing.T) {
	rs := mustParse(t, `alert tcp any any -> any 80 (msg:"a"; detect:slowloris; kind:slow_headers; track:by_dst; count:20; sid:1;)
alert tcp any any -> any 80 (msg:"b"; detect:slowloris; kind:slow_body; track:by_src; count:10; sid:2;)
alert tcp any any -> any 80 (msg:"c"; detect:slowloris; kind:slow_read; track:by_src; count:10; sid:3;)
alert tcp any any -> any 80 (msg:"d"; detect:slowloris; kind:slow_body; track:by_src; count:3; seconds:60; min_age:5; min_rate:50; min_remaining:1000; sid:4;)
alert tcp any any -> any any (msg:"e"; stream_anomaly; sid:5;)
alert ip any any -> any any (msg:"f"; stream_anomaly:overlap_conflict; sid:6;)
`)
	type want struct {
		kind              string
		track             Track
		count, seconds    int
		minAge            time.Duration
		minRate, minRemai int
	}
	for i, w := range []want{
		{SlowHeaders, TrackByDst, 20, 30, 10 * time.Second, 100, 10240},
		{SlowBody, TrackBySrc, 10, 30, 20 * time.Second, 100, 10240},
		{SlowRead, TrackBySrc, 10, 30, 20 * time.Second, 100, 10240},
		{SlowBody, TrackBySrc, 3, 60, 5 * time.Second, 50, 1000},
	} {
		r := rs.rules[i]
		got := want{r.slowKind, r.detect.track, r.detect.count, r.detect.seconds, r.minAge, r.minRate, r.minRemaining}
		if got != w {
			t.Errorf("rule %d: %+v, want %+v", i, got, w)
		}
	}
	if len(rs.slow) != 4 || len(rs.detectors) != 4 {
		t.Errorf("slow %d detectors %d", len(rs.slow), len(rs.detectors))
	}
	if r := rs.rules[4]; !r.hasAnomaly || r.anomaly != "" {
		t.Errorf("stream_anomaly: %v %q", r.hasAnomaly, r.anomaly)
	}
	if r := rs.rules[5]; !r.hasAnomaly || r.anomaly != packet.StreamOverlapConflict {
		t.Errorf("stream_anomaly:overlap_conflict: %v %q", r.hasAnomaly, r.anomaly)
	}
}
