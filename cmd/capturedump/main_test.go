package main

import (
	"encoding/hex"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/app"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

func TestDescribe(t *testing.T) {
	const ethIPv4 = "02000000000b02000000000a0800"
	tests := []struct {
		name    string
		hexData string
		wireLen uint32
		want    string
	}{
		{
			name: "ipv4 tcp",
			hexData: ethIPv4 + "45000028123400004006" + "549a" + "0a0000010a000002" +
				"04d2005000000000000000005002000000000000",
			want: "len=54  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=6 ttl=64  TCP 1234 -> 80 [SYN] seq=0 ack=0 win=0 len=0 [bad-l4csum]",
		},
		{
			name: "ipv4 fragment with bad checksum, truncated capture",
			hexData: ethIPv4 + "45000028123420004006" + "0000" + "0a0000010a000002" +
				"04d2005000000000000000005002000000000000",
			wireLen: 100,
			want:    "len=100 cap=54  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=6 ttl=64 frag bad-csum  TCP 1234 -> 80 [SYN] seq=0 ack=0 win=0 len=0",
		},
		{
			name: "ipv4 tcp syn-ack with payload, valid checksum",
			hexData: ethIPv4 + "4500002b123400004006" + "5497" + "0a0000010a000002" +
				"01bb9c40" + "000003e8" + "000007d0" + "5012faf0" + "32c6" + "0000" + "616263",
			want: "len=57  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=6 ttl=64  TCP 443 -> 40000 [SYN,ACK] seq=1000 ack=2000 win=64240 len=3",
		},
		{
			name: "ipv4 udp, no checksum",
			hexData: ethIPv4 + "45000021123400004011" + "5496" + "0a0000010a000002" +
				"9c400035000d0000" + "7175657279",
			want: "len=47  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=17 ttl=64  UDP 40000 -> 53 len=13" +
				`  DNS [malformed: message shorter than the 12-byte header]  errors=["dns: message shorter than the 12-byte header"]`,
		},
		{
			name: "ipv4 udp dns query",
			hexData: ethIPv4 + "45000038123400004011" + "547f" + "0a0000010a000002" +
				"9c4000350024000012340100000100000000000006676f6f676c6503636f6d0000010001",
			want: "len=70  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=17 ttl=64  UDP 40000 -> 53 len=36  DNS query google.com A",
		},
		{
			name: "ipv4 icmp port unreachable",
			hexData: ethIPv4 + "4500002000000000400" + "1" + "0000" + "0a0000010a000002" +
				"0303fcfc" + "00000000" + "00000000",
			want: "len=46  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=1 ttl=64 bad-csum  ICMP Destination Unreachable (port unreachable)",
		},
		{
			name:    "ipv6",
			hexData: "02000000000b02000000000a86dd" + "6000000000003b40" + "20010db8000000000000000000000001" + "20010db8000000000000000000000002",
			want:    "len=54  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv6 2001:db8::1 -> 2001:db8::2 proto=59 hlim=64",
		},
		{
			name:    "arp request",
			hexData: "ffffffffffff02000000000a0806" + "0001080006040001" + "02000000000a0a000001" + "0000000000000a000002",
			want:    "len=42  02:00:00:00:00:0a -> ff:ff:ff:ff:ff:ff  ARP request who-has 10.0.0.2 tell 10.0.0.1",
		},
		{
			name:    "arp reply",
			hexData: "02000000000b02000000000a0806" + "0001080006040002" + "02000000000a0a000001" + "02000000000b0a000002",
			want:    "len=42  02:00:00:00:00:0a -> 02:00:00:00:00:0b  ARP reply 10.0.0.1 is-at 02:00:00:00:00:0a",
		},
		{
			name:    "other ethertype",
			hexData: "02000000000b02000000000a88cc0207",
			want:    "len=16  02:00:00:00:00:0a -> 02:00:00:00:00:0b  ethertype 0x88cc",
		},
		{
			name:    "802.3",
			hexData: "02000000000b02000000000a0026424203",
			want:    "len=17  02:00:00:00:00:0a -> 02:00:00:00:00:0b  802.3 len=38",
		},
		{
			name:    "truncated ipv4 shows errors",
			hexData: ethIPv4 + "4500",
			want:    `len=16  02:00:00:00:00:0a -> 02:00:00:00:00:0b  ethertype 0x0800  errors=["ipv4: truncated header: 2 bytes captured, need 20"]`,
		},
		{
			name:    "runt frame",
			hexData: "0200",
			want:    `len=2  errors=["ethernet: frame too short: 2 bytes, need 14"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := hex.DecodeString(tt.hexData)
			if err != nil {
				t.Fatal(err)
			}
			wire := tt.wireLen
			if wire == 0 {
				wire = uint32(len(data))
			}
			p := packet.NewParsedPacket(time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC), uint32(len(data)), wire)
			p.RawData = data
			lower.Parse(p)
			upper.Parse(p)
			app.Parse(p)

			got := describe(p)
			const ts = "2026-09-25T10:00:00Z  "
			if !strings.HasPrefix(got, ts) {
				t.Fatalf("describe() = %q, want timestamp prefix %q", got, ts)
			}
			if got = strings.TrimPrefix(got, ts); got != tt.want {
				t.Errorf("describe()\n got: %s\nwant: %s", got, tt.want)
			}
		})
	}
}

func TestDescribeApp(t *testing.T) {
	tests := []struct {
		name   string
		proto  string
		fields map[string]string
		want   string
	}{
		{"not classified", "", nil, ""},
		{"unknown", packet.AppUnknown, nil, ""},
		{"dns query", packet.AppDNS, map[string]string{"id": "1", "is_response": "false", "qname": "google.com", "qtype": "1", "qtype_name": "A"},
			"DNS query google.com A"},
		{"dns query, unnamed type", packet.AppDNS, map[string]string{"id": "1", "is_response": "false", "qname": "x.example", "qtype": "99"},
			"DNS query x.example type 99"},
		{"dns response", packet.AppDNS, map[string]string{"id": "4660", "is_response": "true", "rcode": "0", "ancount": "2", "qname": "google.com"},
			"DNS response id=4660 rcode=0 an=2 google.com"},
		{"dns malformed query", packet.AppDNS, map[string]string{"id": "6", "is_response": "false", "malformed_reason": "qname: compression loop"},
			"DNS query id=6 [malformed: qname: compression loop]"},
		{"dns suspicious", packet.AppDNS, map[string]string{"id": "2", "is_response": "false", "qname": "abc.t.example", "qtype": "16", "qtype_name": "TXT",
			"suspicious_reason": "long high-entropy label (possible DNS tunnelling)"},
			"DNS query abc.t.example TXT [suspicious: long high-entropy label (possible DNS tunnelling)]"},
		{"http request", packet.AppHTTP, map[string]string{"method": "GET", "host": "example.com", "uri": "/path"},
			"HTTP GET example.com /path"},
		{"http basic auth", packet.AppHTTP, map[string]string{"method": "GET", "host": "example.com", "uri": "/", "auth_basic": "true"},
			"HTTP GET example.com / auth"},
		{"http request without host", packet.AppHTTP, map[string]string{"method": "GET", "uri": "/path"}, "HTTP GET /path"},
		{"http response", packet.AppHTTP, map[string]string{"status_code": "200", "version": "1.1"}, "HTTP 200"},
		{"h2c", packet.AppHTTP, map[string]string{"version": "2.0"}, "HTTP/2 preface"},
		{"http malformed", packet.AppHTTP, map[string]string{"malformed_reason": "invalid request method"}, "HTTP [malformed: invalid request method]"},
		{"ftp command", packet.AppFTP, map[string]string{"command": "USER", "argument": "alice"}, "FTP USER alice"},
		{"ftp pass", packet.AppFTP, map[string]string{"command": "PASS", "argument": "<redacted>"}, "FTP PASS <redacted>"},
		{"ftp reply", packet.AppFTP, map[string]string{"response_code": "230"}, "FTP 230"},
		{"tls sni", packet.AppTLS, map[string]string{"sni": "example.com", "sni_status": "found"}, "TLS SNI example.com"},
		{"tls truncated", packet.AppTLS, map[string]string{"sni_status": "truncated"}, "TLS SNI truncated"},
		{"tls absent", packet.AppTLS, map[string]string{"sni_status": "absent"}, "TLS ClientHello without SNI"},
		{"tls other record", packet.AppTLS, nil, "TLS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &packet.ParsedPacket{AppProtocol: tt.proto, AppFields: tt.fields}
			if got := describeApp(p); got != tt.want {
				t.Errorf("describeApp() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDescribeAlert(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	a := rules.Alert{
		Time: t0, FirstSeen: t0, LastSeen: t0, SID: 1000001, Msg: "SYN flood", Severity: "high", Proto: "TCP",
		SrcIP: "10.0.0.1", SrcPort: 40000, DstIP: "10.0.0.2", DstPort: 80, Count: 1, Kind: rules.KindAlert,
		Details: map[string]string{"track": "by_dst", "ratio": "1.00"},
	}
	want := `ALERT [high] sid=1000001 "SYN flood" TCP 10.0.0.1:40000 -> 10.0.0.2:80 count=1 time=2026-09-25T10:00:00Z ratio=1.00 track=by_dst`
	if got := describeAlert(a); got != want {
		t.Errorf("alert\n got: %s\nwant: %s", got, want)
	}
	a.Kind, a.Count, a.LastSeen, a.Details = rules.KindSummary, 42, t0.Add(1500*time.Millisecond), nil
	want = `SUMMARY [high] sid=1000001 "SYN flood" TCP 10.0.0.1:40000 -> 10.0.0.2:80 count=42 first=2026-09-25T10:00:00Z last=2026-09-25T10:00:01.5Z`
	if got := describeAlert(a); got != want {
		t.Errorf("summary\n got: %s\nwant: %s", got, want)
	}
	a = rules.Alert{Kind: rules.KindAlert, SID: 7, Msg: "m", Severity: "low", Proto: "ICMP", SrcIP: "2001:db8::1", DstIP: "2001:db8::2", Count: 1, Time: t0}
	want = `ALERT [low] sid=7 "m" ICMP 2001:db8::1 -> 2001:db8::2 count=1 time=2026-09-25T10:00:00Z`
	if got := describeAlert(a); got != want {
		t.Errorf("icmp\n got: %s\nwant: %s", got, want)
	}
	a.Proto, a.SrcPort, a.DstPort = "UDP", 5353, 53
	if got := describeAlert(a); !strings.Contains(got, "UDP [2001:db8::1]:5353 -> [2001:db8::2]:53 ") {
		t.Errorf("ipv6 udp: %s", got)
	}
}

func TestParseWhitelist(t *testing.T) {
	got, err := parseWhitelist("10.1.2.3/8, 192.168.1.5,2001:db8::/32,::ffff:1.2.3.4")
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.1.5/32"),
		netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("1.2.3.4/32"),
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("parseWhitelist = %v, %v", got, err)
	}
	for _, bad := range []string{"", "10.0.0.0/33", "host", "10.0.0.1,"} {
		if _, err := parseWhitelist(bad); err == nil {
			t.Errorf("parseWhitelist(%q) accepted", bad)
		}
	}
}
