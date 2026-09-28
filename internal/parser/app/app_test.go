package app_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/app"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
)

// ---- frame builders ----

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var (
	macA = []byte{0x02, 0, 0, 0, 0, 0x0a}
	macB = []byte{0x02, 0, 0, 0, 0, 0x0b}
	ip6A = []byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}
	ip6B = []byte{0x20, 0x01, 0x0d, 0xb8, 15: 2}
)

func csum(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum>>16 + sum&0xFFFF
	}
	return ^uint16(sum)
}

func ipv4Frame(proto byte, l4 []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(l4)))
	h[8] = 64
	h[9] = proto
	copy(h[12:], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	binary.BigEndian.PutUint16(h[10:], fold(csum(0, h)))
	return cat(macB, macA, u16(0x0800), h, l4)
}

func tcpSeg(sport, dport uint16, payload []byte) []byte {
	return cat(u16(sport), u16(dport), u32(1), u32(1), []byte{5 << 4, 0x18}, u16(64240), u16(0), u16(0), payload)
}

func udpDgram(sport, dport uint16, payload []byte) []byte {
	return cat(u16(sport), u16(dport), u16(uint16(8+len(payload))), u16(0), payload)
}

func tcp4(sport, dport uint16, payload string) []byte {
	return ipv4Frame(6, tcpSeg(sport, dport, []byte(payload)))
}

func udp4(sport, dport uint16, payload string) []byte {
	return ipv4Frame(17, udpDgram(sport, dport, []byte(payload)))
}

// udp6 builds an IPv6 UDP frame with a correct checksum (a zero UDP
// checksum is an error over IPv6).
func udp6(sport, dport uint16, payload string) []byte {
	d := udpDgram(sport, dport, []byte(payload))
	sum := csum(csum(csum(0, ip6A), ip6B), d)
	sum += uint32(len(d)) + 17
	c := fold(sum)
	if c == 0 {
		c = 0xFFFF
	}
	binary.BigEndian.PutUint16(d[6:], c)
	h := cat([]byte{0x60, 0, 0, 0}, u16(uint16(len(d))), []byte{17, 64}, ip6A, ip6B)
	return cat(macB, macA, u16(0x86DD), h, d)
}

// ---- DNS builders ----

func dnsHeader(id, flags, qd, an, ns, ar uint16) []byte {
	return cat(u16(id), u16(flags), u16(qd), u16(an), u16(ns), u16(ar))
}

// wireName encodes a dotted name without compression. "" is the root.
func wireName(name string) []byte {
	var out []byte
	if name != "" {
		for _, l := range strings.Split(name, ".") {
			out = append(out, byte(len(l)))
			out = append(out, l...)
		}
	}
	return append(out, 0)
}

func question(name string, qtype uint16) []byte {
	return cat(wireName(name), u16(qtype), u16(1))
}

func query(id uint16, name string, qtype uint16) string {
	return string(cat(dnsHeader(id, 0x0100, 1, 0, 0, 0), question(name, qtype)))
}

// answerA is an A record for the name at offset 12 (the first question).
func answerA(ip ...byte) []byte {
	return cat(u16(0xC00C), u16(1), u16(1), u32(300), u16(4), ip)
}

func tcpDNS(msg string) string { return string(u16(uint16(len(msg)))) + msg }

// fields builds a map from key, value pairs.
func fields(kv ...string) map[string]string {
	m := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func with(m map[string]string, kv ...string) map[string]string {
	out := maps.Clone(m)
	maps.Copy(out, fields(kv...))
	return out
}

// dnsWant is the field set of a well-formed message with one question.
func dnsWant(msg string, id int, resp bool, rcode, qd, an int, qname string, qtype int, qtypeName string) map[string]string {
	m := fields(
		"dns_len", strconv.Itoa(len(msg)), "id", strconv.Itoa(id), "is_response", strconv.FormatBool(resp),
		"rcode", strconv.Itoa(rcode), "qdcount", strconv.Itoa(qd), "ancount", strconv.Itoa(an),
		"nscount", "0", "arcount", "0",
		"qname", qname, "qtype", strconv.Itoa(qtype), "qclass", "1")
	if qtypeName != "" {
		m["qtype_name"] = qtypeName
	}
	return m
}

// dnsHeaderWant is the field set when only the header was decoded.
func dnsHeaderWant(msg string, id int, resp bool, qd int) map[string]string {
	return fields("dns_len", strconv.Itoa(len(msg)), "id", strconv.Itoa(id), "is_response", strconv.FormatBool(resp),
		"rcode", "0", "qdcount", strconv.Itoa(qd), "ancount", "0", "nscount", "0", "arcount", "0")
}

// ---- TLS builders ----

func ext(typ uint16, data []byte) []byte { return cat(u16(typ), u16(uint16(len(data))), data) }

func sniExt(name string) []byte {
	entry := cat([]byte{0}, u16(uint16(len(name))), []byte(name))
	return ext(0, cat(u16(uint16(len(entry))), entry))
}

// clientHello builds a TLS 1.2-framed ClientHello record carrying exts
// (nil exts means no extensions block at all).
func clientHello(exts ...[]byte) []byte {
	body := cat(u16(0x0303), bytes.Repeat([]byte{0x42}, 32),
		[]byte{32}, bytes.Repeat([]byte{0x07}, 32), // session id
		u16(4), u16(0x1301), u16(0x1302), // cipher suites
		[]byte{1, 0}) // compression: null
	if exts != nil {
		e := cat(exts...)
		body = cat(body, u16(uint16(len(e))), e)
	}
	hs := cat([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body)
	return cat([]byte{22, 3, 1}, u16(uint16(len(hs))), hs)
}

var (
	supportedVersions = ext(43, []byte{2, 0x03, 0x04})
	bigKeyShare       = ext(51, cat(u16(1220), u16(0x11ec), u16(1216), bytes.Repeat([]byte{0x99}, 1216)))
)

// ---- table ----

type appCase struct {
	name    string
	frame   []byte
	proto   string
	want    map[string]string // exact AppFields, unless partial
	partial bool              // only check the keys in want (reasons still exact)
	errs    []string          // substrings, one per ParseErrors entry
	secrets []string          // must appear nowhere in AppFields or ParseErrors
}

func appCases() []appCase {
	const (
		basicCred   = "YWxpY2U6czNjcjN0UGFzcw==" // alice:s3cr3tPass
		basicPlain  = "s3cr3tPass"
		bearerToken = "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0.dG9rZW4"
		ftpPass     = "hunter2-Secret"
	)

	q := query(0x1234, "google.com", 1)
	resp := string(cat(dnsHeader(0x1234, 0x8180, 1, 2, 0, 0), question("google.com", 1),
		answerA(142, 250, 1, 100), answerA(142, 250, 1, 101)))
	nxdomain := string(cat(dnsHeader(7, 0x8183, 1, 0, 0, 0), question("nope.example", 28)))
	axfr := query(99, "example.com", 252)
	anyQ := query(100, "example.com", 255)
	aaaa := query(0xBEEF, "example.com", 28)
	mixed := query(1, "GoOgLe.CoM", 1)
	// 42 characters of 10 letters: about 3.3 bits/char lowercased, 4.3 if
	// case were counted.
	mixedLong := query(17, "AbcDefGHiJabCdEFghIjaBcdEfgHIjAbcDeFGhiJab.example", 1)
	tunnel := query(2, "nbswy3dpeb3w64tmmqqgc3tqmfzxg4dxn5zgs3tomv2gs5dv.t.evil.example", 16)
	long := query(3, strings.Repeat("a", 40)+"."+strings.Repeat("b", 40)+"."+strings.Repeat("c", 20), 1)
	exactly100 := query(4, strings.Repeat("a", 40)+"."+strings.Repeat("b", 40)+"."+strings.Repeat("c", 18), 1)
	twoQ := string(cat(dnsHeader(5, 0x0100, 2, 0, 0, 0), question("example.com", 1),
		[]byte{3, 'w', 'w', 'w', 0xC0, 12}, u16(28), u16(1))) // www + pointer back to example.com
	fwdPtr := string(cat(dnsHeader(6, 0x0100, 1, 0, 0, 0), []byte{0xC0, 20}, u16(1), u16(1), wireName("x")))
	selfPtr := string(cat(dnsHeader(8, 0x0100, 1, 0, 0, 0), []byte{0xC0, 12}, u16(1), u16(1)))
	label64 := query(9, strings.Repeat("x", 64)+".com", 1)
	label63 := query(10, strings.Repeat("x", 63)+".com", 1)
	name256 := query(11, strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 63)}, "."), 1)
	reserved := string(cat(dnsHeader(12, 0x0100, 1, 0, 0, 0), []byte{0x80, 'a', 0}, u16(1), u16(1)))
	noQ := string(dnsHeader(13, 0x0100, 0, 0, 0, 0))
	overrun := query(14, "example.com", 1)
	overrun = overrun[:len(overrun)-2] // qclass missing

	// A 19-pointer backward chain inside the first question's label, then
	// a second question that enters the chain at its far end.
	chainLabel := []byte{0}
	for k := 0; k < 18; k++ {
		target := 13
		if k > 0 {
			target = 14 + 2*(k-1)
		}
		chainLabel = append(chainLabel, 0xC0, byte(target))
	}
	chain := string(cat(dnsHeader(15, 0x0100, 2, 0, 0, 0),
		[]byte{byte(len(chainLabel))}, chainLabel, []byte{0}, u16(1), u16(1),
		[]byte{0xC0, byte(14 + 2*17)}, u16(1), u16(1)))

	get := "GET /index.html HTTP/1.1\r\nHost: Example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"
	getWant := fields("method", "GET", "uri", "/index.html", "uri_decoded", "/index.html", "version", "1.1",
		"host", "Example.com", "user_agent", "curl/8.5.0", "request_complete", "true",
		"headers_raw", "Host: Example.com\nUser-Agent: curl/8.5.0\nAccept: */*")
	post := "POST /api/login HTTP/1.1\r\nhost: api.example\r\nCONTENT-TYPE: application/json\r\nContent-Length: 17\r\n\r\n{\"user\":\"alice\"}"
	headers := func(n int) string {
		var b strings.Builder
		b.WriteString("GET / HTTP/1.1\r\n")
		for i := range n {
			fmt.Fprintf(&b, "X-H%d: v\r\n", i)
		}
		b.WriteString("\r\n")
		return b.String()
	}
	headersRaw := func(n int) string {
		var lines []string
		for i := range n {
			lines = append(lines, fmt.Sprintf("X-H%d: v", i))
		}
		return strings.Join(lines, "\n")
	}
	simpleGet := fields("method", "GET", "uri", "/", "uri_decoded", "/", "version", "1.1", "request_complete", "true")

	chFull := clientHello(sniExt("Example.COM"), supportedVersions)
	chLate := clientHello(supportedVersions, bigKeyShare, sniExt("late.example.org"))

	return []appCase{
		// ---- DNS ----
		{name: "dns query", frame: udp4(40000, 53, q), proto: packet.AppDNS,
			want: dnsWant(q, 0x1234, false, 0, 1, 0, "google.com", 1, "A")},
		{name: "dns response from port 53", frame: udp4(53, 40000, resp), proto: packet.AppDNS,
			want: dnsWant(resp, 0x1234, true, 0, 1, 2, "google.com", 1, "A")},
		{name: "dns nxdomain response", frame: udp4(53, 40000, nxdomain), proto: packet.AppDNS,
			want: dnsWant(nxdomain, 7, true, 3, 1, 0, "nope.example", 28, "AAAA")},
		{name: "dns over ipv6", frame: udp6(40000, 53, aaaa), proto: packet.AppDNS,
			want: dnsWant(aaaa, 0xBEEF, false, 0, 1, 0, "example.com", 28, "AAAA")},
		{name: "dns over tcp with length prefix", frame: tcp4(40000, 53, tcpDNS(axfr)), proto: packet.AppDNS,
			want: dnsWant(axfr, 99, false, 0, 1, 0, "example.com", 252, "AXFR")},
		{name: "dns over tcp response from port 53", frame: tcp4(53, 40000, tcpDNS(resp)), proto: packet.AppDNS,
			want: dnsWant(resp, 0x1234, true, 0, 1, 2, "google.com", 1, "A")},
		{name: "dns over tcp: two messages, first decoded", frame: tcp4(40000, 53, tcpDNS(q)+tcpDNS(axfr)), proto: packet.AppDNS,
			want: dnsWant(q, 0x1234, false, 0, 1, 0, "google.com", 1, "A")},
		{name: "dns over tcp split mid-question is not malformed",
			frame: tcp4(40000, 53, tcpDNS(axfr)[:2+12+5]), proto: packet.AppDNS,
			want: dnsHeaderWant(axfr, 99, false, 1)},
		{name: "dns over tcp continuation segment", frame: tcp4(53, 40000, "\x00\x05\x00\x01\x00\x00\x0e\x10\x00\x04\x5d\xb8\xd8\x22"),
			proto: packet.AppUnknown},
		// Segments split at arbitrary points, as seen in real captures
		// (tcpdump's dns_tcp.pcap, chrissanders' dns_axfr.pcapng). The
		// first two bytes are not a length, so none of them is DNS.
		{name: "dns over tcp: length prefix alone", frame: tcp4(40000, 53, tcpDNS(axfr)[:2]), proto: packet.AppUnknown},
		{name: "dns over tcp: message without its prefix", frame: tcp4(40000, 53, q), proto: packet.AppUnknown},
		{name: "dns over tcp: prefix split 1+1, second byte then message", frame: tcp4(53, 40000, tcpDNS(resp)[1:]),
			proto: packet.AppUnknown},
		{name: "dns over tcp: query then first prefix byte of the next", frame: tcp4(40000, 53, tcpDNS(q)+"\x00"),
			proto: packet.AppDNS, want: dnsWant(q, 0x1234, false, 0, 1, 0, "google.com", 1, "A")},
		{name: "dns over tcp: query then the start of the next message", frame: tcp4(40000, 53, tcpDNS(q)+tcpDNS(axfr)[:20]),
			proto: packet.AppDNS, want: dnsWant(q, 0x1234, false, 0, 1, 0, "google.com", 1, "A")},
		{name: "dns over tcp: bytes after the message are not a message", frame: tcp4(40000, 53, tcpDNS(q)+"\x00\x05hello"),
			proto: packet.AppUnknown},
		// A malformed message is reported only when its prefix matches
		// the segment; the start of a longer one could be misaligned.
		{name: "dns over tcp self compression pointer", frame: tcp4(40000, 53, tcpDNS(selfPtr)), proto: packet.AppDNS,
			want: with(dnsHeaderWant(selfPtr, 8, false, 1), "malformed_reason", "qname: compression loop: pointer does not point backwards"),
			errs: []string{"dns: qname: compression loop"}},
		{name: "dns over tcp self compression pointer, longer message claimed",
			frame: tcp4(40000, 53, string(u16(uint16(len(selfPtr)+40)))+selfPtr), proto: packet.AppUnknown},
		{name: "dns ANY query", frame: udp4(40000, 53, anyQ), proto: packet.AppDNS,
			want: dnsWant(anyQ, 100, false, 0, 1, 0, "example.com", 255, "ANY")},
		{name: "dns unnamed qtype", frame: udp4(40000, 53, query(16, "example.com", 99)), proto: packet.AppDNS,
			want: dnsWant(query(16, "example.com", 99), 16, false, 0, 1, 0, "example.com", 99, "")},
		{name: "dns mixed case (0x20) is lowercased, not flagged", frame: udp4(40000, 53, mixed), proto: packet.AppDNS,
			want: dnsWant(mixed, 1, false, 0, 1, 0, "google.com", 1, "A")},
		{name: "dns 0x20 long label below the entropy threshold", frame: udp4(40000, 53, mixedLong), proto: packet.AppDNS,
			want: dnsWant(mixedLong, 17, false, 0, 1, 0, strings.Repeat("abcdefghij", 4)+"ab.example", 1, "A")},
		{name: "dns tunnelling-style label", frame: udp4(40000, 53, tunnel), proto: packet.AppDNS,
			want: with(dnsWant(tunnel, 2, false, 0, 1, 0, "nbswy3dpeb3w64tmmqqgc3tqmfzxg4dxn5zgs3tomv2gs5dv.t.evil.example", 16, "TXT"),
				"suspicious_reason", "long high-entropy label (possible DNS tunnelling)")},
		{name: "dns long low-entropy qname", frame: udp4(40000, 53, long), proto: packet.AppDNS,
			want: with(dnsWant(long, 3, false, 0, 1, 0, strings.Repeat("a", 40)+"."+strings.Repeat("b", 40)+"."+strings.Repeat("c", 20), 1, "A"),
				"suspicious_reason", "qname longer than 100 characters")},
		{name: "dns qname of exactly 100 characters", frame: udp4(40000, 53, exactly100), proto: packet.AppDNS,
			want: dnsWant(exactly100, 4, false, 0, 1, 0, strings.Repeat("a", 40)+"."+strings.Repeat("b", 40)+"."+strings.Repeat("c", 18), 1, "A")},
		{name: "dns backward compression pointer in second question", frame: udp4(40000, 53, twoQ), proto: packet.AppDNS,
			want: with(dnsWant(twoQ, 5, false, 0, 2, 0, "example.com", 1, "A"))},
		{name: "dns forward compression pointer", frame: udp4(40000, 53, fwdPtr), proto: packet.AppDNS,
			want: with(dnsHeaderWant(fwdPtr, 6, false, 1), "malformed_reason", "qname: compression loop: pointer does not point backwards"),
			errs: []string{"dns: qname: compression loop"}},
		{name: "dns self compression pointer", frame: udp4(40000, 53, selfPtr), proto: packet.AppDNS,
			want: with(dnsHeaderWant(selfPtr, 8, false, 1), "malformed_reason", "qname: compression loop: pointer does not point backwards"),
			errs: []string{"dns: qname: compression loop"}},
		{name: "dns long pointer chain", frame: udp4(40000, 53, chain), proto: packet.AppDNS, partial: true,
			want: fields("qdcount", "2", "qtype", "1", "malformed_reason", "qname: too many compression pointers"),
			errs: []string{"dns: qname: too many compression pointers"}},
		{name: "dns label of 64", frame: udp4(40000, 53, label64), proto: packet.AppDNS,
			want: with(dnsHeaderWant(label64, 9, false, 1), "malformed_reason", "qname: label longer than 63 bytes"),
			errs: []string{"dns: qname: label longer than 63 bytes"}},
		{name: "dns label of 63", frame: udp4(40000, 53, label63), proto: packet.AppDNS,
			want: dnsWant(label63, 10, false, 0, 1, 0, strings.Repeat("x", 63)+".com", 1, "A")},
		{name: "dns name longer than 255", frame: udp4(40000, 53, name256), proto: packet.AppDNS,
			want: with(dnsHeaderWant(name256, 11, false, 1), "malformed_reason", "qname: name longer than 255 bytes"),
			errs: []string{"dns: qname: name longer than 255 bytes"}},
		{name: "dns reserved label type", frame: udp4(40000, 53, reserved), proto: packet.AppDNS,
			want: with(dnsHeaderWant(reserved, 12, false, 1), "malformed_reason", "qname: reserved label type"),
			errs: []string{"dns: qname: reserved label type"}},
		{name: "dns query with qdcount 0", frame: udp4(40000, 53, noQ), proto: packet.AppDNS,
			want: with(dnsHeaderWant(noQ, 13, false, 0), "malformed_reason", "query has no questions"),
			errs: []string{"dns: query has no questions"}},
		{name: "dns question runs past message", frame: udp4(40000, 53, overrun), proto: packet.AppDNS,
			want: with(dnsHeaderWant(overrun, 14, false, 1), "malformed_reason", "question runs past end of message"),
			errs: []string{"dns: question runs past end of message"}},
		{name: "dns shorter than header", frame: udp4(40000, 53, "\x12\x34\x01"), proto: packet.AppDNS,
			want: fields("dns_len", "3", "malformed_reason", "message shorter than the 12-byte header"),
			errs: []string{"dns: message shorter than the 12-byte header"}},

		// ---- HTTP ----
		{name: "http get", frame: tcp4(40000, 80, get), proto: packet.AppHTTP, want: getWant},
		{name: "http post with headers", frame: tcp4(40000, 8080, post), proto: packet.AppHTTP,
			want: fields("method", "POST", "uri", "/api/login", "uri_decoded", "/api/login", "version", "1.1",
				"host", "api.example", "content_type", "application/json", "content_length", "17", "request_complete", "true",
				"headers_raw", "host: api.example\nCONTENT-TYPE: application/json\nContent-Length: 17")},
		{name: "http response", frame: tcp4(80, 40000, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1256\r\n\r\n<html>"),
			proto: packet.AppHTTP,
			want: fields("version", "1.1", "status_code", "200", "content_type", "text/html", "content_length", "1256", "request_complete", "true",
				"headers_raw", "Content-Type: text/html\nContent-Length: 1256")},
		{name: "http request split before the blank line", frame: tcp4(40000, 80, "GET /a HTTP/1.1\r\nHost: x.example\r\nUser-Ag"),
			proto: packet.AppHTTP,
			want: fields("method", "GET", "uri", "/a", "uri_decoded", "/a", "version", "1.1", "host", "x.example", "request_complete", "false",
				"headers_raw", "Host: x.example")},
		{name: "http request line split", frame: tcp4(40000, 80, "GET /very/long/pa"), proto: packet.AppHTTP,
			want: fields("method", "GET", "uri", "/very/long/pa", "uri_decoded", "/very/long/pa", "request_complete", "false")},
		{name: "http body continuation", frame: tcp4(80, 40000, "</div></body>\r\n</html>\r\n"), proto: packet.AppUnknown},
		{name: "http single percent-encoding", frame: tcp4(40000, 80, "GET /a%20b?q=%41 HTTP/1.1\r\n\r\n"), proto: packet.AppHTTP,
			want: fields("method", "GET", "uri", "/a%20b?q=%41", "uri_decoded", "/a b?q=A", "version", "1.1", "request_complete", "true",
				"query", "q=A")},
		{name: "http double percent-encoding", frame: tcp4(40000, 80, "GET /a/%252e%252e/%252e%252e/etc/passwd HTTP/1.1\r\n\r\n"),
			proto: packet.AppHTTP,
			want: fields("method", "GET", "uri", "/a/%252e%252e/%252e%252e/etc/passwd", "uri_decoded", "/a/%2e%2e/%2e%2e/etc/passwd",
				"version", "1.1", "request_complete", "true", "suspicious_reason", "double percent-encoding")},
		{name: "http double percent-encoding without traversal", frame: tcp4(40000, 80, "GET /t?u=http%253A%252F%252Fa.example%252F%253Fx%253D1 HTTP/1.1\r\n\r\n"),
			proto: packet.AppHTTP,
			want: fields("method", "GET", "uri", "/t?u=http%253A%252F%252Fa.example%252F%253Fx%253D1", "uri_decoded", "/t?u=http%3A%2F%2Fa.example%2F%3Fx%3D1",
				"version", "1.1", "request_complete", "true", "query", "u=http%3A%2F%2Fa.example%2F%3Fx%3D1")},
		{name: "http basic auth", frame: tcp4(40000, 80, "GET /admin HTTP/1.1\r\nHost: h\r\nAuthorization: Basic "+basicCred+"\r\n\r\n"),
			proto: packet.AppHTTP,
			want: fields("method", "GET", "uri", "/admin", "uri_decoded", "/admin", "version", "1.1", "host", "h",
				"auth_basic", "true", "request_complete", "true", "headers_raw", "Host: h\nAuthorization: <redacted>"),
			secrets: []string{basicCred, basicPlain, "alice:"}},
		{name: "http basic auth, lowercase scheme", frame: tcp4(40000, 80, "GET / HTTP/1.1\r\nauthorization:   basic "+basicCred+"\r\n\r\n"),
			proto: packet.AppHTTP, want: with(simpleGet, "auth_basic", "true", "headers_raw", "authorization: <redacted>"),
			secrets: []string{basicCred, basicPlain}},
		{name: "http bearer auth is not basic", frame: tcp4(40000, 80, "GET / HTTP/1.1\r\nAuthorization: Bearer "+bearerToken+"\r\n\r\n"),
			proto: packet.AppHTTP, want: with(simpleGet, "headers_raw", "Authorization: <redacted>"), secrets: []string{bearerToken}},
		{name: "http malformed header carrying a credential", frame: tcp4(40000, 80, "GET / HTTP/1.1\r\n"+basicCred+"\r\n\r\n"),
			proto: packet.AppHTTP, want: with(simpleGet, "malformed_reason", "header line without a name"),
			errs: []string{"http: header line without a name"}, secrets: []string{basicCred}},
		{name: "http h2c preface", frame: tcp4(40000, 80, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x12\x04"), proto: packet.AppHTTP,
			want: fields("version", "2.0")},
		{name: "http 100 headers is fine", frame: tcp4(40000, 80, headers(100)), proto: packet.AppHTTP, want: with(simpleGet, "headers_raw", headersRaw(100))},
		{name: "http more than 100 headers", frame: tcp4(40000, 80, headers(101)), proto: packet.AppHTTP,
			want: with(simpleGet, "malformed_reason", "more than 100 headers", "headers_raw", headersRaw(100)), errs: []string{"http: more than 100 headers"}},
		{name: "http header line of 8 KiB is fine", frame: tcp4(40000, 80, "GET / HTTP/1.1\r\nX: "+strings.Repeat("v", 8192-3)+"\r\n\r\n"),
			proto: packet.AppHTTP, want: with(simpleGet, "headers_raw", "X: "+strings.Repeat("v", 8192-3))},
		{name: "http header line over 8 KiB", frame: tcp4(40000, 80, "GET / HTTP/1.1\r\nX: "+strings.Repeat("v", 8192-2)+"\r\n\r\n"),
			proto: packet.AppHTTP, want: with(simpleGet, "malformed_reason", "line longer than 8192 bytes"),
			errs: []string{"http: line longer than 8192 bytes"}},
		{name: "http request line over 8 KiB", frame: tcp4(40000, 80, "GET /"+strings.Repeat("a", 9000)+" HTTP/1.1\r\n\r\n"),
			proto: packet.AppHTTP, want: fields("request_complete", "true", "malformed_reason", "line longer than 8192 bytes"),
			errs: []string{"http: line longer than 8192 bytes"}},
		{name: "http on a non-standard port, by content", frame: tcp4(40000, 5000, get), proto: packet.AppHTTP, want: getWant},
		{name: "http response on a non-standard port, by content", frame: tcp4(5000, 40000, "HTTP/1.0 404 Not Found\r\n\r\n"),
			proto: packet.AppHTTP, want: fields("version", "1.0", "status_code", "404", "request_complete", "true")},
		{name: "http unknown method on port 80", frame: tcp4(40000, 80, "FOO / HTTP/1.1\r\n\r\n"), proto: packet.AppHTTP,
			want: fields("request_complete", "true", "malformed_reason", "invalid request method"),
			errs: []string{"http: invalid request method"}},
		{name: "http unknown method elsewhere is unknown", frame: tcp4(40000, 5000, "FOO / HTTP/1.1\r\n\r\n"), proto: packet.AppUnknown},
		{name: "http garbage in the request line", frame: tcp4(40000, 80, "GET /\x01\x02 HTTP/1.1\r\n\r\n"), proto: packet.AppHTTP,
			want: fields("request_complete", "true", "malformed_reason", "invalid request line"),
			errs: []string{"http: invalid request line"}},
		{name: "http request line with extra fields", frame: tcp4(40000, 80, "GET / x HTTP/1.1\r\n\r\n"), proto: packet.AppHTTP,
			want: fields("request_complete", "true", "malformed_reason", "invalid request line"),
			errs: []string{"http: invalid request line"}},
		{name: "http bad status line", frame: tcp4(80, 40000, "HTTP/1.1 2x0 OK\r\n\r\n"), proto: packet.AppHTTP,
			want: fields("request_complete", "true", "malformed_reason", "invalid status line"),
			errs: []string{"http: invalid status line"}},
		{name: "http bad content-length", frame: tcp4(40000, 80, "GET / HTTP/1.1\r\nContent-Length: 1e9\r\n\r\n"), proto: packet.AppHTTP,
			want: with(simpleGet, "malformed_reason", "invalid content-length", "headers_raw", "Content-Length: 1e9"), errs: []string{"http: invalid content-length"}},
		{name: "http folded authorization is redacted", frame: tcp4(40000, 80, "GET / HTTP/1.1\r\nAuthorization: Basic\r\n "+basicCred+"\r\nProxy-Authorization: Basic "+basicCred+"\r\nX: y\r\n\r\n"),
			proto: packet.AppHTTP, want: with(simpleGet, "auth_basic", "true",
				"headers_raw", "Authorization: <redacted>\nProxy-Authorization: <redacted>\nX: y"),
			secrets: []string{basicCred}},
		{name: "http headers_raw is capped at 8 KiB", frame: tcp4(40000, 80, "GET / HTTP/1.1\r\n"+strings.Repeat("X-Long: "+strings.Repeat("v", 1000)+"\r\n", 9)+"\r\n"),
			proto: packet.AppHTTP, want: with(simpleGet,
				"headers_raw", strings.Repeat("X-Long: "+strings.Repeat("v", 1000)+"\n", 9)[:8192])},
		{name: "http query decoding", frame: tcp4(40000, 80, "GET /s?q=a+b%2Bc%20d&x=%2527#frag HTTP/1.1\r\n\r\n"),
			proto: packet.AppHTTP, want: fields("method", "GET", "uri", "/s?q=a+b%2Bc%20d&x=%2527#frag", "uri_decoded", "/s?q=a+b+c d&x=%27#frag",
				"version", "1.1", "request_complete", "true", "query", "q=a b+c d&x=%27")},
		{name: "http empty query", frame: tcp4(40000, 80, "GET /s? HTTP/1.1\r\n\r\n"),
			proto: packet.AppHTTP, want: fields("method", "GET", "uri", "/s?", "uri_decoded", "/s?",
				"version", "1.1", "request_complete", "true", "query", "")},
		{name: "http overlong utf-8 traversal", frame: tcp4(40000, 80, "GET /a/%c0%ae%c0%ae/%e0%80%ae%e0%80%ae%c0%afetc/passwd HTTP/1.1\r\n\r\n"),
			proto: packet.AppHTTP, want: fields("method", "GET", "uri", "/a/%c0%ae%c0%ae/%e0%80%ae%e0%80%ae%c0%afetc/passwd", "uri_decoded", "/a/../../etc/passwd",
				"version", "1.1", "request_complete", "true", "suspicious_reason", "overlong utf-8 encoding")},
		{name: "http valid utf-8 is not overlong", frame: tcp4(40000, 80, "GET /caf%c3%a9/%e2%82%ac/%f0%9f%98%80 HTTP/1.1\r\n\r\n"),
			proto: packet.AppHTTP, want: fields("method", "GET", "uri", "/caf%c3%a9/%e2%82%ac/%f0%9f%98%80", "uri_decoded", "/café/€/😀",
				"version", "1.1", "request_complete", "true")},
		{name: "port 80 payload that is not http", frame: tcp4(40000, 80, "\x00\x01\x02binary junk"), proto: packet.AppUnknown},

		// ---- FTP ----
		{name: "ftp USER", frame: tcp4(40000, 21, "USER alice\r\n"), proto: packet.AppFTP,
			want: fields("command", "USER", "argument", "alice")},
		{name: "ftp PASS is redacted", frame: tcp4(40000, 21, "PASS "+ftpPass+"\r\n"), proto: packet.AppFTP,
			want: fields("command", "PASS", "argument", "<redacted>"), secrets: []string{ftpPass}},
		{name: "ftp lowercase pass is redacted", frame: tcp4(40000, 21, "pass "+ftpPass+"\r\n"), proto: packet.AppFTP,
			want: fields("command", "PASS", "argument", "<redacted>"), secrets: []string{ftpPass}},
		{name: "ftp unterminated PASS is redacted", frame: tcp4(40000, 21, "PASS "+ftpPass), proto: packet.AppFTP,
			want: fields("command", "PASS", "argument", "<redacted>"), secrets: []string{ftpPass}},
		{name: "ftp lowercase command", frame: tcp4(40000, 21, "retr report.pdf\r\n"), proto: packet.AppFTP,
			want: fields("command", "RETR", "argument", "report.pdf")},
		{name: "ftp command without argument", frame: tcp4(40000, 21, "PASV\r\n"), proto: packet.AppFTP,
			want: fields("command", "PASV")},
		{name: "ftp unterminated command is not malformed", frame: tcp4(40000, 21, "STOR bi"), proto: packet.AppFTP,
			want: fields("command", "STOR", "argument", "bi")},
		{name: "ftp reply", frame: tcp4(21, 40000, "220 ProFTPD Server ready.\r\n"), proto: packet.AppFTP,
			want: fields("response_code", "220")},
		{name: "ftp multi-line reply", frame: tcp4(21, 40000, "230-Welcome\r\n230-Be nice\r\n230 Logged in\r\n"), proto: packet.AppFTP,
			want: fields("response_code", "230")},
		{name: "ftp middle of multi-line reply", frame: tcp4(21, 40000, " please read the rules\r\n"), proto: packet.AppUnknown},

		// ---- TLS ----
		{name: "tls ClientHello with SNI", frame: tcp4(40000, 443, string(chFull)), proto: packet.AppTLS,
			want: fields("sni", "example.com", "sni_status", "found")},
		{name: "tls ClientHello without SNI", frame: tcp4(40000, 443, string(clientHello(supportedVersions))), proto: packet.AppTLS,
			want: fields("sni_status", "absent")},
		{name: "tls ClientHello without extensions", frame: tcp4(40000, 8443, string(clientHello())), proto: packet.AppTLS,
			want: fields("sni_status", "absent")},
		{name: "tls SNI after a large extension", frame: tcp4(40000, 443, string(chLate)), proto: packet.AppTLS,
			want: fields("sni", "late.example.org", "sni_status", "found")},
		{name: "tls SNI-bearing ClientHello cut short", frame: tcp4(40000, 443, string(chLate[:700])), proto: packet.AppTLS,
			want: fields("sni_status", "truncated")},
		{name: "tls ClientHello cut at an extension boundary, before SNI", frame: tcp4(40000, 443, string(chLate[:93])),
			proto: packet.AppTLS, want: fields("sni_status", "truncated")},
		{name: "tls ClientHello cut inside the extension header", frame: tcp4(40000, 443, string(chLate[:len(chLate)-len(sniExt("late.example.org"))+2])),
			proto: packet.AppTLS, want: fields("sni_status", "truncated")},
		{name: "tls ClientHello cut after SNI", frame: tcp4(40000, 443, string(chFull[:len(chFull)-3])), proto: packet.AppTLS,
			want: fields("sni", "example.com", "sni_status", "found")},
		{name: "tls ClientHello cut in the record header region", frame: tcp4(40000, 443, string(chFull[:7])), proto: packet.AppTLS,
			want: fields("sni_status", "truncated")},
		{name: "tls ClientHello on a non-standard port, by content", frame: tcp4(40000, 9000, string(chFull)), proto: packet.AppTLS,
			want: fields("sni", "example.com", "sni_status", "found")},
		{name: "tls ServerHello", frame: tcp4(443, 40000, "\x16\x03\x03\x00\x04\x02\x00\x00\x00"), proto: packet.AppTLS},
		{name: "tls application data on 443", frame: tcp4(443, 40000, "\x17\x03\x03\x00\x05hello"), proto: packet.AppTLS},
		{name: "tls application data elsewhere is unknown", frame: tcp4(9000, 40000, "\x17\x03\x03\x00\x05hello"), proto: packet.AppUnknown},
		{name: "tls extensions run past a complete record", proto: packet.AppTLS,
			frame: func() []byte {
				b := bytes.Clone(chFull)
				ext := len(b) - len(sniExt("Example.COM")) - len(supportedVersions) - 2
				binary.BigEndian.PutUint16(b[ext:], 0x0FFF)
				return tcp4(40000, 443, string(b))
			}(),
			want: fields("malformed_reason", "ClientHello field runs past end of message"),
			errs: []string{"tls: ClientHello field runs past end of message"}},
		{name: "quic on udp 443 is unknown", frame: udp4(40000, 443, "\xc3\x00\x00\x00\x01\x08quicdata"), proto: packet.AppUnknown},

		// ---- nothing to do ----
		{name: "tcp without payload", frame: tcp4(40000, 80, ""), proto: ""},
		{name: "icmp payload is not application data", proto: "",
			frame: ipv4Frame(1, []byte{8, 0, 0xf7, 0xfe, 0, 1, 0, 0, 'G', 'E', 'T', ' '})},
		{name: "udp on an unknown port", frame: udp4(40000, 5353, "whatever"), proto: packet.AppUnknown},
	}
}

func newPacket(frame []byte) *packet.ParsedPacket {
	p := packet.NewParsedPacket(time.Unix(0, 0), uint32(len(frame)), uint32(len(frame)))
	p.RawData = frame
	return p
}

func parse(frame []byte) *packet.ParsedPacket {
	p := newPacket(frame)
	lower.Parse(p)
	upper.Parse(p)
	app.Parse(p)
	return p
}

func TestParse(t *testing.T) {
	for _, tt := range appCases() {
		t.Run(tt.name, func(t *testing.T) {
			p := newPacket(tt.frame)
			lower.Parse(p)
			upper.Parse(p)
			if p.HasErrors() {
				t.Fatalf("lower/upper errors on a test frame: %q", p.ParseErrors)
			}
			app.Parse(p)

			if p.AppProtocol != tt.proto {
				t.Errorf("AppProtocol = %q, want %q", p.AppProtocol, tt.proto)
			}
			got := p.AppFields
			if tt.partial {
				got = make(map[string]string)
				for k := range tt.want {
					if v, ok := p.AppFields[k]; ok {
						got[k] = v
					}
				}
				for _, k := range []string{"malformed_reason", "suspicious_reason"} {
					if v, ok := p.AppFields[k]; ok {
						got[k] = v
					}
				}
			}
			if len(got) != 0 || len(tt.want) != 0 {
				if !maps.Equal(got, tt.want) {
					t.Errorf("AppFields mismatch\n got: %v\nwant: %v", got, tt.want)
				}
			}
			if len(p.ParseErrors) != len(tt.errs) {
				t.Fatalf("ParseErrors = %q, want %d matching %q", p.ParseErrors, len(tt.errs), tt.errs)
			}
			for i, want := range tt.errs {
				if !strings.Contains(p.ParseErrors[i], want) {
					t.Errorf("ParseErrors[%d] = %q, want it to contain %q", i, p.ParseErrors[i], want)
				}
			}
		})
	}
}

// TestRedaction checks, for every case, that its secrets appear nowhere in
// AppFields (keys or values) or ParseErrors.
func TestRedaction(t *testing.T) {
	n := 0
	for _, tt := range appCases() {
		if len(tt.secrets) > 0 && !bytes.Contains(tt.frame, []byte(tt.secrets[0])) {
			t.Fatalf("%s: first secret is not in the frame, so the test proves nothing", tt.name)
		}
		p := parse(tt.frame)
		for _, s := range tt.secrets {
			n++
			for k, v := range p.AppFields {
				if strings.Contains(k, s) || strings.Contains(v, s) {
					t.Errorf("%s: AppFields[%q] = %q contains secret %q", tt.name, k, v, s)
				}
			}
			for _, e := range p.ParseErrors {
				if strings.Contains(e, s) {
					t.Errorf("%s: ParseErrors entry %q contains secret %q", tt.name, e, s)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no secrets checked")
	}
}

func TestParseNil(t *testing.T) {
	app.Parse(nil) // must not panic

	// Before upper.Parse, PayloadOffset is -1: nothing happens.
	p := newPacket(tcp4(40000, 80, "GET / HTTP/1.1\r\n\r\n"))
	lower.Parse(p)
	app.Parse(p)
	if p.AppProtocol != "" || p.AppFields != nil {
		t.Errorf("Parse before upper.Parse: AppProtocol %q, AppFields %v", p.AppProtocol, p.AppFields)
	}
}

func FuzzParse(f *testing.F) {
	for _, tt := range appCases() {
		f.Add(tt.frame)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p := newPacket(data)
		orig := bytes.Clone(data)
		lower.Parse(p)
		upper.Parse(p)
		app.Parse(p)
		if !bytes.Equal(p.RawData, orig) {
			t.Fatal("Parse modified RawData")
		}
		if p.AppProtocol == "" && p.AppFields != nil {
			t.Errorf("AppFields set without AppProtocol: %v", p.AppFields)
		}
		if v, ok := p.AppFields["argument"]; ok && p.AppFields["command"] == "PASS" && v != "<redacted>" {
			t.Errorf("PASS argument stored: %q", v)
		}
		for _, k := range []string{"malformed_reason", "suspicious_reason"} {
			if v, ok := p.AppFields[k]; ok && v == "" {
				t.Errorf("empty %s", k)
			}
		}
	})
}
