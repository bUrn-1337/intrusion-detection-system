package app_test

import (
	"strings"
	"testing"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/app"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
)

// streamed returns a TCP packet whose direction the stream stage is
// reassembling, with appData as the messages it completed (nil: none).
func streamed(sport, dport uint16, payload, proto string, appData []byte) *packet.ParsedPacket {
	p := newPacket(tcp4(sport, dport, payload))
	lower.Parse(p)
	upper.Parse(p)
	p.StreamProto = proto
	p.AppData = appData
	app.Parse(p)
	return p
}

func TestStreamNoMessageIsNotMalformed(t *testing.T) {
	// Partial segments that the per-segment path would report as
	// malformed or would decode partially.
	for _, tc := range []struct{ proto, payload string }{
		{packet.AppHTTP, "FOO / HTTP/1.1\r\n"},
		{packet.AppHTTP, "GET /partial"},
		{packet.AppDNS, "\x00\x05\x00"},
		{packet.AppTLS, "\x16\x03\x01\x07\x00\x01\x00"},
		{packet.AppFTP, "USER al"},
	} {
		p := streamed(40000, 80, tc.payload, tc.proto, nil)
		if p.AppProtocol != tc.proto || len(p.AppFields) != 0 || len(p.ParseErrors) != 0 {
			t.Errorf("%s %q: proto %q fields %v errs %v", tc.proto, tc.payload, p.AppProtocol, p.AppFields, p.ParseErrors)
		}
	}
}

func TestStreamHTTPPipelined(t *testing.T) {
	a := "GET /one HTTP/1.1\r\nHost: a.example\r\n\r\n"
	b := "POST /two HTTP/1.1\r\nHost: b.example\r\nContent-Length: 3\r\n\r\n"
	c := "FOO /three HTTP/1.1\r\n\r\n"
	// The payload is the tail of c; AppData holds all three heads.
	p := streamed(40000, 80, "\r\n", packet.AppHTTP, []byte(a+b+c))
	if p.AppProtocol != packet.AppHTTP || p.AppFields["method"] != "GET" || p.AppFields["uri"] != "/one" ||
		p.AppFields["host"] != "a.example" || p.AppFields["request_complete"] != "true" {
		t.Fatalf("first: %v", p.AppFields)
	}
	if len(p.AppMore) != 2 {
		t.Fatalf("AppMore = %v", p.AppMore)
	}
	if m := p.AppMore[0]; m["method"] != "POST" || m["uri"] != "/two" || m["content_length"] != "3" || m["request_complete"] != "true" {
		t.Errorf("second: %v", m)
	}
	if m := p.AppMore[1]; m["malformed_reason"] != "invalid request method" {
		t.Errorf("third: %v", m)
	}
	if len(p.ParseErrors) != 1 || !strings.HasPrefix(p.ParseErrors[0], "http: ") {
		t.Errorf("errors %v", p.ParseErrors)
	}
}

func TestStreamDNSMessages(t *testing.T) {
	q := query(7, "example.com", 252)
	msgs := tcpDNS(q) + tcpDNS(query(8, "example.org", 1))
	// The segment carries only the last byte; the prefix was split.
	p := streamed(40000, 53, msgs[len(msgs)-1:], packet.AppDNS, []byte(msgs))
	if p.AppFields["qtype_name"] != "AXFR" || p.AppFields["qname"] != "example.com" || p.AppFields["id"] != "7" {
		t.Fatalf("first: %v", p.AppFields)
	}
	if len(p.AppMore) != 1 || p.AppMore[0]["qname"] != "example.org" {
		t.Fatalf("AppMore %v", p.AppMore)
	}
	// A reassembled message is decoded as complete: a short one is
	// malformed even though the prefix matches nothing else.
	p = streamed(40000, 53, "x", packet.AppDNS, []byte("\x00\x03abc"))
	if p.AppFields["malformed_reason"] == "" {
		t.Fatalf("short message: %v", p.AppFields)
	}
}

func TestStreamTLSSplitClientHello(t *testing.T) {
	rec := clientHello(bigKeyShare, sniExt("www.example.com"))
	// Per segment, the first part is truncated.
	p := parse(tcp4(40000, 443, string(rec[:1000])))
	if p.AppFields["sni_status"] != "truncated" {
		t.Fatalf("per-segment: %v", p.AppFields)
	}
	p = streamed(40000, 443, string(rec[1000:]), packet.AppTLS, rec)
	if p.AppFields["sni"] != "www.example.com" || p.AppFields["sni_status"] != "found" {
		t.Fatalf("reassembled: %v", p.AppFields)
	}
}

func TestStreamFTPLines(t *testing.T) {
	p := streamed(40000, 21, "x\r\n", packet.AppFTP, []byte("USER alice\r\nPASS s3cret\r\n"))
	if p.AppFields["command"] != "USER" || len(p.AppMore) != 1 || p.AppMore[0]["argument"] != "<redacted>" {
		t.Fatalf("%v %v", p.AppFields, p.AppMore)
	}
	for _, m := range append(p.AppMore, p.AppFields) {
		for _, v := range m {
			if strings.Contains(v, "s3cret") {
				t.Fatal("password leaked")
			}
		}
	}
	// Lines that are not FTP (middle of a multi-line reply) are skipped;
	// with none recognized the packet is unknown.
	p = streamed(21, 40000, "x", packet.AppFTP, []byte("   just text\r\n"))
	if p.AppProtocol != packet.AppUnknown {
		t.Fatalf("proto %q", p.AppProtocol)
	}
}

// Without StreamProto, AppData is ignored and the payload parsed.
func TestStreamProtoUnsetUsesPayload(t *testing.T) {
	p := newPacket(tcp4(40000, 80, "GET /seg HTTP/1.1\r\n\r\n"))
	lower.Parse(p)
	upper.Parse(p)
	p.AppData = []byte("GET /other HTTP/1.1\r\n\r\n")
	app.Parse(p)
	if p.AppFields["uri"] != "/seg" {
		t.Fatalf("%v", p.AppFields)
	}
}
