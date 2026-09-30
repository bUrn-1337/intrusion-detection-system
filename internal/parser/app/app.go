// Package app implements Module 4: application-layer parsing of DNS, HTTP/1.x,
// the FTP control channel and the TLS ClientHello (server name and JA3).
//
// Parse runs after the stream stage (internal/stream) and is stateless: it
// looks at one packet at a time and keeps no per-connection memory.
//
// # Input: reassembled or per-segment
//
// When the stream stage is reassembling the packet's direction
// (p.StreamProto is set), Parse decodes only p.AppData, the messages the
// packet completed, and never the segment on its own: each HTTP message
// head (pipelined requests one by one), each length-prefixed DNS message,
// each FTP line, or the first TLS record. The first message recognized
// fills AppFields and the others AppMore. A packet that completed no
// message gets AppProtocol = StreamProto and no fields, and its partial
// payload is never reported as malformed.
//
// Otherwise (UDP, ports the stream stage does not track, and TCP
// directions that are desynced, evicted, picked up mid-stream before a
// clean boundary, or handed back to per-segment parsing, such as TLS after
// its first record) Parse decodes p.Payload() alone, so a message split
// across segments is decoded only as far as this segment goes. That path
// keeps its workarounds for split messages: a DNS-over-TCP segment that
// does not frame cleanly is unknown traffic, and a ClientHello cut off by
// the segment end has sni_status "truncated".
//
// # Classification
//
// A well-known port (source or destination, since responses come from the
// server port) is only a hint: the payload must also look like that
// protocol. If no hinted protocol matches, the payload is sniffed for an
// HTTP request or status line or a TLS handshake record on any TCP port.
// Anything else, such as the middle of an HTTP body, is AppUnknown with no
// error. ICMP and other non-TCP/UDP payloads are left alone (AppProtocol
// stays ""), as are packets with no payload.
//
// # Errors and reasons
//
// A protocol violation in a recognized message is recorded twice: as a
// "malformed" reason through AddAppReason, and as a ParseErrors entry
// prefixed with the protocol ("dns:", "http:", "ftp:", "tls:"). Suspicious
// but well-formed content only gets a "suspicious" reason. A message cut
// short by the end of the segment is not malformed. Reasons and errors never
// quote packet bytes, so they cannot leak credentials or contain the ";"
// reason separator.
//
// # JA3
//
// A complete ClientHello also gets a JA3 fingerprint
// (github.com/salesforce/ja3): ja3 is the string
// "TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats" (decimal
// values, lists joined with '-', empty when absent) and ja3_hash its MD5
// in lowercase hex. TLSVersion is the ClientHello's legacy_version, and
// GREASE values (RFC 8701, 0x0a0a to 0xfafa) are left out of every list.
// A ClientHello that is cut off or has an extension overrunning its block
// gets no fingerprint, since a partial one would be a different JA3; a
// ClientHello split across segments is fingerprinted from the reassembled
// record when the stream stage has it.
//
// JA3 is stable for most non-browser clients (curl, OpenSSL, language
// runtimes, most malware), which is what feed matching relies on. It is
// not stable for browsers: Chrome randomizes its extension order on every
// connection since 2023 (Chrome 110), so one browser produces many JA3
// hashes. JA4, which sorts the lists to avoid this, is
// out of scope.
//
// # Credentials
//
// Credentials are never stored: an HTTP Authorization header only sets
// auth_basic, and the argument of an FTP PASS command is stored as
// "<redacted>".
package app

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Well-known ports used as classification hints.
const (
	portFTP      = 21
	portDNS      = 53
	portHTTP     = 80
	portHTTPAlt1 = 8000
	portHTTPAlt2 = 8080
	portHTTPS    = 443
	portHTTPSAlt = 8443
)

// Parse classifies p's payload and fills AppProtocol and AppFields.
func Parse(p *packet.ParsedPacket) {
	if p == nil || p.PayloadOffset < 0 {
		return
	}
	isTCP := p.L4Proto == packet.L4TCP
	if !isTCP && p.L4Proto != packet.L4UDP {
		return
	}
	payload := p.Payload()
	if len(payload) == 0 {
		return
	}
	if isTCP && p.StreamProto != "" {
		parseStream(p)
		return
	}

	var r *result
	for _, proto := range hints(p.DstPort, p.SrcPort, isTCP) {
		if r = parseAs(proto, payload, isTCP); r != nil {
			break
		}
	}
	if r == nil && isTCP {
		if r = parseHTTP(payload, false); r == nil {
			r = parseTLS(payload, false)
		}
	}
	if r == nil {
		r = &result{proto: packet.AppUnknown}
	}
	r.commit(p)
}

// hints returns the protocols suggested by the two ports, destination
// first, without duplicates.
func hints(dst, src uint16, isTCP bool) []string {
	var out []string
	for _, port := range [2]uint16{dst, src} {
		var proto string
		switch {
		case port == portDNS:
			proto = packet.AppDNS
		case !isTCP:
		case port == portHTTP || port == portHTTPAlt1 || port == portHTTPAlt2:
			proto = packet.AppHTTP
		case port == portFTP:
			proto = packet.AppFTP
		case port == portHTTPS || port == portHTTPSAlt:
			proto = packet.AppTLS
		}
		if proto != "" && (len(out) == 0 || out[0] != proto) {
			out = append(out, proto)
		}
	}
	return out
}

// parseAs runs the parser for a port-hinted protocol. It returns nil if the
// payload is not that protocol.
func parseAs(proto string, payload []byte, isTCP bool) *result {
	switch proto {
	case packet.AppDNS:
		return parseDNS(payload, isTCP)
	case packet.AppHTTP:
		return parseHTTP(payload, true)
	case packet.AppFTP:
		return parseFTP(payload)
	case packet.AppTLS:
		return parseTLS(payload, true)
	}
	return nil
}

// result collects what a parser found, so that a parser that gives up
// leaves no trace in the packet. commit copies it into the packet.
type result struct {
	proto      string
	fields     []field
	malformed  []string
	suspicious []string
}

type field struct{ key, value string }

func (r *result) set(key, value string) {
	for i := range r.fields {
		if r.fields[i].key == key {
			r.fields[i].value = value
			return
		}
	}
	r.fields = append(r.fields, field{key, value})
}

func (r *result) has(key string) bool {
	for _, f := range r.fields {
		if f.key == key {
			return true
		}
	}
	return false
}

// bad records a protocol violation. reason must not quote packet bytes.
func (r *result) bad(reason string) { r.malformed = append(r.malformed, reason) }

// flag records suspicious content. reason must not quote packet bytes.
func (r *result) flag(reason string) {
	for _, s := range r.suspicious {
		if s == reason {
			return
		}
	}
	r.suspicious = append(r.suspicious, reason)
}

func (r *result) commit(p *packet.ParsedPacket) {
	p.AppProtocol = r.proto
	for _, f := range r.fields {
		p.SetAppField(f.key, f.value)
	}
	prefix := errPrefix(r.proto)
	for _, m := range r.malformed {
		p.AddAppReason(packet.ReasonMalformed, m)
		p.AddError(prefix + m)
	}
	for _, s := range r.suspicious {
		p.AddAppReason(packet.ReasonSuspicious, s)
	}
}

// parseStream decodes the reassembled messages in p.AppData.
func parseStream(p *packet.ParsedPacket) {
	if p.AppData == nil {
		p.AppProtocol = p.StreamProto
		return
	}
	var results []*result
	add := func(r *result) {
		if r != nil {
			results = append(results, r)
		}
	}
	b := p.AppData
	switch p.StreamProto {
	case packet.AppHTTP:
		for len(b) > 0 {
			n := httpHeadLen(b)
			r := parseHTTP(b[:n], true)
			if r != nil && r.has("request_complete") {
				r.set("request_complete", "true")
			}
			add(r)
			b = b[n:]
		}
	case packet.AppDNS:
		for len(b) >= 2 {
			n := min(len(b), 2+int(binary.BigEndian.Uint16(b)))
			add(decodeDNS(b[2:n], n-2, true))
			b = b[n:]
		}
	case packet.AppFTP:
		for len(b) > 0 {
			n := len(b)
			if i := bytes.IndexByte(b, '\n'); i >= 0 {
				n = i + 1
			}
			add(parseFTP(b[:n]))
			b = b[n:]
		}
	case packet.AppTLS:
		add(parseTLS(b, true))
	}
	if len(results) == 0 {
		(&result{proto: packet.AppUnknown}).commit(p)
		return
	}
	results[0].commit(p)
	for _, r := range results[1:] {
		p.AppMore = append(p.AppMore, r.fieldMap(p))
	}
}

// httpHeadLen returns the length of the first message head in b, up to
// and including its blank line ("\r\n\r\n", or "\n\n" from lenient
// senders), or len(b).
func httpHeadLen(b []byte) int {
	for i := 0; i < len(b); {
		j := bytes.IndexByte(b[i:], '\n')
		if j < 0 {
			break
		}
		k := i + j + 1
		if k < len(b) && b[k] == '\n' {
			return k + 1
		}
		if k+1 < len(b) && b[k] == '\r' && b[k+1] == '\n' {
			return k + 2
		}
		i = k
	}
	return len(b)
}

// fieldMap returns the result as an AppMore entry, and records its
// malformed reasons in p.ParseErrors like commit does.
func (r *result) fieldMap(p *packet.ParsedPacket) map[string]string {
	m := make(map[string]string, len(r.fields)+2)
	for _, f := range r.fields {
		m[f.key] = f.value
	}
	if len(r.malformed) > 0 {
		m[packet.ReasonMalformed+"_reason"] = strings.Join(r.malformed, ";")
		for _, s := range r.malformed {
			p.AddError(errPrefix(r.proto) + s)
		}
	}
	if len(r.suspicious) > 0 {
		m[packet.ReasonSuspicious+"_reason"] = strings.Join(r.suspicious, ";")
	}
	return m
}

func errPrefix(proto string) string {
	switch proto {
	case packet.AppDNS:
		return "dns: "
	case packet.AppHTTP:
		return "http: "
	case packet.AppFTP:
		return "ftp: "
	case packet.AppTLS:
		return "tls: "
	}
	return "app: "
}
