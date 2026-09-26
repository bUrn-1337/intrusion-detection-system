// Package app implements Module 4: application-layer parsing of DNS, HTTP/1.x,
// the FTP control channel and the TLS ClientHello server name.
//
// Parse runs after upper.Parse and hand-decodes p.Payload(). It is
// stateless: it looks at one packet at a time and keeps no per-connection
// memory, so a message split across TCP segments is decoded only as far as
// this segment goes.
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
// # Credentials
//
// Credentials are never stored: an HTTP Authorization header only sets
// auth_basic, and the argument of an FTP PASS command is stored as
// "<redacted>".
package app

import (
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
