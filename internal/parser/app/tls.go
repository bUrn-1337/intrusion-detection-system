package app

import (
	"encoding/binary"
	"strings"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

const (
	tlsRecordHeaderLen = 5
	tlsHandshakeHdrLen = 4
	// maxTLSRecordLen is 2^14 plus the 2048 bytes of expansion allowed for
	// protected records (RFC 8446 5.2).
	maxTLSRecordLen = 1<<14 + 2048

	tlsContentChangeCipherSpec = 20
	tlsContentHeartbeat        = 24
	tlsContentHandshake        = 22
	tlsHandshakeClientHello    = 1
	tlsExtServerName           = 0
	tlsServerNameHost          = 0
	tlsRandomLen               = 32
	tlsMaxSessionIDLen         = 32
)

// Values of the sni_status field.
const (
	sniFound     = "found"
	sniAbsent    = "absent"
	sniTruncated = "truncated"
)

const (
	reasonClientHelloOverrun = "ClientHello field runs past end of message"
	reasonBadSessionID       = "ClientHello session id longer than 32 bytes"
	reasonBadServerName      = "invalid server_name extension"
)

// parseTLS recognizes a TLS record header and extracts the server name
// from a ClientHello. Sniffing (hinted false) accepts only handshake
// records; on a TLS port any record type (20-24) is accepted. Non-handshake
// records and other handshake messages are AppTLS with no fields. A
// ClientHello longer than b is reported with sni_status truncated when the
// server name lies beyond it; the stream stage passes the whole record
// when it reassembles the direction.
func parseTLS(b []byte, hinted bool) *result {
	if len(b) < tlsRecordHeaderLen || b[1] != 3 || b[2] > 4 {
		return nil
	}
	ct := b[0]
	if ct != tlsContentHandshake && !(hinted && ct >= tlsContentChangeCipherSpec && ct <= tlsContentHeartbeat) {
		return nil
	}
	recLen := int(binary.BigEndian.Uint16(b[3:]))
	if recLen == 0 || recLen > maxTLSRecordLen {
		return nil
	}
	r := &result{proto: packet.AppTLS}
	if ct != tlsContentHandshake {
		return r
	}

	rec := b[tlsRecordHeaderLen:]
	truncated := len(rec) < recLen // the record continues in the next segment
	if !truncated {
		rec = rec[:recLen]
	}
	if len(rec) < 1 || rec[0] != tlsHandshakeClientHello {
		return r
	}
	if len(rec) < tlsHandshakeHdrLen {
		r.set("sni_status", sniTruncated)
		return r
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	body := rec[tlsHandshakeHdrLen:]
	if len(body) < hsLen {
		// Cut by the segment end, or fragmented over several records.
		truncated = true
	} else {
		body = body[:hsLen]
	}
	walkClientHello(r, body, truncated)
	return r
}

// walkClientHello reads the server name and the JA3 fingerprint of a
// ClientHello body. If the body is truncated, running out of bytes means
// "truncated", not malformed, and no JA3 is computed: a fingerprint of
// part of the extensions would be wrong. An extension that runs past the
// end after the server name was found is not reported, as before JA3
// walked the extensions after it.
func walkClientHello(r *result, body []byte, truncated bool) {
	c := cursor{b: body}
	overrun := func() {
		if truncated {
			r.set("sni_status", sniTruncated)
		} else {
			r.bad(reasonClientHelloOverrun)
		}
	}

	version, _ := c.u16() // legacy_version
	c.skip(tlsRandomLen)
	sidLen, ok := c.u8()
	if ok && sidLen > tlsMaxSessionIDLen {
		r.bad(reasonBadSessionID)
		return
	}
	c.skip(int(sidLen))
	n16, _ := c.u16()
	ciphers, _ := c.take(int(n16))
	n8, _ := c.u8()
	c.skip(int(n8)) // compression_methods
	if c.failed {
		overrun()
		return
	}
	var fp ja3
	fp.init(version, ciphers)
	if c.done() {
		r.set("sni_status", sniAbsent) // no extensions at all
		if !truncated {
			fp.commit(r)
		}
		return
	}
	extLen, _ := c.u16()
	present := c.rest()
	exts, ok := c.take(int(extLen))
	if !ok {
		if !truncated {
			overrun()
			return
		}
		exts = present // walk what is here
	}

	e := cursor{b: exts}
	sni := false
	for !e.done() {
		typ, _ := e.u16()
		n, _ := e.u16()
		data, ok := e.take(int(n))
		if !ok {
			if !sni {
				overrun()
			}
			return
		}
		fp.extension(typ, data)
		if typ == tlsExtServerName && !sni {
			sni = true
			if !parseServerName(r, data) {
				return
			}
		}
	}
	switch {
	case truncated && !sni:
		r.set("sni_status", sniTruncated)
	case !sni:
		r.set("sni_status", sniAbsent)
	}
	if !truncated {
		fp.commit(r)
	}
}

// parseServerName reads the host_name entry of a server_name extension.
// It reports false if the extension is malformed.
func parseServerName(r *result, data []byte) bool {
	c := cursor{b: data}
	listLen, _ := c.u16()
	list, ok := c.take(int(listLen))
	if !ok || !c.done() {
		r.bad(reasonBadServerName)
		return false
	}
	l := cursor{b: list}
	for !l.done() {
		typ, _ := l.u8()
		n, _ := l.u16()
		name, ok := l.take(int(n))
		if !ok || len(name) == 0 {
			r.bad(reasonBadServerName)
			return false
		}
		if typ == tlsServerNameHost {
			r.set("sni", strings.ToLower(string(name)))
			r.set("sni_status", sniFound)
			return true
		}
	}
	r.set("sni_status", sniAbsent)
	return true
}

// cursor reads big-endian values from b. Once a read runs past the end,
// failed is set and all later reads return zero values.
type cursor struct {
	b      []byte
	off    int
	failed bool
}

func (c *cursor) take(n int) ([]byte, bool) {
	if c.failed || n < 0 || n > len(c.b)-c.off {
		c.failed = true
		return nil, false
	}
	out := c.b[c.off : c.off+n]
	c.off += n
	return out, true
}

func (c *cursor) skip(n int) { c.take(n) }

func (c *cursor) u8() (uint8, bool) {
	b, ok := c.take(1)
	if !ok {
		return 0, false
	}
	return b[0], true
}

func (c *cursor) u16() (uint16, bool) {
	b, ok := c.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

func (c *cursor) rest() []byte {
	if c.failed {
		return nil
	}
	return c.b[c.off:]
}

func (c *cursor) done() bool { return c.failed || c.off >= len(c.b) }
