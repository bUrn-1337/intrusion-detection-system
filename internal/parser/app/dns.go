package app

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/bUrn-1337/intrusion-detection-system/internal/entropy"
	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

const (
	dnsHeaderLen = 12
	// maxQuestions caps how many questions of a multi-question message are
	// decoded. Only the first is stored.
	maxQuestions = 8
	// maxLabelLen and maxNameLen are the RFC 1035 limits. maxNameLen is the
	// wire length, including length bytes and the root label.
	maxLabelLen = 63
	maxNameLen  = 255
	// maxPointerJumps caps compression pointers followed in one name.
	maxPointerJumps = 16
	// Opcodes 0-2 and 4-6 are assigned; anything else over TCP is not DNS.
	dnsOpcodeUnassigned = 3
	dnsOpcodeMax        = 6
)

// Suspicious-content thresholds.
const (
	// suspiciousQNameLen is the dotted qname length above which a name is
	// suspicious.
	suspiciousQNameLen = 100
	// A leftmost label longer than suspiciousLabelLen characters with more
	// than suspiciousLabelEntropy bits/char looks like encoded tunnel data.
	suspiciousLabelLen     = 40
	suspiciousLabelEntropy = 3.5
)

// Malformed and suspicious reasons.
var (
	reasonLongQName        = fmt.Sprintf("qname longer than %d characters", suspiciousQNameLen)
	reasonHighEntropyLabel = "long high-entropy label (possible DNS tunnelling)"
	reasonQueryNoQuestions = "query has no questions"
	reasonQuestionOverrun  = "question runs past end of message"
	reasonShortDNSMessage  = fmt.Sprintf("message shorter than the %d-byte header", dnsHeaderLen)
)

// qtypeNames names the common query types.
var qtypeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
	28: "AAAA", 33: "SRV", 65: "HTTPS", 252: "AXFR", 255: "ANY",
}

// Name decoding errors. Their text is used as the malformed reason.
var (
	errNameTruncated   = errors.New("name runs past end of message")
	errCompressionLoop = errors.New("compression loop: pointer does not point backwards")
	errTooManyJumps    = errors.New("too many compression pointers")
	errLabelTooLong    = errors.New("label longer than 63 bytes")
	errReservedLabel   = errors.New("reserved label type")
	errNameTooLong     = errors.New("name longer than 255 bytes")
)

// parseDNS decodes a DNS message. Over TCP the message has a 2-byte length
// prefix (RFC 1035 4.2.2). A UDP datagram on port 53 is always taken as
// DNS, so garbage sent to a resolver is reported as malformed rather than
// hidden as unknown.
//
// This is the per-segment path, used when the stream stage is not
// reassembling the direction (another port, a desynced flow); reassembled
// messages go through parseStream, which decodes each as complete.
//
// Over TCP, parseDNS returns nil (unknown traffic) for a segment that does
// not frame cleanly as DNS. Without reassembly, a segment boundary can fall
// anywhere: the prefix can arrive alone, split 1+1 across segments, or a
// segment can be the continuation of a large response. The first two bytes
// of such a segment are then not a length at all. A segment frames cleanly
// when it starts with a plausible prefix and header and either
//   - holds exactly the message, or several messages whose prefixes are all
//     plausible (the last one may be cut short), or
//   - holds the start of a longer message whose header and questions
//     decode without error as far as the segment goes.
//
// So a malformed message is reported only when its length prefix matches
// the segment. A malformed first segment of a longer message is missed; it
// cannot be told from a misaligned one without reassembly.
func parseDNS(payload []byte, isTCP bool) *result {
	if !isTCP {
		return decodeDNS(payload, len(payload), true)
	}
	if len(payload) < 2+dnsHeaderLen {
		return nil
	}
	dnsLen := int(binary.BigEndian.Uint16(payload))
	if dnsLen < dnsHeaderLen {
		return nil
	}
	opcode := payload[2+2] >> 3 & 0x0F
	if opcode == dnsOpcodeUnassigned || opcode > dnsOpcodeMax {
		return nil
	}
	msg := payload[2:]
	if len(msg) > dnsLen {
		if !plausibleFrames(msg[dnsLen:]) {
			return nil
		}
		msg = msg[:dnsLen]
	}
	complete := len(msg) == dnsLen
	r := decodeDNS(msg, dnsLen, complete)
	if !complete && len(r.malformed) > 0 {
		return nil
	}
	return r
}

// plausibleFrames reports whether rest, the bytes after the first message
// of a TCP segment, is a run of length-prefixed messages of at least a
// header each. The last message, or the last prefix byte, may be cut short.
func plausibleFrames(rest []byte) bool {
	for len(rest) >= 2 {
		n := int(binary.BigEndian.Uint16(rest))
		if n < dnsHeaderLen {
			return false
		}
		if len(rest) < 2+n {
			return true
		}
		rest = rest[2+n:]
	}
	return true
}

// decodeDNS decodes one unprefixed message. dnsLen is its declared length,
// and complete says whether all of it is in msg; a name or question cut off
// by the end of an incomplete message is not malformed.
func decodeDNS(msg []byte, dnsLen int, complete bool) *result {
	r := &result{proto: packet.AppDNS}
	r.set("dns_len", strconv.Itoa(dnsLen))
	if len(msg) < dnsHeaderLen {
		r.bad(reasonShortDNSMessage)
		return r
	}
	flags := binary.BigEndian.Uint16(msg[2:])
	isResponse := flags&0x8000 != 0
	qd := binary.BigEndian.Uint16(msg[4:])
	r.set("id", strconv.Itoa(int(binary.BigEndian.Uint16(msg[0:]))))
	r.set("is_response", strconv.FormatBool(isResponse))
	r.set("rcode", strconv.Itoa(int(flags&0x0F)))
	r.set("qdcount", strconv.Itoa(int(qd)))
	r.set("ancount", strconv.Itoa(int(binary.BigEndian.Uint16(msg[6:]))))
	r.set("nscount", strconv.Itoa(int(binary.BigEndian.Uint16(msg[8:]))))
	r.set("arcount", strconv.Itoa(int(binary.BigEndian.Uint16(msg[10:]))))
	if !isResponse && qd == 0 {
		r.bad(reasonQueryNoQuestions)
	}

	off := dnsHeaderLen
	for i := 0; i < int(min(qd, maxQuestions)); i++ {
		labels, next, err := decodeName(msg, off)
		if err != nil {
			if !(err == errNameTruncated && !complete) {
				r.bad("qname: " + err.Error())
			}
			return r
		}
		if next+4 > len(msg) {
			if complete {
				r.bad(reasonQuestionOverrun)
			}
			return r
		}
		qtype := binary.BigEndian.Uint16(msg[next:])
		qclass := binary.BigEndian.Uint16(msg[next+2:])
		off = next + 4

		if i == 0 {
			r.set("qname", nameString(labels))
			r.set("qtype", strconv.Itoa(int(qtype)))
			if name, ok := qtypeNames[qtype]; ok {
				r.set("qtype_name", name)
			}
			r.set("qclass", strconv.Itoa(int(qclass)))
		}
		checkQName(r, labels)
	}
	return r
}

// checkQName flags names that look like DNS tunnelling. Letter case is
// ignored: resolvers randomize it (DNS 0x20) as a spoofing defence.
func checkQName(r *result, labels [][]byte) {
	dotted := len(labels) - 1
	for _, l := range labels {
		dotted += len(l)
	}
	if dotted > suspiciousQNameLen {
		r.flag(reasonLongQName)
	}
	if len(labels) > 0 && len(labels[0]) > suspiciousLabelLen &&
		entropy.Shannon(lowerASCII(labels[0])) > suspiciousLabelEntropy {
		r.flag(reasonHighEntropyLabel)
	}
}

// decodeName decodes the domain name at msg[off:], following compression
// pointers. It returns the labels (slices of msg, root label excluded) and
// the offset just past the name where it started. Pointers must point
// strictly backwards, at most maxPointerJumps are followed, labels are at
// most 63 bytes and the name at most 255 bytes on the wire.
func decodeName(msg []byte, off int) (labels [][]byte, next int, err error) {
	next = -1
	pos := off
	wireLen := 1 // the root label
	jumps := 0
	for {
		if pos < 0 || pos >= len(msg) {
			return nil, 0, errNameTruncated
		}
		b := msg[pos]
		switch {
		case b&0xC0 == 0xC0:
			if pos+1 >= len(msg) {
				return nil, 0, errNameTruncated
			}
			target := int(binary.BigEndian.Uint16(msg[pos:]) & 0x3FFF)
			if target >= pos {
				return nil, 0, errCompressionLoop
			}
			if jumps++; jumps > maxPointerJumps {
				return nil, 0, errTooManyJumps
			}
			if next < 0 {
				next = pos + 2
			}
			pos = target
			continue
		case b&0xC0 == 0x80:
			return nil, 0, errReservedLabel
		case int(b) > maxLabelLen: // 0x40-0x7F: extended label type 01
			return nil, 0, errLabelTooLong
		case b == 0:
			if next < 0 {
				next = pos + 1
			}
			return labels, next, nil
		}
		n := int(b)
		if wireLen += 1 + n; wireLen > maxNameLen {
			return nil, 0, errNameTooLong
		}
		if pos+1+n > len(msg) {
			return nil, 0, errNameTruncated
		}
		labels = append(labels, msg[pos+1:pos+1+n])
		pos += 1 + n
	}
}

// nameString formats labels as a lowercase dotted name, "." for the root.
// Dots and backslashes inside a label are escaped as "\." and "\\", and
// non-printable bytes as "\DDD" (RFC 4343 style).
func nameString(labels [][]byte) string {
	if len(labels) == 0 {
		return "."
	}
	var b strings.Builder
	for i, l := range labels {
		if i > 0 {
			b.WriteByte('.')
		}
		for _, c := range l {
			switch {
			case 'A' <= c && c <= 'Z':
				b.WriteByte(c + 'a' - 'A')
			case c == '.' || c == '\\':
				b.WriteByte('\\')
				b.WriteByte(c)
			case c < 0x21 || c > 0x7E:
				fmt.Fprintf(&b, "\\%03d", c)
			default:
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

func lowerASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}
