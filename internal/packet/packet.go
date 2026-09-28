// Package packet defines ParsedPacket, the shared record passed between
// pipeline stages.
//
// ParsedPacket is the ONLY contract between pipeline stages. Each field is
// written by exactly one stage (documented per field below) and may be read
// by any later stage. The exceptions are ParseErrors, which any stage may
// append to through AddError; the reason keys in AppFields, which are only
// written through AddAppReason; and the "http_*" keys in AppFields, which
// the stream stage writes before Module 4 adds its own.
//
// Every module depends on the exact shape of this struct. No stage may add,
// remove, or change a field without updating this file and notifying the
// team first.
//
// This package must not import any other internal package.
package packet

import (
	"net"
	"time"
)

// Values for ParsedPacket.EthType.
const (
	EthTypeIPv4 uint16 = 0x0800
	EthTypeARP  uint16 = 0x0806
	EthTypeIPv6 uint16 = 0x86DD
)

// Values for ParsedPacket.ARPOp. 0 means the packet is not ARP.
const (
	ARPRequest uint16 = 1
	ARPReply   uint16 = 2
)

// Values for ParsedPacket.L4Proto. The empty string means Module 3 has not
// set it.
const (
	L4TCP   = "TCP"
	L4UDP   = "UDP"
	L4ICMP  = "ICMP"
	L4Other = "OTHER"
)

// Values for ParsedPacket.StreamAnomaly. The empty string means none.
const (
	// StreamOverlapConflict: the segment overlaps bytes already seen in
	// its direction with different content.
	StreamOverlapConflict = "overlap_conflict"
	// StreamOversizeHeaders: an HTTP message head grew past the stream
	// stage's header cap without ending.
	StreamOversizeHeaders = "oversize_headers"
	// StreamTooManyOOO: more out-of-order segments arrived ahead of a gap
	// than the stream stage holds.
	StreamTooManyOOO = "too_many_ooo_segments"
)

// Values for ParsedPacket.L4ChecksumStatus.
const (
	L4ChecksumUnchecked uint8 = iota
	L4ChecksumValid
	L4ChecksumInvalid
)

// Values for ParsedPacket.AppProtocol. The empty string means Module 4 has
// not set it.
const (
	AppHTTP    = "HTTP"
	AppDNS     = "DNS"
	AppFTP     = "FTP"
	AppTLS     = "TLS"
	AppUnknown = "UNKNOWN"
)

// Kinds accepted by AddAppReason. A reason of kind K is stored under the
// AppFields key K + "_reason".
const (
	ReasonMalformed  = "malformed"
	ReasonSuspicious = "suspicious"
)

// reasonSep separates multiple reasons stored under one AppFields key.
const reasonSep = ";"

// TCPFlags holds the TCP control bits that the rule engine matches on.
type TCPFlags struct {
	SYN, ACK, FIN, RST, PSH, URG bool
}

// ParsedPacket is one captured frame, filled in stage by stage as it moves
// through the pipeline. Stages identify themselves by module number:
// 1 capture, 2 parser/lower, 3 parser/upper, stream (TCP reassembly,
// between 3 and 4), 4 parser/app.
type ParsedPacket struct {
	// ---- Module 1: capture ----

	// Timestamp is when the packet was captured, taken from the capture
	// source (pcap record header or kernel timestamp). It is not the time
	// the packet was processed.
	Timestamp time.Time
	// CaptureLen is the number of bytes actually captured.
	CaptureLen uint32
	// WireLen is the packet's original length on the wire. If CaptureLen is
	// less than WireLen, the capture was truncated (snaplen) and later
	// stages must expect short buffers.
	WireLen uint32
	// RawData is the full captured frame, starting at the Ethernet header.
	// Its length is CaptureLen. It must be a copy owned by this packet,
	// never a buffer the capture library reuses for the next packet
	// (for example, gopacket's ZeroCopyReadPacketData). Later stages read
	// it but must not modify it.
	RawData []byte

	// ---- Module 2: Ethernet / IP / ARP ----

	// EthSrc is the Ethernet source MAC address. It is nil until Module 2
	// parses the frame.
	EthSrc net.HardwareAddr
	// EthDst is the Ethernet destination MAC address. It is nil until
	// Module 2 parses the frame.
	EthDst net.HardwareAddr
	// EthType is the EtherType of the frame, e.g. EthTypeIPv4, EthTypeIPv6
	// or EthTypeARP. If the frame has VLAN tags, this is the EtherType
	// after the last tag.
	EthType uint16
	// L3Offset is the byte offset in RawData where the IP or ARP header
	// starts, after the Ethernet header and any VLAN tags. It is -1 if not
	// determined.
	L3Offset int
	// L4Offset is the byte offset in RawData where the TCP, UDP or ICMP
	// header starts, after IPv4 options or IPv6 extension headers. It is -1
	// if not determined, which includes ARP, a truncated IP header, and
	// non-first fragments (FragOffset > 0), which carry no L4 header.
	L4Offset int

	// IPVersion is 4 or 6, or 0 if no IP header was parsed (for example,
	// for ARP or a truncated frame). None of the other IP* fields, or the
	// fragmentation fields, mean anything while it is 0.
	IPVersion uint8
	// IPSrc is the source address: 4 bytes for IPv4, 16 bytes for IPv6.
	IPSrc net.IP
	// IPDst is the destination address: 4 bytes for IPv4, 16 bytes for IPv6.
	IPDst net.IP
	// IPTTL is the IPv4 TTL or the IPv6 hop limit.
	IPTTL uint8
	// IPProto is the IPv4 protocol number or, for IPv6, the final Next
	// Header value after any extension headers (6=TCP, 17=UDP, 1=ICMP,
	// 58=ICMPv6).
	IPProto uint8
	// IPTotalLen is the IPv4 Total Length field, or the IPv6 Payload Length
	// plus 40 for the fixed header. It is taken from the header, not from
	// RawData, so it can be larger than what was captured. It can also be
	// smaller than RawData minus L3Offset when the frame has Ethernet
	// padding; use IPEnd() to find where the IP packet really ends.
	IPTotalLen uint32
	// IPChecksumValid reports whether the IPv4 header checksum verified.
	// IPv6 has no header checksum, so Module 2 sets it to true for IPv6.
	// That way false always means a real failure whenever IPVersion != 0.
	IPChecksumValid bool

	// IPID is the IPv4 Identification field (16 bits) or, for IPv6, the
	// Fragment extension header's Identification (32 bits). It is 0 for
	// IPv6 packets without a Fragment header.
	IPID uint32
	// FragOffset is the fragment offset in bytes, already multiplied by 8.
	FragOffset uint16
	// MoreFragments is the IPv4 MF flag or the IPv6 Fragment header M flag.
	MoreFragments bool
	// IPFragmented is a convenience flag equal to
	// (MoreFragments || FragOffset > 0). Module 3 should not expect a
	// complete L4 header in non-first fragments.
	IPFragmented bool
	// FragPayloadLen is the number of bytes this fragment carries of the
	// original packet's fragmentable part, taken from the length fields
	// (not from what was captured): for IPv4, IPTotalLen minus the header
	// length; for IPv6, the bytes after the Fragment header (IPTotalLen
	// minus the fixed header and every extension header up to and
	// including the Fragment header). The fragment covers bytes
	// [FragOffset, FragOffset+FragPayloadLen) of the original packet. It
	// is 0 when IPFragmented is false.
	FragPayloadLen uint32

	// ARPOp is the ARP opcode, normally ARPRequest or ARPReply, or 0 if the
	// packet is not ARP. Any other opcode is stored as-is and Module 2 also
	// records a parse error. The ARP* address fields are only meaningful
	// when it is non-zero.
	ARPOp uint16
	// ARPSenderMAC is the ARP sender hardware address.
	ARPSenderMAC net.HardwareAddr
	// ARPTargetMAC is the ARP target hardware address.
	ARPTargetMAC net.HardwareAddr
	// ARPSenderIP is the ARP sender protocol address (4 bytes for IPv4).
	ARPSenderIP net.IP
	// ARPTargetIP is the ARP target protocol address (4 bytes for IPv4).
	ARPTargetIP net.IP

	// ---- Module 3: TCP / UDP / ICMP ----

	// L4Proto is one of L4TCP, L4UDP, L4ICMP or L4Other, or "" if Module 3
	// has not run. ICMPv6 is reported as L4ICMP.
	L4Proto string
	// PayloadOffset is the byte offset in RawData where the application
	// payload starts, after the TCP header and options or the UDP or ICMP
	// header (8 bytes for an echo request or reply, else 4; see
	// HasICMPEcho). It is -1 if not determined. Read the payload through
	// Payload(), not by slicing RawData directly.
	PayloadOffset int
	// SrcPort is the TCP or UDP source port. It is 0 for other protocols.
	SrcPort uint16
	// DstPort is the TCP or UDP destination port. It is 0 for other
	// protocols.
	DstPort uint16
	// TCPFlags holds the TCP control bits. All are false unless L4Proto is
	// L4TCP.
	TCPFlags TCPFlags
	// TCPSeq is the TCP sequence number. It is only meaningful for TCP.
	TCPSeq uint32
	// TCPAck is the TCP acknowledgment number. It is only meaningful when
	// TCPFlags.ACK is set.
	TCPAck uint32
	// TCPWindow is the raw TCP window size, without window scaling applied.
	// It is only meaningful for TCP.
	TCPWindow uint16
	// UDPLen is the UDP Length field (header plus data), taken from the
	// header. It is only meaningful for UDP.
	UDPLen uint16
	// ICMPType is the ICMP (or ICMPv6) type. It is only meaningful when
	// L4Proto is L4ICMP.
	ICMPType uint8
	// ICMPCode is the ICMP (or ICMPv6) code. It is only meaningful when
	// L4Proto is L4ICMP.
	ICMPCode uint8
	// ICMPEchoID and ICMPEchoSeq are the Identifier and Sequence Number
	// of an echo request or reply (ICMP type 8 or 0, ICMPv6 type 128 or
	// 129) whose 8-byte echo header was captured. They are 0 for every
	// other message; HasICMPEcho tells a real id or seq of 0 apart.
	ICMPEchoID  uint16
	ICMPEchoSeq uint16
	// HasICMPEcho is true when ICMPEchoID and ICMPEchoSeq were set. For
	// such a message PayloadOffset is past the id and seq, so Payload()
	// is the echo data (what ping -s sizes); for every other ICMP message
	// it starts right after the 4-byte type, code and checksum.
	HasICMPEcho bool
	// ICMPInnerSrc and ICMPInnerDst are the addresses of the packet quoted
	// by an ICMP or ICMPv6 error message (Destination Unreachable, Time
	// Exceeded, Parameter Problem, Redirect, Source Quench, Packet Too
	// Big): the packet that caused the error, as its sender sent it. For a
	// port unreachable, ICMPInnerSrc is the host that sent the probe and is
	// normally the outer IPDst. Both are nil when the message is not an
	// error or its quoted IP header could not be decoded (truncated, wrong
	// IP version, broken IPv6 extension headers); that is not a parse
	// error. ICMPInnerSrc != nil means every ICMPInner* field below is set.
	ICMPInnerSrc net.IP
	ICMPInnerDst net.IP
	// ICMPInnerProto is the quoted IPv4 protocol, or for IPv6 the Next
	// Header after any extension headers (6=TCP, 17=UDP).
	ICMPInnerProto uint8
	// ICMPInnerSrcPort and ICMPInnerDstPort are the quoted TCP or UDP
	// ports, valid only when ICMPInnerHasPorts is true: the quoted protocol
	// is TCP or UDP, it is not a non-first fragment, and the quote includes
	// at least the first 4 bytes of the transport header.
	ICMPInnerSrcPort  uint16
	ICMPInnerDstPort  uint16
	ICMPInnerHasPorts bool
	// L4ChecksumStatus is the result of verifying the TCP, UDP, ICMPv4 or
	// ICMPv6 checksum: L4ChecksumUnchecked, L4ChecksumValid or
	// L4ChecksumInvalid. TCP, UDP and ICMPv6 include the IP pseudo-header;
	// ICMPv4 covers the ICMP message only.
	//
	// It stays Unchecked when the checksum cannot be verified from this
	// frame alone: the segment was not fully captured (snaplen); the packet
	// is a GRO/TSO merge (IPTotalLen > 1500, which includes the BIG TCP and
	// jumbogram cases), whose checksum was never recomputed for the merged
	// packet; the packet is a fragment (IPFragmented), since the checksum
	// covers the reassembled datagram; the header is malformed; or the
	// protocol has no checksum to check. A UDP checksum of 0 over IPv4
	// means "no checksum" and is also Unchecked.
	//
	// Otherwise it is Valid or Invalid. Invalid is not a parse error, and
	// is not an attack by itself: with checksum offloading, packets
	// captured on the sending host usually carry an unfilled checksum that
	// the NIC fills in after capture. The one exception is a zero UDP
	// checksum over IPv6, which is forbidden, so it is Invalid and also
	// recorded in ParseErrors.
	L4ChecksumStatus uint8

	// ---- Stream: TCP reassembly (internal/stream) ----
	//
	// The stream stage tracks TCP flows with a port in its set (by
	// default 21, 53, 80, 443, 8000, 8080 and 8443) and leaves every other
	// packet untouched, with all of these fields at their zero values.

	// FlowID identifies the tracked TCP flow this packet belongs to, in
	// both directions. IDs are never reused within a run. It is 0 for a
	// packet the stream stage does not track (another protocol or port,
	// or a segment that opens no flow: a RST, or a bare ACK or FIN of a
	// flow it does not know).
	FlowID uint64
	// FlowStart is the engine time (packet time, never going backwards)
	// of the flow's first packet. It is zero when FlowID is 0.
	FlowStart time.Time
	// StreamProto is AppHTTP, AppDNS, AppFTP or AppTLS when the stream
	// stage is reassembling this packet's direction of the flow, and ""
	// otherwise: the flow is not tracked, the direction is desynced
	// (waiting for a clean message boundary), or it has been handed back
	// to per-segment parsing (TLS after its first handshake record, HTTP
	// after an upgrade). When it is set, the payload belongs to the
	// reassembled stream: Module 4 parses only AppData and never this
	// segment's payload on its own.
	StreamProto string
	// AppData holds the application messages this packet completed, as an
	// owned copy, in stream order: whole HTTP message heads (request or
	// status line and headers up to the blank line, without bodies),
	// DNS-over-TCP messages with their 2-byte length prefix, FTP lines
	// with their line ending, or the first TLS record of a direction. It
	// may hold several messages (pipelined HTTP requests, several DNS
	// messages or FTP lines). It is nil when the packet completed none,
	// including every packet with StreamProto "". Later stages must not
	// modify it.
	AppData []byte
	// StreamAnomaly is one of the Stream* reason constants, or "". It is
	// set on the packet where the stream stage saw the anomaly; the
	// direction's buffered message is dropped and it waits for a clean
	// boundary.
	StreamAnomaly string
	// ClosedFlows lists the FlowIDs the stream stage stopped tracking
	// while it processed this packet: this packet's own flow on a RST or
	// after both sides sent FIN, and other flows that timed out idle or
	// were evicted at the memory cap. Later stages drop any state they
	// keep per FlowID for them. It is nil when none closed.
	ClosedFlows []uint64

	// ---- Module 4: HTTP / DNS / FTP / TLS ----

	// AppProtocol is one of AppHTTP, AppDNS, AppFTP, AppTLS or AppUnknown,
	// or "" if Module 4 has not run or had nothing to parse (no payload).
	// A packet whose StreamProto is set but that completed no message
	// gets AppProtocol = StreamProto and no fields.
	AppProtocol string
	// AppFields holds protocol-specific values. It is nil until something is
	// written. Write it only through SetAppField and AddAppReason, which
	// allocate it when needed. Reading a nil map is safe. Missing keys mean
	// "not present in the packet".
	//
	// Keys by protocol:
	//   HTTP: "method", "uri", "uri_decoded" (uri percent-decoded once),
	//         "version" ("1.1", or "2.0" for the h2c preface), "host",
	//         "user_agent", "status_code", "content_type",
	//         "content_length", "auth_basic" ("true" if an
	//         Authorization: Basic header is present), "request_complete"
	//         ("true" if the blank line ending the headers is in this
	//         segment, and always for a message from AppData; set for
	//         requests and responses)
	//         HTTP state, written by the stream stage (not Module 4) on
	//         every client-to-server packet of a reassembled HTTP flow,
	//         before Module 4 runs: "http_state" ("headers_partial": a
	//         request head has started and not ended; "headers_complete":
	//         this packet completed a request with no body to follow;
	//         "body_partial": a request head is complete and its body is
	//         not; "idle": no request in progress), "http_hdr_bytes"
	//         (bytes of the current request head so far), and while a
	//         body is in progress "http_body_expected" (Content-Length;
	//         absent for chunked bodies) and "http_body_seen" (body bytes
	//         received so far), and "http_msg_start" (engine time the
	//         current request started, in Unix nanoseconds; absent when
	//         idle)
	//   DNS:  "id", "qname" (first question, lowercased), "qtype"
	//         (number), "qtype_name" ("A", "AAAA", ... for common types),
	//         "qclass", "is_response", "rcode", "qdcount", "ancount",
	//         "nscount", "arcount", "dns_len" (message length in bytes,
	//         without the TCP length prefix)
	//   FTP:  "command" (uppercased), "argument", "response_code"
	//   TLS:  "sni" (ClientHello server name, lowercased; no decryption),
	//         "sni_status" ("found", "absent" for a complete ClientHello
	//         without one, or "truncated" when the ClientHello continues
	//         past the parsed bytes, this segment or the record in
	//         AppData, and no server name was seen)
	//   All:  "malformed_reason", "suspicious_reason". Write these only
	//         through AddAppReason, never through SetAppField.
	//
	// Credentials are never stored, in AppFields or in ParseErrors: an
	// Authorization header sets only "auth_basic", and the argument of an
	// FTP PASS command is stored as "<redacted>". Reasons and errors must
	// not quote payload bytes.
	//
	// Add a new key here before any module starts writing it.
	//
	// When AppData holds several messages, AppFields describes the first
	// one and AppMore the others.
	AppFields map[string]string
	// AppMore holds the fields of the second and later messages in
	// AppData, one map per message, in order, with the same keys as
	// AppFields (the reason keys included). It is nil for a packet with
	// at most one message. Written only by Module 4.
	AppMore []map[string]string

	// ---- Any stage ----

	// ParseErrors lists problems found while parsing malformed or truncated
	// input. Append only through AddError. When a parser hits bad input, it
	// records an error and stops parsing that layer. It must never panic or
	// drop the packet.
	ParseErrors []string
}

// NewParsedPacket returns a packet with only the capture-stage (Module 1)
// fields set, except RawData, which the caller assigns. L3Offset, L4Offset
// and PayloadOffset are set to -1 ("not determined"). Every other field is
// left at its zero value.
func NewParsedPacket(ts time.Time, captureLen, wireLen uint32) *ParsedPacket {
	return &ParsedPacket{
		Timestamp:     ts,
		CaptureLen:    captureLen,
		WireLen:       wireLen,
		L3Offset:      -1,
		L4Offset:      -1,
		PayloadOffset: -1,
	}
}

// Payload returns the application payload: RawData[PayloadOffset:end],
// where end is IPEnd() for IP packets and len(RawData) otherwise, so
// Ethernet padding is never returned as payload. For UDP, end is also
// capped at the end of the datagram given by UDPLen, so bytes that follow
// the datagram inside the IP packet are not returned either. It returns nil
// if PayloadOffset is negative or past end, and never panics. If
// PayloadOffset equals end, the result is empty.
func (p *ParsedPacket) Payload() []byte {
	end := len(p.RawData)
	if e := p.IPEnd(); e >= 0 {
		end = e
	}
	if p.L4Proto == L4UDP && p.L4Offset >= 0 && p.UDPLen >= 8 {
		end = min(end, p.L4Offset+int(p.UDPLen))
	}
	if p.PayloadOffset < 0 || p.PayloadOffset > end {
		return nil
	}
	return p.RawData[p.PayloadOffset:end]
}

// IPEnd returns the offset in RawData just past the last byte of the IP
// packet: L3Offset + IPTotalLen, capped at len(RawData).
//
// Use it instead of len(RawData) as the end of the transport header and
// payload. Ethernet pads frames shorter than 60 bytes (and some links add
// trailers), so the bytes from IPEnd() to len(RawData) are link-layer
// filler, never IP data. For example, a 40-byte TCP SYN in a 60-byte frame
// has IPEnd() == 54, and bytes 54-59 are padding.
//
// It returns -1 if no IP header was parsed (IPVersion == 0 or L3Offset
// out of range). Otherwise the result is in [L3Offset, len(RawData)]. It
// can be less than L4Offset in a malformed packet whose length field is
// smaller than its headers, so callers must still check before slicing.
func (p *ParsedPacket) IPEnd() int {
	if p.IPVersion == 0 || p.L3Offset < 0 || p.L3Offset > len(p.RawData) {
		return -1
	}
	end := int64(p.L3Offset) + int64(p.IPTotalLen)
	if end > int64(len(p.RawData)) {
		return len(p.RawData)
	}
	return int(end)
}

// AddError records a parse error on the packet. Every parser module should
// call it instead of changing ParseErrors directly, so that error handling
// (counters, logging) can be added here later without touching callers.
func (p *ParsedPacket) AddError(msg string) {
	p.ParseErrors = append(p.ParseErrors, msg)
}

// HasErrors reports whether any stage has recorded a parse error.
func (p *ParsedPacket) HasErrors() bool {
	return len(p.ParseErrors) > 0
}

// SetAppField sets AppFields[key] = value, allocating the map if it is nil.
// Do not use it for the reason keys; use AddAppReason instead.
func (p *ParsedPacket) SetAppField(key, value string) {
	if p.AppFields == nil {
		p.AppFields = make(map[string]string)
	}
	p.AppFields[key] = value
}

// AddAppReason appends reason to AppFields[kind + "_reason"], where kind is
// ReasonMalformed or ReasonSuspicious. Multiple reasons are kept in order,
// separated by ";", so a reason must not itself contain ";". An unknown
// kind is recorded with AddError and the reason is dropped.
func (p *ParsedPacket) AddAppReason(kind, reason string) {
	if kind != ReasonMalformed && kind != ReasonSuspicious {
		p.AddError("packet: AddAppReason: unknown kind " + kind)
		return
	}
	key := kind + "_reason"
	if prev := p.AppFields[key]; prev != "" {
		reason = prev + reasonSep + reason
	}
	p.SetAppField(key, reason)
}
