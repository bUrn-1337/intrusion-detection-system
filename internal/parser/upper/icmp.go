package upper

import "fmt"

// icmpType describes one ICMP message type: its name and, for types whose
// code has a meaning, the known codes.
type icmpType struct {
	name  string
	codes map[uint8]string
}

// ICMPv4 types (RFC 792, RFC 1256, RFC 1812).
var icmpv4Types = map[uint8]icmpType{
	0: {name: "Echo Reply"},
	3: {name: "Destination Unreachable", codes: map[uint8]string{
		0:  "net unreachable",
		1:  "host unreachable",
		2:  "protocol unreachable",
		3:  "port unreachable",
		4:  "fragmentation needed",
		5:  "source route failed",
		6:  "destination network unknown",
		7:  "destination host unknown",
		9:  "network administratively prohibited",
		10: "host administratively prohibited",
		13: "communication administratively prohibited",
	}},
	5: {name: "Redirect", codes: map[uint8]string{
		0: "for network",
		1: "for host",
		2: "for TOS and network",
		3: "for TOS and host",
	}},
	8:  {name: "Echo Request"},
	9:  {name: "Router Advertisement"},
	10: {name: "Router Solicitation"},
	11: {name: "Time Exceeded", codes: map[uint8]string{
		0: "TTL exceeded in transit",
		1: "fragment reassembly time exceeded",
	}},
	12: {name: "Parameter Problem", codes: map[uint8]string{
		0: "pointer indicates the error",
		1: "missing a required option",
		2: "bad length",
	}},
	13: {name: "Timestamp Request"},
	14: {name: "Timestamp Reply"},
}

// ICMPv6 types (RFC 4443, RFC 4861).
var icmpv6Types = map[uint8]icmpType{
	1: {name: "Destination Unreachable", codes: map[uint8]string{
		0: "no route to destination",
		1: "administratively prohibited",
		2: "beyond scope of source address",
		3: "address unreachable",
		4: "port unreachable",
		5: "source address failed policy",
		6: "reject route to destination",
	}},
	2: {name: "Packet Too Big"},
	3: {name: "Time Exceeded", codes: map[uint8]string{
		0: "hop limit exceeded in transit",
		1: "fragment reassembly time exceeded",
	}},
	4: {name: "Parameter Problem", codes: map[uint8]string{
		0: "erroneous header field",
		1: "unrecognized next header",
		2: "unrecognized IPv6 option",
	}},
	128: {name: "Echo Request"},
	129: {name: "Echo Reply"},
	133: {name: "Router Solicitation"},
	134: {name: "Router Advertisement"},
	135: {name: "Neighbor Solicitation"},
	136: {name: "Neighbor Advertisement"},
	137: {name: "Redirect"},
}

// ICMPLabel returns a human-readable label for an ICMP (ipVersion 4) or
// ICMPv6 (ipVersion 6) type and code, for example "Echo Request" or
// "Destination Unreachable (port unreachable)". The two versions number
// their types differently (Echo Request is 8 in ICMPv4, 128 in ICMPv6).
// A known type with an unexpected code is labeled "<name> (code N)". An
// unknown type, or an ipVersion other than 4 or 6, gives "type N code M".
func ICMPLabel(ipVersion, typ, code uint8) string {
	var types map[uint8]icmpType
	switch ipVersion {
	case 4:
		types = icmpv4Types
	case 6:
		types = icmpv6Types
	}
	t, ok := types[typ]
	if !ok {
		return fmt.Sprintf("type %d code %d", typ, code)
	}
	if meaning, ok := t.codes[code]; ok {
		return t.name + " (" + meaning + ")"
	}
	if code != 0 || t.codes != nil {
		return fmt.Sprintf("%s (code %d)", t.name, code)
	}
	return t.name
}
