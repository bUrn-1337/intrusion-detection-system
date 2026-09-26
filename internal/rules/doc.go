// Package rules implements Module 5: the rule engine. It loads Snort-like
// rules from a file and matches them against packets that have been
// through the Module 2-4 parsers, with alert deduplication and a stateful
// SYN flood detector.
//
// # Rule file
//
// One rule per line. Blank lines and lines starting with '#' are ignored.
//
//	action proto src_addr src_port direction dst_addr dst_port (options)
//
// The header fields are:
//
//   - action: alert, or pass. Pass rules are checked first; a packet that
//     matches one is not checked against any alert rule.
//   - proto: ip, tcp, udp, icmp, arp. "ip" rules apply to every IPv4/IPv6
//     packet. tcp and udp rules need a fully decoded transport header (so
//     non-first fragments only match ip rules). icmp covers ICMPv6. arp
//     rules match the ARP sender and target IPs as src and dst.
//   - addresses: any, an IPv4/IPv6 address, a CIDR prefix, or a list
//     [a,b,...] of addresses and prefixes. '!' negates the whole spec (!a,
//     ![a,b]) or a list item ([10.0.0.0/8,!10.0.0.1]). A list with only
//     negated items matches everything else.
//   - ports: any, N, N:M, N: (N and up), :M (up to M), or a list of those,
//     with the same negation forms. Ports must be any for ip, icmp and arp.
//   - direction: -> or <> (either way round).
//
// Options, separated by ';' (the last ';' is optional). Strings are in
// double quotes, where \" \\ and \; are the escapes.
//
//	msg:"...";                 required, non-empty
//	sid:N;                     required, 1..2^31-1, unique in the file
//	rev:N;                     default 1
//	severity:low|medium|high|critical;       default medium
//	category:NAME;             letters, digits, '_', '-'
//	flags:SAF;                 tcp only; letters SAFRPU. Exact match of those
//	                           six flags; "SA+" = at least these; "0" = none
//	content:"text";            substring of the payload; |0d 0a| hex bytes and
//	                           \| are allowed; repeatable, all must match
//	nocase;                    makes the preceding content case-insensitive
//	                           (ASCII only)
//	app_proto:dns|http|ftp|tls;
//	app_field:KEY=VALUE;       AppFields[KEY] equals VALUE, ignoring case;
//	                           VALUE may be quoted; repeatable
//	app_reason:malformed|suspicious;         that reason key is present
//	detection_filter:track by_src|by_dst, count N, seconds S;
//	                           fire only once N matches for the same tracked
//	                           address fall within S seconds
//	detect:syn_flood;          run the SYN flood detector (tcp alert rules
//	                           only) instead of per-packet matching. Takes
//	                           track:by_src|by_dst; count:N; seconds:S;
//	                           (required) and min_incomplete_ratio:F
//	                           (0..1, default 0.8). The rule's addresses and
//	                           ports select which handshakes (client ->
//	                           server) it counts.
//
// count is at most 100000 and seconds at most 86400. Every problem is
// reported with file:line (unknown option, bad value, missing msg or sid,
// duplicate sid, invalid address or port, option not valid for the
// protocol), and Load returns all of them at once.
//
// # Engine
//
// See Engine for the concurrency contract and the packet-time clock,
// windowCounter for sliding windows, deduper for alert deduplication,
// handshakeTracker and synFlood for the detector.
package rules
