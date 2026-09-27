// Package rules implements Module 5: the rule engine. It loads Snort-like
// rules from a file and matches them against packets that have been
// through the Module 2-4 parsers, with alert deduplication and stateful
// detectors: SYN flood, port scan, host sweep, ping sweep, TTL anomaly,
// fragment attacks, ARP spoofing, UDP floods, ICMP floods and ICMP
// tunnels.
//
// # Rule file
//
// The rule language (header fields, every option, the app fields each
// parser sets) is documented in docs/RULES.md. Variables (var NAME value,
// $NAME) are expanded at load time, see vars.go. Load reports every
// problem with file:line and returns all of them at once. arpbind IP MAC
// lines (static ARP bindings) are parsed by parseARPBinds.
//
// # Engine
//
// See Engine for the concurrency contract and the packet-time clock,
// windowCounter, distinctCounter and rateCounter for sliding windows,
// recentSet for keys remembered for a while, deduper for alert
// deduplication, handshakeTracker for handshake outcomes, synFlood for the
// SYN flood detector, and scan.go (packetProbe, scanDetector) for what
// counts as a probe and the scan detectors, ttlAnomaly for the TTL
// anomaly detector, fragmentTracker (frag.go) for the fragment attack
// detectors, arpTable, arpRequests and arpSpoof (arp.go) for the ARP
// spoofing detector, udpFlood and icmpFlood for the flood detectors, and
// icmpTunnel and standardEcho (icmptunnel.go, echopayload.go) for the
// ICMP tunnel detector.
package rules
