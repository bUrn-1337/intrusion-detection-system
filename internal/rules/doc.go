// Package rules implements Module 5: the rule engine. It loads Snort-like
// rules from a file and matches them against packets that have been
// through the Module 2-4 parsers, with alert deduplication and a stateful
// SYN flood detector.
//
// # Rule file
//
// The rule language (header fields, every option, the app fields each
// parser sets) is documented in docs/RULES.md. Load reports every problem
// with file:line and returns all of them at once.
//
// # Engine
//
// See Engine for the concurrency contract and the packet-time clock,
// windowCounter for sliding windows, deduper for alert deduplication,
// handshakeTracker and synFlood for the detector.
package rules
