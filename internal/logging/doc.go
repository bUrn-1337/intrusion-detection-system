// Package logging implements Module 6: the alert log, log queries, and the
// traffic statistics behind the dashboard (whose UI is in the tui
// subpackage).
//
// # Log format
//
// The log is JSON Lines: one JSON object per line, each with a "type":
//
//   - "alert": a rules.Alert exactly as its JSON tags encode it, plus the
//     type field. "kind" is "alert" for the first match and "summary" for a
//     dedup window's summary.
//   - "stats": a StatsRecord, written every 60s and once at shutdown
//     ("reason" is "periodic" or "shutdown").
//   - "event": an EventRecord, written for rule reloads (successful or not).
//
// A Writer owns the file. Other goroutines hand it records through a
// bounded channel and are never blocked: a record that does not fit is
// dropped and counted. The file is created with mode 0600, opened with
// O_APPEND, gets one write per record, and is rotated by size (path.1 is
// the newest rotated file, path.N the oldest).
//
// Query and Follow read the log and its rotated files back, oldest first.
//
// An Aggregator turns the packet and alert stream into the rates, protocol
// breakdowns and top-N tables the dashboard shows. It is fed from the
// pipeline goroutine and publishes a Snapshot once per Tick, so readers on
// other goroutines never contend with the per-packet path.
package logging
