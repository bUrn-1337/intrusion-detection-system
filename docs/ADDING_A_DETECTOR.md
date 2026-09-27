# Adding a detector

A detector is a stateful check that a single-packet rule cannot express,
switched on with `detect:NAME;` in a rule. This guide follows
`syn_flood` ([internal/rules/synflood.go](../internal/rules/synflood.go)),
the one detector so far. Each step names the syn_flood code to copy. The
example new detector here is `port_scan` (refused handshakes from one
source); replace it with yours.

## 1. Decide what you count, per what key, and when it fires

Write it down as one sentence before writing code. For syn_flood: "per
tracked address (server for by_dst, client for by_src), fire when the last
`count` incomplete handshakes fall within `seconds` and at least
`min_incomplete_ratio` of the handshakes in that span were incomplete."

Then list what must not fire (the look-alikes). For syn_flood that is a
busy server whose handshakes complete; for a port scan, a client that
opens many connections to one service. Each look-alike becomes a scenario
in step 7.

## 2. Accept the rule syntax

- [rule.go](../internal/rules/rule.go): add `const DetectPortScan =
  "port_scan"` next to `DetectSYNFlood`. `newRuleSet` puts every rule with
  `Detect != ""` into `rs.synFlood`; rename that slice to `detectors`, or
  add one slice per detector.
- [parse.go](../internal/rules/parse.go): the `case "detect":` branch
  rejects everything except syn_flood. Accept the new name. `track`,
  `count` and `seconds` are already parsed into `r.detect`. Add a `case`
  only for options specific to your detector, and list them in
  `detectOpts` so they are rejected on rules without `detect`.
- Keep limits on every number (`parsePositive(v, maxCount)`). An unbounded
  count is a memory bug waiting for a rule typo.
- Add parse tests for the good rule and each error (unknown option, missing
  `track`, option without `detect`) in `parse_test.go`.

## 3. Keep state in bounded window counters

Create `internal/rules/portscan.go` with a struct like `synFlood`:

```go
type portScan struct {
	rule *Rule
	refused *windowCounter[netip.Addr] // per tracked address
}

func newPortScan(r *Rule, max int, stat *tableStat) *portScan {
	return &portScan{rule: r, refused: newWindowCounter[netip.Addr](r.detect.count, r.detect.span(), max, stat)}
}
```

`windowCounter` ([window.go](../internal/rules/window.go)) does the
sliding window, the key cap and eviction counting for you. It stores at
most `count` timestamps per key and at most `max` keys. Never keep a plain
map that grows with traffic. If you need a second counter (syn_flood keeps
completions for the ratio), bound it by what can change the decision, as
`newSYNFlood` does with `count*(1-r)/r + 2`.

Give the detector its own table in
[engine.go](../internal/rules/engine.go): add `tPortScan` before
`numTables`, a `TablePortScan = "port_scan"` name and an entry in
`tableNames`. Its keys and evictions then appear in every stats record
and in the dashboard with no further work.

## 4. Wire it into the engine

In `engine.go`:

- `ruleState`: add a `scan *portScan` field.
- `activate`: create it for rules with `r.Detect == DetectPortScan`
  (`e.cfg.MaxKeys`, `&e.tables[tPortScan]`). A rule whose text is unchanged
  keeps its state across a reload; update `st.<det>.rule = r` there, and
  `clear()` the state of rules that were removed.
- Feed events. syn_flood consumes handshake outcomes in `handshakeEvents`,
  which also applies the whitelist, pass rules and the rule's addresses
  and ports to each outcome as if it were the opening SYN. A port-scan
  detector would take the same `hsEvent`s; a per-packet detector would be
  called from `Process` after the whitelist and pass checks.
- `Flush`: if the detector holds pending work (syn_flood times out every
  open handshake), finish it there so the end of a pcap still fires.

Use the engine clock (`e.now` or the event time), never `time.Now`.

## 5. Build the alert Details

When the detector fires, return the tracked key and a `details` function,
then call `e.emit(r, key, &view, details, out)`. `emit` handles dedup: one
alert, then one summary with the total count. syn_flood's details are:

```
detector, track, tracked_addr, incomplete, completed, ratio, top_dst_port, window
```

Include `detector`, `track` and `tracked_addr`, plus the numbers that
justify the alert so an analyst can judge it without the pcap. Keys are
part of the log format: keep them stable, and never put payload bytes in
them.

## 6. Unit tests

Follow [synflood_test.go](../internal/rules/synflood_test.go): build frames,
replay them through the parsers and a real engine, and assert on the
alerts. Cover: fires at exactly `count`, stays quiet at `count - 1`, the
window edge, each look-alike, the whitelist, pass rules, and the table cap
(a small `EngineConfig.MaxKeys` plus the eviction counter).

## 7. Scenarios

Add at least two scenarios ([SCENARIOS.md](SCENARIOS.md)): one that fires
and one look-alike that must not. For syn_flood these are
`syn_flood_single_source`, `syn_flood_spoofed` and
`completed_handshakes_busy`. Write the generators with `pcapgen` in
[cmd/ids/scenario_gen_test.go](../cmd/ids/scenario_gen_test.go) and match
on `details` in expected.json, for example:

```json
{"sid": 1000001, "kind": "alert", "dst_ip": "192.0.2.10",
 "details": {"track": "by_dst", "tracked_addr": "192.0.2.10", "completed": "0"}}
```

Make the look-alike depend on the part of the logic it exercises.
completed_handshakes_busy has 120 refused connections, above `count`, so
only the ratio check keeps it quiet.

## 8. Mutation check

Prove the tests can fail. Break the detector on purpose, one change at a
time, and run `make test scenarios`:

- flip the threshold comparison (`<` to `<=`)
- drop the ratio check or the second condition
- track the wrong key (client instead of server)
- ignore the whitelist

Each mutation must make at least one test fail. If one survives, add the
test that catches it, then revert the mutation.

## 9. Document it

Add the option to [RULES.md](RULES.md), a rule to [rules.conf](../rules.conf)
with a comment on what it catches, and a paragraph to the design decisions
in [ARCHITECTURE.md](ARCHITECTURE.md) if the detector makes a trade-off.
