# Adding a detector

A detector is a stateful check that a single-packet rule cannot express,
switched on with `detect:NAME;` in a rule. There are seventeen so far, in
eleven shapes; copy the one closer to yours:

- `syn_flood` ([synflood.go](../internal/rules/synflood.go)) counts
  events per key in a sliding window: "N incomplete handshakes within S
  seconds" (`windowCounter`).
- `port_scan`, `host_sweep` and `ping_sweep`
  ([scan.go](../internal/rules/scan.go)) count distinct values per key:
  "N different ports (or hosts) within S seconds" (`distinctCounter`).
- `ttl_anomaly` ([ttl.go](../internal/rules/ttl.go)) learns a per-key
  baseline (hop distances) in its own LRU table and counts deviations
  from it in a `windowCounter`.
- `frag_attack` ([frag.go](../internal/rules/frag.go)) checks single
  packets (`kind:tiny`, `oversize`) and, through a shared per-datagram
  tracker that every rule reads, events (`overlap`, and datagrams that
  expire incomplete for `flood`).
- `arp_spoof` ([arp.go](../internal/rules/arp.go)) keeps engine-wide
  tables that every ARP packet feeds (IP→MAC bindings with a change
  history, outstanding requests), and each `kind` compares the packet
  with them: single-packet checks (`static_violation`, `mismatch`,
  `invalid_mac`, `mac_change`) and windowed ones (`flip_flop`,
  `unsolicited_reply` in a `windowCounter`, `multi_ip` in a
  `distinctCounter`).
- `udp_flood` and `icmp_flood` ([udpflood.go](../internal/rules/udpflood.go),
  [icmpflood.go](../internal/rules/icmpflood.go)) sum packets (and
  bytes, and replies) per key in a `rateCounter`, with a `recentSet` of
  recent flows or outstanding echo requests to tell replies from
  unsolicited traffic.
- `icmp_tunnel` ([icmptunnel.go](../internal/rules/icmptunnel.go)) keeps
  a value per event (payload size and entropy) in a `windowCounter` and
  judges the whole window when it is full.
- `slowloris` ([slowloris.go](../internal/rules/slowloris.go)) keeps one
  entry per TCP connection, fed by the per-flow state the stream stage
  writes (`FlowID`, the `http_*` AppFields, `ClosedFlows`), and a group
  per tracked address of the connections that currently qualify. Its
  conditions are about time passing with no packet, so every entry has a
  due time in a heap, checked on every packet and in `Flush`.
- `dns_spoof`, `dns_amplification`, `dns_tunnel` and
  `dns_nxdomain_burst` ([dns.go](../internal/rules/dns.go)) read DNS
  messages. An engine-wide outstanding query table, fed by every query
  whatever the rules say, classifies each response as matched,
  mismatched or unsolicited; the rules then count those outcomes
  (`windowCounter`), distinct ids or names (`distinctCounter`, with a
  per-value entropy or a caller bit), or response and query bytes
  (`rateCounter`). Grouping by domain uses the registered domain
  (eTLD+1 from the Public Suffix List), never "the last two labels".
- `beacon` ([beacon.go](../internal/rules/beacon.go)) keeps a ring of
  the last 32 connection-start times per (source, destination, port,
  protocol) in its own LRU table, and judges the intervals on each new
  start. What counts as a start needs memory of its own: two
  `recentSet`s, one of recent SYNs (to skip retransmissions) and one of
  recent UDP flows (to skip packets inside a flow).
- `baseline` ([baseline.go](../internal/rules/baseline.go)) learns what
  is normal instead of taking a threshold: per metric, an EWMA of the
  value and of its absolute deviation, updated when a fixed interval of
  packet time closes (on the first packet after it). Distinct addresses
  are counted in fixed bitmaps, and per-host state lives in its own LRU
  table. It is ticked on every packet before the whitelist, since time
  passes whatever the packet, and counts only the packets that get past
  it. A learning detector also has to say when it is ready: it queues
  `Notice`s that the IDS logs as events, and publishes a status for the
  dashboard.

The example new detector here is `conn_burst` (a made-up name: many
connections from one source); replace it with yours.

## 1. Decide what you count, per what key, and when it fires

Write it down as one sentence before writing code. For syn_flood: "per
tracked address (server for by_dst, client for by_src), fire when the last
`count` incomplete handshakes fall within `seconds` and at least
`min_incomplete_ratio` of the handshakes in that span were incomplete."

For port_scan: "per source, fire when probes (see scan.go for what
counts) reached `distinct_ports` different ports within `seconds`."

Then list what must not fire (the look-alikes). For syn_flood that is a
busy server whose handshakes complete, and a SYN scan (many incompletes,
but over many ports); for port_scan, a SYN flood (one port), a browser
opening connections to many hosts, and FIN/ACKs from connections that
started before the IDS. Each look-alike becomes a scenario in step 7.

## 2. Accept the rule syntax

- [rule.go](../internal/rules/rule.go): add `const DetectConnBurst =
  "conn_burst"` next to `DetectSYNFlood`. `newRuleSet` puts every rule with
  `Detect != ""` into `rs.detectors`, and sets `rs.handshakes` (run the
  handshake tracker) and `rs.probes` (classify probes) for the detectors
  that need them. Set whichever your detector needs, so rule sets without
  it pay nothing.
- [parse.go](../internal/rules/parse.go): add an entry to
  `detectorOptions` with the options your detector requires and accepts.
  The parser then accepts the name, rejects missing required options,
  rejects options your detector does not take, and rejects detector
  options on rules without `detect`. `track`, `count` and `seconds` are
  already parsed into `r.detect`. Add a `case` only for a new option, add
  it to `knownOption` and the once-only map, and append it to
  `detectOpts`. If the detector only makes sense for some protocols, check
  that in `checkProtoOptions`.
- A detector with several checks takes `kind:` (frag_attack,
  arp_spoof). `kind` is parsed once and validated against the
  detector's own list, so the error names the valid kinds; also check
  which kinds need `count`/`seconds` and reject them on the others.
- A new top-level directive (like `arpbind IP MAC`) is parsed from the
  raw lines before the rules, skipped by the rule loop, and reports
  `file:line` errors the same way (see `parseARPBinds`).
- An option that takes a list of names (dns_tunnel's `allow`) takes a
  name-list variable (`allow:$DNS_TUNNEL_ALLOW;`), resolved by the
  parser like address and port variables, so the list lives once at the
  top of rules.conf.
- Keep limits on every number (`parsePositive(v, maxCount)`). An unbounded
  count is a memory bug waiting for a rule typo.
- Add parse tests for the good rule and each error (unknown option, missing
  required option, option without `detect`, option of another detector)
  in `parse_test.go`, and bump the rule and detector counts in `TestLoad`
  if you add a rule to rules.conf.

## 3. Keep state in bounded counters

Create `internal/rules/connburst.go` with a struct like `synFlood`:

```go
type connBurst struct {
	rule  *Rule
	conns *windowCounter[netip.Addr] // per source
}

func newConnBurst(r *Rule, max int, stat *tableStat) *connBurst {
	return &connBurst{rule: r, conns: newWindowCounter[netip.Addr](r.detect.count, r.detect.span(), max, stat)}
}
```

These do the window, the key cap and eviction counting for you:

- `windowCounter` ([window.go](../internal/rules/window.go)): "count
  events within span". It stores at most `count` timestamps per key.
- `distinctCounter` ([distinct.go](../internal/rules/distinct.go)): "N
  distinct values within span". It stores at most N+1 values per key
  (the +1 tells "more than N" from "exactly N"), each with its last-seen
  time and a few caller bits (the scan detectors keep the probe kinds
  there). Values are searched linearly, so cap N in the parser
  (`maxDistinct`).
- `rateCounter` ([rate.go](../internal/rules/rate.go)): "how much within
  span" as sums in 10 sub-buckets, so memory per key does not grow with
  `count`. Use it for volume thresholds (thousands of packets, bytes);
  it can be up to a tenth of the span late and keeps the most frequent
  tag (a port, an ICMP type) for the alert.
- `recentSet` ([recent.go](../internal/rules/recent.go)): keys seen
  within the last idle, with `has` to ask later ("did this flow send
  anything recently?").

All hold at most `max` keys. Never keep a plain map that grows with
traffic. If you need a second counter, bound it by what can change the
decision: syn_flood keeps completions for the ratio, bounded by
`count*(1-r)/r + 2`, and at most `max_distinct_ports+1` ports per key.

Give the detector its own table in
[engine.go](../internal/rules/engine.go): add `tConnBurst` before
`numTables`, a `TableConnBurst = "conn_burst"` name and an entry in
`tableNames`. Its keys and evictions then appear in every stats record
and in the dashboard with no further work. A helper counter with the same
keys as the main one (syn_flood's ports, port_scan's hosts) gets its own
`tableStat` field in the detector instead, so keys are not counted twice.

## 4. Wire it into the engine

In `engine.go`:

- `ruleState`: add a `burst *connBurst` field.
- `activate`: create it for rules with `r.Detect == DetectConnBurst`
  (`e.cfg.MaxKeys`, `&e.tables[tConnBurst]`). A rule whose text is
  unchanged keeps its state across a reload; update `st.<det>.rule = r`
  there, and `clear()` the state of rules that were removed.
- Feed events. There are three sources:
  - Handshake outcomes, in `handshakeEvents`, which applies the
    whitelist, pass rules and the rule's addresses and ports to each
    outcome as if it were the opening SYN. syn_flood uses these.
  - Probes, in `probe`: scan.go turns packets (`packetProbe`) and
    incomplete handshakes (`handshakeProbe`) into probes, each seen as a
    packet from the prober to the target, and `probe` applies the same
    checks. The scan detectors use these.
  - Single packets, from `Process` after the whitelist and pass checks
    (ttl_anomaly, via `rs.ttl`).
  - TCP flow state, from the stream stage (internal/stream): `FlowID`
    names the connection, the `http_*` AppFields describe the request in
    progress, and `ClosedFlows` lists connections to forget. slowloris
    uses these; it applies the whitelist and pass rules to the
    connection's first packet, and drops the connection when it closes.
  - ARP packets, in `arp` (called from `Process` when `rs.arp` is not
    empty): it feeds the shared ARP tables first, then applies the
    whitelist, pass rules and each rule's addresses.
  - DNS messages, in `dns` (called from `Process` for `AppDNS` packets
    when `rs.dns` is not empty): each query goes into the query table and
    each response is looked up there before the whitelist and pass
    checks, then the rules run on the outcome.
  - Shared trackers that must see every packet whatever the rules say:
    the fragment tracker runs before the whitelist and pass checks so its
    state does not depend on them, and `fragments` applies them to each
    resulting alert instead. Such a tracker is engine state, not rule
    state: it runs only while some rule needs it, is cleared when a
    reload leaves no such rule, and is drained in `Flush`.
- `Flush`: if the detector holds pending work (syn_flood times out every
  open handshake, slowloris re-checks connections that are due), finish
  it there so the end of a pcap still fires.

Use the engine clock (`e.now` or the event time), never `time.Now`.

## 5. Build the alert Details

When the detector fires, return a `dedupKey` and a `details` function,
then call `e.emit(r, key, &view, details, out)`. `emit` handles dedup: one
alert per key, then one summary with the total count. The key is
`dedupKey{sid: r.SID, addr: tracked}`; add `port`/`hasPort` when one
tracked address should alert once per port (host_sweep alerts once per
swept port), and `mac`/`hasMAC` to key on a MAC address (arp_spoof's
unsolicited_reply keys on address and MAC, multi_ip on the MAC alone), and
`peer` for a pair of addresses (icmp_tunnel alerts once per client and
server). syn_flood's details are:

```
detector, track, tracked_addr, incomplete, completed, ratio, distinct_ports, top_dst_port, window
```

port_scan's are `detector, track, tracked_addr, seconds, window,
distinct_ports, scan_types, target_hosts, ports, open_ports`. Cap lists
(the scan detectors list at most 20 hosts or ports).

Include `detector`, `track` and `tracked_addr`, plus the numbers that
justify the alert so an analyst can judge it without the pcap. Keys are
part of the log format: keep them stable, and never put payload bytes in
them.

**Attribution.** `emit` adds `attribution` itself, from `reliable()` in
[attribution.go](../internal/rules/attribution.go). Decide whether your
detector's source address is proven: it is when the source completed a
TCP handshake (or the alert comes from the stream or application layer);
it is not when the alert rests on SYNs, UDP or ICMP packets, which anyone
can forge. An unlisted detector is spoofable, which is the safe default:
its alerts still add to the victim's side of an incident but never name
an attacker. If yours is reliable (always, or on TCP only), add a case to
`reliable()`, add a row to the table in
[ARCHITECTURE.md](ARCHITECTURE.md#attribution), and extend
`TestAttributionClasses`. Give the rule a `category` that a `stage`
directive maps if its alerts should count as a kill-chain stage (see
[RULES.md](RULES.md#stage)); a new category must be added to
`standardCategories` in stage.go, or it is only known when a rule uses it.

## 6. Unit tests

Follow [synflood_test.go](../internal/rules/synflood_test.go) or
[scan_test.go](../internal/rules/scan_test.go): build frames with the
`pkt` helper (it can also build ICMP port unreachables with `unreach`),
run them through the parsers and a real engine, and assert on the alerts.
Cover: fires at exactly `count`, stays quiet at `count - 1`, the window
edge (exactly `seconds` and just over), timestamps that go backwards,
each look-alike, the whitelist, pass rules, and the table cap (a small
`EngineConfig.MaxKeys` plus the eviction counter). New counters get their
own table-driven test, like distinct_test.go.

## 7. Scenarios

Add at least two scenarios ([SCENARIOS.md](SCENARIOS.md)): one that fires
and one look-alike that must not. For syn_flood these are
`syn_flood_single_source`, `syn_flood_spoofed`,
`completed_handshakes_busy` and `scan_is_not_flood`; for port_scan,
`vertical_syn_scan`, `udp_scan`, `flood_is_not_scan` and
`browsing_many_hosts`; for slowloris, `slowloris_slow_headers` and
`browser_keepalive_idle`; for dns_tunnel, `dns_tunnel_base32` and
`dns_cdn_many_subdomains_couk`. Write the generators with `pcapgen` in
[cmd/ids/scenario_gen_test.go](../cmd/ids/scenario_gen_test.go) and match
on `details` in expected.json. A scenario that needs extra rule
lines (an `arpbind`, a pass rule for the look-alike) lists them in
`extra_rules` instead of copying rules.conf. For example:

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
- count what must not count (a completed handshake as a probe)
- let old values live (`> span` to `>= 0`)
- learn from the wrong source (arp_spoof: IP traffic instead of ARP, or
  a `0.0.0.0` sender)

Each mutation must make at least one test fail. If one survives, add the
test that catches it, then revert the mutation.

## 9. Document it

Add the option to [RULES.md](RULES.md), a rule to [rules.conf](../rules.conf)
with a comment on what it catches, and a paragraph to the design decisions
in [ARCHITECTURE.md](ARCHITECTURE.md) if the detector makes a trade-off.
