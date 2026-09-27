# Architecture

## Pipeline

```
 capture goroutine            pipeline goroutine (one)                     writer goroutine
 -----------------            ------------------------                     ----------------
 libpcap (iface / file)
   |  copy frame into a
   |  new ParsedPacket
   v
 [queue: chan, 10000] ---> lower.Parse   Ethernet, VLAN, IPv4/IPv6, ARP
   live: drop when full      upper.Parse   TCP, UDP, ICMP/ICMPv6, checksums
   file: wait                app.Parse     HTTP, DNS, FTP, TLS ClientHello
                             engine.Process  rules, handshakes, dedup
                               |
                               +--> alerts --> [chan] --> JSON Lines log (rotating)
                               +--> alerts --> dashboard (or stdout with -no-tui)
                               +--> traffic counters (dashboard, stats records)
```

The entry point is `run()` in [cmd/ids/run.go](../cmd/ids/run.go): it
loads the rules, opens the capture, opens the log and then starts the
three goroutines. On shutdown the capture closes its channel. The
pipeline then calls `engine.Flush` (so pending summaries are logged),
writes a final stats record and closes the log.

## The ParsedPacket contract

[internal/packet](../internal/packet/packet.go) defines `ParsedPacket`, the
only thing stages share.

- Each field is written by exactly one stage and read only by later ones.
  The field comments name the owner (1 capture, 2 lower, 3 upper, 4 app).
- `RawData` is a copy owned by the packet, never a buffer libpcap reuses,
  and no stage modifies it.
- A stage never rejects a packet. It fills in what it could decode and
  records problems with `AddError` (for `ParseErrors`) or `AddAppReason`
  (for `malformed` / `suspicious` reasons). Later stages check the offsets
  (`L3Offset`, `L4Offset`, `-1` when unknown) before reading.
- `internal/packet` imports no other internal package, and a change to the
  struct is a change to every module.

## Design decisions

**Stateless parsers.** Every parser decodes one frame on its own: there is
no TCP reassembly, flow table or IP defragmentation. That keeps parsing
bounded and impossible to exhaust with state, at the price of missing
anything split across segments (see [Known gaps](#known-gaps)). State
lives in the rule engine, in bounded tables.

**Single-threaded parse and engine.** One goroutine parses and matches
every packet, in capture order. The handshake tracker and the dedup
windows need packets in order and would need locks otherwise. The whole
path measured about 2.7 s for a million flood SYNs from a pcap, so one
core is not the bottleneck for this project. Capture and log writing are
the only other goroutines, joined by channels.

**Packet-time clock.** The engine's clock is the packet timestamp, never
`time.Now`, and it never goes backwards: `now = max(now, p.Timestamp)`.
Replaying a pcap gives the same alerts every time. A capture clock that
steps back (WSL2 does this) can neither reopen a closed window nor shrink
an open one.

**Checksum policy.** Transport checksums are verified and reported
(`L4ChecksumStatus`), but nothing alerts on them and the handshake
tracker ignores them. With checksum offload, every packet the capturing
host sends has a checksum the NIC has not filled in yet (12,732 of 27,908
frames in the 10-minute eth0 recording), and receive offload can merge
inbound segments without fixing theirs.

**GRO and oversized frames.** GRO/TSO hands libpcap merged frames of up to
64 KB, so the default snaplen is 262144 and an IP length over 1500 is not
malformed. Such frames keep their checksum unchecked, because it never
covered the merged bytes. Rules see one large payload, which only helps
content matching.

**Credential redaction.** Parsers never store credentials. The HTTP
`Authorization` header only sets `auth_basic=true`, and the FTP `PASS`
argument is stored as `<redacted>`. Alert records never include app fields
at all, and parse errors never quote packet bytes. The scenarios check the
log and stdout for the planted passwords; the parser unit tests check the
redaction itself.

**Bounded tables.** Every engine table (dedup, handshakes,
detection_filter and syn_flood windows) holds at most 50,000 keys. At the
cap, the least recently seen key is evicted and counted in the stats
record (`evictions`), so memory stays flat under attack. An evicted
handshake counts as incomplete, which is right for a flood. In the
stress test, 1,000,000 spoofed sources peaked at 104 MB RSS (about 35 MB
of live heap), evicted 950,000 keys from each table and still raised the
by_dst alert.

**by_dst SYN-flood tracking.** A spoofed flood uses a new source for every
SYN, so no source ever reaches the threshold. `track:by_dst` counts failed
handshakes per server, and `min_incomplete_ratio` (default 0.8) keeps a
busy server quiet as long as most of its handshakes complete. The
completions window keeps only the `count*(1-r)/r + 2` entries that can
change the ratio decision. That bounds it at 27 per server for the default
rule.

**WSL2 limitations.** The development machine is WSL2, where DNS goes to a
proxy on `lo` rather than `eth0`, the clock sometimes steps backwards, and
Hyper-V coalescing produces oversized frames and bad inbound checksums.
Each of these looked like a bug at first; the decisions above are how the
IDS stays correct regardless. Linux `lo` is Ethernet-framed, so it can be
captured; the `any` device and macOS loopback cannot.

## Known gaps

**DNS over TCP split across segments.** Without TCP reassembly, the DNS
parser sees each segment alone. When a client or server writes the 2-byte
length prefix and the message separately, or a boundary splits the prefix
1+1, the segment holding the message does not start with its length. Such
a segment does not frame cleanly and is classed as unknown traffic, not
malformed DNS (it used to raise a false `Malformed DNS message` alert on
tcpdump's `dns_tcp.pcap`). The price is that the message is not decoded at
all: in chrissanders' `dns_axfr.pcapng` the AXFR query arrives as a
2-byte prefix segment followed by the message, so a rule on
`app_field:qtype_name=AXFR` misses it. Likewise, a malformed message is
reported only when its length prefix matches the segment, since the start
of a longer message could be misaligned. TCP stream reassembly, planned
for the next step, closes this gap.

## Testing layers

| layer | where | what it proves |
|---|---|---|
| unit tests | `internal/*/..._test.go` | each parser and engine table |
| scenarios | [testdata/scenarios](../testdata/scenarios), [SCENARIOS.md](SCENARIOS.md) | end-to-end alerts through `run()` |
| fuzz | `FuzzPipeline` in cmd/ids | no panics, well-formed alerts on any input |
| edge cases | `TestPcapEdgeCases`, `TestSpoofedFloodTableCap` | damaged pcaps, time jumps, the table cap |

`make test`, `make scenarios` and `make fuzz` run them; CI runs all of them
with `-race`.
